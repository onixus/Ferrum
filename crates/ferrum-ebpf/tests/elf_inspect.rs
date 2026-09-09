//! Static inspection of the compiled `ferrum-ebpf-progs` ELF: every
//! tracepoint program and map must be present before attach is even tried.
//!
//! The ELF path comes from `FERRUM_BPF_ELF` (CI builds it with nightly +
//! bpfel-unknown-none and exports the path); without the env var the test
//! skips, because the stable workspace build cannot produce the ELF itself.
//! Parsing is hand-rolled ELF64LE (headers + symtab) to keep ferrum-ebpf
//! free of ELF crates.

use ferrum_ebpf::{
    elf_map_def, verify_map_defs, CGROUPS_MAX_ENTRIES, EVENTS_RING_BYTES, KERNEL_RULE_SIZE,
    LSM_PROGRAMS, MAP_CGROUPS, MAP_DEF_LEN, MAP_EVENTS, MAP_RULES, MAP_SELECTED, MAP_SELF,
    MAX_KERNEL_RULES, REQUIRED_MAPS, TRACEPOINTS,
};

const SHT_SYMTAB: u32 = 2;
const STT_FUNC: u8 = 2;
const STT_OBJECT: u8 = 1;

const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_MAP_TYPE_RINGBUF: u32 = 27;

struct Sym {
    name: String,
    kind: u8,
    section: String,
    /// Offset of the symbol inside its section, and its declared size.
    value: usize,
    size: usize,
    shndx: usize,
}

fn u16_at(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(data[off..off + 2].try_into().expect("u16"))
}

fn u32_at(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().expect("u32"))
}

fn u64_at(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().expect("u64"))
}

fn cstr_at(strtab: &[u8], off: usize) -> String {
    let end = strtab[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|len| off + len)
        .expect("unterminated string in strtab");
    String::from_utf8_lossy(&strtab[off..end]).into_owned()
}

/// Section byte range (offset, size, type, link, name offset) per header.
struct Section {
    name_off: usize,
    kind: u32,
    offset: usize,
    size: usize,
    link: usize,
    entsize: usize,
}

fn sections(elf: &[u8]) -> Vec<Section> {
    assert_eq!(&elf[..4], b"\x7fELF", "not an ELF file");
    assert_eq!(elf[4], 2, "expected ELF64");
    assert_eq!(elf[5], 1, "expected little-endian (bpfel)");
    let shoff = u64_at(elf, 0x28) as usize;
    let shentsize = u16_at(elf, 0x3a) as usize;
    let shnum = u16_at(elf, 0x3c) as usize;
    (0..shnum)
        .map(|i| {
            let base = shoff + i * shentsize;
            Section {
                name_off: u32_at(elf, base) as usize,
                kind: u32_at(elf, base + 4),
                offset: u64_at(elf, base + 24) as usize,
                size: u64_at(elf, base + 32) as usize,
                link: u32_at(elf, base + 40) as usize,
                entsize: u64_at(elf, base + 56) as usize,
            }
        })
        .collect()
}

fn symbols(elf: &[u8]) -> Vec<Sym> {
    let sections = sections(elf);
    let shstrndx = u16_at(elf, 0x3e) as usize;
    let shstrtab = &elf[sections[shstrndx].offset..][..sections[shstrndx].size];
    let section_name = |index: usize| -> String { cstr_at(shstrtab, sections[index].name_off) };

    let symtab = sections
        .iter()
        .find(|s| s.kind == SHT_SYMTAB)
        .expect("no symtab in bpf ELF");
    let strtab = &elf[sections[symtab.link].offset..][..sections[symtab.link].size];
    let entsize = if symtab.entsize == 0 {
        24
    } else {
        symtab.entsize
    };
    let bytes = &elf[symtab.offset..][..symtab.size];
    bytes
        .chunks_exact(entsize)
        .map(|entry| {
            let shndx = u16_at(entry, 6) as usize;
            Sym {
                name: cstr_at(strtab, u32_at(entry, 0) as usize),
                kind: entry[4] & 0xf,
                section: if shndx < sections.len() {
                    section_name(shndx)
                } else {
                    String::new()
                },
                value: u64_at(entry, 8) as usize,
                size: u64_at(entry, 16) as usize,
                shndx,
            }
        })
        .collect()
}

/// Bytes of the section a symbol lives in.
fn section_data<'a>(elf: &'a [u8], sym: &Sym) -> &'a [u8] {
    let section = &sections(elf)[sym.shndx];
    &elf[section.offset..section.offset + section.size]
}

fn u32_field(def: &[u8], index: usize) -> u32 {
    u32_at(def, index * 4)
}

/// The compiled ELF, or None when there is nothing to inspect. In the BPF ELF
/// CI stage a skip is a failure, or a lost env var silently turns the only
/// real gate into a no-op.
fn elf_or_skip() -> Option<(String, Vec<u8>)> {
    let Ok(path) = std::env::var("FERRUM_BPF_ELF") else {
        if std::env::var_os("FERRUM_BPF_ELF_REQUIRED").is_some() {
            panic!("FERRUM_BPF_ELF_REQUIRED is set but FERRUM_BPF_ELF is not");
        }
        println!("skipping: FERRUM_BPF_ELF not set (no compiled bpf ELF to inspect)");
        return None;
    };
    let elf = std::fs::read(&path).unwrap_or_else(|err| panic!("read {path}: {err}"));
    Some((path, elf))
}

#[test]
fn elf_contains_all_tracepoints() {
    let Some((path, elf)) = elf_or_skip() else {
        return;
    };
    let syms = symbols(&elf);

    for (prog, category, name) in TRACEPOINTS {
        let section = format!("tracepoint/{category}/{name}");
        let sym = syms
            .iter()
            .find(|s| s.name == *prog)
            .unwrap_or_else(|| panic!("program symbol {prog} missing from {path}"));
        assert_eq!(sym.kind, STT_FUNC, "{prog} is not a function");
        assert_eq!(sym.section, section, "{prog} is in the wrong section");
    }

    for (prog, hook) in LSM_PROGRAMS {
        let section = format!("lsm/{hook}");
        let sym = syms
            .iter()
            .find(|s| s.name == *prog)
            .unwrap_or_else(|| panic!("LSM program symbol {prog} missing from {path}"));
        assert_eq!(sym.kind, STT_FUNC, "{prog} is not a function");
        assert_eq!(sym.section, section, "{prog} is in the wrong section");
    }

    // Over REQUIRED_MAPS and not a list written here: a map added to the
    // userspace ABI and dropped by the bpf linker for want of a reader is
    // exactly the failure this test exists for, and a hand-kept list would
    // have to be remembered at the same moment it is needed.
    for map in REQUIRED_MAPS.iter().map(|def| def.name) {
        let sym = syms
            .iter()
            .find(|s| s.name == map)
            .unwrap_or_else(|| panic!("map symbol {map} missing from {path}"));
        assert_eq!(sym.kind, STT_OBJECT, "{map} is not a map object");
        assert_eq!(sym.section, "maps", "{map} is outside the maps section");
    }
}

/// Read one map definition with this test's own ELF parser, so the crate's
/// `elf_map_def` — which the agent runs before every attach — is checked
/// against a second implementation rather than only against itself.
fn map_def_here(elf: &[u8], path: &str, name: &str) -> [u32; 4] {
    let syms = symbols(elf);
    let sym = syms
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("map symbol {name} missing from {path}"));
    assert_eq!(
        sym.size, MAP_DEF_LEN,
        "{name} is {} bytes, expected a {MAP_DEF_LEN}-byte bpf_map_def",
        sym.size
    );
    let data = section_data(elf, sym);
    let def = &data[sym.value..sym.value + MAP_DEF_LEN];
    [
        u32_field(def, 0),
        u32_field(def, 1),
        u32_field(def, 2),
        u32_field(def, 3),
    ]
}

/// Static ABI check of `ferrum_cgroups`, NOT a check that attach works: the
/// map definition compiled into the ELF must match what
/// `KernelHandle::sync_container_cgroups` writes (u64 -> u8) and what
/// `plan_cgroup_sync` sizes against. A silent drift here means the container
/// flag is never set and every `container_only` rule stops matching.
#[test]
fn cgroups_map_definition_matches_the_userspace_abi() {
    let Some((path, elf)) = elf_or_skip() else {
        return;
    };
    let def = map_def_here(&elf, &path, MAP_CGROUPS);
    assert_eq!(def[0], BPF_MAP_TYPE_HASH, "{MAP_CGROUPS} is not a hash map");
    assert_eq!(def[1], 8, "{MAP_CGROUPS} key is not a u64 cgroup id");
    assert_eq!(def[2], 1, "{MAP_CGROUPS} value is not a u8 flag");
    assert_eq!(
        def[3], CGROUPS_MAX_ENTRIES,
        "{MAP_CGROUPS} max_entries disagrees with CGROUPS_MAX_ENTRIES, which is what \
         plan_cgroup_sync refuses to overflow"
    );
}

/// Static ABI check of `ferrum_selected`. Same shape as `ferrum_cgroups`, and
/// a drift here is the dangerous direction: a set the hook reads as membership
/// while userspace writes something else makes a selected policy fire in
/// containers it does not select, or in none at all.
#[test]
fn selected_map_definition_matches_the_userspace_abi() {
    let Some((path, elf)) = elf_or_skip() else {
        return;
    };
    let def = map_def_here(&elf, &path, MAP_SELECTED);
    assert_eq!(
        def[0], BPF_MAP_TYPE_HASH,
        "{MAP_SELECTED} is not a hash map"
    );
    assert_eq!(def[1], 8, "{MAP_SELECTED} key is not a u64 cgroup id");
    assert_eq!(def[2], 1, "{MAP_SELECTED} value is not a u8 flag");
    assert_eq!(
        def[3], CGROUPS_MAX_ENTRIES,
        "{MAP_SELECTED} max_entries disagrees with CGROUPS_MAX_ENTRIES, which is what \
         plan_cgroup_sync refuses to overflow for this set too"
    );
}

/// Static ABI check of `ferrum_rules`. The two sides both write and read
/// `KernelRule` by its byte layout, so a slot that grew on one side and not
/// the other has the kernel matching on fields that are not there. An array
/// and not a hash on purpose: the in-kernel walk has a fixed trip count.
#[test]
fn rules_map_definition_matches_the_userspace_abi() {
    let Some((path, elf)) = elf_or_skip() else {
        return;
    };
    let def = map_def_here(&elf, &path, MAP_RULES);
    assert_eq!(
        def[0], BPF_MAP_TYPE_ARRAY,
        "{MAP_RULES} is not an array map"
    );
    assert_eq!(def[1], 4, "{MAP_RULES} key is not a u32 slot index");
    assert_eq!(
        def[2], KERNEL_RULE_SIZE,
        "{MAP_RULES} value is not a KernelRule; the shipped object and this build disagree \
         about the layout both of them write"
    );
    assert_eq!(
        def[3], MAX_KERNEL_RULES,
        "{MAP_RULES} max_entries disagrees with MAX_KERNEL_RULES, which is the bound \
         compile_kernel_rules refuses to exceed and the trip count the hook walks"
    );
}

/// `ferrum_events` is the only path records take out of the kernel. A type
/// that is no longer a ring buffer, or a byte size that is not the one the
/// reader expects, means `take_ring` fails or the ring silently drops under a
/// load the drop counter was sized for.
#[test]
fn events_map_definition_matches_the_userspace_abi() {
    let Some((path, elf)) = elf_or_skip() else {
        return;
    };
    let def = map_def_here(&elf, &path, MAP_EVENTS);
    assert_eq!(
        def[0], BPF_MAP_TYPE_RINGBUF,
        "{MAP_EVENTS} is not a ring buffer; RingBuf::try_from would fail at attach"
    );
    assert_eq!(def[1], 0, "{MAP_EVENTS} ring buffers carry no key");
    assert_eq!(def[2], 0, "{MAP_EVENTS} ring buffers carry no value size");
    assert_eq!(
        def[3], EVENTS_RING_BYTES,
        "{MAP_EVENTS} byte size disagrees with EVENTS_RING_BYTES"
    );
}

/// `ferrum_self` carries the agent's own tgid. If its value width drifts, the
/// datapath compares against a truncated tgid, `EVENT_FLAG_AGENT_SELF` stops
/// being set, and the agent can be told to kill itself.
#[test]
fn self_map_definition_matches_the_userspace_abi() {
    let Some((path, elf)) = elf_or_skip() else {
        return;
    };
    let def = map_def_here(&elf, &path, MAP_SELF);
    assert_eq!(def[0], BPF_MAP_TYPE_ARRAY, "{MAP_SELF} is not an array map");
    assert_eq!(def[1], 4, "{MAP_SELF} key is not a u32 array index");
    assert_eq!(
        def[2], 8,
        "{MAP_SELF} value is not the u64 set_self_tgid writes"
    );
    assert_eq!(
        def[3], 1,
        "{MAP_SELF} is not the single slot Array::get(0) reads"
    );
}

/// The gate the agent itself runs: `KernelHandle::attach` refuses to load an
/// ELF whose maps do not match, so the shipped ELF must pass the same check
/// here, before it reaches a node.
#[test]
fn the_shipped_elf_passes_the_attach_time_map_check() {
    let Some((path, elf)) = elf_or_skip() else {
        return;
    };
    verify_map_defs(&elf).unwrap_or_else(|err| panic!("{path} would be refused at attach: {err}"));
    for expected in REQUIRED_MAPS {
        let found = elf_map_def(&elf, expected.name).expect("map def");
        assert_eq!(&found, expected);
        assert_eq!(
            map_def_here(&elf, &path, expected.name),
            [
                expected.map_type,
                expected.key_size,
                expected.value_size,
                expected.max_entries
            ],
            "{} read differently by the two parsers",
            expected.name
        );
    }
}
