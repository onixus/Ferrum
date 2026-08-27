//! Static inspection of the compiled `ferrum-ebpf-progs` ELF: every
//! tracepoint program and map must be present before attach is even tried.
//!
//! The ELF path comes from `FERRUM_BPF_ELF` (CI builds it with nightly +
//! bpfel-unknown-none and exports the path); without the env var the test
//! skips, because the stable workspace build cannot produce the ELF itself.
//! Parsing is hand-rolled ELF64LE (headers + symtab) to keep ferrum-ebpf
//! free of ELF crates.

use ferrum_ebpf::{CGROUPS_MAX_ENTRIES, MAP_CGROUPS, MAP_EVENTS, MAP_SELF, TRACEPOINTS};

const SHT_SYMTAB: u32 = 2;
const STT_FUNC: u8 = 2;
const STT_OBJECT: u8 = 1;

/// `bpf_map_def` as aya-ebpf emits it into the `maps` section: seven u32s
/// (type, key_size, value_size, max_entries, map_flags, id, pinning).
const MAP_DEF_LEN: usize = 28;
const BPF_MAP_TYPE_HASH: u32 = 1;

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

    for map in [MAP_EVENTS, MAP_CGROUPS, MAP_SELF] {
        let sym = syms
            .iter()
            .find(|s| s.name == map)
            .unwrap_or_else(|| panic!("map symbol {map} missing from {path}"));
        assert_eq!(sym.kind, STT_OBJECT, "{map} is not a map object");
        assert_eq!(sym.section, "maps", "{map} is outside the maps section");
    }
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
    let syms = symbols(&elf);
    let sym = syms
        .iter()
        .find(|s| s.name == MAP_CGROUPS)
        .unwrap_or_else(|| panic!("map symbol {MAP_CGROUPS} missing from {path}"));
    assert_eq!(
        sym.size, MAP_DEF_LEN,
        "{MAP_CGROUPS} is {} bytes, expected a {MAP_DEF_LEN}-byte bpf_map_def",
        sym.size
    );
    let data = section_data(&elf, sym);
    let def = &data[sym.value..sym.value + MAP_DEF_LEN];
    assert_eq!(
        u32_field(def, 0),
        BPF_MAP_TYPE_HASH,
        "{MAP_CGROUPS} is not BPF_MAP_TYPE_HASH"
    );
    assert_eq!(
        u32_field(def, 1),
        8,
        "{MAP_CGROUPS} key is not a u64 cgroup id"
    );
    assert_eq!(u32_field(def, 2), 1, "{MAP_CGROUPS} value is not a u8 flag");
    assert_eq!(
        u32_field(def, 3),
        CGROUPS_MAX_ENTRIES,
        "{MAP_CGROUPS} max_entries disagrees with CGROUPS_MAX_ENTRIES, which is what \
         plan_cgroup_sync refuses to overflow"
    );
}
