//! Static inspection of the compiled `ferrum-ebpf-progs` ELF: every
//! tracepoint program and map must be present before attach is even tried.
//!
//! The ELF path comes from `FERRUM_BPF_ELF` (CI builds it with nightly +
//! bpfel-unknown-none and exports the path); without the env var the test
//! skips, because the stable workspace build cannot produce the ELF itself.
//! Parsing is hand-rolled ELF64LE (headers + symtab) to keep ferrum-ebpf
//! free of ELF crates.

use ferrum_ebpf::{MAP_CGROUPS, MAP_EVENTS, MAP_SELF, TRACEPOINTS};

const SHT_SYMTAB: u32 = 2;
const STT_FUNC: u8 = 2;
const STT_OBJECT: u8 = 1;

struct Sym {
    name: String,
    kind: u8,
    section: String,
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
            }
        })
        .collect()
}

#[test]
fn elf_contains_all_tracepoints() {
    let Ok(path) = std::env::var("FERRUM_BPF_ELF") else {
        // In the BPF ELF CI stage the skip must be a failure, or a lost env
        // var silently turns the only real gate into a no-op.
        if std::env::var_os("FERRUM_BPF_ELF_REQUIRED").is_some() {
            panic!("FERRUM_BPF_ELF_REQUIRED is set but FERRUM_BPF_ELF is not");
        }
        println!("skipping: FERRUM_BPF_ELF not set (no compiled bpf ELF to inspect)");
        return;
    };
    let elf = std::fs::read(&path).unwrap_or_else(|err| panic!("read {path}: {err}"));
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
