//! Where `linux_binprm::filename` lives in the running kernel, read out of
//! that kernel's own BTF.
//!
//! This is the CO-RE this tree does not have, cut down to the one field the
//! exec hook needs. `aya-ebpf` emits no field relocations, so the program
//! cannot ask the loader to fix an offset up; instead the agent reads the
//! offset here and hands it to the program as a read-only global before load
//! (`KernelHandle::attach_for_arch`). aya freezes `.rodata` after filling it,
//! so the value the verifier sees is the value every exec is decided with.
//!
//! The parser is written here rather than borrowed from `aya-obj`, whose
//! `Btf` keeps type lookup crate-private: what is needed is one struct's
//! members by name, and a type chain followed to its end. It is plain bytes
//! in, no `aya`, so it is built and tested on every host and not only under
//! the `attach` feature.
//!
//! What it refuses, and why each is a refusal rather than a guess:
//!
//! * a blob that is not little-endian BTF version 1 — every target this ships
//!   to is little-endian, and a byte-swapped read would produce offsets that
//!   look plausible;
//! * no `struct linux_binprm`, or more than one with different layouts;
//! * no `filename` member, or one that is a bitfield or not byte-aligned;
//! * a `filename` that is not a pointer to `char` through any number of
//!   `const`/`volatile`/`typedef` — an offset that lands on a field of another
//!   type is the exact failure a hand-written offset had.

use std::fmt;

/// Where vmlinux BTF is served on a kernel built with `CONFIG_DEBUG_INFO_BTF`.
pub const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";

const MAGIC: u16 = 0xeb9f;
const HEADER_LEN: usize = 24;
const TYPE_LEN: usize = 12;

const KIND_INT: u32 = 1;
const KIND_PTR: u32 = 2;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_FWD: u32 = 7;
const KIND_TYPEDEF: u32 = 8;
const KIND_VOLATILE: u32 = 9;
const KIND_CONST: u32 = 10;
const KIND_RESTRICT: u32 = 11;
const KIND_FUNC: u32 = 12;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_FLOAT: u32 = 16;
const KIND_DECL_TAG: u32 = 17;
const KIND_TYPE_TAG: u32 = 18;
const KIND_ENUM64: u32 = 19;

/// Why the offset could not be established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfError(pub String);

impl fmt::Display for BtfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn err<T>(msg: impl Into<String>) -> Result<T, BtfError> {
    Err(BtfError(msg.into()))
}

#[derive(Clone, Copy)]
struct Type {
    name_off: u32,
    kind: u32,
    vlen: u32,
    kind_flag: bool,
    /// `size` or `type`, depending on the kind.
    size_or_type: u32,
    /// Byte offset of the trailing data in the type section.
    extra: usize,
}

struct Btf<'a> {
    types: Vec<Type>,
    type_sec: &'a [u8],
    strings: &'a [u8],
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

impl<'a> Btf<'a> {
    fn parse(blob: &'a [u8]) -> Result<Self, BtfError> {
        let magic = u16_at(blob, 0).ok_or_else(|| BtfError("BTF shorter than its magic".into()))?;
        if magic != MAGIC {
            return err(format!(
                "BTF magic {magic:#06x}, want {MAGIC:#06x} little-endian; a byte-swapped read \
                 would yield offsets that only look right"
            ));
        }
        if blob.get(2) != Some(&1) {
            return err(format!("BTF version {:?}, want 1", blob.get(2)));
        }
        let field = |at| u32_at(blob, at).ok_or_else(|| BtfError("BTF header is truncated".into()));
        let hdr_len = field(4)? as usize;
        if hdr_len < HEADER_LEN {
            return err(format!("BTF header length {hdr_len} < {HEADER_LEN}"));
        }
        let (type_off, type_len) = (field(8)? as usize, field(12)? as usize);
        let (str_off, str_len) = (field(16)? as usize, field(20)? as usize);
        let section = |off: usize, len: usize, what: &str| {
            hdr_len
                .checked_add(off)
                .and_then(|start| Some((start, start.checked_add(len)?)))
                .and_then(|(start, end)| blob.get(start..end))
                .ok_or_else(|| BtfError(format!("BTF {what} section lies outside the blob")))
        };
        let type_sec = section(type_off, type_len, "type")?;
        let strings = section(str_off, str_len, "string")?;

        // Type ids start at 1; id 0 is `void` and has no record.
        let mut types = Vec::new();
        let mut at = 0;
        while at < type_sec.len() {
            let truncated = || BtfError(format!("BTF type record at {at} is truncated"));
            let name_off = u32_at(type_sec, at).ok_or_else(truncated)?;
            let info = u32_at(type_sec, at + 4).ok_or_else(truncated)?;
            let size_or_type = u32_at(type_sec, at + 8).ok_or_else(truncated)?;
            let vlen = info & 0xffff;
            let kind = (info >> 24) & 0x1f;
            let extra = at + TYPE_LEN;
            let trailing = match kind {
                KIND_INT | KIND_VAR | KIND_DECL_TAG => 4,
                KIND_ARRAY => 12,
                KIND_STRUCT | KIND_UNION | KIND_DATASEC | KIND_ENUM64 => 12 * vlen as usize,
                KIND_ENUM | KIND_FUNC_PROTO => 8 * vlen as usize,
                KIND_PTR | KIND_FWD | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT
                | KIND_FUNC | KIND_FLOAT | KIND_TYPE_TAG => 0,
                other => {
                    // An unknown kind has an unknown length, so every record
                    // after it would be read out of frame.
                    return err(format!(
                        "BTF type {} has kind {other}, which this reader does not know the \
                         length of",
                        types.len() + 1
                    ));
                }
            };
            types.push(Type {
                name_off,
                kind,
                vlen,
                kind_flag: info >> 31 == 1,
                size_or_type,
                extra,
            });
            at = extra + trailing;
        }
        if at != type_sec.len() {
            return err("BTF type section ends inside a record");
        }
        Ok(Self {
            types,
            type_sec,
            strings,
        })
    }

    fn name(&self, off: u32) -> &'a [u8] {
        let rest = self.strings.get(off as usize..).unwrap_or(&[]);
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        &rest[..end]
    }

    fn by_id(&self, id: u32) -> Option<&Type> {
        id.checked_sub(1).and_then(|i| self.types.get(i as usize))
    }

    /// Follow `typedef`, `const`, `volatile`, `restrict` and type tags to the
    /// type they qualify. Bounded, because a cycle in a hostile blob would
    /// otherwise not end.
    fn strip(&self, mut id: u32) -> Option<&Type> {
        for _ in 0..32 {
            let t = self.by_id(id)?;
            match t.kind {
                KIND_TYPEDEF | KIND_CONST | KIND_VOLATILE | KIND_RESTRICT | KIND_TYPE_TAG => {
                    id = t.size_or_type
                }
                _ => return Some(t),
            }
        }
        None
    }

    /// `(name, type id, bit offset)` of every member of a struct record.
    fn members(&self, t: &Type) -> Vec<(&'a [u8], u32, u32)> {
        (0..t.vlen as usize)
            .filter_map(|i| {
                let at = t.extra + 12 * i;
                let name = self.name(u32_at(self.type_sec, at)?);
                let type_id = u32_at(self.type_sec, at + 4)?;
                let offset = u32_at(self.type_sec, at + 8)?;
                // With kind_flag set the offset word also carries a bitfield
                // size in its top byte.
                let (bits, bitfield) = if t.kind_flag {
                    (offset & 0x00ff_ffff, offset >> 24)
                } else {
                    (offset, 0)
                };
                Some((name, type_id, if bitfield == 0 { bits } else { u32::MAX }))
            })
            .collect()
    }
}

/// Byte offset of `filename` in `struct linux_binprm`, checked to be a
/// pointer to `char`.
pub fn binprm_filename_offset(blob: &[u8]) -> Result<u32, BtfError> {
    let btf = Btf::parse(blob)?;
    let mut found: Option<u32> = None;
    for t in &btf.types {
        if t.kind != KIND_STRUCT || btf.name(t.name_off) != b"linux_binprm" {
            continue;
        }
        let member = btf
            .members(t)
            .into_iter()
            .find(|(name, _, _)| *name == b"filename");
        let Some((_, type_id, bits)) = member else {
            return err("struct linux_binprm has no member `filename`");
        };
        if bits == u32::MAX || bits % 8 != 0 {
            return err("linux_binprm::filename is a bitfield or not byte-aligned");
        }
        let pointer = btf.strip(type_id);
        let pointee = match pointer {
            Some(p) if p.kind == KIND_PTR => btf.strip(p.size_or_type),
            _ => return err("linux_binprm::filename is not a pointer"),
        };
        match pointee {
            Some(c) if c.kind == KIND_INT && btf.name(c.name_off) == b"char" => {}
            _ => return err("linux_binprm::filename does not point at char"),
        }
        let offset = bits / 8;
        if found.is_some_and(|prev| prev != offset) {
            return err("two `struct linux_binprm` in one BTF disagree about where `filename` is");
        }
        found = Some(offset);
    }
    // Zero is never the answer: `filename` is not the first member on any
    // kernel, and the program reads a zero offset as "unknown".
    match found {
        Some(0) => err("linux_binprm::filename at offset 0, which the hook reads as unknown"),
        Some(offset) => Ok(offset),
        None => err("no struct linux_binprm in this BTF"),
    }
}

/// [`binprm_filename_offset`] of the running kernel.
pub fn running_kernel_binprm_filename_offset() -> Result<u32, BtfError> {
    let blob =
        std::fs::read(VMLINUX_BTF).map_err(|e| BtfError(format!("read {VMLINUX_BTF}: {e}")))?;
    binprm_filename_offset(&blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal BTF blob, written out the way the kernel lays it out.
    #[derive(Default)]
    struct Blob {
        types: Vec<u8>,
        strings: Vec<u8>,
        next_id: u32,
    }

    impl Blob {
        fn new() -> Self {
            Self {
                types: Vec::new(),
                strings: vec![0],
                next_id: 1,
            }
        }

        fn str(&mut self, s: &str) -> u32 {
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(s.as_bytes());
            self.strings.push(0);
            off
        }

        fn record(&mut self, name: &str, kind: u32, vlen: u32, flag: bool, word: u32) -> u32 {
            let name = if name.is_empty() { 0 } else { self.str(name) };
            self.types.extend_from_slice(&name.to_le_bytes());
            let info = (u32::from(flag) << 31) | (kind << 24) | vlen;
            self.types.extend_from_slice(&info.to_le_bytes());
            self.types.extend_from_slice(&word.to_le_bytes());
            let id = self.next_id;
            self.next_id += 1;
            id
        }

        fn int(&mut self, name: &str) -> u32 {
            let id = self.record(name, KIND_INT, 0, false, 1);
            self.types.extend_from_slice(&8u32.to_le_bytes());
            id
        }

        fn wrap(&mut self, kind: u32, of: u32) -> u32 {
            self.record("", kind, 0, false, of)
        }

        fn strukt(&mut self, name: &str, members: &[(&str, u32, u32)], flag: bool) -> u32 {
            let id = self.record(name, KIND_STRUCT, members.len() as u32, flag, 256);
            for (m, ty, bits) in members {
                let n = self.str(m);
                self.types.extend_from_slice(&n.to_le_bytes());
                self.types.extend_from_slice(&ty.to_le_bytes());
                self.types.extend_from_slice(&bits.to_le_bytes());
            }
            id
        }

        fn bytes(&self) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&MAGIC.to_le_bytes());
            out.push(1);
            out.push(0);
            out.extend_from_slice(&(HEADER_LEN as u32).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(self.types.len() as u32).to_le_bytes());
            out.extend_from_slice(&(self.types.len() as u32).to_le_bytes());
            out.extend_from_slice(&(self.strings.len() as u32).to_le_bytes());
            out.extend_from_slice(&self.types);
            out.extend_from_slice(&self.strings);
            out
        }
    }

    /// `const char *filename` behind a typedef'd `char`, at byte 72.
    fn kernel_like(filename_bits: u32) -> Blob {
        let mut b = Blob::new();
        let char_ = b.int("char");
        let long = b.int("long");
        let constc = b.wrap(KIND_CONST, char_);
        let ptr = b.wrap(KIND_PTR, constc);
        let longptr = b.wrap(KIND_PTR, long);
        b.strukt(
            "linux_binprm",
            &[
                ("vma", longptr, 0),
                ("p", long, 64),
                ("filename", ptr, filename_bits),
            ],
            false,
        );
        b
    }

    #[test]
    fn the_offset_of_a_char_pointer_named_filename_is_found() {
        assert_eq!(binprm_filename_offset(&kernel_like(576).bytes()), Ok(72));
    }

    #[test]
    fn a_member_of_another_type_is_refused_rather_than_used() {
        let mut b = Blob::new();
        let long = b.int("long");
        let longptr = b.wrap(KIND_PTR, long);
        b.strukt(
            "linux_binprm",
            &[("p", long, 0), ("filename", longptr, 64)],
            false,
        );
        let e = binprm_filename_offset(&b.bytes()).unwrap_err();
        assert!(e.0.contains("char"), "{e}");

        let mut b = Blob::new();
        let long = b.int("long");
        b.strukt(
            "linux_binprm",
            &[("p", long, 0), ("filename", long, 64)],
            false,
        );
        assert!(binprm_filename_offset(&b.bytes())
            .unwrap_err()
            .0
            .contains("pointer"));
    }

    #[test]
    fn a_missing_struct_or_member_is_named() {
        let mut b = Blob::new();
        let long = b.int("long");
        b.strukt("linux_binprm", &[("p", long, 0)], false);
        assert!(binprm_filename_offset(&b.bytes())
            .unwrap_err()
            .0
            .contains("filename"));

        let mut b = Blob::new();
        b.int("char");
        assert!(binprm_filename_offset(&b.bytes())
            .unwrap_err()
            .0
            .contains("no struct"));
    }

    #[test]
    fn a_bitfield_or_unaligned_member_is_refused() {
        assert!(binprm_filename_offset(&kernel_like(577).bytes()).is_err());
        let mut b = Blob::new();
        let char_ = b.int("char");
        let ptr = b.wrap(KIND_PTR, char_);
        // kind_flag set and a bitfield size of 3 in the top byte.
        b.strukt("linux_binprm", &[("filename", ptr, (3 << 24) | 64)], true);
        assert!(binprm_filename_offset(&b.bytes()).is_err());
        // kind_flag set, no bitfield: the offset is the low 24 bits.
        let mut b = Blob::new();
        let char_ = b.int("char");
        let ptr = b.wrap(KIND_PTR, char_);
        b.strukt("linux_binprm", &[("filename", ptr, 64)], true);
        assert_eq!(binprm_filename_offset(&b.bytes()), Ok(8));
    }

    #[test]
    fn two_layouts_in_one_blob_are_a_refusal() {
        let mut b = kernel_like(576);
        let char_ = b.int("char");
        let ptr = b.wrap(KIND_PTR, char_);
        b.strukt("linux_binprm", &[("filename", ptr, 640)], false);
        assert!(binprm_filename_offset(&b.bytes())
            .unwrap_err()
            .0
            .contains("disagree"));
    }

    #[test]
    fn a_damaged_blob_is_refused_not_misread() {
        let good = kernel_like(576).bytes();
        let mut swapped = good.clone();
        swapped.swap(0, 1);
        assert!(binprm_filename_offset(&swapped)
            .unwrap_err()
            .0
            .contains("magic"));
        assert!(binprm_filename_offset(&good[..good.len() - 40]).is_err());
        assert!(binprm_filename_offset(&good[..10]).is_err());
        let mut unknown_kind = good.clone();
        // The first record's info word: kind 31.
        unknown_kind[HEADER_LEN + 7] = 31;
        assert!(binprm_filename_offset(&unknown_kind)
            .unwrap_err()
            .0
            .contains("kind"));
    }

    /// Against a real vmlinux BTF: the one named by `FERRUM_VMLINUX_BTF`, or
    /// the running kernel's where it serves one.
    ///
    /// The variable is what lets a kernel without a stand be checked: its BTF
    /// is a file (`/sys/kernel/btf/vmlinux` copied off a host, or an archive
    /// such as BTFHub's), and the question this module answers needs nothing
    /// else from that kernel. The datapath stages run it with no variable on
    /// the CI nodes, which is where the reader meets the kernel it loads into.
    #[test]
    fn a_real_vmlinux_btf_answers() {
        let path = std::env::var("FERRUM_VMLINUX_BTF").unwrap_or_else(|_| VMLINUX_BTF.into());
        let Ok(blob) = std::fs::read(&path) else {
            println!("skipping: no {path} here");
            return;
        };
        let offset = binprm_filename_offset(&blob).expect("read a real vmlinux BTF");
        println!("linux_binprm::filename at byte {offset} in {path}");
        assert!(
            offset > 0 && offset < 4096 && offset.is_multiple_of(8),
            "{offset}"
        );
    }
}
