//! Wasm policy ABI. Keep `ABI_VERSION` aligned with `ferrum_ids::{AGENT_ABI, ADMISSION_ABI}`.
//!
//! The compiler ships a versioned placeholder, not wasm bytecode. The host must
//! fail closed on empty, unknown ABI, or placeholder modules.

#![deny(unsafe_code)]

/// Wasm policy ABI. Must stay aligned with `ferrum_ids` bundle ABI numbers.
pub const ABI_VERSION: u32 = 1;

/// Magic prefix of a Ferrum wasm blob (`FWSM`).
pub const MODULE_MAGIC: [u8; 4] = *b"FWSM";

/// Non-executable placeholder. Real wasm bytecode is not shipped in this ABI.
pub const KIND_PLACEHOLDER: u8 = 0;

/// `MODULE_MAGIC` (4) + ABI u32 LE (4) + kind u8 (1).
pub const HEADER_LEN: usize = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleHeader {
    pub abi: u32,
    pub kind: u8,
}

/// Deterministic 9-byte blob: magic + ABI + kind=placeholder.
pub fn placeholder_module() -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0..4].copy_from_slice(&MODULE_MAGIC);
    out[4..8].copy_from_slice(&ABI_VERSION.to_le_bytes());
    out[8] = KIND_PLACEHOLDER;
    out
}

/// Parse magic + ABI + kind. `None` if truncated or magic mismatches.
pub fn parse_header(module: &[u8]) -> Option<ModuleHeader> {
    if module.len() < HEADER_LEN {
        return None;
    }
    if module[0..4] != MODULE_MAGIC {
        return None;
    }
    let mut abi_bytes = [0u8; 4];
    abi_bytes.copy_from_slice(&module[4..8]);
    Some(ModuleHeader {
        abi: u32::from_le_bytes(abi_bytes),
        kind: module[8],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_version_generation() {
        assert_eq!(ABI_VERSION, 1);
    }

    #[test]
    fn placeholder_header_roundtrip() {
        let blob = placeholder_module();
        assert_eq!(blob.len(), HEADER_LEN);
        let header = parse_header(&blob).expect("header");
        assert_eq!(header.abi, ABI_VERSION);
        assert_eq!(header.kind, KIND_PLACEHOLDER);
    }

    #[test]
    fn truncated_and_bad_magic_are_none() {
        assert!(parse_header(&[]).is_none());
        assert!(parse_header(&placeholder_module()[..HEADER_LEN - 1]).is_none());
        assert!(parse_header(b"XXXX\x01\x00\x00\x00\x00").is_none());
    }
}
