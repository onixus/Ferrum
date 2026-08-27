//! 32-byte Ed25519 seed. All-zero is rejected by ferrum-crypto on sign.

use ferrum_common::{FerrumError, Result};
use ferrum_crypto::{ED25519_PUBLIC_KEY_LEN, ED25519_SECRET_KEY_LEN};
use std::path::Path;

pub const SEED_ENV: &str = "FERRUM_SEED";
pub const SEED_FILE_ENV: &str = "FERRUM_SEED_FILE";

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(FerrumError::Validation("hex has odd length".into()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(FerrumError::Validation(
            "hex contains a non-hex character".into(),
        )),
    }
}

pub fn parse_seed_hex(hex: &str) -> Result<Vec<u8>> {
    let bytes = hex_decode(hex)?;
    if bytes.len() != ED25519_SECRET_KEY_LEN {
        return Err(FerrumError::Validation(format!(
            "Ed25519 seed must be {} bytes ({} hex chars), got {}",
            ED25519_SECRET_KEY_LEN,
            ED25519_SECRET_KEY_LEN * 2,
            bytes.len()
        )));
    }
    Ok(bytes)
}

pub fn parse_public_key_hex(hex: &str) -> Result<Vec<u8>> {
    let bytes = hex_decode(hex)?;
    if bytes.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(FerrumError::Validation(format!(
            "Ed25519 public key must be {ED25519_PUBLIC_KEY_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Raw 32-byte seed, or trimmed hex of that length.
pub fn parse_seed_bytes(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() == ED25519_SECRET_KEY_LEN {
        return Ok(raw.to_vec());
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| FerrumError::Validation("signing seed is not UTF-8 hex".into()))?;
    parse_seed_hex(text)
}

pub fn load_seed_file(path: &Path) -> Result<Vec<u8>> {
    let raw = std::fs::read(path)
        .map_err(|e| FerrumError::Validation(format!("read seed file {}: {e}", path.display())))?;
    parse_seed_bytes(&raw)
}

pub fn load_seed(seed_file: Option<&Path>) -> Result<Vec<u8>> {
    if let Some(path) = seed_file {
        return load_seed_file(path);
    }
    if let Ok(path) = std::env::var(SEED_FILE_ENV) {
        let path = path.trim();
        if !path.is_empty() {
            return load_seed_file(Path::new(path));
        }
    }
    if let Ok(hex) = std::env::var(SEED_ENV) {
        return parse_seed_hex(&hex);
    }
    Err(FerrumError::Validation(
        "signing seed is missing: pass --seed-file or set FERRUM_SEED / FERRUM_SEED_FILE".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip_seed() {
        let seed = vec![0x9d; ED25519_SECRET_KEY_LEN];
        let hex = hex_encode(&seed);
        assert_eq!(hex.len(), 64);
        assert_eq!(parse_seed_hex(&hex).expect("hex"), seed);
        assert_eq!(parse_seed_hex(&format!("{hex}\n")).expect("nl"), seed);
    }

    #[test]
    fn raw_32_byte_file_bytes() {
        let seed = [0x11u8; ED25519_SECRET_KEY_LEN];
        assert_eq!(parse_seed_bytes(&seed).expect("raw"), seed.to_vec());
    }

    #[test]
    fn odd_hex_and_wrong_len_fail() {
        assert!(parse_seed_hex("abc").is_err());
        assert!(parse_seed_hex("aa").is_err());
        assert!(parse_public_key_hex("aa").is_err());
    }

    #[test]
    fn load_seed_file_hex() {
        let dir = std::env::temp_dir();
        let path = dir.join("ferrum-controller-seed-hex-test");
        let seed = [0xabu8; ED25519_SECRET_KEY_LEN];
        std::fs::write(&path, hex_encode(&seed)).expect("write");
        let got = load_seed_file(&path).expect("load");
        let _ = std::fs::remove_file(&path);
        assert_eq!(got, seed);
    }
}
