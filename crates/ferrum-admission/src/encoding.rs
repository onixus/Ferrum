//! Hex and standard Base64. No extra crates on the admit path.

use ferrum_common::{FerrumError, Result};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[cfg(test)]
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
        return Err(FerrumError::Integrity(
            "hex string must have even length".into(),
        ));
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
        _ => Err(FerrumError::Integrity("invalid hex digit".into())),
    }
}

pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;
    while i < data.len() {
        let rem = data.len() - i;
        let b0 = data[i];
        let b1 = if rem > 1 { data[i + 1] } else { 0 };
        let b2 = if rem > 2 { data[i + 2] } else { 0 };
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        if rem > 1 {
            out.push(B64[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if rem > 2 {
            out.push(B64[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

#[cfg(test)]
pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if s.len() % 4 != 0 {
        return Err(FerrumError::Integrity(
            "base64 length must be a multiple of 4".into(),
        ));
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c0 = b64_val(bytes[i])?;
        let c1 = b64_val(bytes[i + 1])?;
        let c2 = bytes[i + 2];
        let c3 = bytes[i + 3];
        let n = (u32::from(c0) << 18) | (u32::from(c1) << 12);
        if c2 == b'=' {
            if c3 != b'=' || i + 4 != bytes.len() {
                return Err(FerrumError::Integrity("invalid base64 padding".into()));
            }
            out.push((n >> 16) as u8);
        } else {
            let v2 = b64_val(c2)?;
            let n = n | (u32::from(v2) << 6);
            out.push((n >> 16) as u8);
            if c3 == b'=' {
                if i + 4 != bytes.len() {
                    return Err(FerrumError::Integrity("invalid base64 padding".into()));
                }
                out.push((n >> 8) as u8);
            } else {
                let v3 = b64_val(c3)?;
                let n = n | u32::from(v3);
                out.push((n >> 8) as u8);
                out.push(n as u8);
            }
        }
        i += 4;
    }
    Ok(out)
}

#[cfg(test)]
fn b64_val(b: u8) -> Result<u8> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a' + 26),
        b'0'..=b'9' => Ok(b - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(FerrumError::Integrity("invalid base64 digit".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let bytes = [0xde, 0xad, 0xbe, 0xef];
        assert_eq!(hex_encode(&bytes), "deadbeef");
        assert_eq!(hex_decode("DEADBEEF").unwrap(), bytes);
        assert!(hex_decode("xyz").is_err());
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn b64_rfc4648_vectors() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_decode("Zg==").unwrap(), b"f");
        assert_eq!(b64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(b64_decode("Zm9v").unwrap(), b"foo");
    }
}
