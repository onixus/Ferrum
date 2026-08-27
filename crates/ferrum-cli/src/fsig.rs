//! FSIG wrapper for offline sign/verify. Same on-wire contract as the
//! admission/agent Secret mount (`FSIG` | u32 format=1 | len pk | len sig
//! | len raw, little-endian); ferrum-cli must not depend on those crates,
//! so the codec is repeated here and pinned by the testkit roundtrip test.

use anyhow::{bail, Context, Result};
use ferrum_crypto::{ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN};

pub const SIGNED_MAGIC: [u8; 4] = *b"FSIG";
pub const SIGNED_FORMAT: u32 = 1;

pub fn encode_fsig(raw: &[u8], signature: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    if signature.len() != ED25519_SIGNATURE_LEN {
        bail!(
            "Ed25519 signature must be {ED25519_SIGNATURE_LEN} bytes, got {}",
            signature.len()
        );
    }
    if public_key.len() != ED25519_PUBLIC_KEY_LEN {
        bail!(
            "Ed25519 public key must be {ED25519_PUBLIC_KEY_LEN} bytes, got {}",
            public_key.len()
        );
    }
    let mut out = Vec::with_capacity(20 + public_key.len() + signature.len() + raw.len());
    out.extend_from_slice(&SIGNED_MAGIC);
    out.extend_from_slice(&SIGNED_FORMAT.to_le_bytes());
    put_len_prefixed(&mut out, public_key)?;
    put_len_prefixed(&mut out, signature)?;
    put_len_prefixed(&mut out, raw)?;
    Ok(out)
}

/// Decode FSIG into `(public_key, signature, raw)`. The embedded key is not a
/// trust root; verify must compare it to the caller pin.
pub fn decode_fsig(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut r = Reader { buf: bytes, pos: 0 };
    if r.take(4)? != SIGNED_MAGIC {
        bail!("signed bundle magic is not FSIG");
    }
    let format = r.u32()?;
    if format != SIGNED_FORMAT {
        bail!("unsupported signed bundle format {format}");
    }
    let public_key = r.len_prefixed()?;
    let signature = r.len_prefixed()?;
    let raw = r.len_prefixed()?;
    if r.pos != bytes.len() {
        bail!("trailing bytes in signed bundle");
    }
    if public_key.len() != ED25519_PUBLIC_KEY_LEN {
        bail!(
            "Ed25519 public key must be {ED25519_PUBLIC_KEY_LEN} bytes, got {}",
            public_key.len()
        );
    }
    if signature.len() != ED25519_SIGNATURE_LEN {
        bail!(
            "Ed25519 signature must be {ED25519_SIGNATURE_LEN} bytes, got {}",
            signature.len()
        );
    }
    Ok((public_key, signature, raw))
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        bail!("hex string must have even length");
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0]).context("invalid hex digit")?;
        let lo = hex_nibble(pair[1]).context("invalid hex digit")?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => bail!("invalid hex byte 0x{other:02x}"),
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.buf.len())
            .context("truncated signed bundle")?;
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn len_prefixed(&mut self) -> Result<Vec<u8>> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }
}

fn put_len_prefixed(out: &mut Vec<u8>, blob: &[u8]) -> Result<()> {
    let len = u32::try_from(blob.len()).context("blob exceeds u32 length")?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(blob);
    Ok(())
}
