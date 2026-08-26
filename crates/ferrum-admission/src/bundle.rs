//! Signed PolicyBundle load. Verify before parse. No live Rekor/OCI/CT.
//!
//! On-wire signed artifact (little-endian), copied from the controller
//! layout (this crate must not depend on ferrum-controller):
//! `FSIG` | u32 format=1
//! | u32 public_key_len | public_key
//! | u32 signature_len | signature
//! | u32 raw_len | raw
//!
//! The embedded FSIG public key is not a trust root. It may only equal the
//! caller-supplied 32-byte pin. Verification always uses that pin.

use ferrum_common::{FerrumError, Result};
use ferrum_crypto::{ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN};
use ferrum_ids::Digest;

use crate::encoding::hex_decode;
use crate::program::{parse_program, AdmissionProgram, ADMISSION_ABI, ADMISSION_MAGIC};

const BUNDLE_MAGIC: [u8; 4] = *b"FRMB";
const BUNDLE_FORMAT: u32 = 1;

/// Signed-bundle magic (`FSIG`).
pub const SIGNED_MAGIC: [u8; 4] = *b"FSIG";
/// Signed-bundle format version.
pub const SIGNED_FORMAT: u32 = 1;

/// Verify Ed25519 over `FERRUM-POLICY-BUNDLE-v1 || raw`, then parse FADM or FRMB.
/// Empty signatures and verify failures deny; there is no unsigned fallback.
pub fn load_signed(raw: &[u8], signature: &[u8], public_key: &[u8]) -> Result<AdmissionProgram> {
    ferrum_crypto::verify_bundle_signature(raw, signature, public_key)?;
    parse_verified(raw)
}

/// Compare SHA-256(`raw`) to `expected`, then parse. Empty expected digest fails.
pub fn load_digest(raw: &[u8], expected: &Digest) -> Result<AdmissionProgram> {
    ferrum_crypto::verify_bundle_digest(raw, expected)?;
    parse_verified(raw)
}

/// Parse 32-byte Ed25519 trust-root pin from hex. Empty or wrong size is Integrity.
pub fn parse_trust_root(hex: &str) -> Result<Vec<u8>> {
    let bytes = hex_decode(hex)?;
    if bytes.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(FerrumError::Integrity(format!(
            "trust-root pin must be {ED25519_PUBLIC_KEY_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Load FSIG (verify with caller pin), or reject unsigned FRMB/FADM.
/// Missing program, empty/wrong signature, and pin mismatch are Integrity.
/// FRMB `minAdmissionAbi` newer than this host is Degraded.
pub fn load_bundle(bytes: &[u8], trust_root: &[u8]) -> Result<AdmissionProgram> {
    if trust_root.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(FerrumError::Integrity(format!(
            "trust-root pin must be {ED25519_PUBLIC_KEY_LEN} bytes, got {}",
            trust_root.len()
        )));
    }
    if bytes.starts_with(&SIGNED_MAGIC) {
        return load_fsig(bytes, trust_root);
    }
    if bytes.starts_with(&BUNDLE_MAGIC) || bytes.starts_with(&ADMISSION_MAGIC) {
        return Err(FerrumError::Integrity(
            "unsigned FRMB/FADM rejected; admission requires a verified FSIG".into(),
        ));
    }
    Err(FerrumError::Integrity(
        "bytes are not a signed FSIG policy bundle".into(),
    ))
}

/// Encode FSIG. Empty signatures are refused.
pub fn encode_fsig(raw: &[u8], signature: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    if signature.is_empty() {
        return Err(FerrumError::Integrity(
            "refusing to encode unsigned bundle".into(),
        ));
    }
    if public_key.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(FerrumError::Integrity(format!(
            "Ed25519 public key must be {ED25519_PUBLIC_KEY_LEN} bytes, got {}",
            public_key.len()
        )));
    }
    if signature.len() != ED25519_SIGNATURE_LEN {
        return Err(FerrumError::Integrity(format!(
            "Ed25519 signature must be {ED25519_SIGNATURE_LEN} bytes, got {}",
            signature.len()
        )));
    }
    let mut out = Vec::with_capacity(16 + public_key.len() + signature.len() + raw.len());
    out.extend_from_slice(&SIGNED_MAGIC);
    out.extend_from_slice(&SIGNED_FORMAT.to_le_bytes());
    append_len_prefixed(&mut out, public_key, "public_key")?;
    append_len_prefixed(&mut out, signature, "signature")?;
    append_len_prefixed(&mut out, raw, "raw")?;
    Ok(out)
}

fn load_fsig(bytes: &[u8], trust_root: &[u8]) -> Result<AdmissionProgram> {
    let (public_key, signature, raw) = decode_fsig(bytes)?;
    if public_key.as_slice() != trust_root {
        return Err(FerrumError::Integrity(
            "embedded FSIG public key does not match caller trust-root pin".into(),
        ));
    }
    ferrum_crypto::verify_bundle_signature(&raw, &signature, trust_root)?;
    parse_verified(&raw)
}

fn decode_fsig(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut r = RawReader::new(bytes);
    r.expect_magic(&SIGNED_MAGIC)
        .map_err(|_| FerrumError::Integrity("signed bundle magic is not FSIG".into()))?;
    let format = r
        .u32()
        .map_err(|_| FerrumError::Integrity("truncated signed bundle".into()))?;
    if format != SIGNED_FORMAT {
        return Err(FerrumError::Integrity(format!(
            "unsupported signed bundle format {format}"
        )));
    }
    let public_key = r
        .len_prefixed("public_key")
        .map_err(|_| FerrumError::Integrity("truncated signed bundle public_key".into()))?;
    let signature = r
        .len_prefixed("signature")
        .map_err(|_| FerrumError::Integrity("truncated signed bundle signature".into()))?;
    let raw = r
        .len_prefixed("raw")
        .map_err(|_| FerrumError::Integrity("truncated signed bundle raw".into()))?;
    r.finish()
        .map_err(|_| FerrumError::Integrity("trailing bytes in signed bundle".into()))?;
    if signature.is_empty() {
        return Err(FerrumError::Integrity(
            "bundle signature is empty; unsigned bundles are rejected".into(),
        ));
    }
    if public_key.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(FerrumError::Integrity(format!(
            "Ed25519 public key must be {ED25519_PUBLIC_KEY_LEN} bytes, got {}",
            public_key.len()
        )));
    }
    if signature.len() != ED25519_SIGNATURE_LEN {
        return Err(FerrumError::Integrity(format!(
            "Ed25519 signature must be {ED25519_SIGNATURE_LEN} bytes, got {}",
            signature.len()
        )));
    }
    Ok((public_key, signature, raw))
}

fn append_len_prefixed(out: &mut Vec<u8>, blob: &[u8], name: &str) -> Result<()> {
    let len = u32::try_from(blob.len())
        .map_err(|_| FerrumError::Integrity(format!("{name} exceeds u32 length")))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(blob);
    Ok(())
}

fn parse_verified(raw: &[u8]) -> Result<AdmissionProgram> {
    if raw.starts_with(&ADMISSION_MAGIC) {
        return parse_program(raw);
    }
    if raw.starts_with(&BUNDLE_MAGIC) {
        let fadm = extract_admission_program(raw)?;
        return parse_program(&fadm);
    }
    Err(FerrumError::Compile(
        "verified bytes are neither FADM nor FRMB".into(),
    ))
}

fn extract_admission_program(raw: &[u8]) -> Result<Vec<u8>> {
    let mut r = RawReader::new(raw);
    r.expect_magic(&BUNDLE_MAGIC)?;
    let format = r.u32()?;
    if format != BUNDLE_FORMAT {
        return Err(FerrumError::Compile(format!(
            "unknown policy bundle format {format}"
        )));
    }
    let _min_agent_abi = r.u32()?;
    let min_admission_abi = r.u32()?;
    if min_admission_abi > ADMISSION_ABI {
        return Err(FerrumError::Degraded(format!(
            "bundle minAdmissionAbi {min_admission_abi} incompatible with host {ADMISSION_ABI}"
        )));
    }
    let admission = r.len_prefixed("admission_program")?;
    let _ebpf = r.len_prefixed("ebpf_spec")?;
    let _wasm = r.len_prefixed("wasm")?;
    r.finish()?;
    if admission.is_empty() {
        return Err(FerrumError::Integrity(
            "bundle admission_program is empty".into(),
        ));
    }
    Ok(admission)
}

struct RawReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> RawReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| FerrumError::Compile("truncated policy bundle".into()))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| FerrumError::Compile("truncated policy bundle".into()))?;
        self.pos = end;
        Ok(slice)
    }

    fn expect_magic(&mut self, magic: &[u8; 4]) -> Result<()> {
        let got = self.take(4)?;
        if got != magic {
            return Err(FerrumError::Compile(
                "unexpected policy bundle magic".into(),
            ));
        }
        Ok(())
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn len_prefixed(&mut self, name: &str) -> Result<Vec<u8>> {
        let len = self.u32()? as usize;
        Ok(self
            .take(len)
            .map_err(|_| FerrumError::Compile(format!("truncated bundle {name}")))?
            .to_vec())
    }

    fn finish(self) -> Result<()> {
        if self.pos != self.buf.len() {
            return Err(FerrumError::Compile(
                "trailing bytes in policy bundle".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_crypto::{public_key_from_secret, sign_bundle};

    const SK: [u8; 32] = [0x11; 32];
    const SK2: [u8; 32] = [0x22; 32];

    #[test]
    fn unsigned_fadm_rejected() {
        let pk = public_key_from_secret(&SK).unwrap();
        match load_bundle(b"FADM\x00\x00\x00\x01", &pk) {
            Err(FerrumError::Integrity(_)) => {}
            other => panic!("expected Integrity, got {other:?}"),
        }
    }

    #[test]
    fn truncated_fsig_is_integrity() {
        let pk = public_key_from_secret(&SK).unwrap();
        let mut bytes = Vec::from(SIGNED_MAGIC);
        bytes.extend_from_slice(&SIGNED_FORMAT.to_le_bytes());
        match load_bundle(&bytes, &pk) {
            Err(FerrumError::Integrity(_)) => {}
            other => panic!("expected Integrity, got {other:?}"),
        }
    }

    #[test]
    fn wrong_pin_is_integrity() {
        let raw = b"hello-bundle";
        let pk = public_key_from_secret(&SK).unwrap();
        let other = public_key_from_secret(&SK2).unwrap();
        let sig = sign_bundle(raw, &SK).unwrap();
        let fsig = encode_fsig(raw, &sig, &pk).unwrap();
        match load_bundle(&fsig, &other) {
            Err(FerrumError::Integrity(_)) => {}
            other => panic!("expected Integrity, got {other:?}"),
        }
    }

    #[test]
    fn empty_signature_encode_rejected() {
        let pk = public_key_from_secret(&SK).unwrap();
        match encode_fsig(b"raw", &[], &pk) {
            Err(FerrumError::Integrity(msg)) => assert!(msg.contains("unsigned")),
            other => panic!("expected Integrity, got {other:?}"),
        }
    }
}
