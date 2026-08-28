//! Signed FRMB artifact. Agents verify with a configured trust-root key;
//! the embedded public key is not a trust root.

use ferrum_common::{FerrumError, Result};
use ferrum_compiler::{BUNDLE_FORMAT, BUNDLE_MAGIC};
use ferrum_crypto::{bundle_digest, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN};
use ferrum_ids::Digest;

/// On-wire signed artifact (little-endian):
/// `FSIG` | u32 format=1
/// | u32 public_key_len | public_key
/// | u32 signature_len | signature
/// | u32 raw_len | raw
///
/// `raw` is `ferrum_compiler::bundle_digest_material` (FRMB envelope).
/// Signature is `ferrum_crypto::sign_bundle(raw, secret)` (domain-separated).
pub const SIGNED_MAGIC: [u8; 4] = *b"FSIG";
pub const SIGNED_FORMAT: u32 = 1;

/// Bytes an agent/admission loads. Not a kube type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBundle {
    pub raw: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub digest: Digest,
    pub min_agent_abi: u32,
    pub min_admission_abi: u32,
}

impl SignedBundle {
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_fsig_envelope(&self.public_key, &self.signature, &self.raw)
    }

    /// Parse FSIG bytes. Does not treat the embedded public key as trusted.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (public_key, signature, raw) = decode_fsig_envelope(bytes)?;
        let (min_agent_abi, min_admission_abi) = parse_framb_abis(&raw)?;
        Ok(Self {
            digest: bundle_digest(&raw),
            raw,
            signature,
            public_key,
            min_agent_abi,
            min_admission_abi,
        })
    }
}

/// Verify `bundle` against a caller-supplied trust-root public key.
/// Agents must not call this with the embedded key unless it is that trust root.
pub fn verify_signed_bundle(bundle: &SignedBundle, trusted_public_key: &[u8]) -> Result<Digest> {
    ferrum_crypto::verify_bundle_signature(&bundle.raw, &bundle.signature, trusted_public_key)
}

/// Encode any signed payload into the FSIG envelope shared by `bundle.fsig`
/// and `exceptions.fsig`. Empty signatures are refused.
pub fn encode_fsig_envelope(
    public_key: &[u8],
    signature: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
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
    let mut out =
        Vec::with_capacity(4 + 4 + 4 + public_key.len() + 4 + signature.len() + 4 + payload.len());
    out.extend_from_slice(&SIGNED_MAGIC);
    out.extend_from_slice(&SIGNED_FORMAT.to_le_bytes());
    append_len_prefixed(&mut out, public_key, "public_key")?;
    append_len_prefixed(&mut out, signature, "signature")?;
    append_len_prefixed(&mut out, payload, "raw")?;
    Ok(out)
}

/// Decode `(public_key, signature, payload)` from an FSIG envelope. The
/// embedded public key is not a trust root; callers verify against their pin.
pub fn decode_fsig_envelope(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut pos = 0usize;
    let magic = take(bytes, &mut pos, 4)?;
    if magic != SIGNED_MAGIC {
        return Err(FerrumError::Integrity(
            "signed bundle magic is not FSIG".into(),
        ));
    }
    let format = u32_le(take(bytes, &mut pos, 4)?);
    if format != SIGNED_FORMAT {
        return Err(FerrumError::Integrity(format!(
            "unsupported signed bundle format {format}"
        )));
    }
    let public_key = take_len_prefixed(bytes, &mut pos)?.to_vec();
    let signature = take_len_prefixed(bytes, &mut pos)?.to_vec();
    let payload = take_len_prefixed(bytes, &mut pos)?.to_vec();
    if pos != bytes.len() {
        return Err(FerrumError::Integrity(
            "trailing bytes in signed bundle".into(),
        ));
    }
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
    Ok((public_key, signature, payload))
}

/// Verify an FSIG envelope against a caller-supplied trust root: the embedded
/// key must equal the pin and the signature must verify. Returns the payload.
pub fn verify_fsig_envelope(bytes: &[u8], trusted_public_key: &[u8]) -> Result<Vec<u8>> {
    let (public_key, signature, payload) = decode_fsig_envelope(bytes)?;
    if public_key != trusted_public_key {
        return Err(FerrumError::Integrity(
            "embedded FSIG public key does not match caller trust-root pin".into(),
        ));
    }
    ferrum_crypto::verify_bundle_signature(&payload, &signature, trusted_public_key)?;
    Ok(payload)
}

pub(crate) fn parse_framb_abis(raw: &[u8]) -> Result<(u32, u32)> {
    if raw.len() < 16 {
        return Err(FerrumError::Integrity("truncated FRMB envelope".into()));
    }
    if raw[..4] != BUNDLE_MAGIC {
        return Err(FerrumError::Integrity(
            "signed raw is not an FRMB envelope".into(),
        ));
    }
    let format = u32_le(&raw[4..8]);
    if format != BUNDLE_FORMAT {
        return Err(FerrumError::Integrity(format!(
            "unsupported FRMB format {format}"
        )));
    }
    Ok((u32_le(&raw[8..12]), u32_le(&raw[12..16])))
}

fn append_len_prefixed(out: &mut Vec<u8>, blob: &[u8], name: &str) -> Result<()> {
    let len = u32::try_from(blob.len())
        .map_err(|_| FerrumError::Integrity(format!("{name} exceeds u32 length")))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(blob);
    Ok(())
}

fn take<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8]> {
    let end = pos
        .checked_add(n)
        .ok_or_else(|| FerrumError::Integrity("truncated signed bundle".into()))?;
    let slice = buf
        .get(*pos..end)
        .ok_or_else(|| FerrumError::Integrity("truncated signed bundle".into()))?;
    *pos = end;
    Ok(slice)
}

fn take_len_prefixed<'a>(buf: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let len = u32_le(take(buf, pos, 4)?) as usize;
    take(buf, pos, len)
}

fn u32_le(bytes: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(bytes);
    u32::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_rejects_bad_magic() {
        assert!(SignedBundle::decode(b"XXXX").is_err());
    }

    #[test]
    fn decode_rejects_truncated() {
        let mut bytes = Vec::from(SIGNED_MAGIC);
        bytes.extend_from_slice(&SIGNED_FORMAT.to_le_bytes());
        assert!(SignedBundle::decode(&bytes).is_err());
    }

    #[test]
    fn encode_rejects_empty_signature() {
        let bundle = SignedBundle {
            raw: b"FRMB".to_vec(),
            signature: vec![],
            public_key: vec![1; ED25519_PUBLIC_KEY_LEN],
            digest: Digest::new("00".repeat(32)),
            min_agent_abi: 1,
            min_admission_abi: 1,
        };
        match bundle.encode() {
            Err(FerrumError::Integrity(msg)) => {
                assert!(msg.contains("unsigned"));
            }
            other => panic!("expected Integrity, got {other:?}"),
        }
    }
}
