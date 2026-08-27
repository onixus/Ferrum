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

use std::path::{Path, PathBuf};

use ferrum_common::{FerrumError, Result};
use ferrum_crypto::{ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN};
use ferrum_ids::Digest;

use crate::encoding::{b64_decode, hex_decode};
use crate::program::{parse_program, AdmissionProgram, ADMISSION_ABI, ADMISSION_MAGIC};

const BUNDLE_MAGIC: [u8; 4] = *b"FRMB";
const BUNDLE_FORMAT: u32 = 1;

/// Signed-bundle magic (`FSIG`).
pub const SIGNED_MAGIC: [u8; 4] = *b"FSIG";
/// Signed-bundle format version.
pub const SIGNED_FORMAT: u32 = 1;

/// Controller Secret data key for the signed FSIG blob. Duplicated on purpose:
/// this crate must not depend on ferrum-controller.
pub const BUNDLE_FSIG_KEY: &str = "bundle.fsig";
/// Controller Secret data key for SHA-256(raw) as UTF-8 hex bytes.
pub const BUNDLE_DIGEST_KEY: &str = "digest";
/// kubelet projected-volume symlink to the current Secret snapshot directory.
pub const KUBELET_DATA_DIR: &str = "..data";

/// Bytes extracted from a raw FSIG or a controller-shaped Secret JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedFsig {
    pub fsig: Vec<u8>,
    pub digest: Option<Digest>,
}

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

/// Raw FSIG, or Secret JSON `{data:{"bundle.fsig": b64, "digest": b64}}`.
/// Empty or missing `bundle.fsig` is Integrity.
pub fn extract_fsig(bytes: &[u8]) -> Result<ExtractedFsig> {
    if bytes.starts_with(&SIGNED_MAGIC)
        || bytes.starts_with(&BUNDLE_MAGIC)
        || bytes.starts_with(&ADMISSION_MAGIC)
    {
        return Ok(ExtractedFsig {
            fsig: bytes.to_vec(),
            digest: None,
        });
    }
    if looks_like_json(bytes) {
        return extract_secret_json(bytes);
    }
    Err(FerrumError::Integrity(
        "bytes are not a signed FSIG policy bundle".into(),
    ))
}

/// Extract FSIG, verify with the caller pin, then parse.
/// If Secret `digest` is present it must equal `bundle_digest` of the verified raw.
pub fn load_source(bytes: &[u8], trust_root: &[u8]) -> Result<AdmissionProgram> {
    Ok(load_source_with_digest(bytes, trust_root, None)?.0)
}

/// Like [`load_source`], plus an expected SHA-256(raw) hex digest (directory sibling).
pub fn load_source_with_expected(
    bytes: &[u8],
    trust_root: &[u8],
    expected_digest: Option<&Digest>,
) -> Result<AdmissionProgram> {
    Ok(load_source_with_digest(bytes, trust_root, expected_digest)?.0)
}

/// Read a raw FSIG / Secret JSON file, or a directory (kubelet Secret mount).
/// A directory requires sibling `digest` from the same `..data` snapshot as `bundle.fsig`.
pub fn read_source_path(path: &Path) -> Result<(Vec<u8>, Option<Digest>)> {
    if path.is_dir() {
        return read_dir_snapshot(path);
    }
    if is_secret_fsig_file(path) {
        if let Some(parent) = path.parent() {
            return read_dir_snapshot(parent);
        }
    }
    let bytes = std::fs::read(path)
        .map_err(|err| FerrumError::Integrity(format!("read {}: {err}", path.display())))?;
    Ok((bytes, None))
}

/// Verify and parse whatever kubelet/file `--bundle` points at.
pub fn load_path(path: &Path, trust_root: &[u8]) -> Result<(AdmissionProgram, Digest)> {
    let (bytes, expected) = read_source_path(path)?;
    load_source_with_digest(&bytes, trust_root, expected.as_ref())
}

/// Snapshot directory used for mtime+len watches. `None` for a plain file.
pub(crate) fn source_snapshot_dir(path: &Path) -> Option<PathBuf> {
    if path.is_dir() {
        Some(snapshot_dir(path))
    } else if is_secret_fsig_file(path) {
        path.parent().map(snapshot_dir)
    } else {
        None
    }
}

pub(crate) fn load_source_with_digest(
    bytes: &[u8],
    trust_root: &[u8],
    expected_digest: Option<&Digest>,
) -> Result<(AdmissionProgram, Digest)> {
    let extracted = extract_fsig(bytes)?;
    let program = load_bundle(&extracted.fsig, trust_root)?;
    let raw = decode_fsig(&extracted.fsig)?.2;
    if let Some(expected) = extracted.digest.as_ref() {
        ferrum_crypto::verify_bundle_digest(&raw, expected)?;
    }
    if let Some(expected) = expected_digest {
        ferrum_crypto::verify_bundle_digest(&raw, expected)?;
    }
    Ok((program, ferrum_crypto::bundle_digest(&raw)))
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

fn snapshot_dir(dir: &Path) -> PathBuf {
    // Resolve `..data` once so bundle.fsig and digest come from one kubelet snapshot.
    let data = dir.join(KUBELET_DATA_DIR);
    match std::fs::read_link(data) {
        Ok(target) if target.is_absolute() => target,
        Ok(target) => dir.join(target),
        Err(_) => dir.to_path_buf(),
    }
}

fn is_secret_fsig_file(path: &Path) -> bool {
    if path.file_name().and_then(|n| n.to_str()) != Some(BUNDLE_FSIG_KEY) {
        return false;
    }
    let Some(parent) = path.parent() else {
        return false;
    };
    parent.join(BUNDLE_DIGEST_KEY).is_file() || parent.join(KUBELET_DATA_DIR).exists()
}

fn read_dir_snapshot(dir: &Path) -> Result<(Vec<u8>, Option<Digest>)> {
    let snap = snapshot_dir(dir);
    let fsig = read_required(&snap.join(BUNDLE_FSIG_KEY), "empty/missing bundle.fsig")?;
    let digest_bytes = read_required(&snap.join(BUNDLE_DIGEST_KEY), "empty/missing digest")?;
    Ok((fsig, Some(parse_dir_digest(&digest_bytes)?)))
}

fn read_required(path: &Path, missing: &str) -> Result<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) if !bytes.is_empty() => Ok(bytes),
        Ok(_) => Err(FerrumError::Integrity(missing.into())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Err(FerrumError::Integrity(missing.into()))
        }
        Err(err) => Err(FerrumError::Integrity(format!(
            "{missing}: {}: {err}",
            path.display()
        ))),
    }
}

fn parse_dir_digest(bytes: &[u8]) -> Result<Digest> {
    let hex = std::str::from_utf8(bytes)
        .map_err(|_| FerrumError::Integrity("digest is not utf-8 hex".into()))?;
    let hex = hex.trim();
    if hex.is_empty() {
        return Err(FerrumError::Integrity("empty/missing digest".into()));
    }
    Ok(Digest::new(hex))
}

fn looks_like_json(bytes: &[u8]) -> bool {
    bytes.iter().copied().find(|b| !b.is_ascii_whitespace()) == Some(b'{')
}

fn extract_secret_json(bytes: &[u8]) -> Result<ExtractedFsig> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| FerrumError::Integrity("Secret JSON is invalid".into()))?;
    let Some(data) = value.get("data").and_then(|v| v.as_object()) else {
        return Err(FerrumError::Integrity("empty/missing bundle.fsig".into()));
    };
    let Some(fsig_b64) = data.get(BUNDLE_FSIG_KEY).and_then(|v| v.as_str()) else {
        return Err(FerrumError::Integrity("empty/missing bundle.fsig".into()));
    };
    if fsig_b64.trim().is_empty() {
        return Err(FerrumError::Integrity("empty/missing bundle.fsig".into()));
    }
    let fsig = b64_decode(fsig_b64)?;
    if fsig.is_empty() {
        return Err(FerrumError::Integrity("empty/missing bundle.fsig".into()));
    }
    let digest = match data.get(BUNDLE_DIGEST_KEY) {
        None => None,
        Some(v) => {
            let b64 = v
                .as_str()
                .ok_or_else(|| FerrumError::Integrity("Secret digest is not base64".into()))?;
            let raw = b64_decode(b64)?;
            let hex = std::str::from_utf8(&raw)
                .map_err(|_| FerrumError::Integrity("Secret digest is not utf-8 hex".into()))?;
            Some(Digest::new(hex.trim()))
        }
    };
    Ok(ExtractedFsig { fsig, digest })
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
    use crate::encoding::b64_encode;
    use ferrum_crypto::{public_key_from_secret, sign_bundle};

    const SK: [u8; 32] = [0x11; 32];
    const SK2: [u8; 32] = [0x22; 32];

    fn assert_integrity<T: std::fmt::Debug>(result: Result<T>) {
        match result {
            Err(FerrumError::Integrity(_)) => {}
            other => panic!("expected Integrity, got {other:?}"),
        }
    }

    fn put_u16(out: &mut Vec<u8>, v: u16) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    fn put_str(out: &mut Vec<u8>, s: &str) {
        put_u16(out, u16::try_from(s.len()).unwrap());
        out.extend_from_slice(s.as_bytes());
    }

    fn put_str_list(out: &mut Vec<u8>, items: &[&str]) {
        put_u16(out, u16::try_from(items.len()).unwrap());
        for item in items {
            put_str(out, item);
        }
    }

    fn tiny_fadm() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ADMISSION_MAGIC);
        bytes.extend_from_slice(&ADMISSION_ABI.to_le_bytes());
        bytes.push(2); // enforce
        bytes.push(0); // disabled
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.push(0); // Fail
        bytes.push(2); // restricted
        bytes.push(1); // require_signed
        bytes.push(1); // deny_unsigned
        bytes.push(1); // deny_latest_tag
        put_u16(&mut bytes, 1);
        put_str(&mut bytes, "org-cosign");
        put_str_list(&mut bytes, &[]);
        put_str_list(
            &mut bytes,
            &["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
        );
        bytes.extend_from_slice(&[1, 1, 1, 1, 1, 1, 1, 1, 1]);
        put_str_list(&mut bytes, &[]);
        bytes.extend_from_slice(&[0, 0, 0]);
        for _ in 0..4 {
            put_u16(&mut bytes, 0);
            put_u16(&mut bytes, 0);
        }
        put_str_list(&mut bytes, &[]);
        bytes.push(0);
        bytes
    }

    fn wrap_frmb(admission: &[u8], min_admission_abi: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&BUNDLE_MAGIC);
        out.extend_from_slice(&BUNDLE_FORMAT.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&min_admission_abi.to_le_bytes());
        append_len_prefixed(&mut out, admission, "admission_program").unwrap();
        append_len_prefixed(&mut out, b"", "ebpf_spec").unwrap();
        append_len_prefixed(&mut out, b"", "wasm").unwrap();
        out
    }

    fn sign_raw(raw: &[u8], sk: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let pk = public_key_from_secret(sk).unwrap();
        let sig = sign_bundle(raw, sk).unwrap();
        (encode_fsig(raw, &sig, &pk).unwrap(), pk)
    }

    fn secret_json(fsig: &[u8], digest: Option<&str>) -> Vec<u8> {
        let mut data = serde_json::Map::new();
        data.insert(
            BUNDLE_FSIG_KEY.to_string(),
            serde_json::Value::String(b64_encode(fsig)),
        );
        if let Some(digest) = digest {
            data.insert(
                BUNDLE_DIGEST_KEY.to_string(),
                serde_json::Value::String(b64_encode(digest.as_bytes())),
            );
        }
        serde_json::to_vec(&serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "ferrum-bundle-prod-restricted", "namespace": "ferrum"},
            "type": "Opaque",
            "data": data,
        }))
        .unwrap()
    }

    #[test]
    fn unsigned_fadm_rejected() {
        let pk = public_key_from_secret(&SK).unwrap();
        assert_integrity(load_bundle(b"FADM\x00\x00\x00\x01", &pk));
        assert_integrity(load_source(b"FADM\x00\x00\x00\x01", &pk));
    }

    #[test]
    fn truncated_fsig_is_integrity() {
        let pk = public_key_from_secret(&SK).unwrap();
        let mut bytes = Vec::from(SIGNED_MAGIC);
        bytes.extend_from_slice(&SIGNED_FORMAT.to_le_bytes());
        assert_integrity(load_bundle(&bytes, &pk));
        assert_integrity(load_source(&bytes, &pk));
    }

    #[test]
    fn wrong_pin_is_integrity() {
        let raw = tiny_fadm();
        let (fsig, _pk) = sign_raw(&raw, &SK);
        let other = public_key_from_secret(&SK2).unwrap();
        assert_integrity(load_bundle(&fsig, &other));
        assert_integrity(load_source(&fsig, &other));
        let secret = secret_json(&fsig, None);
        assert_integrity(load_source(&secret, &other));
    }

    #[test]
    fn empty_signature_encode_rejected() {
        let pk = public_key_from_secret(&SK).unwrap();
        match encode_fsig(b"raw", &[], &pk) {
            Err(FerrumError::Integrity(msg)) => assert!(msg.contains("unsigned")),
            other => panic!("expected Integrity, got {other:?}"),
        }
    }

    #[test]
    fn controller_secret_json_loads_with_matching_digest() {
        let raw = tiny_fadm();
        let (fsig, pk) = sign_raw(&raw, &SK);
        let digest = ferrum_crypto::bundle_digest(&raw);
        let secret = secret_json(&fsig, Some(digest.as_str()));
        let extracted = extract_fsig(&secret).expect("extract secret");
        assert_eq!(extracted.fsig, fsig);
        assert_eq!(
            extracted.digest.as_ref().map(Digest::as_str),
            Some(digest.as_str())
        );
        load_source(&secret, &pk).expect("secret + trust-root");
        load_source(&fsig, &pk).expect("raw FSIG");
    }

    #[test]
    fn digest_mismatch_is_integrity() {
        let raw = tiny_fadm();
        let (fsig, pk) = sign_raw(&raw, &SK);
        load_source(&fsig, &pk).expect("raw FSIG still loads");
        let secret = secret_json(&fsig, Some(&"00".repeat(32)));
        assert_integrity(load_source(&secret, &pk));
    }

    #[test]
    fn empty_or_missing_bundle_fsig_is_integrity() {
        let pk = public_key_from_secret(&SK).unwrap();
        let missing = br#"{"apiVersion":"v1","kind":"Secret","data":{}}"#;
        assert_integrity(extract_fsig(missing));
        assert_integrity(load_source(missing, &pk));
        let empty = secret_json(b"", None);
        assert_integrity(extract_fsig(&empty));
        assert_integrity(load_source(&empty, &pk));
        assert_integrity(extract_fsig(b""));
        assert_integrity(load_source(b"", &pk));
    }

    #[test]
    fn unsigned_frmb_or_fadm_in_secret_is_integrity() {
        let pk = public_key_from_secret(&SK).unwrap();
        let fadm = tiny_fadm();
        let frmb = wrap_frmb(&fadm, ADMISSION_ABI);
        assert_integrity(load_source(&secret_json(&fadm, None), &pk));
        assert_integrity(load_source(&secret_json(&frmb, None), &pk));
        assert_integrity(load_bundle(&fadm, &pk));
        assert_integrity(load_bundle(&frmb, &pk));
    }

    #[test]
    fn min_admission_abi_too_new_is_degraded() {
        let raw = wrap_frmb(&tiny_fadm(), ADMISSION_ABI.saturating_add(1));
        let (fsig, pk) = sign_raw(&raw, &SK);
        match load_source(&fsig, &pk) {
            Err(FerrumError::Degraded(_)) => {}
            other => panic!("expected Degraded, got {other:?}"),
        }
        let digest = ferrum_crypto::bundle_digest(&raw);
        match load_source(&secret_json(&fsig, Some(digest.as_str())), &pk) {
            Err(FerrumError::Degraded(_)) => {}
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ferrum-admission-bundle-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn write_secret_dir(dir: &Path, fsig: &[u8], digest: &str) {
        std::fs::write(dir.join(BUNDLE_FSIG_KEY), fsig).expect("bundle.fsig");
        std::fs::write(dir.join(BUNDLE_DIGEST_KEY), digest.as_bytes()).expect("digest");
    }

    #[test]
    fn dir_with_matching_digest_loads() {
        let raw = tiny_fadm();
        let (fsig, pk) = sign_raw(&raw, &SK);
        let digest = ferrum_crypto::bundle_digest(&raw);
        let dir = temp_dir("match");
        write_secret_dir(&dir, &fsig, digest.as_str());
        load_path(&dir, &pk).expect("dir + matching digest");
        load_source_with_expected(&fsig, &pk, Some(&digest)).expect("expected digest");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dir_without_digest_or_mismatched_digest_is_integrity() {
        let raw = tiny_fadm();
        let (fsig, pk) = sign_raw(&raw, &SK);
        let dir = temp_dir("mismatch");
        std::fs::write(dir.join(BUNDLE_FSIG_KEY), &fsig).expect("bundle.fsig");
        assert_integrity(load_path(&dir, &pk));
        write_secret_dir(&dir, &fsig, &"00".repeat(32));
        assert_integrity(load_path(&dir, &pk));
        assert_integrity(load_source_with_expected(
            &fsig,
            &pk,
            Some(&Digest::new("00".repeat(32))),
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kubelet_data_snapshot_pairs_fsig_and_digest() {
        let raw = tiny_fadm();
        let (fsig, pk) = sign_raw(&raw, &SK);
        let digest = ferrum_crypto::bundle_digest(&raw);
        let dir = temp_dir("kubelet");
        let snap1 = dir.join("..snap1");
        std::fs::create_dir_all(&snap1).expect("snap1");
        write_secret_dir(&snap1, &fsig, digest.as_str());
        std::os::unix::fs::symlink("..snap1", dir.join(KUBELET_DATA_DIR)).expect("..data");
        load_path(&dir, &pk).expect("kubelet snapshot matching digest");

        let snap2 = dir.join("..snap2");
        std::fs::create_dir_all(&snap2).expect("snap2");
        write_secret_dir(&snap2, &fsig, &"00".repeat(32));
        let tmp = dir.join("..data.tmp");
        std::os::unix::fs::symlink("..snap2", &tmp).expect("tmp link");
        std::fs::rename(&tmp, dir.join(KUBELET_DATA_DIR)).expect("rotate ..data");
        assert_integrity(load_path(&dir, &pk));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
