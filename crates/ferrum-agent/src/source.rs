//! Signed PolicyBundle load. Verify before parse. No live Rekor/OCI/CT.
//!
//! On-wire signed artifact (little-endian), copied from the admission
//! mount contract (this crate must not depend on ferrum-admission):
//! `FSIG` | u32 format=1
//! | u32 public_key_len | public_key
//! | u32 signature_len | signature
//! | u32 raw_len | raw
//!
//! The embedded FSIG public key is not a trust root. It may only equal the
//! caller-supplied 32-byte pin. Verification always uses that pin.
//! Secret JSON is not accepted; only raw FSIG/FRMB/FEBP magic.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use ferrum_common::{FerrumError, Result};
use ferrum_crypto::{ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN};
use ferrum_ebpf::{extract_febp, BUNDLE_MAGIC, EBPF_MAGIC};
use ferrum_ids::Digest;

/// Signed-bundle magic (`FSIG`).
pub const SIGNED_MAGIC: [u8; 4] = *b"FSIG";
/// Signed-bundle format version.
pub const SIGNED_FORMAT: u32 = 1;

/// Controller Secret data key for the signed FSIG blob.
pub const BUNDLE_FSIG_KEY: &str = "bundle.fsig";
/// Controller Secret data key for SHA-256(raw) as UTF-8 hex bytes.
pub const BUNDLE_DIGEST_KEY: &str = "digest";
/// kubelet projected-volume symlink to the current Secret snapshot directory.
pub const KUBELET_DATA_DIR: &str = "..data";

/// Bytes extracted from a raw FSIG, FRMB, or FEBP blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedFsig {
    pub fsig: Vec<u8>,
    pub digest: Option<Digest>,
}

/// Raw FSIG / FRMB / FEBP magic only. Secret JSON is Integrity.
pub fn extract_fsig(bytes: &[u8]) -> Result<ExtractedFsig> {
    if bytes.starts_with(&SIGNED_MAGIC)
        || bytes.starts_with(&BUNDLE_MAGIC)
        || bytes.starts_with(&EBPF_MAGIC)
    {
        return Ok(ExtractedFsig {
            fsig: bytes.to_vec(),
            digest: None,
        });
    }
    Err(FerrumError::Integrity(
        "bytes are not a signed FSIG policy bundle".into(),
    ))
}

/// Parse 32-byte Ed25519 trust-root pin from hex. Empty, all-zero, or wrong size is Integrity.
pub fn parse_trust_root(hex: &str) -> Result<Vec<u8>> {
    let bytes = hex_decode(hex)?;
    pin_bytes(&bytes)?;
    Ok(bytes)
}

/// Verify FSIG with the caller pin. Returns FRMB/FEBP payload and its digest, never the FSIG wrapper.
/// Unsigned FRMB/FEBP is Integrity. Directory `digest` is checked when `expected_digest` is present.
pub fn load_source(
    bytes: &[u8],
    trust_root: &[u8],
    expected_digest: Option<&Digest>,
) -> Result<(Vec<u8>, Digest)> {
    pin_bytes(trust_root)?;
    let extracted = extract_fsig(bytes)?;
    if !extracted.fsig.starts_with(&SIGNED_MAGIC) {
        return Err(FerrumError::Integrity(
            "unsigned FRMB/FEBP rejected; agent requires a verified FSIG".into(),
        ));
    }
    let (public_key, signature, raw) = decode_fsig(&extracted.fsig)?;
    if public_key.as_slice() != trust_root {
        return Err(FerrumError::Integrity(
            "embedded FSIG public key does not match caller trust-root pin".into(),
        ));
    }
    ferrum_crypto::verify_bundle_signature(&raw, &signature, trust_root)?;
    if let Some(expected) = extracted.digest.as_ref() {
        ferrum_crypto::verify_bundle_digest(&raw, expected)?;
    }
    if let Some(expected) = expected_digest {
        ferrum_crypto::verify_bundle_digest(&raw, expected)?;
    }
    extract_febp(&raw)?;
    let digest = ferrum_crypto::bundle_digest(&raw);
    Ok((raw, digest))
}

/// Read a raw FSIG file, or a directory (kubelet Secret mount).
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

/// Verify and extract whatever kubelet/file `--bundle` points at.
pub fn load_path(path: &Path, trust_root: &[u8]) -> Result<(Vec<u8>, Digest)> {
    let (bytes, expected) = read_source_path(path)?;
    load_source(&bytes, trust_root, expected.as_ref())
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

/// Decode FSIG into (public_key, signature, raw). Does not treat the embedded key as trusted.
pub fn decode_fsig(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
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

fn pin_bytes(trust_root: &[u8]) -> Result<()> {
    if trust_root.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(FerrumError::Integrity(format!(
            "trust-root pin must be {ED25519_PUBLIC_KEY_LEN} bytes, got {}",
            trust_root.len()
        )));
    }
    if is_all_zero(trust_root) {
        return Err(FerrumError::Integrity(
            "Ed25519 public key must not be all zeros".into(),
        ));
    }
    Ok(())
}

fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |acc, b| acc | b) == 0
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

fn append_len_prefixed(out: &mut Vec<u8>, blob: &[u8], name: &str) -> Result<()> {
    let len = u32::try_from(blob.len())
        .map_err(|_| FerrumError::Integrity(format!("{name} exceeds u32 length")))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(blob);
    Ok(())
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
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
            .ok_or_else(|| FerrumError::Integrity("truncated signed bundle".into()))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| FerrumError::Integrity("truncated signed bundle".into()))?;
        self.pos = end;
        Ok(slice)
    }

    fn expect_magic(&mut self, magic: &[u8; 4]) -> Result<()> {
        let got = self.take(4)?;
        if got != magic {
            return Err(FerrumError::Integrity(
                "signed bundle magic is not FSIG".into(),
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
            .map_err(|_| FerrumError::Integrity(format!("truncated bundle {name}")))?
            .to_vec())
    }

    fn finish(self) -> Result<()> {
        if self.pos != self.buf.len() {
            return Err(FerrumError::Integrity(
                "trailing bytes in signed bundle".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    mtime: SystemTime,
    len: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SourceStamp {
    fsig: FileStamp,
    digest: Option<FileStamp>,
}

fn stamp_one(path: &Path) -> Option<FileStamp> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.is_dir() {
        return None;
    }
    Some(FileStamp {
        mtime: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        len: meta.len(),
    })
}

/// Stat the path as given so kubelet `..data` rotates are visible; do not canonicalize.
/// Vanished files return `None` so a poll loop keeps last-known-good.
pub(crate) fn source_stamp(path: &Path) -> Option<SourceStamp> {
    if let Some(snap) = source_snapshot_dir(path) {
        Some(SourceStamp {
            fsig: stamp_one(&snap.join(BUNDLE_FSIG_KEY))?,
            digest: Some(stamp_one(&snap.join(BUNDLE_DIGEST_KEY))?),
        })
    } else {
        Some(SourceStamp {
            fsig: stamp_one(path)?,
            digest: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_crypto::{public_key_from_secret, sign_bundle};

    const SK: [u8; 32] = [0x11; 32];
    const SK2: [u8; 32] = [0x22; 32];

    fn assert_integrity<T: std::fmt::Debug>(result: Result<T>) {
        match result {
            Err(FerrumError::Integrity(_)) => {}
            other => panic!("expected Integrity, got {other:?}"),
        }
    }

    fn tiny_febp() -> Vec<u8> {
        let mut bytes = Vec::from(EBPF_MAGIC);
        bytes.extend_from_slice(&[0u8; 8]);
        bytes
    }

    fn sign_raw(raw: &[u8], sk: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let pk = public_key_from_secret(sk).unwrap();
        let sig = sign_bundle(raw, sk).unwrap();
        (encode_fsig(raw, &sig, &pk).unwrap(), pk)
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ferrum-agent-source-{tag}-{}-{}",
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
    fn unsigned_febp_rejected() {
        let pk = public_key_from_secret(&SK).unwrap();
        assert_integrity(load_source(b"FEBP\x00\x00\x00\x01", &pk, None));
        assert_integrity(extract_fsig(b""));
        assert_integrity(extract_fsig(br#"{"data":{"bundle.fsig":"QQ=="}}"#));
    }

    #[test]
    fn unsigned_frmb_is_integrity() {
        let pk = public_key_from_secret(&SK).unwrap();
        let mut frmb = Vec::from(BUNDLE_MAGIC);
        frmb.extend_from_slice(&1u32.to_le_bytes());
        assert_integrity(load_source(&frmb, &pk, None));
        let extracted = extract_fsig(&frmb).expect("magic accepted");
        assert_eq!(extracted.digest, None);
    }

    #[test]
    fn truncated_fsig_is_integrity() {
        let pk = public_key_from_secret(&SK).unwrap();
        let mut bytes = Vec::from(SIGNED_MAGIC);
        bytes.extend_from_slice(&SIGNED_FORMAT.to_le_bytes());
        assert_integrity(load_source(&bytes, &pk, None));
    }

    #[test]
    fn wrong_pin_is_integrity() {
        let raw = tiny_febp();
        let (fsig, _pk) = sign_raw(&raw, &SK);
        let other = public_key_from_secret(&SK2).unwrap();
        assert_integrity(load_source(&fsig, &other, None));
    }

    #[test]
    fn empty_or_zero_pin_is_integrity() {
        let raw = tiny_febp();
        let (fsig, _pk) = sign_raw(&raw, &SK);
        assert_integrity(load_source(&fsig, &[], None));
        assert_integrity(load_source(&fsig, &[0u8; 32], None));
        assert_integrity(parse_trust_root(""));
        assert_integrity(parse_trust_root(&"00".repeat(32)));
    }

    #[test]
    fn matching_fsig_returns_payload_not_wrapper() {
        let raw = tiny_febp();
        let (fsig, pk) = sign_raw(&raw, &SK);
        let (got, digest) = load_source(&fsig, &pk, None).expect("load");
        assert_eq!(got, raw);
        assert_eq!(digest, ferrum_crypto::bundle_digest(&raw));
        assert_ne!(got, fsig);
    }

    #[test]
    fn dir_with_matching_digest_loads() {
        let raw = tiny_febp();
        let (fsig, pk) = sign_raw(&raw, &SK);
        let digest = ferrum_crypto::bundle_digest(&raw);
        let dir = temp_dir("match");
        write_secret_dir(&dir, &fsig, digest.as_str());
        let (got, got_digest) = load_path(&dir, &pk).expect("dir + matching digest");
        assert_eq!(got, raw);
        assert_eq!(got_digest, digest);
        load_source(&fsig, &pk, Some(&digest)).expect("expected digest");
        let named = dir.join(BUNDLE_FSIG_KEY);
        load_path(&named, &pk).expect("bundle.fsig + sibling digest");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dir_without_digest_or_mismatched_digest_is_integrity() {
        let raw = tiny_febp();
        let (fsig, pk) = sign_raw(&raw, &SK);
        let dir = temp_dir("mismatch");
        std::fs::write(dir.join(BUNDLE_FSIG_KEY), fsig.as_slice()).expect("bundle.fsig");
        assert_integrity(load_path(&dir, &pk));
        write_secret_dir(&dir, &fsig, &"00".repeat(32));
        assert_integrity(load_path(&dir, &pk));
        assert_integrity(load_source(&fsig, &pk, Some(&Digest::new("00".repeat(32)))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kubelet_data_snapshot_pairs_fsig_and_digest() {
        let raw = tiny_febp();
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
        assert!(source_stamp(&dir).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vanished_mount_has_no_stamp() {
        let dir = temp_dir("vanished");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(source_stamp(&dir).is_none());
    }

    #[test]
    fn parse_trust_root_roundtrip() {
        let pk = public_key_from_secret(&SK).unwrap();
        let mut hex = String::new();
        for b in &pk {
            hex.push_str(&format!("{b:02x}"));
        }
        assert_eq!(parse_trust_root(&hex).unwrap(), pk);
        assert_integrity(parse_trust_root("aabb"));
    }
}
