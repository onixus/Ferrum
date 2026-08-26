//! Signed PolicyBundle load. Verify before parse. No live Rekor/OCI/CT.

use ferrum_common::{FerrumError, Result};
use ferrum_ids::Digest;

use crate::program::{parse_program, AdmissionProgram, ADMISSION_ABI, ADMISSION_MAGIC};

const BUNDLE_MAGIC: [u8; 4] = *b"FRMB";
const BUNDLE_FORMAT: u32 = 1;

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
