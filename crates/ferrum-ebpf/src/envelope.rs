//! FRMB envelope. Extract FEBP after digest/signature checks.

use crate::spec::EBPF_MAGIC;
use crate::AGENT_ABI;
use ferrum_common::{FerrumError, Result};

pub const BUNDLE_MAGIC: [u8; 4] = *b"FRMB";
pub const BUNDLE_FORMAT: u32 = 1;

/// FEBP slice from a verified payload. Accepts raw FEBP or an FRMB envelope.
pub fn extract_febp(raw: &[u8]) -> Result<&[u8]> {
    if raw.len() >= 4 && raw[..4] == EBPF_MAGIC {
        return Ok(raw);
    }
    parse_frmb(raw)
}

fn parse_frmb(raw: &[u8]) -> Result<&[u8]> {
    let mut r = Reader::new(raw);
    r.expect_magic(&BUNDLE_MAGIC)?;
    let format = r.u32()?;
    if format != BUNDLE_FORMAT {
        return Err(FerrumError::Compile(format!(
            "unknown policy bundle format {format}"
        )));
    }
    let min_agent_abi = r.u32()?;
    let _min_admission_abi = r.u32()?;
    if min_agent_abi != AGENT_ABI {
        return Err(FerrumError::Degraded(format!(
            "bundle minAgentAbi {min_agent_abi} incompatible with AGENT_ABI {AGENT_ABI}"
        )));
    }
    let admission_len = r.u32()? as usize;
    let _ = r.take(admission_len)?;
    let ebpf_len = r.u32()? as usize;
    let spec = r.take(ebpf_len)?;
    let wasm_len = r.u32()? as usize;
    let wasm = r.take(wasm_len)?;
    r.finish()?;
    if spec.len() < 4 || spec[..4] != EBPF_MAGIC {
        return Err(FerrumError::Compile("FRMB eBPF slice is not FEBP".into()));
    }
    // Before the FEBP slice is handed to a loader, and not after: a bundle
    // carrying a module this plane cannot execute must not be half-applied.
    ferrum_wasm_host::accept_bundle_slot(wasm)?;
    Ok(spec)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
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
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(bytes))
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
