//! FADM parser. Unknown ABI, bad magic, truncation, or trailing bytes deny.
//! Extra supply material that this ABI cannot parse is not skipped.

use std::collections::BTreeMap;

use ferrum_api::{
    AdmitDeny, AdmitMutate, AdmitSpec, FailurePolicy, ImageSelector, LabelSelector,
    LabelSelectorRequirement, PolicyMode, PolicySelector, PssProfile, SupplySpec, TrustRoot,
};
use ferrum_common::{FerrumError, Result};

/// Compiled admission program magic (`FADM`).
pub const ADMISSION_MAGIC: [u8; 4] = *b"FADM";
/// Unknown values fail closed.
pub const ADMISSION_ABI: u32 = ferrum_ids::ADMISSION_ABI;

/// Parsed FADM program. Trust roots are those encoded in the bundle.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmissionProgram {
    pub abi: u32,
    pub mode: PolicyMode,
    pub disabled: bool,
    pub priority: i32,
    pub supply: SupplySpec,
    pub admit: AdmitSpec,
    pub selector: PolicySelector,
}

impl AdmissionProgram {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        parse_program(bytes)
    }

    /// Namespaced programs cannot Ignore. Cluster Ignore is break-glass for
    /// webhook availability, never for a missing/invalid/unverified bundle.
    pub fn effective_failure_policy(&self, namespaced: bool) -> FailurePolicy {
        if namespaced {
            FailurePolicy::Fail
        } else {
            self.admit.failure_policy
        }
    }
}

/// Parse a compiled `FADM` program. Does not fetch trust roots.
pub fn parse_program(bytes: &[u8]) -> Result<AdmissionProgram> {
    if bytes.is_empty() {
        return Err(FerrumError::Integrity(
            "admission program is empty; missing bundle is not fail-open".into(),
        ));
    }
    let mut r = Reader::new(bytes);
    r.expect_magic(&ADMISSION_MAGIC)?;
    let abi = r.u32()?;
    if abi != ADMISSION_ABI {
        return Err(FerrumError::Compile(format!(
            "unknown admission ABI {abi}, want {ADMISSION_ABI}"
        )));
    }
    let mode = mode_from_u8(r.u8()?)?;
    let disabled = r.bool()?;
    let priority = r.i32()?;
    let failure_policy = failure_policy_from_u8(r.u8()?)?;
    let pss = pss_from_u8(r.u8()?)?;
    let supply = decode_supply(&mut r)?;
    let deny = decode_deny(&mut r)?;
    let mutate = decode_mutate(&mut r)?;
    let selector = decode_selector(&mut r)?;
    r.finish()?;
    Ok(AdmissionProgram {
        abi,
        mode,
        disabled,
        priority,
        supply,
        admit: AdmitSpec {
            failure_policy,
            pss,
            deny,
            mutate,
        },
        selector,
    })
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
            .ok_or_else(|| FerrumError::Compile("truncated admission program".into()))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| FerrumError::Compile("truncated admission program".into()))?;
        self.pos = end;
        Ok(slice)
    }

    fn expect_magic(&mut self, magic: &[u8; 4]) -> Result<()> {
        let got = self.take(4)?;
        if got != magic {
            return Err(FerrumError::Compile(
                "unexpected admission program magic".into(),
            ));
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn i32(&mut self) -> Result<i32> {
        let b = self.take(4)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(FerrumError::Compile(format!("invalid bool byte {other}"))),
        }
    }

    fn str(&mut self) -> Result<String> {
        let len = self.u16()? as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| FerrumError::Compile("non-utf8 string in admission program".into()))
    }

    fn str_list(&mut self) -> Result<Vec<String>> {
        let count = self.u16()? as usize;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.str()?);
        }
        Ok(out)
    }

    fn finish(self) -> Result<()> {
        if self.pos != self.buf.len() {
            return Err(FerrumError::Compile(
                "trailing bytes in admission program; extra supply data is not ignored".into(),
            ));
        }
        Ok(())
    }
}

fn decode_supply(r: &mut Reader<'_>) -> Result<SupplySpec> {
    let require_signed = r.bool()?;
    let deny_unsigned = r.bool()?;
    let deny_latest_tag = r.bool()?;
    let count = r.u16()? as usize;
    let mut trust_roots = Vec::with_capacity(count);
    for _ in 0..count {
        trust_roots.push(TrustRoot {
            name: r.str()?,
            keyless_issuer_allow: r.str_list()?,
            public_keys: r.str_list()?,
        });
    }
    Ok(SupplySpec {
        require_signed,
        deny_unsigned,
        deny_latest_tag,
        trust_roots,
    })
}

fn decode_deny(r: &mut Reader<'_>) -> Result<AdmitDeny> {
    Ok(AdmitDeny {
        privileged: r.bool()?,
        host_pid: r.bool()?,
        host_ipc: r.bool()?,
        host_network: r.bool()?,
        host_path: r.bool()?,
        allow_privilege_escalation: r.bool()?,
        run_as_root: r.bool()?,
        wildcards_rbac: r.bool()?,
        cluster_admin_bind: r.bool()?,
        added_capabilities: r.str_list()?,
    })
}

fn decode_mutate(r: &mut Reader<'_>) -> Result<AdmitMutate> {
    Ok(AdmitMutate {
        inject_seccomp_runtime_default: r.bool()?,
        drop_all_capabilities: r.bool()?,
        read_only_root_filesystem: r.bool()?,
    })
}

fn decode_selector(r: &mut Reader<'_>) -> Result<PolicySelector> {
    Ok(PolicySelector {
        cluster_selector: decode_label_selector(r)?,
        namespace_selector: decode_label_selector(r)?,
        workload_selector: decode_label_selector(r)?,
        service_account_selector: decode_label_selector(r)?,
        image: ImageSelector {
            registries_allow: r.str_list()?,
            require_digest: r.bool()?,
        },
    })
}

fn decode_label_selector(r: &mut Reader<'_>) -> Result<LabelSelector> {
    let label_count = r.u16()? as usize;
    let mut match_labels = BTreeMap::new();
    for _ in 0..label_count {
        match_labels.insert(r.str()?, r.str()?);
    }
    let expr_count = r.u16()? as usize;
    let mut match_expressions = Vec::with_capacity(expr_count);
    for _ in 0..expr_count {
        match_expressions.push(LabelSelectorRequirement {
            key: r.str()?,
            operator: r.str()?,
            values: r.str_list()?,
        });
    }
    Ok(LabelSelector {
        match_labels,
        match_expressions,
    })
}

fn mode_from_u8(v: u8) -> Result<PolicyMode> {
    match v {
        0 => Ok(PolicyMode::Observe),
        1 => Ok(PolicyMode::Audit),
        2 => Ok(PolicyMode::Enforce),
        other => Err(FerrumError::Compile(format!("unknown policy mode {other}"))),
    }
}

fn failure_policy_from_u8(v: u8) -> Result<FailurePolicy> {
    match v {
        0 => Ok(FailurePolicy::Fail),
        1 => Ok(FailurePolicy::Ignore),
        other => Err(FerrumError::Compile(format!(
            "unknown failurePolicy {other}"
        ))),
    }
}

fn pss_from_u8(v: u8) -> Result<PssProfile> {
    match v {
        0 => Ok(PssProfile::Privileged),
        1 => Ok(PssProfile::Baseline),
        2 => Ok(PssProfile::Restricted),
        3 => Ok(PssProfile::Custom),
        other => Err(FerrumError::Compile(format!("unknown pss {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_compile_err(bytes: &[u8]) {
        match parse_program(bytes) {
            Err(FerrumError::Compile(_) | FerrumError::Integrity(_)) => {}
            other => panic!("expected fail-closed parse error, got {other:?}"),
        }
    }

    #[test]
    fn empty_and_truncated_fail_closed() {
        assert_compile_err(&[]);
        assert_compile_err(b"FAD");
        assert_compile_err(b"FADM");
        let mut hdr = Vec::from(ADMISSION_MAGIC);
        hdr.extend_from_slice(&ADMISSION_ABI.to_le_bytes());
        assert_compile_err(&hdr);
    }

    #[test]
    fn bad_magic_fails_closed() {
        let mut bytes = vec![0u8; 16];
        bytes[..4].copy_from_slice(b"XXXX");
        bytes[4..8].copy_from_slice(&ADMISSION_ABI.to_le_bytes());
        assert_compile_err(&bytes);
    }

    #[test]
    fn unknown_abi_fails_closed() {
        let mut bytes = vec![0u8; 16];
        bytes[..4].copy_from_slice(&ADMISSION_MAGIC);
        bytes[4..8].copy_from_slice(&0xFFFFu32.to_le_bytes());
        assert_compile_err(&bytes);
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

    fn empty_selector(out: &mut Vec<u8>) {
        put_u16(out, 0);
        put_u16(out, 0);
    }

    #[test]
    fn decode_supply_reads_public_keys_and_rejects_trailing() {
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
        bytes.push(0); // deny_latest_tag
        put_u16(&mut bytes, 1);
        put_str(&mut bytes, "org-cosign");
        put_str_list(&mut bytes, &["https://token.actions.githubusercontent.com"]);
        put_str_list(
            &mut bytes,
            &["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
        );
        bytes.extend_from_slice(&[0; 9]); // deny flags
        put_str_list(&mut bytes, &[]); // added_capabilities
        bytes.extend_from_slice(&[0, 0, 0]); // mutate
        for _ in 0..4 {
            empty_selector(&mut bytes);
        }
        put_str_list(&mut bytes, &[]);
        bytes.push(0); // require_digest

        let parsed = parse_program(&bytes).expect("three-list trust root");
        assert_eq!(parsed.supply.trust_roots[0].name, "org-cosign");
        assert_eq!(parsed.supply.trust_roots[0].public_keys[0].len(), 64);

        let mut trailing = bytes.clone();
        trailing.push(0xFF);
        assert_compile_err(&trailing);
    }
}
