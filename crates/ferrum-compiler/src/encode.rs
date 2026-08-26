//! Compact program encodings. No YAML, no kube types.

use ferrum_api::{
    AdmitDeny, AdmitMutate, AdmitSpec, ClusterSecurityPolicySpec, FailurePolicy, LabelSelector,
    PolicyMode, PolicySelector, PssProfile, RuntimeAction, RuntimeRule, RuntimeSpec,
    SecurityPolicySpec, SupplySpec,
};
use ferrum_common::{FerrumError, Result};
use ferrum_ids::{ADMISSION_ABI, AGENT_ABI};

#[cfg(test)]
use ferrum_api::{ImageSelector, LabelSelectorRequirement, RuntimeMatch, TrustRoot};
#[cfg(test)]
use std::collections::BTreeMap;

pub(crate) const ADMISSION_MAGIC: [u8; 4] = *b"FADM";
pub(crate) const EBPF_MAGIC: [u8; 4] = *b"FEBP";

pub(crate) struct Effects<'a> {
    pub mode: PolicyMode,
    pub priority: i32,
    pub disabled: bool,
    pub selector: &'a PolicySelector,
    pub supply: &'a SupplySpec,
    pub admit: &'a AdmitSpec,
    pub runtime: &'a RuntimeSpec,
}

macro_rules! effects_from {
    ($ty:ty) => {
        impl<'a> From<&'a $ty> for Effects<'a> {
            fn from(spec: &'a $ty) -> Self {
                Self {
                    mode: spec.mode,
                    priority: spec.priority,
                    disabled: spec.disabled,
                    selector: &spec.selector,
                    supply: &spec.supply,
                    admit: &spec.admit,
                    runtime: &spec.runtime,
                }
            }
        }
    };
}

effects_from!(ClusterSecurityPolicySpec);
effects_from!(SecurityPolicySpec);

struct Writer(Vec<u8>);

impl Writer {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn put_magic(&mut self, magic: &[u8; 4]) {
        self.0.extend_from_slice(magic);
    }

    fn put_u8(&mut self, v: u8) {
        self.0.push(v);
    }

    fn put_u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    fn put_u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    fn put_i32(&mut self, v: i32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    fn put_bool(&mut self, v: bool) {
        self.put_u8(u8::from(v));
    }

    fn put_str(&mut self, s: &str) -> Result<()> {
        let len = u16::try_from(s.len()).map_err(|_| {
            FerrumError::Compile(format!("string exceeds u16 length ({})", s.len()))
        })?;
        self.put_u16(len);
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }

    fn put_str_list(&mut self, items: &[String]) -> Result<()> {
        let count = u16::try_from(items.len()).map_err(|_| {
            FerrumError::Compile(format!("list exceeds u16 count ({})", items.len()))
        })?;
        self.put_u16(count);
        for item in items {
            self.put_str(item)?;
        }
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// `FADM` | u32 ADMISSION_ABI | mode | disabled | i32 priority | failure_policy | pss
/// | supply (trust root: name | keyless_issuer_allow | public_keys) | deny | mutate | selector
pub(crate) fn encode_admission(fx: &Effects<'_>) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.put_magic(&ADMISSION_MAGIC);
    w.put_u32(ADMISSION_ABI);
    w.put_u8(mode_to_u8(fx.mode));
    w.put_bool(fx.disabled);
    w.put_i32(fx.priority);
    w.put_u8(failure_policy_to_u8(fx.admit.failure_policy));
    w.put_u8(pss_to_u8(fx.admit.pss));
    encode_supply(&mut w, fx.supply)?;
    encode_deny(&mut w, &fx.admit.deny)?;
    encode_mutate(&mut w, &fx.admit.mutate);
    encode_selector(&mut w, fx.selector)?;
    Ok(w.finish())
}

/// `FEBP` | u32 AGENT_ABI | mode | disabled | i32 priority | default_action | selector | rules
///
/// Selector and priority are duplicated from FADM so runtime can scope without
/// parsing the admission program.
pub(crate) fn encode_ebpf(fx: &Effects<'_>) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.put_magic(&EBPF_MAGIC);
    w.put_u32(AGENT_ABI);
    w.put_u8(mode_to_u8(fx.mode));
    w.put_bool(fx.disabled);
    w.put_i32(fx.priority);
    w.put_u8(action_to_u8(fx.runtime.default_action));
    encode_selector(&mut w, fx.selector)?;
    let count = u16::try_from(fx.runtime.rules.len()).map_err(|_| {
        FerrumError::Compile(format!(
            "runtime rule count exceeds u16 ({})",
            fx.runtime.rules.len()
        ))
    })?;
    w.put_u16(count);
    for rule in &fx.runtime.rules {
        encode_rule(&mut w, rule)?;
    }
    Ok(w.finish())
}

fn encode_supply(w: &mut Writer, supply: &SupplySpec) -> Result<()> {
    w.put_bool(supply.require_signed);
    w.put_bool(supply.deny_unsigned);
    w.put_bool(supply.deny_latest_tag);
    let count = u16::try_from(supply.trust_roots.len()).map_err(|_| {
        FerrumError::Compile(format!(
            "trust root count exceeds u16 ({})",
            supply.trust_roots.len()
        ))
    })?;
    w.put_u16(count);
    for root in &supply.trust_roots {
        w.put_str(&root.name)?;
        w.put_str_list(&root.keyless_issuer_allow)?;
        w.put_str_list(&root.public_keys)?;
    }
    Ok(())
}

fn encode_deny(w: &mut Writer, deny: &AdmitDeny) -> Result<()> {
    w.put_bool(deny.privileged);
    w.put_bool(deny.host_pid);
    w.put_bool(deny.host_ipc);
    w.put_bool(deny.host_network);
    w.put_bool(deny.host_path);
    w.put_bool(deny.allow_privilege_escalation);
    w.put_bool(deny.run_as_root);
    w.put_bool(deny.wildcards_rbac);
    w.put_bool(deny.cluster_admin_bind);
    w.put_str_list(&deny.added_capabilities)
}

fn encode_mutate(w: &mut Writer, mutate: &AdmitMutate) {
    w.put_bool(mutate.inject_seccomp_runtime_default);
    w.put_bool(mutate.drop_all_capabilities);
    w.put_bool(mutate.read_only_root_filesystem);
}

fn encode_selector(w: &mut Writer, selector: &PolicySelector) -> Result<()> {
    encode_label_selector(w, &selector.cluster_selector)?;
    encode_label_selector(w, &selector.namespace_selector)?;
    encode_label_selector(w, &selector.workload_selector)?;
    encode_label_selector(w, &selector.service_account_selector)?;
    w.put_str_list(&selector.image.registries_allow)?;
    w.put_bool(selector.image.require_digest);
    Ok(())
}

fn encode_label_selector(w: &mut Writer, selector: &LabelSelector) -> Result<()> {
    let count = u16::try_from(selector.match_labels.len()).map_err(|_| {
        FerrumError::Compile(format!(
            "matchLabels count exceeds u16 ({})",
            selector.match_labels.len()
        ))
    })?;
    w.put_u16(count);
    for (key, value) in &selector.match_labels {
        w.put_str(key)?;
        w.put_str(value)?;
    }
    let expr_count = u16::try_from(selector.match_expressions.len()).map_err(|_| {
        FerrumError::Compile(format!(
            "matchExpressions count exceeds u16 ({})",
            selector.match_expressions.len()
        ))
    })?;
    w.put_u16(expr_count);
    for expr in &selector.match_expressions {
        w.put_str(&expr.key)?;
        w.put_str(&expr.operator)?;
        w.put_str_list(&expr.values)?;
    }
    Ok(())
}

fn encode_rule(w: &mut Writer, rule: &RuntimeRule) -> Result<()> {
    w.put_str(&rule.id)?;
    w.put_str_list(&rule.syscalls)?;
    w.put_u8(action_to_u8(rule.action));
    w.put_str_list(&rule.match_on.comm_in)?;
    w.put_bool(rule.match_on.container_only);
    w.put_str_list(&rule.match_on.path_prefix)?;
    w.put_str_list(&rule.match_on.path_suffix)?;
    w.put_bool(rule.match_on.not_agent_self);
    Ok(())
}

fn mode_to_u8(mode: PolicyMode) -> u8 {
    match mode {
        PolicyMode::Observe => 0,
        PolicyMode::Audit => 1,
        PolicyMode::Enforce => 2,
    }
}

fn failure_policy_to_u8(policy: FailurePolicy) -> u8 {
    match policy {
        FailurePolicy::Fail => 0,
        FailurePolicy::Ignore => 1,
    }
}

fn pss_to_u8(pss: PssProfile) -> u8 {
    match pss {
        PssProfile::Privileged => 0,
        PssProfile::Baseline => 1,
        PssProfile::Restricted => 2,
        PssProfile::Custom => 3,
    }
}

fn action_to_u8(action: RuntimeAction) -> u8 {
    match action {
        RuntimeAction::Allow => 0,
        RuntimeAction::Audit => 1,
        RuntimeAction::Deny => 2,
        RuntimeAction::Kill => 3,
        RuntimeAction::Isolate => 4,
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DecodedAdmission {
    pub abi: u32,
    pub mode: PolicyMode,
    pub disabled: bool,
    pub priority: i32,
    pub supply: SupplySpec,
    pub admit: AdmitSpec,
    pub selector: PolicySelector,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DecodedEbpf {
    pub abi: u32,
    pub mode: PolicyMode,
    pub disabled: bool,
    pub priority: i32,
    pub selector: PolicySelector,
    pub runtime: RuntimeSpec,
}

#[cfg(test)]
pub(crate) fn decode_admission(buf: &[u8]) -> Result<DecodedAdmission> {
    let mut r = Reader::new(buf);
    r.expect_magic(&ADMISSION_MAGIC)?;
    let abi = r.u32()?;
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
    Ok(DecodedAdmission {
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

#[cfg(test)]
pub(crate) fn decode_ebpf(buf: &[u8]) -> Result<DecodedEbpf> {
    let mut r = Reader::new(buf);
    r.expect_magic(&EBPF_MAGIC)?;
    let abi = r.u32()?;
    let mode = mode_from_u8(r.u8()?)?;
    let disabled = r.bool()?;
    let priority = r.i32()?;
    let default_action = action_from_u8(r.u8()?)?;
    let selector = decode_selector(&mut r)?;
    let count = r.u16()? as usize;
    let mut rules = Vec::with_capacity(count);
    for _ in 0..count {
        rules.push(decode_rule(&mut r)?);
    }
    r.finish()?;
    Ok(DecodedEbpf {
        abi,
        mode,
        disabled,
        priority,
        selector,
        runtime: RuntimeSpec {
            default_action,
            rules,
        },
    })
}

#[cfg(test)]
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

#[cfg(test)]
impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| FerrumError::Compile("truncated compiled program".into()))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| FerrumError::Compile("truncated compiled program".into()))?;
        self.pos = end;
        Ok(slice)
    }

    fn expect_magic(&mut self, magic: &[u8; 4]) -> Result<()> {
        let got = self.take(4)?;
        if got != magic {
            return Err(FerrumError::Compile("unexpected program magic".into()));
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32> {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(bytes))
    }

    fn i32(&mut self) -> Result<i32> {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(self.take(4)?);
        Ok(i32::from_le_bytes(bytes))
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
            .map_err(|_| FerrumError::Compile("non-utf8 string in program".into()))
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
                "trailing bytes in compiled program".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
fn decode_mutate(r: &mut Reader<'_>) -> Result<AdmitMutate> {
    Ok(AdmitMutate {
        inject_seccomp_runtime_default: r.bool()?,
        drop_all_capabilities: r.bool()?,
        read_only_root_filesystem: r.bool()?,
    })
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
fn decode_rule(r: &mut Reader<'_>) -> Result<RuntimeRule> {
    Ok(RuntimeRule {
        id: r.str()?,
        syscalls: r.str_list()?,
        action: action_from_u8(r.u8()?)?,
        match_on: RuntimeMatch {
            comm_in: r.str_list()?,
            container_only: r.bool()?,
            path_prefix: r.str_list()?,
            path_suffix: r.str_list()?,
            not_agent_self: r.bool()?,
        },
    })
}

#[cfg(test)]
fn mode_from_u8(v: u8) -> Result<PolicyMode> {
    match v {
        0 => Ok(PolicyMode::Observe),
        1 => Ok(PolicyMode::Audit),
        2 => Ok(PolicyMode::Enforce),
        other => Err(FerrumError::Compile(format!("unknown policy mode {other}"))),
    }
}

#[cfg(test)]
fn failure_policy_from_u8(v: u8) -> Result<FailurePolicy> {
    match v {
        0 => Ok(FailurePolicy::Fail),
        1 => Ok(FailurePolicy::Ignore),
        other => Err(FerrumError::Compile(format!(
            "unknown failurePolicy {other}"
        ))),
    }
}

#[cfg(test)]
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
fn action_from_u8(v: u8) -> Result<RuntimeAction> {
    match v {
        0 => Ok(RuntimeAction::Allow),
        1 => Ok(RuntimeAction::Audit),
        2 => Ok(RuntimeAction::Deny),
        3 => Ok(RuntimeAction::Kill),
        4 => Ok(RuntimeAction::Isolate),
        other => Err(FerrumError::Compile(format!(
            "unknown runtime action {other}"
        ))),
    }
}
