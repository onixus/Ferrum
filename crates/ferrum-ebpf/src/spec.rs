//! FEBP encoding. Trailing bytes, truncation, and unknown enums fail closed.

use ferrum_common::{FerrumError, Result};
use ferrum_ids::AGENT_ABI;
use std::collections::BTreeMap;

pub const EBPF_MAGIC: [u8; 4] = *b"FEBP";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Observe = 0,
    Audit = 1,
    Enforce = 2,
}

impl Mode {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Observe),
            1 => Ok(Self::Audit),
            2 => Ok(Self::Enforce),
            other => Err(FerrumError::Compile(format!("unknown policy mode {other}"))),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Action {
    Allow = 0,
    Audit = 1,
    Deny = 2,
    Kill = 3,
    Isolate = 4,
}

impl Action {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Allow),
            1 => Ok(Self::Audit),
            2 => Ok(Self::Deny),
            3 => Ok(Self::Kill),
            4 => Ok(Self::Isolate),
            other => Err(FerrumError::Compile(format!(
                "unknown runtime action {other}"
            ))),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Audit => "audit",
            Self::Deny => "deny",
            Self::Kill => "kill",
            Self::Isolate => "isolate",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::Audit => 1,
            Self::Deny => 2,
            Self::Isolate => 3,
            Self::Kill => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub syscalls: Vec<String>,
    pub action: Action,
    pub comm_in: Vec<String>,
    pub container_only: bool,
    pub path_prefix: Vec<String>,
    pub path_suffix: Vec<String>,
    pub not_agent_self: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LabelSelector {
    pub match_labels: BTreeMap<String, String>,
    pub match_expressions: Vec<LabelRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelRequirement {
    pub key: String,
    pub operator: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImageSelector {
    pub registries_allow: Vec<String>,
    pub require_digest: bool,
}

/// Same encoding as FADM: 4 label selectors + registriesAllow + requireDigest.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicySelector {
    pub cluster_selector: LabelSelector,
    pub namespace_selector: LabelSelector,
    pub workload_selector: LabelSelector,
    pub service_account_selector: LabelSelector,
    pub image: ImageSelector,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfSpec {
    pub abi: u32,
    pub mode: Mode,
    pub disabled: bool,
    pub priority: i32,
    pub default_action: Action,
    pub selector: PolicySelector,
    pub rules: Vec<Rule>,
}

/// Parse FEBP. ABI mismatch is `Degraded` (keep LKG). Truncation / bad magic
/// is `Compile` (also keep LKG; do not apply).
pub fn parse_febp(spec: &[u8]) -> Result<EbpfSpec> {
    let mut r = Reader::new(spec);
    r.expect_magic(&EBPF_MAGIC)?;
    let abi = r.u32()?;
    if abi != AGENT_ABI {
        return Err(FerrumError::Degraded(format!(
            "eBPF ABI {abi} incompatible with AGENT_ABI {AGENT_ABI}"
        )));
    }
    let mode = Mode::from_u8(r.u8()?)?;
    let disabled = r.bool()?;
    let priority = r.i32()?;
    let default_action = Action::from_u8(r.u8()?)?;
    let selector = decode_selector(&mut r)?;
    let count = r.u16()? as usize;
    let mut rules = Vec::with_capacity(count);
    for _ in 0..count {
        rules.push(decode_rule(&mut r)?);
    }
    r.finish()?;
    reject_kill_all(&rules)?;
    reject_unobservable_syscalls(&rules)?;
    Ok(EbpfSpec {
        abi,
        mode,
        disabled,
        priority,
        default_action,
        selector,
        rules,
    })
}

fn trim_syscall(name: String) -> String {
    if name.trim().len() == name.len() {
        name
    } else {
        name.trim().to_string()
    }
}

/// Load-path copy of the compiler's "the datapath never observes this" gate,
/// alongside `reject_kill_all`. The encoder is a plain library call, so a FEBP
/// can reach this loader without passing through the compiler's checks at all;
/// a rule naming an unhooked syscall is dead weight in a signed bundle, and
/// the loader is the last place that can say so.
fn reject_unobservable_syscalls(rules: &[Rule]) -> Result<()> {
    for rule in rules {
        for syscall in &rule.syscalls {
            if !ferrum_ids::is_datapath_syscall(syscall.as_str()) {
                return Err(FerrumError::Compile(format!(
                    "rule '{}': syscall '{syscall}' is not hooked by the datapath; the rule can \
                     never fire. Observed: {}",
                    rule.id,
                    ferrum_ids::DATAPATH_SYSCALLS.join(", ")
                )));
            }
        }
    }
    Ok(())
}

fn reject_kill_all(rules: &[Rule]) -> Result<()> {
    for rule in rules {
        if matches!(rule.action, Action::Kill | Action::Isolate)
            && rule.syscalls.is_empty()
            && rule.comm_in.is_empty()
            && rule.path_prefix.is_empty()
            && rule.path_suffix.is_empty()
        {
            return Err(FerrumError::Compile(format!(
                "rule '{}' kill/isolate without match is kill-all",
                rule.id
            )));
        }
    }
    Ok(())
}

impl LabelSelector {
    pub fn is_empty(&self) -> bool {
        self.match_labels.is_empty() && self.match_expressions.is_empty()
    }
}

impl PolicySelector {
    pub fn is_empty(&self) -> bool {
        self.cluster_selector.is_empty()
            && self.namespace_selector.is_empty()
            && self.workload_selector.is_empty()
            && self.service_account_selector.is_empty()
            && self.image.registries_allow.is_empty()
            && !self.image.require_digest
    }

    pub fn is_namespaced(&self) -> bool {
        !self.namespace_selector.is_empty()
            || !self.workload_selector.is_empty()
            || !self.service_account_selector.is_empty()
    }
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
        match_expressions.push(LabelRequirement {
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

fn decode_rule(r: &mut Reader<'_>) -> Result<Rule> {
    Ok(Rule {
        id: r.str()?,
        // The one normalization point for syscall names. Validator and
        // compiler compare `trim()`ed names against DATAPATH_SYSCALLS, so a
        // name that reached the wire with surrounding whitespace (YAML
        // `[" execve"]`, a trailing CR) passed both gates; if the matcher
        // then compared it raw it would never fire. Comm and paths are NOT
        // trimmed: whitespace there is part of the value.
        syscalls: r.str_list()?.into_iter().map(trim_syscall).collect(),
        action: Action::from_u8(r.u8()?)?,
        comm_in: r.str_list()?,
        container_only: r.bool()?,
        path_prefix: r.str_list()?,
        path_suffix: r.str_list()?,
        not_agent_self: r.bool()?,
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
            .ok_or_else(|| FerrumError::Compile("truncated FEBP".into()))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| FerrumError::Compile("truncated FEBP".into()))?;
        self.pos = end;
        Ok(slice)
    }

    fn expect_magic(&mut self, magic: &[u8; 4]) -> Result<()> {
        let got = self.take(4)?;
        if got != magic {
            return Err(FerrumError::Compile("unexpected FEBP magic".into()));
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
            .map_err(|_| FerrumError::Compile("non-utf8 string in FEBP".into()))
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
            return Err(FerrumError::Compile("trailing bytes in FEBP".into()));
        }
        Ok(())
    }
}
