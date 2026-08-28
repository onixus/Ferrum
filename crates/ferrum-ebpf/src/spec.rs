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

/// `Deny` and `Isolate` are decided by this plane and executed by neither.
/// The validator and the CRDs refuse them; [`parse_febp_with`] deliberately
/// does not, and says why.
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

/// What to do with a rule no record can ever match (see `dead_rule_reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadRules {
    /// Refuse the whole spec. Every path that installs a *new* bundle: a dead
    /// rule there is a compiler that let something through, and the operator
    /// still has the previous policy running.
    Reject,
    /// Drop the rule, keep the rest. Restoring last-known-good only, where the
    /// alternative is no policy at all on the node.
    Drop,
}

/// Parse FEBP. ABI mismatch is `Degraded` (keep LKG). Truncation / bad magic
/// is `Compile` (also keep LKG; do not apply).
pub fn parse_febp(spec: &[u8]) -> Result<EbpfSpec> {
    parse_febp_with(spec, DeadRules::Reject).map(|(spec, _)| spec)
}

/// Parse FEBP, choosing what happens to rules no record can match. Returns the
/// reason for each dropped rule; empty under [`DeadRules::Reject`], which
/// fails instead. Nothing else is relaxed: a malformed, ABI-mismatched or
/// kill-all spec is still refused whole.
///
/// # The one gate that is deliberately not here: `action`
///
/// `ferrum_policy::validate_rule_action` and the CEL copy on both
/// SecurityPolicy CRDs refuse a runtime `deny` / `isolate`, because the
/// runtime plane executes allow / audit / kill and nothing else. This loader
/// does not, on either path, and that is a decision rather than the same
/// omission the syscall gate above was written to close. Three reasons, and
/// all three have to hold:
///
/// 1. It is not a dead rule. An unhooked syscall or an over-long `comm`
///    produces no record at all, which is what makes it droppable. A `deny`
///    rule matches: `ferrum-agent` exports the event with `executed=false`
///    and `REFUSE_DENY_NOT_ENFORCEABLE` (`REFUSE_ISOLATE` for the other), and
///    counts it in `respond_refused_total`. The gap is on the record, per
///    event, by name — nothing is silently downgraded to a verdict nobody
///    carried out. That premise is the whole justification, so it is held by
///    a gate: `a_pre_gate_deny_bundle_loads_and_every_match_is_recorded` in
///    `ferrum-testkit/tests/replay.rs`.
/// 2. Refusing it buys nothing against the threat model. Only a bundle signed
///    by the pinned trust root gets this far, and whoever can sign one can
///    write `action: allow` instead — no loader gate can catch that. The
///    action gate is a drift gate for policy authors, and it belongs where the
///    author is: at validation and at admission, where refusal costs the
///    operator nothing because the previous policy keeps running.
/// 3. Refusing it costs the fleet. The bundles that carry a runtime `deny`
///    are the ones an older controller signs — the shipped example carried
///    exactly one until cycle 7 — so a newer agent refusing them whole stops
///    that node taking any update at all from a control plane that is still
///    serving every other agent correctly. That is cycle 6's "agent upgrade +
///    control plane down = zero enforcement", moved onto the live path, and
///    [`DeadRules::Drop`] cannot soften it: dropping a matching rule silently
///    substitutes `defaultAction` for a verdict the operator wrote.
///
/// If any of the three stops holding — in particular if a `deny` match ever
/// becomes indistinguishable from an audit one — the gate belongs here after
/// all, and this note goes with it.
///
/// # Why `defaultAction` splits where a rule `action` does not
///
/// `default_action` is refused for `kill` and `isolate` (see `reject_kill_all`)
/// and accepted for `deny`, and that asymmetry is the point rather than an
/// oversight to tidy up. Both are "an action no plane executes", but they do
/// not cost the same. A `deny` default decides nothing that is carried out:
/// every unmatched record is exported with `REFUSE_DENY_NOT_ENFORCEABLE`, by
/// name, exactly as a `deny` rule is — inert, visible, and the identical drift
/// from the identical older compiler that signs a `deny` rule, so reason 3
/// above applies to it unchanged: refusing it would strand the node on a
/// rolling upgrade. A `kill` or `isolate` default decides *kill* on every
/// record no rule matched, which on a respond node with `ferrum_cgroups`
/// synced is a kill-all — the one thing `AGENTS.md` forbids outright, and the
/// one an operator cannot walk back. Only one of the two can kill a pod, so
/// only one of the two is worth refusing a whole fleet's bundle over.
pub fn parse_febp_with(spec: &[u8], dead: DeadRules) -> Result<(EbpfSpec, Vec<String>)> {
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
    reject_kill_all(default_action, &rules)?;
    let mut dropped = Vec::new();
    match dead {
        DeadRules::Reject => {
            if let Some(reason) = rules.iter().find_map(dead_rule_reason) {
                return Err(FerrumError::Compile(reason));
            }
        }
        DeadRules::Drop => {
            let mut kept = Vec::with_capacity(rules.len());
            for rule in rules {
                match dead_rule_reason(&rule) {
                    Some(reason) => dropped.push(reason),
                    None => kept.push(rule),
                }
            }
            rules = kept;
        }
    }
    Ok((
        EbpfSpec {
            abi,
            mode,
            disabled,
            priority,
            default_action,
            selector,
            rules,
        },
        dropped,
    ))
}

fn trim_syscall(name: String) -> String {
    if name.trim().len() == name.len() {
        name
    } else {
        name.trim().to_string()
    }
}

/// Why this rule can never fire, if it cannot. Load-path copy of the
/// compiler's "the datapath never observes this" gates: the encoder is a plain
/// library call, so a FEBP can reach this loader without passing through the
/// compiler at all, and a bundle signed by an older compiler that had no such
/// gate must not load quietly into a newer agent.
///
/// Every reason here is "dead weight", never "unsafe": an unhooked syscall
/// produces no record, and a `comm` longer than TASK_COMM_LEN or a path
/// fragment longer than the datapath path buffer appears in no record field.
/// That is what makes [`DeadRules::Drop`] admissible on the restore path.
fn dead_rule_reason(rule: &Rule) -> Option<String> {
    for syscall in &rule.syscalls {
        if !ferrum_ids::is_datapath_syscall(syscall.as_str()) {
            return Some(format!(
                "rule '{}': syscall '{syscall}' is not hooked by the datapath; the rule can \
                 never fire. Observed: {}",
                rule.id,
                ferrum_ids::DATAPATH_SYSCALLS.join(", ")
            ));
        }
    }
    if let Some((comm, len)) = ferrum_ids::unobservable_comm(&rule.comm_in) {
        return Some(format!(
            "rule '{}': comm '{comm}' is {len} bytes, the kernel reports at most {}; \
             the rule can never match",
            rule.id,
            ferrum_ids::COMM_MATCH_MAX
        ));
    }
    for patterns in [&rule.path_prefix, &rule.path_suffix] {
        if let Some((pattern, len)) = ferrum_ids::unobservable_path_pattern(patterns) {
            return Some(format!(
                "rule '{}': path pattern '{pattern}' is {len} bytes, the datapath path \
                 buffer carries at most {}; the rule can never match",
                rule.id,
                ferrum_ids::PATH_MATCH_MAX
            ));
        }
    }
    None
}

/// Load-path copy of `ferrum_policy`'s kill-all invariant, on both halves.
///
/// This is not a dead-rule reason and [`DeadRules::Drop`] must never reach it.
/// Dropping is admissible only for a rule no record can match; a kill-all
/// matches every record, and substituting `Allow` for it would be the exact
/// fail-open the last-known-good path exists to prevent. So a kill-all refuses
/// the whole spec on both paths, live and restore.
///
/// `default_action` matters most of the two here and had no gate at all: the
/// loader decoded it and never looked at it again, so a signed FEBP with
/// `default_action = Kill` installed cleanly and every record no rule matched
/// decided Kill. No rule-level gate can catch that, because a default is not a
/// rule and no `match` narrows it. `Deny` is deliberately still accepted — see
/// `parse_febp_with`'s note on why the two defaults do not cost the same.
fn reject_kill_all(default_action: Action, rules: &[Rule]) -> Result<()> {
    if matches!(default_action, Action::Kill | Action::Isolate) {
        return Err(FerrumError::Compile(format!(
            "defaultAction {default_action:?} is kill-all: it decides every record no rule matched, and no match narrows it"
        )));
    }
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
