use crate::spec::{Action, EbpfSpec, LabelRequirement, LabelSelector, Mode, PolicySelector, Rule};
use ferrum_k8smeta::WorkloadIdentity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallEvent<'a> {
    pub syscall: &'a str,
    pub comm: &'a str,
    pub path: &'a str,
    pub in_container: bool,
    pub agent_self: bool,
    /// `path` is not the argument: the datapath buffer could not hold it, or
    /// the pointer could not be read. A non-empty `path` is then a head with
    /// an unknown tail; an empty one means the argument was never read and
    /// nothing about the path is known.
    pub path_truncated: bool,
}

/// Structural identity of one ring record, kept beside the string view a rule
/// matches on. `SyscallEvent` is instantiated by other crates, so the pid/tgid
/// a reaction needs live here instead of being bolted onto it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EventMeta {
    pub cgroup_id: u64,
    pub pid: u32,
    pub tgid: u32,
    pub in_container: bool,
    pub agent_self: bool,
    pub path_truncated: bool,
}

impl EventMeta {
    /// Cgroup-only meta. Carries no tgid, so no reaction can fire from it.
    pub fn from_cgroup(cgroup_id: u64) -> Self {
        Self {
            cgroup_id,
            ..Self::default()
        }
    }
}

impl From<u64> for EventMeta {
    fn from(cgroup_id: u64) -> Self {
        Self::from_cgroup(cgroup_id)
    }
}

impl From<&EventMeta> for EventMeta {
    fn from(meta: &EventMeta) -> Self {
        *meta
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    pub rule_id: Option<String>,
    /// The selector could not be resolved: a non-empty cluster / namespace /
    /// ServiceAccount selector was matched against labels nobody has observed
    /// yet. The rules were applied anyway (fail closed), and the carrier must
    /// treat this as Degraded rather than as a clean decision.
    pub labels_unknown: bool,
    /// A path predicate was accepted against a path the datapath could not
    /// carry whole, so the match is asserted, not proven. Same contract as
    /// `labels_unknown`: the rules were applied, and the carrier must treat
    /// this as Degraded.
    pub path_unknown: bool,
}

/// Outcome of matching a program selector against a workload identity.
///
/// Cluster / namespace / ServiceAccount labels are not carried by the event:
/// they are joined in from watch caches that can be cold, relisting after a
/// 410, or dead. An empty map there means "never observed", not "no labels",
/// so it is not a non-match. Admission fails closed on exactly this condition
/// (`require_labels_if_selected`); the runtime plane must not diverge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorMatch {
    Match,
    NoMatch,
    LabelsUnknown,
}

/// Raw rule match. Ignores `mode` / `disabled` / selector so tests can assert MVP effects.
pub fn matched_action(spec: &EbpfSpec, event: &SyscallEvent<'_>) -> Decision {
    let mut best: Option<(&Rule, bool, u8)> = None;
    for rule in &spec.rules {
        let Some(path_unknown) = rule_matches(rule, event) else {
            continue;
        };
        let rank = rule.action.rank();
        let take = match best {
            None => true,
            Some((_, _, best_rank)) => rank > best_rank,
        };
        if take {
            best = Some((rule, path_unknown, rank));
        }
    }
    match best {
        Some((rule, path_unknown, _)) => Decision {
            action: rule.action,
            rule_id: Some(rule.id.clone()),
            labels_unknown: false,
            path_unknown,
        },
        None => Decision {
            action: spec.default_action,
            rule_id: None,
            labels_unknown: false,
            path_unknown: false,
        },
    }
}

/// Apply selector, then mode / disabled. Observe and Audit never deny/kill/isolate.
/// Selector miss: this program does not apply (`Allow`). Empty selector is cluster-wide.
/// Labels not observed: the program is applied and the decision is flagged
/// `labels_unknown`, because skipping the rules there is a silent fail-open.
pub fn decide(spec: &EbpfSpec, event: &SyscallEvent<'_>, identity: &WorkloadIdentity) -> Decision {
    let labels_unknown = match selector_match(&spec.selector, identity) {
        SelectorMatch::NoMatch => {
            return Decision {
                action: Action::Allow,
                rule_id: None,
                labels_unknown: false,
                path_unknown: false,
            }
        }
        SelectorMatch::Match => false,
        SelectorMatch::LabelsUnknown => true,
    };
    let mut decision = matched_action(spec, event);
    decision.action = cap_for_mode(spec.mode, spec.disabled, decision.action);
    decision.labels_unknown = labels_unknown;
    decision
}

/// True only for a resolved match. An unresolved selector is NOT a match here;
/// callers that must not fail open use [`selector_match`].
pub fn selector_matches(selector: &PolicySelector, identity: &WorkloadIdentity) -> bool {
    matches!(selector_match(selector, identity), SelectorMatch::Match)
}

pub fn selector_match(selector: &PolicySelector, identity: &WorkloadIdentity) -> SelectorMatch {
    if selector.is_empty() {
        return SelectorMatch::Match;
    }
    // No pod behind the cgroup at all: the index missed, which is its own
    // Degraded signal. Nothing here can be resolved against that identity.
    if selector.is_namespaced() && identity.is_unknown() {
        return SelectorMatch::NoMatch;
    }
    // Workload labels ride on the pod record itself, so they are known as soon
    // as the pod is; the other three are joined in from separate watches.
    if labels_missing(&selector.cluster_selector, &identity.cluster_labels)
        || labels_missing(&selector.namespace_selector, &identity.namespace_labels)
        || labels_missing(
            &selector.service_account_selector,
            &identity.service_account_labels,
        )
    {
        return SelectorMatch::LabelsUnknown;
    }
    let matched = label_selector_matches(&selector.cluster_selector, &identity.cluster_labels)
        && label_selector_matches(&selector.namespace_selector, &identity.namespace_labels)
        && label_selector_matches(&selector.workload_selector, &identity.workload_labels)
        && label_selector_matches(
            &selector.service_account_selector,
            &identity.service_account_labels,
        )
        && image_matches(selector, identity);
    if matched {
        SelectorMatch::Match
    } else {
        SelectorMatch::NoMatch
    }
}

fn labels_missing(
    selector: &LabelSelector,
    labels: &std::collections::BTreeMap<String, String>,
) -> bool {
    !selector.is_empty() && labels.is_empty()
}

fn image_matches(selector: &PolicySelector, identity: &WorkloadIdentity) -> bool {
    if !selector.image.registries_allow.is_empty() {
        let ok = selector
            .image
            .registries_allow
            .iter()
            .any(|reg| !reg.is_empty() && identity.image.starts_with(reg.as_str()));
        if !ok {
            return false;
        }
    }
    if selector.image.require_digest {
        let has_digest = !identity.image_digest.is_empty() || identity.image.contains("@sha256:");
        if !has_digest {
            return false;
        }
    }
    true
}

fn label_selector_matches(
    selector: &LabelSelector,
    labels: &std::collections::BTreeMap<String, String>,
) -> bool {
    if selector.is_empty() {
        return true;
    }
    for (key, value) in &selector.match_labels {
        if labels.get(key) != Some(value) {
            return false;
        }
    }
    for expr in &selector.match_expressions {
        if !expression_matches(expr, labels) {
            return false;
        }
    }
    true
}

fn expression_matches(
    expr: &LabelRequirement,
    labels: &std::collections::BTreeMap<String, String>,
) -> bool {
    match expr.operator.as_str() {
        "In" => labels
            .get(&expr.key)
            .map(|v| expr.values.iter().any(|want| want == v))
            .unwrap_or(false),
        "NotIn" => labels
            .get(&expr.key)
            .map(|v| expr.values.iter().all(|want| want != v))
            .unwrap_or(true),
        "Exists" => labels.contains_key(&expr.key),
        "DoesNotExist" => !labels.contains_key(&expr.key),
        _ => false,
    }
}

fn cap_for_mode(mode: Mode, disabled: bool, action: Action) -> Action {
    if disabled || matches!(mode, Mode::Observe | Mode::Audit) {
        match action {
            Action::Allow | Action::Audit => action,
            _ => Action::Audit,
        }
    } else {
        action
    }
}

/// `None`: the rule does not apply. `Some(path_unknown)`: it applies, with
/// `path_unknown` true when a path predicate was accepted against a path the
/// datapath could not carry instead of proven.
///
/// The datapath sets one flag for two different failures, and the buffer tells
/// them apart. A path longer than the buffer leaves a valid head with an
/// unknown tail: `ends_with` is undecidable, so a `path_suffix` predicate may
/// not reject, while `path_prefix` still decides on the head. A pointer the
/// helper could not read (`-EFAULT`: `bpf_probe_read_user_*` does not fault in
/// a non-resident page, and the syscall itself proceeds) leaves the buffer
/// empty: nothing about the path is known, so neither predicate may reject.
///
/// Both cases over-enforce: every rule naming a path applies to a record whose
/// path was not observed. Deliberate, and the same trade already made for
/// `LabelsUnknown` — over-enforce with an explicit signal rather than
/// under-enforce in silence. Downgrading the action to Audit on an unreadable
/// path is exactly the fail-open this closes, so it is not an option here.
fn rule_matches(rule: &Rule, event: &SyscallEvent<'_>) -> Option<bool> {
    if !rule.syscalls.is_empty() && !rule.syscalls.iter().any(|s| s.as_str() == event.syscall) {
        return None;
    }
    if !rule.comm_in.is_empty() && !rule.comm_in.iter().any(|c| c.as_str() == event.comm) {
        return None;
    }
    // Flag set and buffer empty: the argument was never read, so not even the
    // head is known.
    let path_unreadable = event.path_truncated && event.path.is_empty();
    let mut path_unknown = false;
    if !rule.path_prefix.is_empty() {
        let hit = rule
            .path_prefix
            .iter()
            .any(|p| !p.is_empty() && event.path.starts_with(p.as_str()));
        if !hit {
            if !path_unreadable {
                return None;
            }
            path_unknown = true;
        }
    }
    if !rule.path_suffix.is_empty() {
        let hit = rule
            .path_suffix
            .iter()
            .any(|p| !p.is_empty() && event.path.ends_with(p.as_str()));
        if !hit {
            if !event.path_truncated {
                return None;
            }
            path_unknown = true;
        }
    }
    if rule.container_only && !event.in_container {
        return None;
    }
    if rule.not_agent_self && event.agent_self {
        return None;
    }
    Some(path_unknown)
}
