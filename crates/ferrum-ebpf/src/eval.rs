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
    /// A `containerOnly` rule that would have decided this record was skipped
    /// because `EVENT_FLAG_CONTAINER` was not set, on a record whose caller
    /// the carrier cannot yet prove is not a container.
    ///
    /// Unlike `labels_unknown` and `path_unknown` this does NOT change the
    /// action: the datapath flag is the authority for a reaction, and cycle 7
    /// settled that a missing flag never upgrades a decision - a wrong kill on
    /// the node is worse than a missed one. What it changes is the silence.
    /// Before `containerOnly` the rule matched and the reaction was refused
    /// with `REFUSE_NOT_CONTAINER`, which is a visible "the kill did not
    /// happen, and here is why"; after it, the same record is exported under
    /// the default action with no reason at all. This carries that reason back
    /// out, and only for the records where the outcome would really have
    /// differed.
    pub container_unknown: bool,
}

/// Why a rule did or did not decide a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleMatch {
    /// A predicate other than `containerOnly` rejected it.
    No,
    /// Every other predicate held and `containerOnly` did not: this rule
    /// decides the record on any datapath that flags it as a container.
    SkippedContainer,
    /// It decides the record; `path_unknown` when a path predicate was
    /// asserted rather than proven.
    Yes(bool),
}

/// Outcome of matching a program selector against a workload identity.
///
/// Cluster / namespace / ServiceAccount labels are not carried by the event:
/// they are joined in from watch caches that can be cold, relisting after a
/// 410, or dead. "Never observed" is not a non-match, and the identity carries
/// that fact per group in `*_labels_observed`. It used to be read off an empty
/// map instead, which made `LabelsUnknown` — and `DEG_LABELS_UNKNOWN` behind it
/// — true forever on any cluster holding one unlabelled namespace: a reason
/// that is always true decides nothing.
///
/// Admission fails closed on exactly this condition
/// (`require_labels_if_selected`) and the runtime plane must not diverge; that
/// agreement is executed by
/// `ferrum-testkit/tests/acceptance.rs::both_planes_answer_an_unlabelled_namespace_the_same_way`,
/// not by this sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorMatch {
    Match,
    NoMatch,
    LabelsUnknown,
}

/// Raw rule match. Ignores `mode` / `disabled` / selector so tests can assert MVP effects.
pub fn matched_action(spec: &EbpfSpec, event: &SyscallEvent<'_>) -> Decision {
    matched_action_with(spec, event, false)
}

/// `matched_action`, told whether the carrier can prove this record's caller
/// is not a container.
///
/// It cannot during the window between a container starting and its cgroup
/// reaching `ferrum_cgroups`: the flag is unset there for exactly the same
/// reason it is unset for the node's own containerd, and nothing in the record
/// tells the two apart. When the carrier says so, a `containerOnly` rule that
/// every other predicate matched is reported in `container_unknown` instead of
/// vanishing - and only when it would have decided the record differently, so
/// an `audit` rule skipped under a kill that fired anyway stays quiet.
pub fn matched_action_with(
    spec: &EbpfSpec,
    event: &SyscallEvent<'_>,
    container_unproven: bool,
) -> Decision {
    let mut best: Option<(&Rule, bool, u8)> = None;
    let mut skipped_container: Option<u8> = None;
    for rule in &spec.rules {
        let path_unknown = match rule_matches(rule, event) {
            RuleMatch::No => continue,
            RuleMatch::SkippedContainer => {
                if container_unproven {
                    let rank = rule.action.rank();
                    skipped_container = Some(skipped_container.map_or(rank, |b: u8| b.max(rank)));
                }
                continue;
            }
            RuleMatch::Yes(path_unknown) => path_unknown,
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
    let taken_rank = match best {
        Some((_, _, rank)) => rank,
        None => spec.default_action.rank(),
    };
    let container_unknown = skipped_container.is_some_and(|rank| rank > taken_rank);
    match best {
        Some((rule, path_unknown, _)) => Decision {
            action: rule.action,
            rule_id: Some(rule.id.clone()),
            labels_unknown: false,
            path_unknown,
            container_unknown,
        },
        None => Decision {
            action: spec.default_action,
            rule_id: None,
            labels_unknown: false,
            path_unknown: false,
            container_unknown,
        },
    }
}

/// Apply selector, then mode / disabled. Observe and Audit never deny/kill/isolate.
/// Selector miss: this program does not apply (`Allow`). Empty selector is cluster-wide.
/// Labels not observed: the program is applied and the decision is flagged
/// `labels_unknown`, because skipping the rules there is a silent fail-open.
pub fn decide(spec: &EbpfSpec, event: &SyscallEvent<'_>, identity: &WorkloadIdentity) -> Decision {
    decide_with(spec, event, identity, false)
}

/// `decide`, with the carrier's answer to "can this record's caller be proven
/// not to be a container". See `matched_action_with`.
pub fn decide_with(
    spec: &EbpfSpec,
    event: &SyscallEvent<'_>,
    identity: &WorkloadIdentity,
    container_unproven: bool,
) -> Decision {
    let labels_unknown = match selector_match(&spec.selector, identity) {
        SelectorMatch::NoMatch => {
            return Decision {
                action: Action::Allow,
                rule_id: None,
                labels_unknown: false,
                path_unknown: false,
                container_unknown: false,
            }
        }
        SelectorMatch::Match => false,
        SelectorMatch::LabelsUnknown => true,
    };
    let mut decision = matched_action_with(spec, event, container_unproven);
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
    // as the pod is; the other three are joined in from separate watches, and
    // each says whether that join found anything.
    if labels_unobserved(&selector.cluster_selector, identity.cluster_labels_observed)
        || labels_unobserved(
            &selector.namespace_selector,
            identity.namespace_labels_observed,
        )
        || labels_unobserved(
            &selector.service_account_selector,
            identity.service_account_labels_observed,
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

/// A selector this identity cannot answer. Only "the join never saw this
/// group" counts: an observed group that holds no labels answers every
/// selector with a plain non-match, which is a decision.
fn labels_unobserved(selector: &LabelSelector, observed: bool) -> bool {
    !selector.is_empty() && !observed
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
fn rule_matches(rule: &Rule, event: &SyscallEvent<'_>) -> RuleMatch {
    if !rule.syscalls.is_empty() && !rule.syscalls.iter().any(|s| s.as_str() == event.syscall) {
        return RuleMatch::No;
    }
    if !rule.comm_in.is_empty() && !rule.comm_in.iter().any(|c| c.as_str() == event.comm) {
        return RuleMatch::No;
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
                return RuleMatch::No;
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
                return RuleMatch::No;
            }
            path_unknown = true;
        }
    }
    if rule.not_agent_self && event.agent_self {
        return RuleMatch::No;
    }
    // Last, so the answer is "only the container flag stood in the way" and
    // not "some other predicate would have rejected it anyway".
    if rule.container_only && !event.in_container {
        return RuleMatch::SkippedContainer;
    }
    RuleMatch::Yes(path_unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone_selector() -> PolicySelector {
        let mut selector = PolicySelector::default();
        selector
            .namespace_selector
            .match_labels
            .insert("ferrum.io/zone".into(), "pci".into());
        selector
    }

    fn pod_in(namespace: &str) -> WorkloadIdentity {
        WorkloadIdentity {
            namespace: namespace.into(),
            pod: "web-1".into(),
            container: "app".into(),
            service_account: "web".into(),
            ..Default::default()
        }
    }

    /// The mirror of the defect this cycle removed: `LabelsUnknown` used to be
    /// read off an empty map, so every namespace that carries no labels raised
    /// it, and `DEG_LABELS_UNKNOWN` behind it was true on every node of any
    /// cluster holding one such namespace for as long as the policy existed. A
    /// reason that is always true names nothing. The three cases below are the
    /// three answers, and only the third is a reason to degrade.
    #[test]
    fn an_observed_namespace_without_labels_is_a_non_match_not_labels_unknown() {
        let selector = zone_selector();

        // Listed, and it genuinely has no labels: the selector does not match.
        let mut plain = pod_in("plain");
        plain.namespace_labels_observed = true;
        assert!(plain.namespace_labels.is_empty());
        assert_eq!(selector_match(&selector, &plain), SelectorMatch::NoMatch);
        assert!(!selector_matches(&selector, &plain));

        // Listed with labels that do not match: also a non-match, and the
        // empty-map reading got this one right, which is why it survived.
        let mut public = pod_in("public");
        public.namespace_labels_observed = true;
        public
            .namespace_labels
            .insert("ferrum.io/zone".into(), "public".into());
        assert_eq!(selector_match(&selector, &public), SelectorMatch::NoMatch);

        // Never listed: unknown, and the only one of the three that is.
        let unseen = pod_in("unseen");
        assert!(!unseen.namespace_labels_observed);
        assert_eq!(
            selector_match(&selector, &unseen),
            SelectorMatch::LabelsUnknown
        );

        // And a match is still a match.
        let mut pci = pod_in("pci-ns");
        pci.namespace_labels_observed = true;
        pci.namespace_labels
            .insert("ferrum.io/zone".into(), "pci".into());
        assert_eq!(selector_match(&selector, &pci), SelectorMatch::Match);
    }

    /// A group nothing selects is never asked whether it was observed: the
    /// agent has no cluster labels at all, and that must not make every
    /// namespaced policy unknown.
    #[test]
    fn an_unselected_label_group_is_never_unknown() {
        let selector = zone_selector();
        let mut pci = pod_in("pci-ns");
        pci.namespace_labels_observed = true;
        pci.namespace_labels
            .insert("ferrum.io/zone".into(), "pci".into());
        assert!(!pci.cluster_labels_observed);
        assert!(!pci.service_account_labels_observed);
        assert_eq!(selector_match(&selector, &pci), SelectorMatch::Match);

        let mut with_cluster = zone_selector();
        with_cluster
            .cluster_selector
            .match_labels
            .insert("env".into(), "prod".into());
        assert_eq!(
            selector_match(&with_cluster, &pci),
            SelectorMatch::LabelsUnknown,
            "a cluster selector on a node that never receives cluster labels is unresolved"
        );
    }

    #[test]
    fn an_empty_selector_matches_without_asking_about_labels() {
        let identity = pod_in("anything");
        assert_eq!(
            selector_match(&PolicySelector::default(), &identity),
            SelectorMatch::Match
        );
        let unknown = WorkloadIdentity::unknown();
        assert_eq!(
            selector_match(&PolicySelector::default(), &unknown),
            SelectorMatch::Match
        );
    }
}
