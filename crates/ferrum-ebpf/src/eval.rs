use crate::spec::{Action, EbpfSpec, LabelRequirement, LabelSelector, Mode, PolicySelector, Rule};
use ferrum_k8smeta::WorkloadIdentity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallEvent<'a> {
    pub syscall: &'a str,
    pub comm: &'a str,
    pub path: &'a str,
    pub in_container: bool,
    pub agent_self: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    pub rule_id: Option<String>,
}

/// Raw rule match. Ignores `mode` / `disabled` / selector so tests can assert MVP effects.
pub fn matched_action(spec: &EbpfSpec, event: &SyscallEvent<'_>) -> Decision {
    let mut best: Option<(&Rule, u8)> = None;
    for rule in &spec.rules {
        if !rule_matches(rule, event) {
            continue;
        }
        let rank = rule.action.rank();
        let take = match best {
            None => true,
            Some((_, best_rank)) => rank > best_rank,
        };
        if take {
            best = Some((rule, rank));
        }
    }
    match best {
        Some((rule, _)) => Decision {
            action: rule.action,
            rule_id: Some(rule.id.clone()),
        },
        None => Decision {
            action: spec.default_action,
            rule_id: None,
        },
    }
}

/// Apply selector, then mode / disabled. Observe and Audit never deny/kill/isolate.
/// Selector miss: this program does not apply (`Allow`). Empty selector is cluster-wide.
pub fn decide(spec: &EbpfSpec, event: &SyscallEvent<'_>, identity: &WorkloadIdentity) -> Decision {
    if !selector_matches(&spec.selector, identity) {
        return Decision {
            action: Action::Allow,
            rule_id: None,
        };
    }
    let mut decision = matched_action(spec, event);
    decision.action = cap_for_mode(spec.mode, spec.disabled, decision.action);
    decision
}

pub fn selector_matches(selector: &PolicySelector, identity: &WorkloadIdentity) -> bool {
    if selector.is_empty() {
        return true;
    }
    if selector.is_namespaced() && identity.is_unknown() {
        return false;
    }
    label_selector_matches(&selector.cluster_selector, &identity.cluster_labels)
        && label_selector_matches(&selector.namespace_selector, &identity.namespace_labels)
        && label_selector_matches(&selector.workload_selector, &identity.workload_labels)
        && label_selector_matches(
            &selector.service_account_selector,
            &identity.service_account_labels,
        )
        && image_matches(selector, identity)
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

fn rule_matches(rule: &Rule, event: &SyscallEvent<'_>) -> bool {
    if !rule.syscalls.is_empty() && !rule.syscalls.iter().any(|s| s.as_str() == event.syscall) {
        return false;
    }
    if !rule.comm_in.is_empty() && !rule.comm_in.iter().any(|c| c.as_str() == event.comm) {
        return false;
    }
    if !rule.path_prefix.is_empty()
        && !rule
            .path_prefix
            .iter()
            .any(|p| !p.is_empty() && event.path.starts_with(p.as_str()))
    {
        return false;
    }
    if !rule.path_suffix.is_empty()
        && !rule
            .path_suffix
            .iter()
            .any(|p| !p.is_empty() && event.path.ends_with(p.as_str()))
    {
        return false;
    }
    if rule.container_only && !event.in_container {
        return false;
    }
    if rule.not_agent_self && event.agent_self {
        return false;
    }
    true
}
