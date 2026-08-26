//! Deterministic combination of matched effects. No kube, no clock inside.

use chrono::{DateTime, Days, Utc};
use ferrum_api::{PolicyExceptionSpec, RuntimeAction};

use crate::{MAX_EXCEPTION_DAYS, MIN_REASON_LEN};

/// One rule that already matched a workload.
/// `namespace` empty = cluster-scoped policy hit; SecurityPolicy hits set it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleHit {
    pub namespace: String,
    pub policy: String,
    pub rule: String,
    pub action: RuntimeAction,
}

impl RuleHit {
    pub fn new(
        namespace: impl Into<String>,
        policy: impl Into<String>,
        rule: impl Into<String>,
        action: RuntimeAction,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            policy: policy.into(),
            rule: rule.into(),
            action,
        }
    }
}

/// Combine matched actions. Deny beats allow. A live in-scope exception
/// waives that hit until `expiresAt`. `FailurePolicy` is never consulted.
/// No remaining hits → `default_action` (including when the input is empty).
pub fn evaluate(
    hits: &[RuleHit],
    default_action: RuntimeAction,
    exceptions: &[PolicyExceptionSpec],
    now: DateTime<Utc>,
) -> RuntimeAction {
    hits.iter()
        .filter(|hit| !exception_applies_to(exceptions, hit, now))
        .map(|hit| hit.action)
        .max_by_key(|action| action_rank(*action))
        .unwrap_or(default_action)
}

/// True when this exception waives `(namespace, policy, rule)` at `now`.
/// Empty target axes, expired, over-90d, out-of-scope, or paperwork-invalid
/// exceptions are a no-op.
pub fn exception_applies(
    spec: &PolicyExceptionSpec,
    namespace: &str,
    policy: &str,
    rule: &str,
    now: DateTime<Utc>,
) -> bool {
    if spec.ticket.trim().is_empty() || spec.reason.trim().len() < MIN_REASON_LEN {
        return false;
    }
    if spec.four_eyes && spec.approved_by.trim().is_empty() {
        return false;
    }
    if now >= spec.expires_at {
        return false;
    }
    if spec.expires_at > now + Days::new(MAX_EXCEPTION_DAYS) {
        return false;
    }
    if !namespace_matches(&spec.target.namespace, namespace) {
        return false;
    }
    // Empty axis is no-match (fail-closed), not a global waiver.
    if !spec.target.policies.iter().any(|p| p == policy) {
        return false;
    }
    if !spec.target.rules.iter().any(|r| r == rule) {
        return false;
    }
    true
}

fn namespace_matches(exception_ns: &str, hit_ns: &str) -> bool {
    let exception_ns = exception_ns.trim();
    let hit_ns = hit_ns.trim();
    if exception_ns.is_empty() {
        hit_ns.is_empty()
    } else {
        exception_ns == hit_ns
    }
}

fn exception_applies_to(
    exceptions: &[PolicyExceptionSpec],
    hit: &RuleHit,
    now: DateTime<Utc>,
) -> bool {
    exceptions
        .iter()
        .any(|spec| exception_applies(spec, &hit.namespace, &hit.policy, &hit.rule, now))
}

fn action_rank(action: RuntimeAction) -> u8 {
    match action {
        RuntimeAction::Allow => 0,
        RuntimeAction::Audit => 1,
        RuntimeAction::Deny => 2,
        RuntimeAction::Isolate => 3,
        RuntimeAction::Kill => 4,
    }
}
