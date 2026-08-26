//! Admit a simplified workload against one compiled program.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use ferrum_api::{
    FailurePolicy, LabelSelector, PolicyExceptionSpec, PolicyMode, PssProfile, RuntimeAction,
    SupplySpec,
};
use ferrum_common::FerrumError;
use ferrum_policy::{evaluate, exception_applies, RuleHit};
use serde::{Deserialize, Serialize};

use crate::program::AdmissionProgram;

pub const RULE_PRIVILEGED: &str = "privileged";
pub const RULE_HOST_PID: &str = "hostPID";
pub const RULE_HOST_IPC: &str = "hostIPC";
pub const RULE_HOST_NETWORK: &str = "hostNetwork";
pub const RULE_HOST_PATH: &str = "hostPath";
pub const RULE_ALLOW_PRIVILEGE_ESCALATION: &str = "allowPrivilegeEscalation";
pub const RULE_RUN_AS_ROOT: &str = "runAsRoot";
pub const RULE_WILDCARDS_RBAC: &str = "wildcardsRbac";
pub const RULE_CLUSTER_ADMIN_BIND: &str = "clusterAdminBind";
pub const RULE_ADDED_CAPABILITIES: &str = "addedCapabilities";
pub const RULE_UNSIGNED: &str = "unsigned";
pub const RULE_LATEST_TAG: &str = "latestTag";
pub const RULE_REQUIRE_DIGEST: &str = "requireDigest";
pub const RULE_REGISTRY_ALLOW: &str = "registryAllow";

/// Restricted PSS may add only this capability (drop ALL otherwise).
const PSS_RESTRICTED_ALLOWED_CAP: &str = "NET_BIND_SERVICE";

/// Kubernetes PSS baseline default add-capabilities allow-list.
const PSS_BASELINE_ALLOWED_CAPS: &[&str] = &[
    "AUDIT_WRITE",
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "MKNOD",
    "NET_BIND_SERVICE",
    "SETFCAP",
    "SETGID",
    "SETPCAP",
    "SETUID",
    "SYS_CHROOT",
];

/// Simplified Pod / RBAC view. Callers must fill this from the admission review;
/// this crate does not talk to the API server or registries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct AdmissionSubject {
    pub policy_name: String,
    /// Empty = ClusterSecurityPolicy. Non-empty = namespaced SecurityPolicy.
    pub policy_namespace: String,
    pub namespace: String,
    pub cluster_labels: BTreeMap<String, String>,
    pub namespace_labels: BTreeMap<String, String>,
    pub workload_labels: BTreeMap<String, String>,
    pub service_account: String,
    pub service_account_labels: BTreeMap<String, String>,
    pub image: String,
    /// Proven out of band with bundle trust roots. Default false (fail closed).
    pub image_signed: bool,
    pub privileged: bool,
    pub host_pid: bool,
    pub host_ipc: bool,
    pub host_network: bool,
    pub host_path: bool,
    pub allow_privilege_escalation: bool,
    pub run_as_root: bool,
    pub added_capabilities: Vec<String>,
    pub wildcard_rbac: bool,
    pub cluster_admin_bind: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Patch {
    InjectSeccompRuntimeDefault,
    DropAllCapabilities,
    ReadOnlyRootFilesystem,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionDecision {
    pub allowed: bool,
    /// True for missing/invalid/unverified bundle. Never paired with `allowed`.
    pub fail_closed: bool,
    pub mode: PolicyMode,
    pub failure_policy: FailurePolicy,
    pub reasons: Vec<String>,
    pub rule_ids: Vec<String>,
    pub patches: Vec<Patch>,
}

impl AdmissionDecision {
    pub(crate) fn fail_closed(err: FerrumError) -> Self {
        Self {
            allowed: false,
            fail_closed: true,
            mode: PolicyMode::Enforce,
            failure_policy: FailurePolicy::Fail,
            reasons: vec![err.to_string()],
            rule_ids: Vec::new(),
            patches: Vec::new(),
        }
    }
}

struct PendingHit {
    rule: &'static str,
    reason: String,
}

/// Evaluate `subject` against a parsed program. Observe/audit never fail the
/// request; enforce denies. Invalid programs must go through [`crate::admit_bytes`].
pub fn admit(
    program: &AdmissionProgram,
    subject: &AdmissionSubject,
    exceptions: &[PolicyExceptionSpec],
    now: DateTime<Utc>,
) -> AdmissionDecision {
    let namespaced = !subject.policy_namespace.is_empty();
    let failure_policy = program.effective_failure_policy(namespaced);

    if program.disabled && program.mode == PolicyMode::Enforce {
        return AdmissionDecision::fail_closed(FerrumError::Validation(
            "disabled=true with mode=enforce".into(),
        ));
    }

    match program_applies(program, subject) {
        Ok(false) => {
            return AdmissionDecision {
                allowed: true,
                fail_closed: false,
                mode: program.mode,
                failure_policy,
                reasons: Vec::new(),
                rule_ids: Vec::new(),
                patches: Vec::new(),
            };
        }
        Ok(true) => {}
        Err(err) => return AdmissionDecision::fail_closed(err),
    }

    if program.disabled {
        return AdmissionDecision {
            allowed: true,
            fail_closed: false,
            mode: program.mode,
            failure_policy,
            reasons: Vec::new(),
            rule_ids: Vec::new(),
            patches: Vec::new(),
        };
    }

    let pending = collect_hits(program, subject);
    let hit_ns = hit_namespace(subject);
    let hits: Vec<RuleHit> = pending
        .iter()
        .map(|h| {
            RuleHit::new(
                hit_ns,
                subject.policy_name.clone(),
                h.rule,
                RuntimeAction::Deny,
            )
        })
        .collect();

    let blocked = matches!(
        evaluate(&hits, RuntimeAction::Allow, exceptions, now),
        RuntimeAction::Deny | RuntimeAction::Kill | RuntimeAction::Isolate
    );
    let remaining: Vec<&PendingHit> = pending
        .iter()
        .filter(|h| {
            !exceptions
                .iter()
                .any(|spec| exception_applies(spec, hit_ns, &subject.policy_name, h.rule, now))
        })
        .collect();

    let allowed = if blocked {
        !matches!(program.mode, PolicyMode::Enforce)
    } else {
        true
    };

    AdmissionDecision {
        allowed,
        fail_closed: false,
        mode: program.mode,
        failure_policy,
        reasons: remaining.iter().map(|h| h.reason.clone()).collect(),
        rule_ids: remaining.iter().map(|h| h.rule.to_string()).collect(),
        patches: mutations(program),
    }
}

fn hit_namespace(subject: &AdmissionSubject) -> &str {
    if subject.policy_namespace.is_empty() {
        ""
    } else {
        subject.policy_namespace.as_str()
    }
}

fn program_applies(
    program: &AdmissionProgram,
    subject: &AdmissionSubject,
) -> Result<bool, FerrumError> {
    if !subject.policy_namespace.is_empty() && subject.namespace != subject.policy_namespace {
        return Ok(false);
    }
    Ok(
        label_selector_matches(&program.selector.cluster_selector, &subject.cluster_labels)?
            && label_selector_matches(
                &program.selector.namespace_selector,
                &subject.namespace_labels,
            )?
            && label_selector_matches(
                &program.selector.workload_selector,
                &subject.workload_labels,
            )?
            && label_selector_matches(
                &program.selector.service_account_selector,
                &subject.service_account_labels,
            )?,
    )
}

fn label_selector_matches(
    selector: &LabelSelector,
    labels: &BTreeMap<String, String>,
) -> Result<bool, FerrumError> {
    for (key, value) in &selector.match_labels {
        if labels.get(key) != Some(value) {
            return Ok(false);
        }
    }
    for expr in &selector.match_expressions {
        if !match_expression(
            expr.key.as_str(),
            expr.operator.as_str(),
            &expr.values,
            labels,
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn match_expression(
    key: &str,
    operator: &str,
    values: &[String],
    labels: &BTreeMap<String, String>,
) -> Result<bool, FerrumError> {
    match operator {
        "In" => Ok(labels
            .get(key)
            .map(|v| values.iter().any(|want| want == v))
            .unwrap_or(false)),
        "NotIn" => Ok(labels
            .get(key)
            .map(|v| values.iter().all(|want| want != v))
            .unwrap_or(true)),
        "Exists" => Ok(labels.contains_key(key)),
        "DoesNotExist" => Ok(!labels.contains_key(key)),
        other => Err(FerrumError::Compile(format!(
            "unknown label selector operator {other}"
        ))),
    }
}

fn collect_hits(program: &AdmissionProgram, subject: &AdmissionSubject) -> Vec<PendingHit> {
    let mut hits = Vec::new();
    let mut add = |rule: &'static str, reason: String| {
        hits.push(PendingHit { rule, reason });
    };

    if program.supply.deny_unsigned || program.supply.require_signed {
        if program.supply.trust_roots.is_empty() {
            add(
                RULE_UNSIGNED,
                "unsigned image: no trust roots in bundle".into(),
            );
        } else if !has_verifying_public_keys(&program.supply) {
            // Keyless issuer allow-list is not verifying material in MVP-1.
            add(
                RULE_UNSIGNED,
                "unsigned image: no public keys in bundle".into(),
            );
        } else if !subject.image_signed {
            add(RULE_UNSIGNED, "unsigned image".into());
        }
    }

    if program.supply.deny_latest_tag && image_is_latest(&subject.image) {
        add(RULE_LATEST_TAG, "image tag latest".into());
    }

    if program.selector.image.require_digest && parse_image(&subject.image).digest.is_none() {
        add(RULE_REQUIRE_DIGEST, "image digest required".into());
    }

    if !program.selector.image.registries_allow.is_empty() {
        let registry = parse_image(&subject.image).registry;
        if !program
            .selector
            .image
            .registries_allow
            .iter()
            .any(|allow| allow == &registry)
        {
            add(
                RULE_REGISTRY_ALLOW,
                format!("image registry {registry} is not in registriesAllow"),
            );
        }
    }

    // PSS constraints are OR'd with explicit deny. Privileged/Custom add none.
    let deny = &program.admit.deny;
    let pss = program.admit.pss;
    let baseline = matches!(pss, PssProfile::Baseline | PssProfile::Restricted);
    let restricted = pss == PssProfile::Restricted;

    if (deny.privileged || baseline) && subject.privileged {
        add(RULE_PRIVILEGED, "privileged container".into());
    }
    if (deny.host_pid || baseline) && subject.host_pid {
        add(RULE_HOST_PID, "hostPID".into());
    }
    if (deny.host_ipc || baseline) && subject.host_ipc {
        add(RULE_HOST_IPC, "hostIPC".into());
    }
    if (deny.host_network || baseline) && subject.host_network {
        add(RULE_HOST_NETWORK, "hostNetwork".into());
    }
    if (deny.host_path || baseline) && subject.host_path {
        add(RULE_HOST_PATH, "hostPath".into());
    }
    if (deny.allow_privilege_escalation || restricted) && subject.allow_privilege_escalation {
        add(
            RULE_ALLOW_PRIVILEGE_ESCALATION,
            "allowPrivilegeEscalation".into(),
        );
    }
    if (deny.run_as_root || restricted) && subject.run_as_root {
        add(RULE_RUN_AS_ROOT, "runAsRoot".into());
    }
    if deny.wildcards_rbac && subject.wildcard_rbac {
        add(RULE_WILDCARDS_RBAC, "wildcard RBAC".into());
    }
    if deny.cluster_admin_bind && subject.cluster_admin_bind {
        add(RULE_CLUSTER_ADMIN_BIND, "cluster-admin bind".into());
    }

    let matched: Vec<&String> = subject
        .added_capabilities
        .iter()
        .filter(|cap| {
            pss_forbids_added_capability(pss, cap)
                || deny.added_capabilities.iter().any(|d| d == *cap)
        })
        .collect();
    if !matched.is_empty() {
        let list = matched
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(",");
        add(
            RULE_ADDED_CAPABILITIES,
            format!("added capabilities denied: {list}"),
        );
    }

    hits
}

fn has_verifying_public_keys(supply: &SupplySpec) -> bool {
    supply
        .trust_roots
        .iter()
        .any(|root| root.public_keys.iter().any(|key| !key.trim().is_empty()))
}

fn pss_forbids_added_capability(pss: PssProfile, cap: &str) -> bool {
    match pss {
        PssProfile::Restricted => cap != PSS_RESTRICTED_ALLOWED_CAP,
        PssProfile::Baseline => !PSS_BASELINE_ALLOWED_CAPS.contains(&cap),
        PssProfile::Privileged | PssProfile::Custom => false,
    }
}

fn mutations(program: &AdmissionProgram) -> Vec<Patch> {
    let pss_mutate =
        program.mode == PolicyMode::Enforce && program.admit.pss == PssProfile::Restricted;
    let mut patches = Vec::new();
    if program.admit.mutate.inject_seccomp_runtime_default || pss_mutate {
        patches.push(Patch::InjectSeccompRuntimeDefault);
    }
    if program.admit.mutate.drop_all_capabilities || pss_mutate {
        patches.push(Patch::DropAllCapabilities);
    }
    if program.admit.mutate.read_only_root_filesystem || pss_mutate {
        patches.push(Patch::ReadOnlyRootFilesystem);
    }
    patches
}

struct ImageRef {
    registry: String,
    tag: Option<String>,
    digest: Option<String>,
}

fn parse_image(image: &str) -> ImageRef {
    let (without_digest, digest) = match image.split_once('@') {
        Some((left, right)) if !right.is_empty() => (left, Some(right.to_string())),
        _ => (image, None),
    };

    let (registry, remainder) = match without_digest.split_once('/') {
        None => ("docker.io".to_string(), without_digest),
        Some((first, rest)) => {
            if first == "localhost" || first.contains('.') || first.contains(':') {
                (first.to_string(), rest)
            } else {
                ("docker.io".to_string(), without_digest)
            }
        }
    };

    let tag = match remainder.rsplit_once(':') {
        Some((repo, t)) if !repo.is_empty() && !t.is_empty() && !t.contains('/') => {
            Some(t.to_string())
        }
        _ => None,
    };

    ImageRef {
        registry,
        tag,
        digest,
    }
}

fn image_is_latest(image: &str) -> bool {
    let parsed = parse_image(image);
    match parsed.tag.as_deref() {
        Some("latest") => true,
        None => parsed.digest.is_none(),
        Some(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ferrum_api::{AdmitDeny, AdmitSpec, PolicySelector, TrustRoot};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 26, 12, 0, 0).unwrap()
    }

    fn signed_subject() -> AdmissionSubject {
        AdmissionSubject {
            policy_name: "pss".into(),
            image: "registry.internal.example/app@sha256:abc".into(),
            image_signed: true,
            ..Default::default()
        }
    }

    fn pss_program(pss: PssProfile, mode: PolicyMode) -> AdmissionProgram {
        AdmissionProgram {
            abi: crate::ADMISSION_ABI,
            mode,
            disabled: false,
            priority: 0,
            supply: SupplySpec {
                require_signed: true,
                deny_unsigned: true,
                trust_roots: vec![TrustRoot {
                    name: "org".into(),
                    public_keys: vec!["k".into()],
                    ..Default::default()
                }],
                ..Default::default()
            },
            admit: AdmitSpec {
                failure_policy: FailurePolicy::Fail,
                pss,
                deny: AdmitDeny::default(),
                ..Default::default()
            },
            selector: PolicySelector::default(),
        }
    }

    #[test]
    fn pss_restricted_empty_deny_privileged() {
        let mut subject = signed_subject();
        subject.privileged = true;
        let decision = admit(
            &pss_program(PssProfile::Restricted, PolicyMode::Enforce),
            &subject,
            &[],
            now(),
        );
        assert!(!decision.allowed);
        assert!(!decision.fail_closed);
        assert!(decision.rule_ids.iter().any(|r| r == RULE_PRIVILEGED));
    }

    #[test]
    fn pss_restricted_empty_deny_run_as_root_and_host_path() {
        let program = pss_program(PssProfile::Restricted, PolicyMode::Enforce);
        let mut root = signed_subject();
        root.run_as_root = true;
        let denied_root = admit(&program, &root, &[], now());
        assert!(!denied_root.allowed);
        assert!(denied_root.rule_ids.iter().any(|r| r == RULE_RUN_AS_ROOT));

        let mut host_path = signed_subject();
        host_path.host_path = true;
        let denied_path = admit(&program, &host_path, &[], now());
        assert!(!denied_path.allowed);
        assert!(denied_path.rule_ids.iter().any(|r| r == RULE_HOST_PATH));
    }

    #[test]
    fn pss_restricted_empty_deny_capabilities() {
        let program = pss_program(PssProfile::Restricted, PolicyMode::Enforce);
        let mut sys_admin = signed_subject();
        sys_admin.added_capabilities = vec!["SYS_ADMIN".into()];
        let denied = admit(&program, &sys_admin, &[], now());
        assert!(!denied.allowed);
        assert!(denied.rule_ids.iter().any(|r| r == RULE_ADDED_CAPABILITIES));

        let mut net_bind = signed_subject();
        net_bind.added_capabilities = vec!["NET_BIND_SERVICE".into()];
        let allowed = admit(&program, &net_bind, &[], now());
        assert!(allowed.allowed);
        assert!(allowed.rule_ids.is_empty());
        assert_eq!(
            allowed.patches,
            vec![
                Patch::InjectSeccompRuntimeDefault,
                Patch::DropAllCapabilities,
                Patch::ReadOnlyRootFilesystem,
            ]
        );
    }

    #[test]
    fn pss_restricted_explicit_deny_ors_net_bind_service() {
        let mut program = pss_program(PssProfile::Restricted, PolicyMode::Enforce);
        program.admit.deny.added_capabilities = vec!["NET_BIND_SERVICE".into()];
        let mut subject = signed_subject();
        subject.added_capabilities = vec!["NET_BIND_SERVICE".into()];
        let decision = admit(&program, &subject, &[], now());
        assert!(!decision.allowed);
        assert!(decision
            .rule_ids
            .iter()
            .any(|r| r == RULE_ADDED_CAPABILITIES));
    }

    #[test]
    fn pss_baseline_empty_deny_host_pid_and_host_path() {
        let program = pss_program(PssProfile::Baseline, PolicyMode::Enforce);
        let mut host_pid = signed_subject();
        host_pid.host_pid = true;
        let denied = admit(&program, &host_pid, &[], now());
        assert!(!denied.allowed);
        assert!(denied.rule_ids.iter().any(|r| r == RULE_HOST_PID));

        let mut host_path = signed_subject();
        host_path.host_path = true;
        let denied_path = admit(&program, &host_path, &[], now());
        assert!(!denied_path.allowed);
        assert!(denied_path.rule_ids.iter().any(|r| r == RULE_HOST_PATH));
        assert!(denied_path.patches.is_empty());
    }

    #[test]
    fn pss_baseline_empty_deny_capabilities() {
        let program = pss_program(PssProfile::Baseline, PolicyMode::Enforce);
        let mut sys_admin = signed_subject();
        sys_admin.added_capabilities = vec!["SYS_ADMIN".into()];
        let denied = admit(&program, &sys_admin, &[], now());
        assert!(!denied.allowed);
        assert!(denied.rule_ids.iter().any(|r| r == RULE_ADDED_CAPABILITIES));

        let mut chown = signed_subject();
        chown.added_capabilities = vec!["CHOWN".into()];
        let allowed = admit(&program, &chown, &[], now());
        assert!(allowed.allowed);
        assert!(allowed.rule_ids.is_empty());
        assert!(allowed.patches.is_empty());
    }

    #[test]
    fn pss_privileged_and_custom_empty_deny_add_nothing() {
        let mut subject = signed_subject();
        subject.privileged = true;
        subject.host_pid = true;
        subject.host_path = true;
        subject.run_as_root = true;
        subject.added_capabilities = vec!["SYS_ADMIN".into()];
        for pss in [PssProfile::Privileged, PssProfile::Custom] {
            let decision = admit(&pss_program(pss, PolicyMode::Enforce), &subject, &[], now());
            assert!(decision.allowed, "pss={pss:?}");
            assert!(decision.rule_ids.is_empty(), "pss={pss:?}");
            assert!(decision.patches.is_empty(), "pss={pss:?}");
        }
    }

    #[test]
    fn pss_restricted_observe_and_audit_do_not_fail_request() {
        let mut subject = signed_subject();
        subject.privileged = true;
        for mode in [PolicyMode::Observe, PolicyMode::Audit] {
            let decision = admit(
                &pss_program(PssProfile::Restricted, mode),
                &subject,
                &[],
                now(),
            );
            assert!(decision.allowed, "mode={mode:?}");
            assert!(!decision.fail_closed, "mode={mode:?}");
            assert!(
                decision.rule_ids.iter().any(|r| r == RULE_PRIVILEGED),
                "mode={mode:?}"
            );
            assert!(decision.patches.is_empty(), "mode={mode:?}");
        }
    }

    #[test]
    fn pss_restricted_observe_applies_only_explicit_mutate() {
        let mut program = pss_program(PssProfile::Restricted, PolicyMode::Observe);
        program.admit.mutate.drop_all_capabilities = true;
        let decision = admit(&program, &signed_subject(), &[], now());
        assert!(decision.allowed);
        assert_eq!(decision.patches, vec![Patch::DropAllCapabilities]);
    }

    #[test]
    fn parse_image_registry_tag_digest() {
        let nginx = parse_image("nginx");
        assert_eq!(nginx.registry, "docker.io");
        assert_eq!(nginx.tag, None);
        assert_eq!(nginx.digest, None);
        assert!(image_is_latest("nginx"));
        assert!(image_is_latest("nginx:latest"));
        assert!(!image_is_latest("nginx:1.2"));
        assert!(!image_is_latest("nginx@sha256:abc"));

        let pinned = parse_image("registry.internal.example/app:1.0@sha256:dead");
        assert_eq!(pinned.registry, "registry.internal.example");
        assert_eq!(pinned.tag.as_deref(), Some("1.0"));
        assert_eq!(pinned.digest.as_deref(), Some("sha256:dead"));

        let local = parse_image("localhost:5000/foo:bar");
        assert_eq!(local.registry, "localhost:5000");
        assert_eq!(local.tag.as_deref(), Some("bar"));
    }
}
