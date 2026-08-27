//! Drift gate between the three places an invariant is written down: CEL in the
//! CRD, `ferrum-policy`, and the RFC §D acceptance fixtures. Two of the three
//! agreeing is not enough — the API server enforces only the CEL copy, and the
//! agent enforces only the compiled one.

use chrono::{Days, Utc};
use ferrum_api::{
    ExceptionTarget, FailurePolicy, PolicyExceptionSpec, PolicyMode, RuntimeAction, RuntimeMatch,
    RuntimeRule, RuntimeSpec, SecurityPolicySpec,
};
use ferrum_policy::{validate_cluster_policy, validate_exception, validate_namespaced_policy};
use ferrum_testkit::{
    bpf_deny, cluster_admin_bind_deny, docker_sock_kill, exec_sh_kill, privileged_deny,
    try_exception_from_yaml, unsigned_deny, EXCEPTION_WITHOUT_TTL_YAML,
};
use serde_yaml::Value;

const CRD_POLICY_EXCEPTION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/crd/policyexception.yaml"
));
const CRD_SECURITY_POLICY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/crd/securitypolicy.yaml"
));
const CRD_CLUSTER_SECURITY_POLICY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/crd/clustersecuritypolicy.yaml"
));

/// `expiresAt <= now() + duration('2160h')` is the CEL spelling of 90 days.
const CEL_NINETY_DAYS: &str = "2160h";

fn spec_schema(crd: &str) -> Value {
    let root: Value = serde_yaml::from_str(crd).expect("crd yaml");
    root.get("spec")
        .and_then(|s| s.get("versions"))
        .and_then(Value::as_sequence)
        .and_then(|v| v.first())
        .and_then(|v| v.get("schema"))
        .and_then(|s| s.get("openAPIV3Schema"))
        .and_then(|s| s.get("properties"))
        .and_then(|p| p.get("spec"))
        .expect("spec schema")
        .clone()
}

fn cel_rules(crd: &str) -> Vec<String> {
    spec_schema(crd)
        .get("x-kubernetes-validations")
        .and_then(Value::as_sequence)
        .map(|rules| {
            rules
                .iter()
                .filter_map(|r| r.get("rule").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn required_fields(crd: &str) -> Vec<String> {
    spec_schema(crd)
        .get("required")
        .and_then(Value::as_sequence)
        .map(|r| {
            r.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn exception(requested_by: &str, approved_by: &str, days: u64) -> PolicyExceptionSpec {
    PolicyExceptionSpec {
        ticket: "JIRA-18421".into(),
        requested_by: requested_by.into(),
        approved_by: approved_by.into(),
        reason: "temporary debug sidecar after incident".into(),
        expires_at: Utc::now() + Days::new(days),
        mode: PolicyMode::Audit,
        four_eyes: true,
        target: ExceptionTarget {
            namespace: "payments".into(),
            policies: vec!["prod-restricted".into()],
            rules: vec!["no-shell".into()],
        },
    }
}

#[test]
fn exception_ttl_ceiling_is_ninety_days_in_cel_and_in_policy() {
    let rules = cel_rules(CRD_POLICY_EXCEPTION);
    assert!(
        rules
            .iter()
            .any(|r| r.contains("expiresAt") && r.contains(CEL_NINETY_DAYS)),
        "CRD lost the 90-day CEL ceiling: {rules:?}"
    );
    assert!(
        rules
            .iter()
            .any(|r| r.contains("expiresAt") && r.contains("now()")),
        "CRD lost the expiresAt-in-the-past CEL rule: {rules:?}"
    );

    validate_exception(&exception("sre", "ib", 89)).expect("89 days is inside the window");
    let err = validate_exception(&exception("sre", "ib", 91))
        .expect_err("91 days must be rejected by ferrum-policy too");
    assert!(format!("{err}").contains("90"), "{err}");
}

#[test]
fn exception_expires_at_is_mandatory_in_cel_and_in_decode() {
    assert!(
        required_fields(CRD_POLICY_EXCEPTION)
            .iter()
            .any(|f| f == "expiresAt"),
        "CRD stopped requiring expiresAt: a waiver without TTL becomes policy"
    );
    // RFC §D: exception without TTL → API reject. Same YAML, decoder copy.
    try_exception_from_yaml(EXCEPTION_WITHOUT_TTL_YAML)
        .expect_err("missing expiresAt must not decode");
}

#[test]
fn self_approve_is_rejected_in_cel_and_in_policy() {
    let rules = cel_rules(CRD_POLICY_EXCEPTION);
    assert!(
        rules
            .iter()
            .any(|r| r.contains("approvedBy") && r.contains("requestedBy") && r.contains("!=")),
        "CRD lost the self-approve CEL rule: {rules:?}"
    );

    validate_exception(&exception("sre", "ib", 30)).expect("two distinct people");
    let err = validate_exception(&exception("sre", "sre", 30))
        .expect_err("self-approve must be rejected by ferrum-policy too");
    assert!(format!("{err}").contains("self-approve"), "{err}");
}

#[test]
fn namespaced_policy_cannot_ignore_in_cel_and_in_policy() {
    let rules = cel_rules(CRD_SECURITY_POLICY);
    assert!(
        rules
            .iter()
            .any(|r| r.contains("failurePolicy") && r.contains("Ignore")),
        "namespaced CRD lost the failurePolicy=Ignore CEL rule: {rules:?}"
    );
    // The cluster-scoped CRD must NOT carry it: Ignore is a valid cluster-level
    // break-glass, and copying the rule there would be a different invariant.
    assert!(
        !cel_rules(CRD_CLUSTER_SECURITY_POLICY)
            .iter()
            .any(|r| r.contains("failurePolicy")),
        "cluster CRD gained a namespaced-only rule"
    );

    let mut spec = SecurityPolicySpec::default();
    validate_namespaced_policy(&spec).expect("default Fail is fine");
    spec.admit.failure_policy = FailurePolicy::Ignore;
    let err = validate_namespaced_policy(&spec).expect_err("Ignore must be rejected");
    assert!(format!("{err}").contains("Ignore"), "{err}");
}

#[test]
fn kill_without_match_is_rejected_in_cel_and_in_policy() {
    for (name, crd) in [
        ("securitypolicy", CRD_SECURITY_POLICY),
        ("clustersecuritypolicy", CRD_CLUSTER_SECURITY_POLICY),
    ] {
        let rules = cel_rules(crd);
        assert!(
            rules
                .iter()
                .any(|r| r.contains("'kill'") && r.contains("r.match")),
            "{name} CRD lost the kill/isolate-without-match CEL rule: {rules:?}"
        );
        assert!(
            rules
                .iter()
                .any(|r| r.contains("defaultAction") && r.contains("'kill'")),
            "{name} CRD lost the defaultAction kill/isolate CEL rule: {rules:?}"
        );
    }

    let kill_all = RuntimeSpec {
        rules: vec![RuntimeRule {
            id: "kill-everything".into(),
            syscalls: Vec::new(),
            match_on: RuntimeMatch::default(),
            action: RuntimeAction::Kill,
        }],
        ..Default::default()
    };
    let mut spec = SecurityPolicySpec {
        runtime: kill_all,
        ..Default::default()
    };
    let err = validate_namespaced_policy(&spec).expect_err("kill without match must be rejected");
    assert!(format!("{err}").contains("kill-all"), "{err}");

    // RFC §D acceptance copies must survive the same invariant.
    spec.runtime = exec_sh_kill().runtime;
    validate_namespaced_policy(&spec).expect("exec+sh kill fixture has a match");
}

#[test]
fn acceptance_fixtures_agree_with_the_invariant_copy() {
    for (name, spec) in [
        ("unsigned deny", unsigned_deny()),
        ("privileged deny", privileged_deny()),
        ("cluster-admin bind deny", cluster_admin_bind_deny()),
        ("exec+sh kill", exec_sh_kill()),
        ("docker.sock kill", docker_sock_kill()),
        ("bpf deny", bpf_deny()),
    ] {
        validate_cluster_policy(&spec).unwrap_or_else(|e| panic!("{name} must validate: {e}"));
    }
}
