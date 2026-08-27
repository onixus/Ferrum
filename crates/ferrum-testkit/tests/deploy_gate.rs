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
    bpf_not_from_agent_audit, cluster_admin_bind_deny, docker_sock_kill, exec_sh_kill,
    privileged_deny, runtime_unexecutable_action, runtime_unobservable_syscall,
    try_exception_from_yaml, unsigned_deny, EXCEPTION_WITHOUT_TTL_YAML,
};
use serde_yaml::Value;
use std::collections::BTreeSet;

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

/// Every `RuntimeAction` the API type can carry. The enum is not reflective,
/// so the list is written out; what keeps it complete is the comparison
/// against the CRD `enum` below, which a sixth variant cannot reach without
/// passing through here.
const RUNTIME_ACTIONS: [RuntimeAction; 5] = [
    RuntimeAction::Allow,
    RuntimeAction::Audit,
    RuntimeAction::Deny,
    RuntimeAction::Kill,
    RuntimeAction::Isolate,
];

/// The wire spelling, taken from serde rather than retyped: the CEL literals
/// are compared against what the API server actually receives.
fn action_name(action: RuntimeAction) -> String {
    serde_yaml::to_value(action)
        .expect("RuntimeAction serializes")
        .as_str()
        .expect("RuntimeAction is a scalar")
        .to_string()
}

fn runtime_schema(crd: &str) -> Value {
    spec_schema(crd)
        .get("properties")
        .and_then(|p| p.get("runtime"))
        .and_then(|r| r.get("properties"))
        .expect("runtime schema")
        .clone()
}

fn schema_enum(node: &Value) -> BTreeSet<String> {
    node.get("enum")
        .and_then(Value::as_sequence)
        .map(|v| {
            v.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The literals an unconditional `!(<subject> in ['a', 'b'])` CEL ban names.
/// Only unconditional bans: a rule that goes on to excuse the action under
/// some condition is a different invariant, and the caller filters it out
/// before this sees it.
fn banned_literals(rules: &[&String], subject: &str) -> BTreeSet<String> {
    let needle = format!("!({subject} in [");
    let mut out = BTreeSet::new();
    for rule in rules {
        let mut rest = rule.as_str();
        while let Some(at) = rest.find(&needle) {
            rest = &rest[at + needle.len()..];
            let end = rest.find(']').expect("unterminated CEL list literal");
            for literal in rest[..end].split(',') {
                out.insert(literal.trim().trim_matches('\'').to_string());
            }
            rest = &rest[end..];
        }
    }
    out
}

/// Which actions `ferrum-policy` refuses on a rule that is otherwise
/// well-formed and well-matched. A match cannot rescue an action no plane
/// executes, so whatever is refused here is refused outright.
fn refused_as_rule_action() -> BTreeSet<String> {
    RUNTIME_ACTIONS
        .iter()
        .copied()
        .filter(|action| {
            let spec = SecurityPolicySpec {
                runtime: RuntimeSpec {
                    rules: vec![RuntimeRule {
                        id: "probe".into(),
                        // execve/execveat travel as a pair; naming one alone
                        // fails a different invariant and would poison the set.
                        syscalls: vec!["execve".into(), "execveat".into()],
                        match_on: RuntimeMatch {
                            comm_in: vec!["sh".into()],
                            ..Default::default()
                        },
                        action: *action,
                    }],
                    ..Default::default()
                },
                ..Default::default()
            };
            validate_namespaced_policy(&spec).is_err()
        })
        .map(action_name)
        .collect()
}

/// The same question for `runtime.defaultAction`, which is a separate copy in
/// both `ferrum-policy` and the CEL and refuses a wider set.
fn refused_as_default_action() -> BTreeSet<String> {
    RUNTIME_ACTIONS
        .iter()
        .copied()
        .filter(|action| {
            let spec = SecurityPolicySpec {
                runtime: RuntimeSpec {
                    default_action: *action,
                    ..Default::default()
                },
                ..Default::default()
            };
            validate_namespaced_policy(&spec).is_err()
        })
        .map(action_name)
        .collect()
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
        ("bpf not from the agent", bpf_not_from_agent_audit()),
    ] {
        validate_cluster_policy(&spec).unwrap_or_else(|e| panic!("{name} must validate: {e}"));
    }

    // §D `bpf()` not from the agent → deny. The deny is admission's: it refuses
    // the pod before it can call `bpf()` at all. The runtime row carries the
    // audit record that names the caller, because a tracepoint fires after the
    // syscall has already run — an action this plane decides and cannot
    // execute is a verdict that never happened. Every syscall the row names
    // must also be one the datapath actually hooks: a rule that never fires
    // would pass this drift gate silently.
    let bpf = bpf_not_from_agent_audit();
    let rule = &bpf.runtime.rules[0];
    assert_eq!(rule.action, RuntimeAction::Audit);
    assert!(rule.match_on.not_agent_self);
    for syscall in &rule.syscalls {
        assert!(
            ferrum_ids::is_datapath_syscall(syscall),
            "§D bpf row names {syscall}, which the datapath does not observe"
        );
    }
    assert!(rule.syscalls.iter().any(|s| s == "bpf"));
}

/// The action half of the same family, on the same negative example CI runs:
/// the runtime plane executes allow/audit/kill, and a rule naming anything
/// else is a signed verdict nobody carries out. A match cannot rescue it, so
/// the fixture is deliberately a well-matched rule.
#[test]
fn a_rule_whose_action_the_runtime_plane_cannot_execute_does_not_validate() {
    let spec = runtime_unexecutable_action().spec;
    let err = validate_cluster_policy(&spec).expect_err("runtime deny is not executable");
    let msg = err.to_string();
    assert!(msg.contains("no-module"), "{msg}");
    assert!(msg.contains("deny"), "{msg}");

    // Isolate is the other half: rejected with a match, not only without one.
    let mut isolate = runtime_unexecutable_action().spec;
    isolate.runtime.rules[0].action = RuntimeAction::Isolate;
    let err = validate_cluster_policy(&isolate).expect_err("isolate has no implementation");
    assert!(err.to_string().contains("no-module"), "{err}");
}

/// The CEL copy of that same gate, and the one that decides whether the object
/// is admitted at all. Without it the API server accepts a runtime rule the
/// compiler then refuses: the policy exists, the controller cannot compile it,
/// and the cluster enforces nothing where an operator believes it does.
///
/// Both halves are derived rather than remembered — the refused set by asking
/// `ferrum-policy`, the admitted set by reading the CEL literals back out — so
/// a changed verdict on either side fails here until the other follows.
#[test]
fn every_runtime_action_ferrum_policy_refuses_is_refused_by_the_cel_copy() {
    let declared: BTreeSet<String> = RUNTIME_ACTIONS.iter().copied().map(action_name).collect();
    let rule_actions = refused_as_rule_action();
    let default_actions = refused_as_default_action();
    // If nothing is refused the comparisons below hold vacuously and the gate
    // would pass with the invariant deleted from both copies.
    assert!(!rule_actions.is_empty(), "no rule action is refused at all");
    assert!(!default_actions.is_empty(), "no defaultAction is refused");

    for (name, crd) in [
        ("securitypolicy", CRD_SECURITY_POLICY),
        ("clustersecuritypolicy", CRD_CLUSTER_SECURITY_POLICY),
    ] {
        let runtime = runtime_schema(crd);
        let rule_action_schema = runtime
            .get("rules")
            .and_then(|r| r.get("items"))
            .and_then(|i| i.get("properties"))
            .and_then(|p| p.get("action"))
            .expect("rule action schema");
        assert_eq!(
            schema_enum(runtime.get("defaultAction").expect("defaultAction schema")),
            declared,
            "{name}: defaultAction enum and RuntimeAction disagree"
        );
        assert_eq!(
            schema_enum(rule_action_schema),
            declared,
            "{name}: rule action enum and RuntimeAction disagree"
        );

        let rules = cel_rules(crd);
        // The kill-without-match rule names actions too, but excuses them when
        // the rule carries a match: a different invariant, not a ban.
        let bans: Vec<&String> = rules
            .iter()
            .filter(|r| r.contains("r.action") && !r.contains("r.match"))
            .collect();
        assert_eq!(
            bans.len(),
            1,
            "{name}: expected exactly one unconditional rule-action ban in CEL: {rules:?}"
        );
        assert_eq!(
            banned_literals(&bans, "r.action"),
            rule_actions,
            "{name}: the CRD admits a rule action ferrum-policy refuses (or refuses one it accepts)"
        );

        let default_bans: Vec<&String> = rules
            .iter()
            .filter(|r| r.contains("defaultAction"))
            .collect();
        assert!(
            !default_bans.is_empty(),
            "{name}: CRD lost every defaultAction CEL rule"
        );
        assert_eq!(
            banned_literals(&default_bans, "self.runtime.defaultAction"),
            default_actions,
            "{name}: the CRD admits a runtime.defaultAction ferrum-policy refuses"
        );
    }
}

/// The gate the negative example proves in CI, kept here so it also fails a
/// plain `cargo test`.
#[test]
fn a_rule_naming_an_unhooked_syscall_does_not_validate() {
    let spec = runtime_unobservable_syscall().spec;
    let err = validate_cluster_policy(&spec).expect_err("ptrace is not hooked");
    let msg = err.to_string();
    assert!(msg.contains("ptrace"), "{msg}");
    assert!(msg.contains("no-debugger"), "{msg}");
}

/// `ferrum-ebpf` hand-builds the shape of `prod-restricted` in its prefilter
/// unit test, because that crate may not carry `serde_yaml` and so cannot read
/// the shipped policy. Nothing there notices when the policy changes — it had
/// already drifted to an action the policy no longer carries. Derive the image
/// from the real compiled bundle here, where both crates are in scope, so the
/// hand copy has something to fail against.
#[test]
fn the_prefilter_image_of_the_shipped_policy_is_the_one_its_unit_test_asserts() {
    let yaml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../policies/examples/prod-restricted.yaml"
    ));
    let mut policy: ferrum_api::ClusterSecurityPolicy =
        serde_yaml::from_str(yaml).expect("prod-restricted yaml");
    // The shipped `defaultAction: audit` makes every event mandatory on its
    // own, which would answer the question before a rule is read. The hand
    // copy substitutes an Allow default for exactly that reason, so the image
    // measures the three rules; derive both, and hold both.
    let shipped = image_of(&policy);
    policy.spec.runtime.default_action = RuntimeAction::Allow;
    let rules_only = image_of(&policy);

    for (what, image) in [("as shipped", shipped), ("rules only", rules_only)] {
        assert_eq!(
            image.observed_syscalls(),
            ferrum_ebpf::DATAPATH_SYSCALLS.to_vec(),
            "prod-restricted {what} no longer needs every hooked syscall; ferrum-ebpf's hand copy asserts that it does"
        );
        assert!(
            !image.container_only,
            "prod-restricted {what} now narrows to container events; ferrum-ebpf's hand copy says it does not"
        );
        assert!(
            !image.drop_agent_self,
            "prod-restricted {what} now drops the agent's own events; ferrum-ebpf's hand copy says it does not"
        );
    }
}

fn image_of(policy: &ferrum_api::ClusterSecurityPolicy) -> ferrum_ebpf::PrefilterImage {
    let bundle =
        ferrum_compiler::compile_cluster_policy(&policy.spec).expect("prod-restricted compiles");
    let compiled = ferrum_ebpf::parse_febp(&bundle.ebpf_spec).expect("FEBP decodes");
    ferrum_ebpf::prefilter_image(&compiled)
}

/// The install tree is the fourth place an invariant is written down, and the
/// only one an operator actually applies. Same lint the CLI runs.
mod deploy_tree {
    use ferrum_cli::gen_pki::{self, WEBHOOK_RENDERED_FILE, WEBHOOK_TEMPLATE_FILE};
    use ferrum_cli::lint_deploy::{lint_deploy_dir, CA_BUNDLE_PLACEHOLDER};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn repo_path(rel: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel)
    }

    #[test]
    fn deploy_tree_passes_the_lint() {
        lint_deploy_dir(&repo_path("deploy")).expect("deploy/ must satisfy every invariant");
    }

    #[test]
    fn a_committed_placeholder_ca_bundle_fails_the_lint() {
        let err = lint_deploy_dir(&repo_path(
            "crates/ferrum-testkit/fixtures/deploy-bad-cabundle",
        ))
        .expect_err("a caBundle placeholder outside a template must fail");
        assert!(err.to_string().contains("violated"), "{err}");
    }

    /// End to end: what `gen-webhook-pki` renders is what the lint accepts.
    /// Without this the two halves can drift and the tree is unapplicable again.
    #[test]
    fn issued_pki_makes_the_tree_applicable() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("ferrum-deploy-gate-{nanos}"));
        let admission = root.join("admission");
        std::fs::create_dir_all(&admission).unwrap();
        for entry in std::fs::read_dir(repo_path("deploy/admission")).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                std::fs::copy(&path, admission.join(path.file_name().unwrap())).unwrap();
            }
        }
        assert!(
            std::fs::read_to_string(admission.join(WEBHOOK_TEMPLATE_FILE))
                .unwrap()
                .contains(CA_BUNDLE_PLACEHOLDER)
        );

        gen_pki::gen_webhook_pki(&gen_pki::GenPkiArgs {
            service: "ferrum-admission".into(),
            namespace: "ferrum".into(),
            days: 365,
            out_dir: Some(admission.clone()),
            template: None,
            ca_cert: None,
            ca_key: None,
            webhook_config: None,
        })
        .expect("issue webhook PKI");

        // The rendered file is the one an operator applies; the lint has to
        // accept it, not just the template it came from.
        std::fs::remove_file(admission.join(WEBHOOK_TEMPLATE_FILE)).unwrap();
        assert!(admission.join(WEBHOOK_RENDERED_FILE).is_file());

        // Issuance leaves the CA key in the tree, and the lint says so until it
        // is moved out. That is the whole point of the rule: the tree it lands
        // in is the one that gets committed.
        let ca_key = admission.join(gen_pki::CA_KEY_FILE);
        let err = lint_deploy_dir(&root).expect_err("ca.key in the tree must fail the lint");
        assert!(err.to_string().contains("violated"), "{err}");
        std::fs::remove_file(ca_key).unwrap();

        let result = lint_deploy_dir(&root);
        std::fs::remove_dir_all(&root).ok();
        result.expect("the rendered tree must pass the lint");
    }
}
