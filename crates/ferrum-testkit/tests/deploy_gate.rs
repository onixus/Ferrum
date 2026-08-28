//! Drift gate between the three places an invariant is written down: CEL in the
//! CRD, `ferrum-policy`, and the RFC §D acceptance fixtures. Two of the three
//! agreeing is not enough — the API server enforces only the CEL copy, and the
//! agent enforces only the compiled one.

use chrono::{Days, Utc};
use ferrum_api::{
    ExceptionTarget, FailurePolicy, PolicyExceptionSpec, PolicyMode, RuntimeAction, RuntimeMatch,
    RuntimeRule, RuntimeSpec, SecurityPolicySpec, SupplySpec, TrustRoot,
};
use ferrum_policy::{validate_cluster_policy, validate_exception, validate_namespaced_policy};
use ferrum_testkit::{
    bpf_not_from_agent_audit, cluster_admin_bind_deny, docker_sock_kill, exec_sh_kill,
    privileged_deny, runtime_unexecutable_action, runtime_unobservable_syscall,
    try_exception_from_yaml, unsigned_deny, EXCEPTION_WITHOUT_TTL_YAML, FIXTURE_ED25519_PK,
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

/// Schema node for one property of the PolicyException spec.
fn exception_property(name: &str) -> Value {
    spec_schema(CRD_POLICY_EXCEPTION)
        .get("properties")
        .and_then(|p| p.get(name))
        .unwrap_or_else(|| panic!("PolicyException.{name} left the schema"))
        .clone()
}

fn bound(node: &Value, key: &str) -> Option<usize> {
    node.get(key).and_then(Value::as_u64).map(|v| v as usize)
}

/// The `rules` array schema, shared by both SecurityPolicy CRDs.
fn rules_schema(crd: &str) -> Value {
    runtime_schema(crd)
        .get("rules")
        .expect("rules schema")
        .clone()
}

fn rule_property(crd: &str, name: &str) -> Value {
    rules_schema(crd)
        .get("items")
        .and_then(|i| i.get("properties"))
        .and_then(|p| p.get(name))
        .unwrap_or_else(|| panic!("runtime rule .{name} left the schema"))
        .clone()
}

fn rule_match_property(crd: &str, name: &str) -> Value {
    rule_property(crd, "match")
        .get("properties")
        .and_then(|p| p.get(name))
        .unwrap_or_else(|| panic!("runtime rule match.{name} left the schema"))
        .clone()
}

fn string_items(node: &Value) -> Value {
    node.get("items").expect("array items schema").clone()
}

/// A policy carrying exactly the rules given, otherwise well-formed: the
/// syscall pair travels together and the action is one the runtime executes,
/// so nothing but the field under test can be what fails.
fn policy_with_rules(rules: Vec<RuntimeRule>) -> SecurityPolicySpec {
    SecurityPolicySpec {
        runtime: RuntimeSpec {
            rules,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn probe_rule(id: &str) -> RuntimeRule {
    RuntimeRule {
        id: id.into(),
        syscalls: vec!["execve".into(), "execveat".into()],
        match_on: RuntimeMatch {
            comm_in: vec!["sh".into()],
            ..Default::default()
        },
        action: RuntimeAction::Audit,
    }
}

fn policy_with_trust_root(keys: &[&str]) -> SecurityPolicySpec {
    SecurityPolicySpec {
        supply: SupplySpec {
            trust_roots: vec![TrustRoot {
                name: "internal".into(),
                public_keys: keys.iter().map(|k| (*k).to_string()).collect(),
                ..Default::default()
            }],
            ..Default::default()
        },
        ..Default::default()
    }
}

/// `ferrum-policy` demands a second approver on every waiver, and says why:
/// `fourEyes` is set by the requester, so it cannot be the switch that decides
/// whether anyone else had to agree. The CEL copy made it conditional on
/// exactly that field, so the API server admitted waivers with no approver
/// which the compiler then refused — the object exists, nothing enforces it.
#[test]
fn a_waiver_without_a_second_approver_is_refused_by_the_schema_too() {
    for four_eyes in [false, true] {
        let mut spec = exception("sre", "", 30);
        spec.four_eyes = four_eyes;
        validate_exception(&spec).expect_err("approvedBy is required whatever fourEyes says it is");
    }
    validate_exception(&exception("sre", "ib", 30)).expect("a named approver is accepted");

    assert!(
        required_fields(CRD_POLICY_EXCEPTION)
            .iter()
            .any(|f| f == "approvedBy"),
        "the CRD admits a waiver with no second approver that ferrum-policy refuses"
    );
    assert!(
        bound(&exception_property("approvedBy"), "minLength").unwrap_or(0) >= 1,
        "approvedBy: '' passes `required` and is still no approver"
    );
    assert!(
        !cel_rules(CRD_POLICY_EXCEPTION)
            .iter()
            .any(|r| r.contains("fourEyes")),
        "a CEL rule keyed on fourEyes lets the requester decide whether a second \
         approver was needed; that is the hole, not the gate"
    );
}

/// Same drift, other field: `reason` carried `minLength: 1` against
/// `MIN_REASON_LEN` in the compiler. Both sides are derived — the bound is read
/// out of the schema and the verdicts come from `ferrum-policy` — so neither
/// can move without the other.
#[test]
fn the_minimum_reason_length_is_the_same_in_the_schema_and_in_policy() {
    let min = bound(&exception_property("reason"), "minLength").expect("reason minLength");
    for len in 0..=ferrum_policy::MIN_REASON_LEN + 2 {
        let mut spec = exception("sre", "ib", 30);
        spec.reason = "a".repeat(len);
        assert_eq!(
            validate_exception(&spec).is_ok(),
            len >= min,
            "a reason of {len} characters: the schema and the compiler disagree \
             (schema minLength {min}, ferrum_policy::MIN_REASON_LEN {})",
            ferrum_policy::MIN_REASON_LEN
        );
    }
}

/// The 90-day ceiling, spelled as a duration in CEL. Derived from the same
/// constant rather than from the literal `2160h` written above.
#[test]
fn the_cel_ttl_ceiling_is_the_policy_constant_in_hours() {
    let hours = ferrum_policy::MAX_EXCEPTION_DAYS * 24;
    assert_eq!(CEL_NINETY_DAYS, format!("{hours}h"));
}

/// A rule id names the thing an exception waives and an audit record blames.
/// `ferrum-policy` refuses a blank one and refuses two rules that share one;
/// the schema required the key and bounded nothing, so both passed the API
/// server. Duplicate ids are held by a list-map key rather than CEL: the API
/// server enforces uniqueness itself, and a quadratic `exists_one` over an
/// unbounded list is a CEL cost estimate that can get the whole CRD rejected.
#[test]
fn a_blank_or_duplicated_rule_id_is_refused_by_the_schema_too() {
    for (name, crd) in [
        ("securitypolicy", CRD_SECURITY_POLICY),
        ("clustersecuritypolicy", CRD_CLUSTER_SECURITY_POLICY),
    ] {
        let id = rule_property(crd, "id");
        let min = bound(&id, "minLength").unwrap_or(0);
        let pattern = id.get("pattern").and_then(Value::as_str).unwrap_or("");
        assert_eq!(
            pattern, r"\S",
            "{name}: this gate reads the id pattern rather than running a regex \
             engine, and knows only `\\S`; teach it the new one or drop it"
        );
        for candidate in ["", " ", "\t", "   ", "ok", " padded "] {
            let admitted_by_schema =
                candidate.len() >= min && candidate.bytes().any(|b| !b.is_ascii_whitespace());
            assert_eq!(
                validate_namespaced_policy(&policy_with_rules(vec![probe_rule(candidate)])).is_ok(),
                admitted_by_schema,
                "{name}: rule id {candidate:?} — the schema and the compiler disagree"
            );
        }

        validate_namespaced_policy(&policy_with_rules(vec![probe_rule("a"), probe_rule("b")]))
            .expect("distinct ids are fine");
        validate_namespaced_policy(&policy_with_rules(vec![
            probe_rule("dup"),
            probe_rule("dup"),
        ]))
        .expect_err("ferrum-policy refuses two rules with one id");
        let rules = rules_schema(crd);
        assert_eq!(
            rules.get("x-kubernetes-list-type").and_then(Value::as_str),
            Some("map"),
            "{name}: nothing in the schema stops two rules sharing an id"
        );
        assert_eq!(
            rules
                .get("x-kubernetes-list-map-keys")
                .and_then(Value::as_sequence)
                .map(|k| k.iter().filter_map(Value::as_str).collect::<Vec<_>>()),
            Some(vec!["id"]),
            "{name}: the list-map key is not the rule id"
        );
    }
}

/// The match predicates have the same "can never fire" bound the compiler
/// enforces, and it is the datapath's, not a number retyped into YAML.
#[test]
fn the_match_length_bounds_in_the_schema_are_the_datapath_bounds() {
    for (name, crd) in [
        ("securitypolicy", CRD_SECURITY_POLICY),
        ("clustersecuritypolicy", CRD_CLUSTER_SECURITY_POLICY),
    ] {
        let comm = string_items(&rule_match_property(crd, "commIn"));
        assert_eq!(
            bound(&comm, "maxLength"),
            Some(ferrum_ids::COMM_MATCH_MAX),
            "{name}: commIn maxLength is not TASK_COMM_LEN minus the NUL"
        );
        for field in ["pathPrefix", "pathSuffix"] {
            let path = string_items(&rule_match_property(crd, field));
            assert_eq!(
                bound(&path, "maxLength"),
                Some(ferrum_ids::PATH_MATCH_MAX),
                "{name}: {field} maxLength is not the datapath path buffer"
            );
        }
    }

    // The other side of the same bound, so the numbers above are the ones the
    // compiler actually applies and not a pair of matching typos.
    for (len, admitted) in [
        (ferrum_ids::COMM_MATCH_MAX, true),
        (ferrum_ids::COMM_MATCH_MAX + 1, false),
    ] {
        let mut rule = probe_rule("comm-bound");
        rule.match_on.comm_in = vec!["c".repeat(len)];
        assert_eq!(
            validate_namespaced_policy(&policy_with_rules(vec![rule])).is_ok(),
            admitted,
            "comm of {len} bytes"
        );
    }
    for (len, admitted) in [
        (ferrum_ids::PATH_MATCH_MAX, true),
        (ferrum_ids::PATH_MATCH_MAX + 1, false),
    ] {
        let mut rule = probe_rule("path-bound");
        rule.match_on.path_prefix = vec!["p".repeat(len)];
        assert_eq!(
            validate_namespaced_policy(&policy_with_rules(vec![rule])).is_ok(),
            admitted,
            "pathPrefix of {len} bytes"
        );
    }
}

/// `publicKeys` is verifying material, not a label: a trust root whose key is
/// not 64 hex characters cannot verify anything, and the compiler says so. The
/// schema said `type: string`, so the API server admitted a policy whose supply
/// section could never be built — with `requireSigned` set, that is a cluster
/// believing it demands signatures.
#[test]
fn a_public_key_that_is_not_ed25519_hex_is_refused_by_the_schema_too() {
    let expected = format!(
        "^[0-9a-fA-F]{{{}}}$",
        ferrum_policy::ED25519_PUBLIC_KEY_HEX_LEN
    );
    for (name, crd) in [
        ("securitypolicy", CRD_SECURITY_POLICY),
        ("clustersecuritypolicy", CRD_CLUSTER_SECURITY_POLICY),
    ] {
        let keys = spec_schema(crd)
            .get("properties")
            .and_then(|p| p.get("supply"))
            .and_then(|s| s.get("properties"))
            .and_then(|p| p.get("trustRoots"))
            .and_then(|t| t.get("items"))
            .and_then(|i| i.get("properties"))
            .and_then(|p| p.get("publicKeys"))
            .map(string_items)
            .expect("publicKeys items schema");
        assert_eq!(
            keys.get("pattern").and_then(Value::as_str),
            Some(expected.as_str()),
            "{name}: the schema admits a trustRoot key ferrum-policy cannot use"
        );
    }

    // Same verdicts from the compiler, on the shapes the pattern separates.
    validate_namespaced_policy(&policy_with_trust_root(&[FIXTURE_ED25519_PK]))
        .expect("64 hex characters are a key");
    for bad in ["", "abc", "zz"] {
        validate_namespaced_policy(&policy_with_trust_root(&[bad]))
            .expect_err("not an Ed25519 key");
    }
    let long = format!("{FIXTURE_ED25519_PK}00");
    validate_namespaced_policy(&policy_with_trust_root(&[long.as_str()]))
        .expect_err("too long is not a key either");
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

/// The same trick this file plays on the policy invariants, aimed at the build.
///
/// Everything above checks that two written-down copies of a rule agree. This
/// checks something weaker-sounding and, for a cycle, less true: that what the
/// repository ships is produced by something in the repository. Two of the
/// three binaries named by `deploy/` had never been linked by any stage, in any
/// mode, and neither had an image — `deploy/admission/deployment.yaml` and
/// `deploy/controller/deployment.yaml` named tags that nothing here built.
///
/// A stage is easy to delete and a manifest is easy to add, so this is written
/// as a closure over both directions rather than as three more stages that
/// happen to exist today: every `image:` a manifest names must be produced by a
/// `docker build -t` in the `Jenkinsfile`, and every crate carrying a binary
/// must be named on a cargo invocation that emits object code. `cargo clippy`
/// does not count, and that is the point — it stops at `.rmeta`, which is how
/// the production build of `ferrum-admission` passed CI for a cycle without
/// ever being linked.
mod build_closure {
    use serde::Deserialize;
    use serde_yaml::Value;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .canonicalize()
            .expect("workspace root")
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
    }

    /// The two languages this gate reads, kept apart because their comment
    /// syntaxes contradict each other.
    ///
    /// `/* … */` is a block comment in the Jenkinsfile's Groovy and a path glob
    /// in a Dockerfile's shell. Not reading it in the Jenkinsfile is the hole
    /// this enum exists to close — a `docker build -t ghcr.io/ferrum/… -f
    /// Dockerfile…` line inside a `/* … */` block satisfied both closure tests
    /// below while nothing built — and reading it in a Dockerfile would let
    /// `rm -rf /var/lib/apt/lists/*` swallow the rest of the file, which is the
    /// same defect pointed the other way.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Lang {
        /// `//` and `/* … */`, recognised only outside a triple-quoted string —
        /// which is where every shell command in the Jenkinsfile lives, and
        /// where `#` is a comment because that text is shell.
        Groovy,
        /// `#` only.
        Dockerfile,
    }

    /// Comments, in whichever language this text is written in. Both the
    /// `Jenkinsfile` and the Dockerfiles talk *about* `docker build` and
    /// `cargo build` in prose, and a gate that counted those would report that
    /// the pipeline builds an image because a comment mentions one.
    ///
    /// Line breaks inside a dropped span are kept, so a block comment spanning
    /// lines cannot splice the code above it onto the code below.
    fn strip_comments(text: &str, lang: Lang) -> String {
        let bytes = text.as_bytes();
        // Byte comparison, never `text[i..].starts_with`: this walks one byte
        // at a time and the file carries Russian prose, so a slice taken mid
        // codepoint panics. Every delimiter here is ASCII.
        let starts = |at: usize, needle: &str| bytes[at..].starts_with(needle.as_bytes());
        let mut out = String::with_capacity(text.len());
        let mut keep_from = 0usize;
        let mut i = 0usize;
        // Only whitespace since the last newline. `#` opens a comment there and
        // nowhere else, so the `#` of a fragment or an anchor is not one.
        let mut line_blank = true;
        let mut quote: Option<&'static str> = None;

        let drop_span = |out: &mut String, keep_from: usize, from: usize, to: usize| {
            out.push_str(&text[keep_from..from]);
            for _ in text[from..to].bytes().filter(|c| *c == b'\n') {
                out.push('\n');
            }
        };

        while i < bytes.len() {
            if let Some(q) = quote {
                if starts(i, q) {
                    i += q.len();
                    quote = None;
                    line_blank = false;
                    continue;
                }
            } else if lang == Lang::Groovy {
                if let Some(q) = ["'''", "\"\"\""].into_iter().find(|q| starts(i, q)) {
                    quote = Some(q);
                    i += q.len();
                    line_blank = false;
                    continue;
                }
                // A one-line Groovy string, stepped over whole. Not tracking
                // these is what let `crates/**` in the `stash includes:` list
                // open a block comment that ran to the next `*/` in the file
                // and swallowed four stages, including the `'''` that opens the
                // next shell block — after which every quote boundary in the
                // file was off by one and the block-comment reader was pointed
                // at exactly the wrong halves.
                if bytes[i] == b'\'' || bytes[i] == b'"' {
                    let q = bytes[i];
                    i += 1;
                    while i < bytes.len() && bytes[i] != q && bytes[i] != b'\n' {
                        if bytes[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                    if i < bytes.len() && bytes[i] == q {
                        i += 1;
                    }
                    line_blank = false;
                    continue;
                }
                if starts(i, "//") {
                    let start = i;
                    while i < bytes.len() && bytes[i] != b'\n' {
                        i += 1;
                    }
                    drop_span(&mut out, keep_from, start, i);
                    keep_from = i;
                    continue;
                }
                if starts(i, "/*") {
                    let start = i;
                    i += 2;
                    while i < bytes.len() && !starts(i, "*/") {
                        i += 1;
                    }
                    i = bytes.len().min(i + 2);
                    drop_span(&mut out, keep_from, start, i);
                    keep_from = i;
                    line_blank = false;
                    continue;
                }
            }
            if bytes[i] == b'#' && line_blank {
                let start = i;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                drop_span(&mut out, keep_from, start, i);
                keep_from = i;
                continue;
            }
            if bytes[i] == b'\n' {
                line_blank = true;
            } else if !bytes[i].is_ascii_whitespace() {
                line_blank = false;
            }
            i += 1;
        }
        out.push_str(&text[keep_from..]);
        out
    }

    /// Shell and Dockerfile line continuations, folded away so a command that
    /// spans six lines is one line to look at. Every build command in this
    /// repository is written that way.
    fn joined_lines(text: &str, lang: Lang) -> Vec<String> {
        strip_comments(text, lang)
            .replace("\\\n", " ")
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// The repository half of an image reference. A `:` inside the last path
    /// segment opens the tag; one before the last `/` is a registry port.
    ///
    /// The repository is all the closure below compares, and that is a real
    /// limit rather than a convenience: the pipeline tags with
    /// `${FERRUM_IMAGE_TAG:-dev-$BUILD_NUMBER}` and the manifests pin `v0.1.0`,
    /// so the two tag spaces do not intersect and cannot be made to by reading
    /// them harder. `the_tag_half_of_the_closure_is_open_and_says_why` states
    /// what that leaves open and fails the day it becomes closable.
    fn image_repo(reference: &str) -> String {
        let reference = reference.trim().trim_matches('"');
        let last_segment = reference.rfind('/').map_or(0, |i| i + 1);
        match reference[last_segment..].find(':') {
            Some(colon) => reference[..last_segment + colon].to_string(),
            None => reference.to_string(),
        }
    }

    /// One container as a manifest declares it. Nothing here needs the rest of
    /// a PodSpec.
    ///
    /// `argv` is `command` followed by `args`, which is what the process
    /// receives and what `argv_of` in `crates/ferrum-cli/src/lint_deploy.rs`
    /// reads. Reading `args:` alone — which this did for one cycle — is a
    /// bypass rather than an approximation: `command: ["/ferrum-admission",
    /// "serve", …, "--apiserver"]` with no `args:` key is the other legal
    /// Kubernetes spelling of the same process, and under it every gate below
    /// stops seeing `--apiserver`, both feature requirements evaporate, the
    /// `wanted` tripwire still fires green on the two agent flags, and the
    /// image may then ship a binary whose `--apiserver` reaches `die()`.
    struct Container {
        file: String,
        image: String,
        argv: Vec<String>,
    }

    fn yaml_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap_or_else(|err| panic!("{}: {err}", dir.display()))
        {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                yaml_files(&path, out);
            } else if path.extension().map(|e| e == "yaml").unwrap_or(false) {
                out.push(path);
            }
        }
    }

    fn collect_containers(node: &Value, file: &str, out: &mut Vec<Container>) {
        match node {
            Value::Mapping(map) => {
                if let Some(Value::String(image)) = map.get(&Value::from("image")) {
                    let mut argv = Vec::new();
                    for key in ["command", "args"] {
                        let Some(items) = map.get(&Value::from(key)).and_then(Value::as_sequence)
                        else {
                            continue;
                        };
                        argv.extend(items.iter().filter_map(Value::as_str).map(str::to_string));
                    }
                    out.push(Container {
                        file: file.to_string(),
                        image: image.clone(),
                        argv,
                    });
                }
                for (_, value) in map.iter() {
                    collect_containers(value, file, out);
                }
            }
            Value::Sequence(items) => {
                for item in items {
                    collect_containers(item, file, out);
                }
            }
            _ => {}
        }
    }

    /// Every container in `deploy/`, from every document of every manifest.
    fn deploy_containers(root: &Path) -> Vec<Container> {
        let mut files = Vec::new();
        yaml_files(&root.join("deploy"), &mut files);
        files.sort();
        let mut out = Vec::new();
        for path in files {
            let raw = read(&path);
            let name = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            for doc in serde_yaml::Deserializer::from_str(&raw) {
                let Ok(value) = Value::deserialize(doc) else {
                    continue;
                };
                collect_containers(&value, &name, &mut out);
            }
        }
        out
    }

    /// One `docker build` invocation: which Dockerfile it reads and which image
    /// repositories it produces.
    struct DockerBuild {
        dockerfile: String,
        images: Vec<String>,
    }

    fn docker_builds(script: &str, lang: Lang) -> Vec<DockerBuild> {
        let mut out = Vec::new();
        for line in joined_lines(script, lang) {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let Some(start) = tokens.windows(2).position(|w| w == ["docker", "build"]) else {
                continue;
            };
            let mut dockerfile = "Dockerfile".to_string();
            let mut images = Vec::new();
            let mut i = start + 2;
            while i < tokens.len() {
                match tokens[i] {
                    "-f" | "--file" => {
                        if let Some(value) = tokens.get(i + 1) {
                            dockerfile = value.trim_matches('"').to_string();
                            i += 1;
                        }
                    }
                    "-t" | "--tag" => {
                        if let Some(value) = tokens.get(i + 1) {
                            images.push(image_repo(value));
                            i += 1;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            out.push(DockerBuild { dockerfile, images });
        }
        out
    }

    /// One cargo invocation naming one package: what it does to that package,
    /// under which features, and whether it was asked for every target.
    ///
    /// The subcommand is kept rather than filtered away at parse time because
    /// the difference between them *is* the finding this file exists for.
    /// `build` links a `[[bin]]` and compiles no test target; `clippy` stops at
    /// `.rmeta` and links nothing; `tree` resolves a graph and compiles
    /// nothing at all. A crate can be named by all three and still have never
    /// had a test compiled under the feature it ships in.
    struct CargoRun {
        subcommand: String,
        package: String,
        features: BTreeSet<String>,
        all_targets: bool,
    }

    /// Tokens after which the next word starts a command rather than continuing
    /// one. `sh` is dash here, so this is the whole list it needs.
    /// `RUN` is here because a Dockerfile is the other script this reader
    /// parses and `RUN` is where its shell line begins.
    const COMMAND_STARTS: [&str; 16] = [
        "&&", "||", "|", ";", "&", "(", "{", "!", "if", "elif", "while", "until", "then", "do",
        "else", "RUN",
    ];

    /// Whether the token at `i` is a command being run, rather than a word
    /// inside one.
    ///
    /// `position(|t| *t == "cargo")` — anywhere on the line — was what this
    /// used, and this pipeline's house style is a self-describing `echo` of the
    /// exact command, printed by the gates' own failure messages for the reader
    /// to paste. So `echo "run cargo test -p ferrum-admission --features
    /// apiserver"` satisfied the test half of the feature gate above without
    /// running anything, and a shell `#` comment carrying a cargo line did the
    /// same. A command is the first word of the line or the first word after a
    /// separator; nothing else is.
    fn is_command_position(tokens: &[&str], i: usize) -> bool {
        let mut before = tokens[..i].iter().rev();
        loop {
            match before.next() {
                None => return true,
                Some(prev) if COMMAND_STARTS.contains(prev) => return true,
                // `FOO=bar cargo …` and `sudo cargo …`: still a command.
                Some(prev) if prev.contains('=') && !prev.starts_with('-') => continue,
                Some(&"sudo") | Some(&"env") | Some(&"exec") | Some(&"time") => continue,
                Some(_) => return false,
            }
        }
    }

    /// Every `cargo <subcommand> ... -p <package>` in a script, one entry per
    /// package named.
    fn cargo_runs(script: &str, lang: Lang) -> Vec<CargoRun> {
        let mut out = Vec::new();
        for line in joined_lines(script, lang) {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            // Every `cargo` in command position, not the first `cargo` on the
            // line. Taking only the first and dropping the line when that one
            // was prose is the mirror of the bug `is_command_position` was
            // added for: `echo "... cargo test ..." && cargo test -p X` is the
            // house style these gates' own failure messages ask the reader to
            // write, and it hid the real invocation behind the echo of it.
            let starts: Vec<usize> = (0..tokens.len())
                .filter(|i| tokens[*i] == "cargo" && is_command_position(&tokens, *i))
                .collect();
            for (nth, &start) in starts.iter().enumerate() {
                // Each invocation owns its own arguments: the scan stops at the
                // separator that ends this command, so a later `--features` is
                // not read as belonging to this one.
                let end = tokens[start + 1..]
                    .iter()
                    .position(|t| COMMAND_STARTS.contains(t))
                    .map(|offset| start + 1 + offset)
                    .unwrap_or(tokens.len())
                    .min(starts.get(nth + 1).copied().unwrap_or(usize::MAX));
                // `cargo +nightly build`: the toolchain sits between the two.
                let Some(subcommand) = tokens[start + 1..end].iter().find(|t| !t.starts_with('+'))
                else {
                    continue;
                };
                let subcommand = (*subcommand).to_string();
                let mut packages = Vec::new();
                let mut features = BTreeSet::new();
                let mut all_targets = false;
                let mut i = start;
                while i < end {
                    let token = tokens[i];
                    if token == "-p" || token == "--package" {
                        if let Some(value) = tokens[..end].get(i + 1) {
                            packages.push(value.trim_matches('"').to_string());
                            i += 1;
                        }
                    } else if token == "--features" {
                        if let Some(value) = tokens[..end].get(i + 1) {
                            add_features(value, &mut features);
                            i += 1;
                        }
                    } else if let Some(value) = token.strip_prefix("--features=") {
                        add_features(value, &mut features);
                    } else if token == "--all-targets" {
                        all_targets = true;
                    }
                    i += 1;
                }
                for package in packages {
                    out.push(CargoRun {
                        subcommand: subcommand.clone(),
                        package,
                        features: features.clone(),
                        all_targets,
                    });
                }
            }
        }
        out
    }

    /// One cargo invocation that leaves object code behind, and the features it
    /// leaves it under.
    struct CargoLink {
        package: String,
        features: BTreeSet<String>,
    }

    /// `build` and `run` link; `clippy`, `check`, `tree` and `fmt` do not, and
    /// `test` links a harness rather than the `[[bin]]` a manifest names. Only
    /// the first two are evidence that a shipped binary exists.
    fn cargo_links(script: &str, lang: Lang) -> Vec<CargoLink> {
        cargo_runs(script, lang)
            .into_iter()
            .filter(|run| run.subcommand == "build" || run.subcommand == "run")
            .map(|run| CargoLink {
                package: run.package,
                features: run.features,
            })
            .collect()
    }

    fn add_features(value: &str, out: &mut BTreeSet<String>) {
        for feature in value.trim_matches('"').split(',') {
            let feature = feature.trim();
            if !feature.is_empty() {
                out.insert(feature.to_string());
            }
        }
    }

    fn linked_packages(script: &str, lang: Lang) -> BTreeSet<String> {
        cargo_links(script, lang)
            .into_iter()
            .map(|link| link.package)
            .collect()
    }

    /// A workspace member that produces a binary, and why this gate thinks so.
    struct BinCrate {
        name: String,
        reason: &'static str,
    }

    fn package_name(manifest: &str) -> Option<String> {
        let mut in_package = false;
        for line in manifest.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                in_package = line == "[package]";
                continue;
            }
            if in_package {
                if let Some(rest) = line.strip_prefix("name") {
                    let rest = rest.trim_start().strip_prefix('=')?.trim();
                    return Some(rest.trim_matches('"').to_string());
                }
            }
        }
        None
    }

    /// Both spellings of a binary target: the explicit `[[bin]]` section and
    /// the `src/main.rs` cargo picks up on its own. The second is how three of
    /// the five in this workspace are declared, so a gate that only read
    /// `[[bin]]` would miss the agent, the webhook and the controller — which
    /// is to say all three of the ones that ship in an image.
    fn binary_crates(root: &Path) -> Vec<BinCrate> {
        let mut dirs = Vec::new();
        for entry in std::fs::read_dir(root.join("crates")).expect("crates/") {
            dirs.push(entry.expect("directory entry").path());
        }
        dirs.sort();
        let mut out = Vec::new();
        for dir in dirs {
            let manifest_path = dir.join("Cargo.toml");
            if !manifest_path.is_file() {
                continue;
            }
            let manifest = read(&manifest_path);
            let name = package_name(&manifest)
                .unwrap_or_else(|| panic!("no [package] name in {}", manifest_path.display()));
            if manifest.lines().any(|line| line.trim() == "[[bin]]") {
                out.push(BinCrate {
                    name,
                    reason: "[[bin]]",
                });
            } else if dir.join("src").join("main.rs").is_file() {
                out.push(BinCrate {
                    name,
                    reason: "src/main.rs",
                });
            }
        }
        out
    }

    fn jenkinsfile(root: &Path) -> String {
        read(&root.join("Jenkinsfile"))
    }

    /// Every image *repository* a manifest names is produced by this pipeline.
    ///
    /// The failure this closes is not hypothetical: `ferrum-admission:v0.1.0`
    /// and `ferrum-controller:v0.1.0` were named by Deployments in this tree
    /// and built by nothing in it, so `kubectl apply -f deploy/` produced two
    /// ImagePullBackOffs and an enforcement plane that admits everything.
    ///
    /// It closes the repository half of that failure and no more. The tag half
    /// is open — `image_repo` says why, and
    /// `the_tag_half_of_the_closure_is_open_and_says_why` holds the reason to
    /// the tree — so a manifest naming a repository this pipeline builds under
    /// a tag it never produced still ImagePullBackOffs, and this test passes.
    /// Reading the doc comment above as covering the whole class is the mistake
    /// this paragraph exists to stop.
    #[test]
    fn every_image_a_manifest_names_is_built_by_the_pipeline() {
        let root = repo_root();
        let containers = deploy_containers(&root);
        let built: BTreeSet<String> = docker_builds(&jenkinsfile(&root), Lang::Groovy)
            .into_iter()
            .flat_map(|build| build.images)
            .collect();

        // Both halves must be capable of finding something. A subset check
        // against an empty set is true for the wrong reason, and an empty set
        // is what a renamed directory, a changed manifest layout or a reworked
        // `docker build` line all produce.
        assert!(
            !containers.is_empty(),
            "no container with an image: was found under deploy/, so this gate \
             cannot see what the cluster is asked to pull and proves nothing"
        );
        assert!(
            !built.is_empty(),
            "no `docker build -t` was found in the Jenkinsfile, so this gate \
             cannot see what the pipeline produces and proves nothing"
        );

        let orphans: Vec<String> = containers
            .iter()
            .filter(|container| !built.contains(&image_repo(&container.image)))
            .map(|container| format!("  {} (named by {})", container.image, container.file))
            .collect();
        assert!(
            orphans.is_empty(),
            "these images are named by a manifest and produced by no `docker build -t` \
             in the Jenkinsfile:\n{}\nAn image nothing builds is a tag that never \
             existed: the manifest applies, the Pod never starts, and the plane it \
             belongs to enforces nothing.",
            orphans.join("\n")
        );
    }

    /// What the closure above does not close, said in the gate's own words, and
    /// held to the two facts that make it unclosable here.
    ///
    /// The decision: the tag half cannot honestly be closed *in this
    /// repository*. Nothing pushes — no stage in the Jenkinsfile runs
    /// `docker push` — so the tags the pipeline invents
    /// (`dev-$BUILD_NUMBER`) exist only in one node's local image store, and a
    /// manifest pinned to one of them would name an image no cluster can pull
    /// and would have to be rewritten on every build. Pinning the manifests to
    /// a tag CI invents is its own defect, not a repair. So the comparison
    /// stays on the repository, and this test keeps the two premises honest
    /// instead of the doc comment quietly claiming the whole class:
    ///
    ///   * nothing publishes an image, and
    ///   * every manifest pins a fixed tag rather than a floating one.
    ///
    /// The day the first stops being true — a `docker push` appears, and the
    /// tags become something a cluster can resolve — this test fails, and the
    /// repair is to close the tag half rather than to delete this. `:latest` in
    /// a manifest fails it too: that is the one tag whose value cannot be
    /// checked against anything, on the plane that decides admission.
    #[test]
    fn the_tag_half_of_the_closure_is_open_and_says_why() {
        let root = repo_root();
        let jenkins = strip_comments(&jenkinsfile(&root), Lang::Groovy);
        assert!(
            !jenkins.contains("docker push") && !jenkins.contains("docker image push"),
            "a stage now publishes an image, so the tags this pipeline produces are \
             resolvable and the closure gate can compare them. Close the tag half: \
             `every_image_a_manifest_names_is_built_by_the_pipeline` compares \
             repositories only, and a manifest pinning a tag nothing pushed is the \
             ImagePullBackOff that gate exists to refuse."
        );

        let containers = deploy_containers(&root);
        assert!(!containers.is_empty(), "no container found under deploy/");
        let floating: Vec<String> = containers
            .iter()
            .filter(|c| {
                let tag = c.image[image_repo(&c.image).len()..].trim_start_matches(':');
                tag.is_empty() || tag == "latest"
            })
            .map(|c| format!("  {} (named by {})", c.image, c.file))
            .collect();
        assert!(
            floating.is_empty(),
            "these manifests name a floating tag:\n{}\nNothing in this repository \
             publishes an image, so the tag is the only part of the reference an \
             operator controls; `latest` hands it to whoever pushed last, on the \
             plane that decides admission.",
            floating.join("\n")
        );
    }

    /// Every crate that produces a binary is linked by a stage that emits
    /// object code.
    ///
    /// `cargo clippy` is deliberately not evidence. It stops at `.rmeta`, and
    /// the whole finding this gate exists for is that a crate can pass a clippy
    /// line naming its production features for a cycle without one object file
    /// ever being produced from that combination.
    #[test]
    fn every_crate_with_a_binary_is_linked_by_a_stage_that_emits_object_code() {
        let root = repo_root();
        let crates = binary_crates(&root);
        let linked = linked_packages(&jenkinsfile(&root), Lang::Groovy);

        assert!(
            !crates.is_empty(),
            "no binary crate was found under crates/, so this gate cannot see \
             what the workspace ships and proves nothing"
        );
        assert!(
            !linked.is_empty(),
            "no `cargo build`/`cargo run -p` was found in the Jenkinsfile, so \
             this gate cannot see what the pipeline links and proves nothing"
        );

        let missing: Vec<String> = crates
            .iter()
            .filter(|c| !linked.contains(&c.name))
            .map(|c| format!("  {} (a binary by {})", c.name, c.reason))
            .collect();
        assert!(
            missing.is_empty(),
            "these crates produce a binary and no Jenkinsfile stage links one:\n{}\n\
             A `cargo clippy` line does not count — it stops at .rmeta. A binary \
             that has never been linked is an empty crate with more steps.",
            missing.join("\n")
        );
    }

    /// The parser under both tests above, checked against inputs whose answer is
    /// known. Without this, "no crate is missing" is equally what a `cargo_links`
    /// that has stopped recognising anything reports — and the distinction
    /// between a clippy run and a link is the entire point.
    #[test]
    fn the_scan_counts_a_link_and_refuses_to_count_a_clippy_run() {
        let linked = |s: &str| linked_packages(s, Lang::Groovy);
        assert!(
            linked("cargo clippy -p ferrum-probe --all-targets -- -D warnings").is_empty(),
            "clippy emits .rmeta and no object code; counting it as a link is the \
             fail-open this gate exists to refuse"
        );
        assert!(
            linked("cargo check -p ferrum-probe").is_empty(),
            "`cargo check` does not link either"
        );
        assert!(
            linked("cargo build --release -p ferrum-probe").contains("ferrum-probe"),
            "a plain `cargo build -p` must be recognised, or every check above is \
             satisfied by a scan that finds nothing"
        );
        assert!(
            linked("cargo +nightly build -p ferrum-probe --target x").contains("ferrum-probe"),
            "a toolchain override must not hide the package"
        );
        assert!(
            linked("cargo run -p ferrum-probe --quiet -- validate x").contains("ferrum-probe"),
            "`cargo run` links before it runs"
        );
        // Prose about a build is not a build.
        assert!(
            linked("# cargo build -p ferrum-probe").is_empty(),
            "a comment mentioning a build must not be read as one"
        );
        assert!(
            docker_builds("// docker build -t ghcr.io/ferrum/x:v1 .", Lang::Groovy)
                .into_iter()
                .all(|b| b.images.is_empty()),
            "a comment mentioning an image must not be read as building one"
        );
        assert_eq!(image_repo("ghcr.io/ferrum/x:v0.1.0"), "ghcr.io/ferrum/x");
        assert_eq!(image_repo("\"r:5000/ferrum/x:${TAG}\""), "r:5000/ferrum/x");
    }

    /// The third comment form, which the two above did not read.
    ///
    /// The Jenkinsfile is Groovy, and `/* … */` is a comment in it. A
    /// `docker build -t ghcr.io/ferrum/ferrum-controller… -f
    /// Dockerfile.controller .` commented out that way satisfied
    /// `every_image_a_manifest_names_is_built_by_the_pipeline` *and*
    /// `each_image_is_built_from_a_dockerfile_that_links_its_own_crate` while
    /// the pipeline built nothing at all — a hole in a control this repository
    /// deliberately built, in the one form its own test did not name.
    ///
    /// The same form must NOT be read in a Dockerfile, where `/*` is a path.
    /// `rm -rf /var/lib/apt/lists/*` appears in all three of ours, and a scan
    /// that took it as a comment opener would drop everything after it —
    /// including the `cargo build -p` line every other check here depends on.
    #[test]
    fn a_groovy_block_comment_is_a_comment_and_a_shell_glob_is_not() {
        let commented = "/*\ndocker build -t ghcr.io/ferrum/x:v1 -f Dockerfile.x .\n*/";
        assert!(
            docker_builds(commented, Lang::Groovy)
                .into_iter()
                .all(|b| b.images.is_empty()),
            "a `docker build` inside a Groovy block comment builds nothing, and a \
             gate that counts it reports an image the pipeline never produced"
        );
        assert!(
            linked_packages("/* cargo build -p ferrum-probe */", Lang::Groovy).is_empty(),
            "a `cargo build` inside a block comment links nothing"
        );
        // Trailing block comments and one-line ones, on a line that also builds.
        assert!(
            docker_builds(
                "docker build -t ghcr.io/ferrum/x:v1 . /* was: ghcr.io/ferrum/y */",
                Lang::Groovy
            )
            .into_iter()
            .any(|b| b.images.contains(&"ghcr.io/ferrum/x".to_string())),
            "closing a block comment must not swallow the build beside it"
        );
        assert!(
            !docker_builds(
                "docker build -t ghcr.io/ferrum/x:v1 . /* was: ghcr.io/ferrum/y */",
                Lang::Groovy
            )
            .into_iter()
            .any(|b| b.images.contains(&"ghcr.io/ferrum/y".to_string())),
            "the commented-out image must not be counted"
        );
        // Inside a `sh '''…'''` block the same bytes are shell, not Groovy.
        assert!(
            linked_packages(
                "sh '''\n    cargo build -p ferrum-probe\n    rm -rf /var/lib/apt/lists/*\n'''",
                Lang::Groovy
            )
            .contains("ferrum-probe"),
            "a glob inside a triple-quoted shell block must not open a comment: \
             everything after it is the pipeline this gate reads"
        );
        // And in a Dockerfile there is no such comment at all.
        assert!(
            linked_packages(
                "RUN rm -rf /var/lib/apt/lists/*\nRUN cargo build -p ferrum-probe",
                Lang::Dockerfile
            )
            .contains("ferrum-probe"),
            "`/*` is a path in a Dockerfile; reading it as a comment opener would \
             drop every line after the apt clean-up in all three of ours"
        );
        assert!(
            linked_packages("# RUN cargo build -p ferrum-probe", Lang::Dockerfile).is_empty(),
            "`#` is the Dockerfile comment, and it still has to work"
        );
        // A glob in a one-line Groovy string is not a comment opener either.
        // This is the Jenkinsfile's own `stash includes: '…,crates/**,…'`: read
        // as `/*` it opened a comment that ran to the next `*/` in the file,
        // ate four stages and the `'''` that opens the next shell block, and
        // left every quote boundary after it inverted — so the block-comment
        // reader treated shell as Groovy and Groovy as shell.
        assert_eq!(
            docker_builds(
                "stash includes: 'crates/**,dist/x'\n\
                 sh '''\n    docker build -t ghcr.io/ferrum/x:v1 .\n'''\n\
                 /* docker build -t ghcr.io/ferrum/y:v1 . */\n",
                Lang::Groovy
            )
            .into_iter()
            .flat_map(|b| b.images)
            .collect::<BTreeSet<_>>(),
            BTreeSet::from(["ghcr.io/ferrum/x".to_string()]),
        );
    }

    /// The image an operator pulls is built from the Dockerfile that links the
    /// crate the image is named after.
    ///
    /// One file per image, not one file taking a crate name. The three images
    /// differ by what each has to prove — a bpf object welded to a userspace
    /// that agrees with its map layout, a feature that must have reached the
    /// binary, neither — and a check behind an `if` keyed on a build arg is a
    /// check the wrong argument skips.
    #[test]
    fn each_image_is_built_from_a_dockerfile_that_links_its_own_crate() {
        let root = repo_root();
        let builds = docker_builds(&jenkinsfile(&root), Lang::Groovy);
        assert!(!builds.is_empty(), "no `docker build` in the Jenkinsfile");
        let known: BTreeSet<String> = binary_crates(&root).into_iter().map(|c| c.name).collect();

        for build in &builds {
            let path = root.join(&build.dockerfile);
            assert!(
                path.is_file(),
                "the Jenkinsfile builds -f {} and no such file is in the tree",
                build.dockerfile
            );
            let linked = linked_packages(&read(&path), Lang::Dockerfile);
            for image in &build.images {
                let crate_name = image.rsplit('/').next().unwrap_or(image);
                assert!(
                    known.contains(crate_name),
                    "{image} is built by {}, and {crate_name} is not a binary crate \
                     in this workspace: the image name no longer says what is in it",
                    build.dockerfile
                );
                assert!(
                    linked.contains(crate_name),
                    "{} produces {image} and never links {crate_name}. An image named \
                     after a crate it does not contain is worse than one nothing \
                     builds: it starts.",
                    build.dockerfile
                );
                if let Err(why) = payload_of(&read(&path), crate_name) {
                    panic!(
                        "{} produces {image} and {why}. An image named after a crate it \
                         does not contain is worse than one nothing builds: it starts. \
                         The link above is not that check — a Dockerfile can link \
                         {crate_name} and copy some other binary into the final stage \
                         under that name, and every assertion here passed while it did.",
                        build.dockerfile
                    );
                }
            }
        }
    }

    /// One `COPY --from=<stage> <src> <dst>` as the final stage writes it.
    struct StageCopy {
        from: String,
        src: String,
        dst: String,
    }

    /// The last `FROM` and everything after it: what the image actually
    /// contains. Everything above is a build stage that is thrown away.
    fn final_stage(dockerfile: &str) -> String {
        let lines = joined_lines(dockerfile, Lang::Dockerfile);
        let last = lines
            .iter()
            .rposition(|l| l.trim_start().to_ascii_uppercase().starts_with("FROM "))
            .unwrap_or(0);
        lines[last..].join("\n")
    }

    fn stage_copies(stage: &str) -> Vec<StageCopy> {
        let mut out = Vec::new();
        for line in stage.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.first().map(|t| t.to_ascii_uppercase()) != Some("COPY".to_string()) {
                continue;
            }
            let mut from = String::new();
            let mut operands = Vec::new();
            for token in &tokens[1..] {
                if let Some(stage) = token.strip_prefix("--from=") {
                    from = stage.to_string();
                } else if !token.starts_with("--") {
                    operands.push(token.trim_matches('"').to_string());
                }
            }
            if operands.len() < 2 {
                continue;
            }
            let dst = operands.pop().expect("destination");
            for src in operands {
                out.push(StageCopy {
                    from: from.clone(),
                    src,
                    dst: dst.clone(),
                });
            }
        }
        out
    }

    fn basename(path: &str) -> &str {
        path.rsplit('/').next().unwrap_or(path)
    }

    /// What this Dockerfile puts in the image under `crate_name`, traced back to
    /// the `cargo build` that produced it — or why it cannot be traced.
    ///
    /// `linked_packages` above proves a link happened. It says nothing about
    /// which file the final stage copies, and those are two different claims: a
    /// Dockerfile that links `ferrum-admission` and then copies `/ferrum-agent`
    /// into `/usr/local/bin/ferrum-admission` passes every link assertion in
    /// this file, produces an image an operator pulls by the admission name,
    /// and starts the agent. So the chain is followed all the way: the final
    /// stage's `COPY --from` destination named after the crate, back through
    /// whatever `cp` in the build stage produced its source, back to a path
    /// under a `release/` directory that ends in the crate's own name.
    ///
    /// The ENTRYPOINT is checked with it, because a binary in the image nothing
    /// starts is the same defect one step later.
    fn payload_of(dockerfile: &str, crate_name: &str) -> Result<(), String> {
        let stage = final_stage(dockerfile);
        let copies = stage_copies(&stage);
        if copies.is_empty() {
            return Err(format!(
                "its final stage copies nothing at all, so no file named after \
                 {crate_name} enters the image"
            ));
        }
        let copy = copies
            .iter()
            .find(|c| basename(&c.dst) == crate_name)
            .ok_or_else(|| {
                format!(
                    "its final stage copies nothing to a path named {crate_name} \
                     (it copies to: {})",
                    copies
                        .iter()
                        .map(|c| c.dst.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
        if copy.from.is_empty() {
            return Err(format!(
                "its final stage copies {} to {} from the build context rather than \
                 from a build stage, so nothing here links that file to a compiler",
                copy.src, copy.dst
            ));
        }

        // The source, resolved through the build stage. Every Dockerfile here
        // lifts the binary out of the target directory with one `cp`, because
        // the target triple is a build arg and `COPY --from` takes no variable
        // expansion in the middle of a path.
        let produced = joined_lines(dockerfile, Lang::Dockerfile)
            .into_iter()
            .filter_map(|line| {
                let tokens: Vec<String> = line
                    .split_whitespace()
                    .map(|t| t.trim_matches('"').to_string())
                    .collect();
                let at = tokens.iter().position(|t| t == "cp")?;
                let src = tokens.get(at + 1)?.clone();
                let dst = tokens.get(at + 2)?.clone();
                Some((src, dst))
            })
            .find(|(_, dst)| *dst == copy.src);

        let origin = match &produced {
            Some((src, _)) => src.clone(),
            None => copy.src.clone(),
        };
        if basename(&origin) != crate_name {
            return Err(format!(
                "its final stage copies {} to {}, and that file is {}, which is not \
                 {crate_name}",
                copy.src,
                copy.dst,
                if produced.is_some() {
                    format!("built from {origin}")
                } else {
                    format!("{origin}, produced by no `cp` in a build stage")
                }
            ));
        }
        if !origin.contains("release/") && !origin.contains("debug/") {
            return Err(format!(
                "its final stage copies {} to {}, and nothing in this file shows that \
                 file coming out of a cargo target directory",
                copy.src, copy.dst
            ));
        }

        let entrypoint = stage
            .lines()
            .find(|l| {
                l.trim_start()
                    .to_ascii_uppercase()
                    .starts_with("ENTRYPOINT")
            })
            .ok_or_else(|| format!("it declares no ENTRYPOINT, so {crate_name} never runs"))?;
        if !entrypoint.contains(&copy.dst) {
            return Err(format!(
                "its ENTRYPOINT is {}, which is not the {} it copied {crate_name} to: \
                 the image starts something other than the crate it is named after",
                entrypoint.trim(),
                copy.dst
            ));
        }
        Ok(())
    }

    /// The tracer above, against Dockerfiles whose answer is known — including
    /// the one this whole check exists for, which every other assertion in this
    /// file passes.
    #[test]
    fn the_payload_trace_refuses_an_image_that_ships_another_crates_binary() {
        let honest = "FROM rust AS build\n\
             RUN cargo build --release -p ferrum-admission \\\n\
             \x20&& cp target/x/release/ferrum-admission /ferrum-admission\n\
             FROM scratch\n\
             COPY --from=build /ferrum-admission /usr/local/bin/ferrum-admission\n\
             ENTRYPOINT [\"/usr/local/bin/ferrum-admission\"]\n";
        assert_eq!(payload_of(honest, "ferrum-admission"), Ok(()));

        // The finding. It links the crate the image is named after and ships
        // the agent under that name; `linked_packages` sees the link and is
        // satisfied.
        let swapped = honest.replace(
            "COPY --from=build /ferrum-admission /usr/local/bin/ferrum-admission",
            "COPY --from=build /ferrum-agent /usr/local/bin/ferrum-admission",
        );
        assert!(
            linked_packages(&swapped, Lang::Dockerfile).contains("ferrum-admission"),
            "the link check is satisfied by this file, which is the whole point"
        );
        assert!(payload_of(&swapped, "ferrum-admission").is_err());

        // A binary in the image that nothing starts.
        let unstarted = honest.replace(
            "ENTRYPOINT [\"/usr/local/bin/ferrum-admission\"]",
            "ENTRYPOINT [\"/usr/local/bin/ferrum-agent\"]",
        );
        assert!(payload_of(&unstarted, "ferrum-admission").is_err());

        // A COPY out of the build context is not a build.
        let from_context = honest.replace("COPY --from=build ", "COPY ");
        assert!(payload_of(&from_context, "ferrum-admission").is_err());

        // And a final stage that copies the right name from nowhere it built.
        let unbuilt = honest.replace(
            "&& cp target/x/release/ferrum-admission /ferrum-admission",
            "&& true",
        );
        assert!(payload_of(&unbuilt, "ferrum-admission").is_err());
    }

    /// The flags a shipped manifest passes that only a non-default cargo
    /// feature answers, and the feature each one selects.
    ///
    /// Read as: applying `deploy/` asks for a binary built with this feature.
    /// Both gates below start here — the image must be built with it, and the
    /// crate must be linted and tested with it — because the two failures are
    /// the same one seen from different ends.
    ///
    /// - `--apiserver` (`ferrum-admission`) reaches a `die()` without the
    ///   feature: the webhook CrashLoopBackOffs on a node.
    /// - `--bpf-elf` (`ferrum-agent`) is *quieter* without `attach`, and worse
    ///   for it: the flag is simply not read, and the agent runs with no
    ///   datapath rather than refusing to start.
    /// - `--node` (`ferrum-agent`) opens the pod watch that fills the cgroup
    ///   index. Without `apiserver` the index stays empty, nothing is flagged
    ///   as a container and no kill can pass its guards.
    ///
    /// Hand-written, and held to the sources by
    /// `every_flag_read_under_a_cfg_feature_is_in_the_table` below: a flag a
    /// binary reads inside a `#[cfg(feature = …)]` item and this table does
    /// not name is a fourth entry that would otherwise be invisible to both
    /// gates. The reverse direction stays a judgement and is not derivable:
    /// `--node` is read outside any `cfg`, and what makes it a feature flag is
    /// that the only consumer of its value — `spawn_cgroup_refresh` — is the
    /// `apiserver` build. Nothing in the argv site says so.
    const FEATURE_FLAGS: [(&str, &str); 3] = [
        ("--apiserver", "apiserver"),
        ("--bpf-elf", "attach"),
        ("--node", "apiserver"),
    ];

    /// The crate a manifest's `image:` names, by the convention this file
    /// already rests on twice above: the last path segment of the repository is
    /// the crate name, and
    /// `each_image_is_built_from_a_dockerfile_that_links_its_own_crate` is what
    /// holds that convention to the Dockerfiles.
    fn crate_of(image: &str) -> String {
        let repo = image_repo(image);
        repo.rsplit('/').next().unwrap_or(&repo).to_string()
    }

    /// Every non-default feature a shipped manifest selects is compiled as a
    /// lint target and as a test target.
    ///
    /// The `.rmeta` finding one notch further down. Cycle 9 established that
    /// `cargo clippy` is not a link; this establishes that `cargo build` is not
    /// a test, and that neither of them is the other. Three subcommands name a
    /// crate in this pipeline and each proves a different, smaller thing:
    ///
    ///   * `cargo tree` resolves a dependency graph and compiles nothing;
    ///   * `cargo build --features X` links the `[[bin]]` and compiles no test
    ///     target — `#[cfg(test)]` code and `tests/*.rs` are not in that build
    ///     at all;
    ///   * `cargo clippy --features X` without `--all-targets` skips the test
    ///     targets for the same reason, and stops at `.rmeta` besides.
    ///
    /// `ferrum-admission --features apiserver` was named by two `cargo build`
    /// stages and one `cargo tree` loop, and by no clippy line and no test
    /// line. `cargo test --workspace` runs default features and `apiserver` is
    /// `default = []`. So the crate carrying three of the eight section D
    /// acceptance cases had, in the only configuration it ships in, zero tests
    /// compiled and zero lints run — which is how `WatchedLabels`, the whole
    /// subject of cycle 10's admission slice, reached the end of that cycle
    /// with no test at all. A binary that links is not a crate that is tested.
    ///
    /// What this cannot do, said here rather than left to be read into it: a
    /// `cargo test -p X --features Y --test one_target` satisfies the test
    /// half, which is narrower than the whole target set — and that is exactly
    /// how `ferrum-agent --features attach,apiserver` is satisfied, by the
    /// kernel stage. The gate requires that *a* test target is compiled under
    /// the feature, not that every one is.
    #[test]
    fn every_feature_a_manifest_selects_is_a_lint_and_test_target() {
        let root = repo_root();
        let containers = deploy_containers(&root);
        assert!(
            !containers.is_empty(),
            "no container with an image: was found under deploy/, so this gate cannot see \
             which features the install asks for and proves nothing"
        );
        let runs = cargo_runs(&jenkinsfile(&root), Lang::Groovy);
        assert!(
            !runs.is_empty(),
            "no `cargo ... -p <crate>` was found in the Jenkinsfile, so this gate cannot \
             see what the pipeline compiles and proves nothing"
        );

        // What the install asks for: (crate, feature), from the manifests' own
        // argv and the image each container names.
        let mut wanted: BTreeSet<(String, String)> = BTreeSet::new();
        let mut unselected = Vec::new();
        for (flag, feature) in FEATURE_FLAGS {
            let mut seen = false;
            for container in &containers {
                if container.argv.iter().any(|a| a == flag) {
                    wanted.insert((crate_of(&container.image), feature.to_string()));
                    seen = true;
                }
            }
            if !seen {
                unselected.push(format!("  {flag} (would select {feature})"));
            }
        }
        // The tripwire, per entry rather than over the whole table. `wanted`
        // being non-empty is satisfied by any one surviving flag, which is
        // exactly how a single flag can be made invisible — rewritten into
        // `command:`, renamed, or moved out of `deploy/` — while the other two
        // keep this gate green and the requirement it carried disappears with
        // no build turning red.
        assert!(
            unselected.is_empty(),
            "no container under deploy/ passes these feature-gated flags:\n{}\nEvery entry in \
             FEATURE_FLAGS is a requirement some manifest makes; an entry no manifest selects \
             asserts nothing here. Either the install genuinely stopped asking for it — then \
             delete the row, deliberately, in a diff — or the manifest scan stopped seeing \
             argv.",
            unselected.join("\n")
        );

        let satisfies = |run: &CargoRun, krate: &str, feature: &str| {
            run.package == krate && run.features.contains(feature)
        };
        let mut missing = Vec::new();
        for (krate, feature) in &wanted {
            let linted = runs.iter().any(|run| {
                run.subcommand == "clippy" && run.all_targets && satisfies(run, krate, feature)
            });
            let tested = runs
                .iter()
                .any(|run| run.subcommand == "test" && satisfies(run, krate, feature));
            if !linted {
                missing.push(format!(
                    "  {krate} --features {feature}: no `cargo clippy -p {krate} --features \
                     ...{feature}... --all-targets` line. Without --all-targets clippy skips \
                     every test target, and a `cargo build` of the same combination compiles \
                     none of them at all."
                ));
            }
            if !tested {
                missing.push(format!(
                    "  {krate} --features {feature}: no `cargo test -p {krate} --features \
                     ...{feature}...` line. `cargo test --workspace` is default features and \
                     this feature is not one; `cargo build --features {feature}` links the \
                     binary and compiles no test target; `cargo tree` compiles nothing."
                ));
            }
        }
        assert!(
            missing.is_empty(),
            "deploy/ asks for these features and the pipeline neither lints nor tests \
             them:\n{}\nA binary that links is not a crate that is tested: \
             `ferrum-admission --features apiserver` passed CI for cycles on two `cargo \
             build` stages and a `cargo tree` loop, with no test ever compiled under the \
             feature it ships in.",
            missing.join("\n")
        );
    }

    /// The same claim, executed instead of read.
    ///
    /// The gate above proves a *line exists* in the Jenkinsfile. That is all
    /// it can prove, and cycle 12 measured exactly what the gap costs: a
    /// commit deleted `impl From<BTreeMap> for ClusterLabels` and left its
    /// caller in the `#[cfg(feature = "apiserver")]` half of
    /// `ferrum-admission`'s test module. The tree built, `cargo test
    /// --workspace` reported zero failures because `apiserver` is `default =
    /// []`, and the two lines the gate above requires — the ones cycle 12
    /// added so this could not happen — were the only red in the pipeline.
    /// Seven tests on `WatchedLabels`, the single shipped `LabelSource`, plus
    /// two on a cold and a stale watch, silently did not run. A gate that
    /// reads text cannot see that, by construction: the text was correct.
    ///
    /// So this one runs the commands. For every crate a shipped manifest
    /// selects features for, with the union of those features in one
    /// invocation:
    ///
    ///   * `cargo clippy -p K --features F --all-targets -- -D warnings`
    ///   * `cargo test -p K --features F`
    ///
    /// Deliberately not `--no-run`: "a test target is compiled" and "the tests
    /// pass" are different claims, the Jenkinsfile line makes the second, so
    /// this makes the second. Cost is bounded by sharing the ambient
    /// `target/` — every dependency the outer build already compiled is
    /// reused, and the marginal work is the feature-enabled rebuild of the
    /// named crate.
    ///
    /// What it still cannot do, said here rather than left to be read into it:
    /// prove a *Jenkins* ran anything. Nothing in this tree can. It proves the
    /// commands succeed on the tree that ships, which is the half a reader of
    /// `Jenkinsfile::Test` was taking for free and did not have.
    #[test]
    fn every_feature_a_manifest_selects_actually_compiles_and_passes() {
        let root = repo_root();
        let containers = deploy_containers(&root);
        assert!(
            !containers.is_empty(),
            "no container with an image: was found under deploy/, so this gate cannot see \
             which features the install asks for and proves nothing"
        );

        // Union per crate: two flags selecting `apiserver` and `attach` on the
        // same image are one build of that crate with both, not two.
        let mut wanted: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (flag, feature) in FEATURE_FLAGS {
            for container in &containers {
                if container.argv.iter().any(|a| a == flag) {
                    wanted
                        .entry(crate_of(&container.image))
                        .or_default()
                        .insert(feature.to_string());
                }
            }
        }
        assert!(
            !wanted.is_empty(),
            "no container under deploy/ passes a feature-gated flag, so this gate compiles \
             nothing and proves nothing"
        );

        for (krate, features) in &wanted {
            let features = features.iter().cloned().collect::<Vec<_>>().join(",");
            for argv in [
                vec![
                    "clippy",
                    "-p",
                    krate,
                    "--features",
                    features.as_str(),
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
                vec!["test", "-p", krate, "--features", features.as_str()],
            ] {
                let printed = format!("cargo {}", argv.join(" "));
                let out = std::process::Command::new(env!("CARGO"))
                    .args(&argv)
                    .current_dir(&root)
                    .output()
                    .unwrap_or_else(|err| panic!("{printed}: {err}"));
                assert!(
                    out.status.success(),
                    "`{printed}` failed ({}). This is a configuration the install runs; a \
                     green `cargo test --workspace` says nothing about it, because every \
                     production feature in this tree is off by default.\n--- stdout ---\n{}\n\
                     --- stderr ---\n{}",
                    out.status,
                    tail(&String::from_utf8_lossy(&out.stdout)),
                    tail(&String::from_utf8_lossy(&out.stderr)),
                );
            }
        }
    }

    /// Last lines of a subprocess stream, so a failing feature build reports
    /// the compiler's verdict instead of its whole log.
    fn tail(text: &str) -> String {
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    }

    /// The reader under the gate above, on inputs whose answer is known.
    ///
    /// "Nothing is missing" is also what a `cargo_runs` that has stopped
    /// telling the subcommands apart reports, and telling them apart is the
    /// entire claim. `build` and `tree` must not be able to satisfy either
    /// half, and a clippy line without `--all-targets` must not satisfy the
    /// lint half.
    #[test]
    fn a_build_is_not_a_test_and_a_tree_is_not_a_compile() {
        let one = |line: &str| {
            let runs = cargo_runs(line, Lang::Groovy);
            assert_eq!(runs.len(), 1, "{line:?} parsed as {} runs", runs.len());
            runs.into_iter().next().expect("one run")
        };

        let built = one("cargo build --release -p ferrum-admission --features apiserver");
        assert_eq!(built.subcommand, "build");
        assert!(built.features.contains("apiserver"));
        assert!(
            !built.all_targets,
            "a `cargo build` compiles no test target, and reading one as --all-targets would \
             let the finding this gate exists for pass again"
        );

        let treed = one("cargo tree -p ferrum-admission -e normal --features apiserver");
        assert_eq!(
            treed.subcommand, "tree",
            "`cargo tree` resolves a graph and compiles nothing; counting it as either half \
             is a gate that is green because nothing ran"
        );

        let checked = one("cargo clippy -p ferrum-admission --features apiserver -- -D warnings");
        assert_eq!(checked.subcommand, "clippy");
        assert!(
            !checked.all_targets,
            "without --all-targets clippy skips the test targets, which is the half of this \
             finding that is not about linking"
        );

        let full = one(
            "cargo clippy -p ferrum-admission --features apiserver --all-targets -- -D warnings",
        );
        assert!(full.all_targets);

        let tested = one("cargo test -p ferrum-admission --features apiserver");
        assert_eq!(tested.subcommand, "test");
        assert!(tested.features.contains("apiserver"));

        // The comment forms the rest of this file already refuses, on this
        // reader too: prose about a test is not a test.
        assert!(
            cargo_runs(
                "// cargo test -p ferrum-admission --features apiserver",
                Lang::Groovy
            )
            .is_empty(),
            "a commented-out test line must not satisfy this gate"
        );
        // The `--features=a,b` spelling, which the Jenkinsfile does not use
        // today and which must not silently stop being read if it starts to.
        let joined = one("cargo test -p ferrum-agent --features=attach,apiserver");
        assert!(joined.features.contains("attach") && joined.features.contains("apiserver"));

        // A word inside another command is not that command. This pipeline's
        // house style is a self-describing echo of the exact line to run, and
        // the failure messages above tell the reader to write one — so an echo
        // naming a cargo invocation is the cheapest possible way to satisfy
        // this gate without running anything.
        for prose in [
            "echo \"run cargo test -p ferrum-admission --features apiserver\" >&2",
            "# cargo test -p ferrum-admission --features apiserver",
            "grep -q cargo test -p ferrum-admission --features apiserver \"$out\"",
        ] {
            assert!(
                cargo_runs(prose, Lang::Groovy).is_empty(),
                "{prose:?} names cargo without running it, and counting it would make this \
                 gate satisfiable by a sentence"
            );
        }

        // And the spellings the Jenkinsfile actually uses, which must keep
        // parsing: leading environment assignments, `if !`, and a separator.
        let env_prefixed = one(
            "if ! FERRUM_BPF_ELF_REQUIRED=1 FERRUM_BPF_ELF=\"$elf\" cargo test -p ferrum-agent \
             --features attach,apiserver --lib",
        );
        assert_eq!(env_prefixed.subcommand, "test");
        assert!(env_prefixed.features.contains("attach"));
        let after_separator = one("mkdir -p dist && cargo build -p ferrum-agent --features attach");
        assert_eq!(after_separator.subcommand, "build");

        // The other direction of the same rule, and the one the fix for prose
        // introduced: the echo must not hide the command it echoes. Taking the
        // *first* `cargo` on the line and dropping the line when that one was
        // prose meant a real invocation announced in this pipeline's house
        // style was never recorded by the feature or link gates at all.
        let announced = one(
            "echo \"run cargo test -p ferrum-admission --features apiserver\" && cargo test -p \
             ferrum-admission --features apiserver",
        );
        assert_eq!(
            announced.subcommand, "test",
            "an echo of the command being run must not hide the run of it"
        );
        assert!(announced.features.contains("apiserver"));

        // Two real invocations on one line are two runs, each with its own
        // arguments: a scan that ran to end of line would give the first one
        // the second's features and report a coverage that does not exist.
        let both = cargo_runs(
            "cargo build -p ferrum-agent --features attach && cargo test -p ferrum-agent \
             --features attach,apiserver",
            Lang::Groovy,
        );
        assert_eq!(both.len(), 2, "two commands on one line are two runs");
        assert_eq!(both[0].subcommand, "build");
        assert!(
            !both[0].features.contains("apiserver"),
            "the second command's --features must not be read as the first's"
        );
        assert_eq!(both[1].subcommand, "test");
        assert!(both[1].features.contains("apiserver"));
    }

    /// A flag a manifest passes that only a cargo feature provides is built into
    /// the image that is passed it.
    ///
    /// `deploy/admission/deployment.yaml` passes `--apiserver`, and
    /// `ferrum-admission` has that feature off by default. Built without it the
    /// flag reaches a `die()` and the Pod CrashLoops on a node — a build-time
    /// defect arriving as a runtime one, on the crate carrying three of the
    /// eight section D acceptance cases. Both sides are read out of the tree:
    /// the requirement from the manifest's own argv, the answer from the
    /// Dockerfile that builds the image the manifest names.
    #[test]
    fn a_flag_only_a_feature_provides_is_built_into_the_image_that_is_passed_it() {
        let root = repo_root();
        let containers = deploy_containers(&root);
        let builds = docker_builds(&jenkinsfile(&root), Lang::Groovy);

        let mut unselected = Vec::new();
        for (flag, feature) in FEATURE_FLAGS {
            let passed: Vec<&Container> = containers
                .iter()
                .filter(|c| c.argv.iter().any(|a| a == flag))
                .collect();
            if passed.is_empty() {
                unselected.push(format!("  {flag} (would require --features {feature})"));
            }
            for container in passed {
                let repo = image_repo(&container.image);
                let crate_name = repo.rsplit('/').next().unwrap_or(&repo).to_string();
                let build = builds
                    .iter()
                    .find(|build| build.images.contains(&repo))
                    .unwrap_or_else(|| {
                        panic!("{} passes {flag} and nothing builds {repo}", container.file)
                    });
                let link = cargo_links(&read(&root.join(&build.dockerfile)), Lang::Dockerfile)
                    .into_iter()
                    .find(|link| link.package == crate_name)
                    .unwrap_or_else(|| panic!("{} never links {crate_name}", build.dockerfile));
                assert!(
                    link.features.contains(feature),
                    "{} passes {flag}, and {} links {crate_name} without --features \
                     {feature}. The flag is gated on that feature at compile time, so \
                     the container would die() on start: a defect in this file \
                     arriving as a CrashLoopBackOff on a node.",
                    container.file,
                    build.dockerfile
                );
            }
        }

        // The control, per flag. Every assertion above is inside a filter, and
        // a filter that matches nothing runs no assertion at all — which is
        // exactly what a renamed flag, a manifest moved out of `deploy/`, an
        // argv rewritten from `args:` into `command:` past a scan that only
        // read one of them, or a broken argv scan would produce. Counting the
        // whole table lets any two survivors carry the third.
        assert!(
            unselected.is_empty(),
            "no container under deploy/ passes these feature-gated flags:\n{}\nSo for each of \
             them this gate ran no assertion at all. Either the flags moved, or the manifest \
             scan stopped seeing argv.",
            unselected.join("\n")
        );
    }

    /// The manifest reader under both gates above, on the two spellings
    /// Kubernetes accepts for the same argv.
    ///
    /// A PodSpec may put the whole command line in `command:`, or split it
    /// across `command:` and `args:`, or leave `command:` out and let the
    /// image's ENTRYPOINT supply argv[0]. The process sees one argv either
    /// way, `argv_of` in `crates/ferrum-cli/src/lint_deploy.rs` reads both
    /// keys, and a scan here that read only `args:` would let the webhook be
    /// rewritten into the first spelling — legal, equivalent, reviewable — and
    /// take `--apiserver` out of both gates' sight in the same edit. The
    /// clippy line, the test line and `--features apiserver` in
    /// `Dockerfile.admission` could then all be deleted with CI green, and the
    /// image would ship a binary whose `--apiserver` reaches `die()`: two
    /// replicas in CrashLoopBackOff behind `failurePolicy: Fail`.
    #[test]
    fn a_containers_argv_is_command_then_args_and_either_alone() {
        let one = |yaml: &str| {
            let value: Value = serde_yaml::from_str(yaml).expect("fixture");
            let mut out = Vec::new();
            collect_containers(&value, "fixture.yaml", &mut out);
            assert_eq!(out.len(), 1, "{yaml:?} parsed as {} containers", out.len());
            out.into_iter().next().expect("one container").argv
        };

        assert_eq!(
            one("image: x\nargs: [serve, --apiserver]\n"),
            vec!["serve", "--apiserver"]
        );
        assert_eq!(
            one("image: x\ncommand: [/ferrum-admission, serve, --apiserver]\n"),
            vec!["/ferrum-admission", "serve", "--apiserver"],
            "a manifest that puts the whole command line in `command:` passes the same \
             argv to the same process, and a scan that cannot see it hands every gate \
             built on argv a silent way out"
        );
        assert_eq!(
            one("image: x\ncommand: [/ferrum-admission]\nargs: [serve, --apiserver]\n"),
            vec!["/ferrum-admission", "serve", "--apiserver"],
            "command comes first and args follows it; concatenating them in the other \
             order would still find the flag here and misreport the value of any flag \
             read positionally"
        );
        assert!(one("image: x\n").is_empty());
    }

    /// Every `--flag` a source file reads inside a column-zero
    /// `#[cfg(feature = …)]` item, and the feature that gates it.
    ///
    /// The item's extent is the point. A braced item ends at its column-zero
    /// `}`; a braceless one — `use`, `const`, `mod x;` — ends at its own `;`,
    /// and running that one to the next column-zero `}` sweeps every unrelated
    /// read between here and the end of some later item in under this feature,
    /// which is a gate failing on flags nothing gates. Every `#[cfg]` in the
    /// tree today sits on a braced item, so this is a false positive waiting
    /// rather than a bypass — but a rule that decides an item's extent by
    /// looking for the next `}` is not deciding what it claims to.
    fn cfg_feature_flags(krate: &str, body: &str) -> BTreeSet<(String, String, String)> {
        let mut derived: BTreeSet<(String, String, String)> = BTreeSet::new();
        let lines: Vec<&str> = body.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            // Item-level attributes only.
            let Some(feature) = lines[i]
                .strip_prefix("#[cfg(feature = \"")
                .and_then(|rest| rest.split('"').next())
            else {
                i += 1;
                continue;
            };
            let feature = feature.to_string();
            // The item head is the first line after this attribute and any
            // others stacked on the same item.
            let mut head = i + 1;
            while head < lines.len() && lines[head].starts_with("#[") {
                head += 1;
            }
            // Where the item head ends decides which of the two it is. A `fn`
            // signature runs over several lines before its `{`; a `use` that
            // imports a group carries `{` and its `;` on one line, so the `;`
            // is asked about first.
            let mut k = head;
            while k < lines.len() && !lines[k].trim_end().ends_with(';') && !lines[k].contains('{')
            {
                k += 1;
            }
            let end = if lines
                .get(k)
                .is_some_and(|line| !line.trim_end().ends_with(';'))
            {
                let mut j = k;
                while j < lines.len() && lines[j] != "}" {
                    j += 1;
                }
                j
            } else {
                (k + 1).min(lines.len())
            };
            for line in &lines[i + 1..end] {
                // Every spelling a binary here uses to ask its argv parser
                // for a flag. `ferrum-admission` moved from a bare `BTreeMap`
                // to a `Flags` that keeps every occurrence — so that a
                // `--cluster-label` swallowed by the next flag is a refusal
                // rather than a stated cluster — and its reads became
                // `flags.get`. A scan that knew only the map spelling found
                // nothing to calibrate against and said so.
                for call in ["map.get(\"", "map.contains_key(\"", "flags.get(\""] {
                    for hit in line.split(call).skip(1) {
                        if let Some(flag) = hit.split('"').next() {
                            derived.insert((
                                krate.to_string(),
                                format!("--{flag}"),
                                feature.clone(),
                            ));
                        }
                    }
                }
            }
            i = end;
        }
        derived
    }

    /// Every flag a shipped binary reads inside a `#[cfg(feature = …)]` item is
    /// named in `FEATURE_FLAGS`.
    ///
    /// The table is what both gates above enumerate, and a hand-written table
    /// has one failure mode: the fourth entry nobody adds. A flag whose reader
    /// only exists under a feature is exactly the shape of the two entries
    /// already there — `--apiserver` on the webhook and `--bpf-elf` on the
    /// agent — so a fifth `#[cfg(feature = …)] fn` that reads `flags.map` is a
    /// requirement `deploy/` can make that neither gate would ever check.
    ///
    /// This is one direction only, and deliberately: the table may hold more
    /// than the sources derive. `--node` is read outside any `cfg` and is in
    /// the table because its only consumer is the `apiserver` build, which is
    /// a judgement about the program and not a fact about the argv site.
    #[test]
    fn every_flag_read_under_a_cfg_feature_is_in_the_table() {
        let root = repo_root();
        let mut derived: BTreeSet<(String, String, String)> = BTreeSet::new();
        for krate in ["ferrum-admission", "ferrum-agent"] {
            let path = root.join("crates").join(krate).join("src/main.rs");
            derived.extend(cfg_feature_flags(krate, &read(&path)));
        }

        // A braceless column-zero `#[cfg]` ends at its own `;`. Scanned to the
        // next column-zero `}` instead, the `use` below would put every read
        // in the function after it under `apiserver` and fail this gate on
        // flags nothing gates.
        let braceless = cfg_feature_flags(
            "synthetic",
            "#[cfg(feature = \"apiserver\")]\nuse std::io::Write;\n\nfn unrelated() {\n    \
             map.get(\"swept\");\n}\n",
        );
        assert!(
            braceless.is_empty(),
            "a cfg on a braceless item swept unrelated reads in under its feature: {braceless:?}"
        );
        // And the braced form it must keep reading.
        let braced = cfg_feature_flags(
            "synthetic",
            "#[cfg(feature = \"apiserver\")]\nfn gated() {\n    map.get(\"real\");\n}\n",
        );
        assert_eq!(
            braced,
            [(
                "synthetic".to_string(),
                "--real".to_string(),
                "apiserver".to_string()
            )]
            .into_iter()
            .collect::<BTreeSet<_>>()
        );

        // The calibration. An empty or shrunken derivation is what a moved
        // `main.rs`, a reformatted attribute or a renamed `Flags` field also
        // produces, and it would make every assertion below vacuous.
        for known in [
            ("ferrum-admission", "--apiserver", "apiserver"),
            ("ferrum-agent", "--bpf-elf", "attach"),
        ] {
            let want = (
                known.0.to_string(),
                known.1.to_string(),
                known.2.to_string(),
            );
            assert!(
                derived.contains(&want),
                "the scan no longer finds {} reading {} under #[cfg(feature = \"{}\")], so it \
                 can no longer find a fourth one either and this gate proves nothing. Found: \
                 {derived:?}",
                known.0,
                known.1,
                known.2
            );
        }

        let missing: Vec<String> = derived
            .iter()
            .filter(|(_, flag, feature)| {
                !FEATURE_FLAGS
                    .iter()
                    .any(|(f, feat)| f == flag && feat == feature)
            })
            .map(|(krate, flag, feature)| {
                format!("  {krate} reads {flag} only under --features {feature}")
            })
            .collect();
        assert!(
            missing.is_empty(),
            "these flags are read inside a #[cfg(feature = …)] item and FEATURE_FLAGS does not \
             name them:\n{}\nA manifest may pass any of them, and neither the lint-and-test \
             gate nor the image gate would notice: the flag would reach a build that does not \
             compile its reader.",
            missing.join("\n")
        );
    }
}
