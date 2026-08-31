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
fn exception_ttl_ceiling_is_ninety_days_in_policy_and_no_schema_may_claim_it() {
    // Two CEL rules used to stand here — `self.expiresAt > now()` and
    // `self.expiresAt <= now() + duration('2160h')` — and this test read them
    // out of the file it was asserting about, which is the whole reason they
    // survived. A real API server refuses them: CRD validation has no clock,
    // `now()` is an undeclared reference, and the compilation failure rejects
    // the *whole* CRD. So the tree shipped a PolicyException that could not be
    // installed at all, and every other rule in that file — self-approve,
    // required target — was inert with it. Measured, not read:
    // `e2e_cluster.rs::the_shipped_crds_are_accepted_by_a_real_apiserver`.
    //
    // The direction of this assertion is therefore inverted on purpose. A
    // schema rule about wall-clock time is not a stricter schema, it is an
    // uninstallable one, and this is what stops it coming back.
    let rules = cel_rules(CRD_POLICY_EXCEPTION);
    assert!(
        !rules.iter().any(|r| r.contains("now(")),
        "a PolicyException CEL rule reaches for a clock. The API server has \
         none in CRD validation and refuses the entire CustomResourceDefinition \
         when it sees one, taking every other rule in the file down with it: \
         {rules:?}"
    );

    // The ceiling itself did not move; only the place that can hold it did.
    validate_exception(&exception("sre", "ib", 89)).expect("89 days is inside the window");
    let err = validate_exception(&exception("sre", "ib", 91))
        .expect_err("91 days must be rejected by ferrum-policy");
    assert!(format!("{err}").contains("90"), "{err}");
    assert_eq!(ferrum_policy::MAX_EXCEPTION_DAYS, 90);
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
    /// them harder. The tag half is held elsewhere, against the file that does
    /// publish under a tag a manifest can pin —
    /// `release_supply_chain::the_tag_the_manifests_pin_is_one_the_release_can_publish`.
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
                if let Some(Value::String(image)) = map.get(Value::from("image")) {
                    let mut argv = Vec::new();
                    for key in ["command", "args"] {
                        let Some(items) = map.get(Value::from(key)).and_then(Value::as_sequence)
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
                // `break`, not `continue`: libyaml does not recover from a
                // parse error, so asking this iterator for the next document
                // after one yields the same error again, for ever. A malformed
                // manifest under deploy/ hung this gate instead of failing it.
                let Ok(value) = Value::deserialize(doc) else {
                    break;
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
    /// Обёртки cargo, стоящие перед настоящей подкомандой. Не список
    /// «всех»: здесь ровно те, которые дерево использует, и каждая добавляется
    /// вместе с местом, где она появилась.
    const CARGO_WRAPPERS: [&str; 1] = ["auditable"];

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
                // `cargo auditable build`: so does the wrapper that embeds the
                // dependency list. Reading `auditable` as the subcommand would
                // make the three image builds invisible to every gate below —
                // the failure would be silent and would look like an image
                // that links nothing.
                let Some(subcommand) = tokens[start + 1..end]
                    .iter()
                    .find(|t| !t.starts_with('+') && !CARGO_WRAPPERS.contains(t))
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
    /// It closes the repository half of that failure and no more. A manifest
    /// naming a repository this pipeline builds, under a tag nothing produces,
    /// still ImagePullBackOffs and this test still passes: `image_repo` says
    /// why, and the tag half is held by
    /// `release_supply_chain::the_tag_the_manifests_pin_is_one_the_release_can_publish`
    /// against the release workflow, which is the only file in this tree that
    /// publishes anything. Reading the doc comment above as covering the whole
    /// class is the mistake this paragraph exists to stop.
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
            linked("cargo auditable build --release -p ferrum-probe").contains("ferrum-probe"),
            "`cargo auditable build` is the link the three images run; read as its own \
             subcommand it makes every image look like one that links nothing"
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

/// The one file the SAST stage does not scan, and the reason that is not a hole.
///
/// `deploy-bad-private-key/ca.key` exists so FD023 has something to fire on: a
/// PEM header inside a tree that gets committed. semgrep's secret rule reads
/// the same header and calls it a leaked key, so the two gates were each
/// other's failure — the SAST stage denied every build on the fixture that
/// proves the deploy lint works, and it denied it first, so nothing below it
/// ran at all.
///
/// An exclusion nobody watches is the more expensive of the two failures. This
/// module is the watcher, and it holds three things, none of which semgrep can
/// hold for itself: the stage excludes exactly this one path, the file it
/// excludes is not key material, and the lint that owns the fixture still
/// calls it a finding. Break any one and this gate fails — a second
/// `--exclude`, a fixture quietly replaced by a real key, or an FD023 that
/// stopped firing.
mod scan_exclusions {
    use ferrum_cli::lint_deploy::lint_deploy_dir;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    /// Every path the pipeline is allowed to hide from the secret scanner.
    /// Adding an entry is a deliberate act: it fails this gate until it is
    /// written here, and then it has to survive the checks below.
    const EXCLUDED: [&str; 1] = ["crates/ferrum-testkit/fixtures/deploy-bad-private-key/ca.key"];

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .canonicalize()
            .expect("workspace root")
    }

    /// Every `--exclude='…'` the pipeline passes to semgrep, from any stage.
    /// Deliberately not scoped to `SAST (semgrep)`: an exclusion added to some
    /// other stage would be exactly as unwatched.
    fn pipeline_exclusions() -> BTreeSet<String> {
        let text = std::fs::read_to_string(repo_root().join("Jenkinsfile")).expect("Jenkinsfile");
        text.lines()
            .filter_map(|line| {
                let rest = line.trim().strip_prefix("--exclude=")?;
                let rest = rest.strip_prefix('\'')?;
                let (path, _) = rest.split_once('\'')?;
                Some(path.to_string())
            })
            .collect()
    }

    /// The first byte of a PEM block's payload.
    ///
    /// Every DER-encoded private key — SEC1, PKCS#1, PKCS#8 alike — opens with
    /// a SEQUENCE tag, `0x30`. A fixture that only has to carry the header can
    /// put anything after it, and this is what tells the two apart without a
    /// parser and without a base64 crate in this graph.
    fn pem_payload_first_byte(text: &str) -> u8 {
        let payload = text
            .lines()
            .skip_while(|l| !l.trim_start().starts_with("-----BEGIN "))
            .skip(1)
            .find(|l| !l.trim().is_empty() && !l.trim_start().starts_with("-----END"))
            .expect("PEM payload");
        let quad: Vec<u8> = payload
            .trim()
            .bytes()
            .take(4)
            .map(|c| {
                B64.iter()
                    .position(|&a| a == c)
                    .unwrap_or_else(|| panic!("not base64: {c:?}")) as u8
            })
            .collect();
        assert_eq!(quad.len(), 4, "PEM payload shorter than one base64 quad");
        (quad[0] << 2) | (quad[1] >> 4)
    }

    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    #[test]
    fn the_scanner_skips_exactly_the_files_this_gate_vouches_for() {
        let expected: BTreeSet<String> = EXCLUDED.iter().map(|p| p.to_string()).collect();
        assert_eq!(
            pipeline_exclusions(),
            expected,
            "an --exclude this gate does not vouch for is a file nothing scans"
        );
    }

    #[test]
    fn every_excluded_file_is_a_fixture_that_only_looks_like_a_key() {
        for rel in EXCLUDED {
            assert!(
                rel.starts_with("crates/") && rel.contains("/fixtures/"),
                "{rel}: only a fixture may be hidden from the scanner"
            );
            let text = std::fs::read_to_string(repo_root().join(rel))
                .unwrap_or_else(|err| panic!("{rel}: {err}"));
            assert!(
                text.lines()
                    .any(|l| l.trim_start().starts_with("-----BEGIN ")
                        && l.trim_end().trim_end_matches('-').ends_with("PRIVATE KEY")),
                "{rel}: excluded from the secret scanner but carries no PEM private-key \
                 header — then it was excluded for some other reason, and this gate does \
                 not know what it is"
            );
            assert_ne!(
                pem_payload_first_byte(&text),
                0x30,
                "{rel}: payload opens with a DER SEQUENCE, which is what real key material \
                 does. This is not a fixture any more, and the scanner is being told to \
                 ignore a key"
            );
        }
    }

    /// The direction the exclusion could rot in: FD023 stops firing, the
    /// fixture stops being checked by anything at all, and both gates are
    /// green.
    #[test]
    fn the_excluded_fixture_is_still_a_finding_for_the_lint_that_owns_it() {
        for rel in EXCLUDED {
            let dir = repo_root()
                .join(rel)
                .parent()
                .expect("fixture dir")
                .to_path_buf();
            let err = lint_deploy_dir(&dir)
                .expect_err("a private key in the deploy tree must still fail the lint");
            assert!(err.to_string().contains("violated"), "{err}");
        }
    }
}

/// The image is a claim about a platform, and until this gate the claim was
/// made by the machine that happened to run `docker build`.
///
/// Every binary in these images is linked for `x86_64-unknown-linux-musl` —
/// the stand the kernel rows are measured on. `docker build` on an arm64 node
/// stamps the image `linux/arm64` anyway, because the platform comes from the
/// daemon and not from the payload. The result is an image that runs nowhere:
/// wrong architecture on an arm64 node, wrong manifest on an x86_64 one. None
/// of the checks *inside* the Dockerfiles can see it — they read the binary,
/// and the binary is correct; what is wrong is the manifest around it.
///
/// The two halves have to agree, so both are read here: the builder stage
/// stays on `$BUILDPLATFORM` (compile natively, cross to the target), and the
/// build command names the target platform explicitly.
mod image_platform {
    use std::path::{Path, PathBuf};

    /// The triple the linking stages build, and the platform its images must
    /// declare. One is the Rust spelling and the other is Docker's; they are
    /// written here side by side because nothing else in the tree joins them.
    const TARGET_TRIPLE: &str = "x86_64-unknown-linux-musl";
    const TARGET_PLATFORM: &str = "linux/amd64";

    const DOCKERFILES: [&str; 3] = [
        "Dockerfile",
        "Dockerfile.admission",
        "Dockerfile.controller",
    ];

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .canonicalize()
            .expect("workspace root")
    }

    fn read(rel: &str) -> String {
        let path = repo_root().join(rel);
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
    }

    #[test]
    fn every_docker_build_names_the_platform_its_binaries_are_linked_for() {
        let jenkinsfile = read("Jenkinsfile");
        let builds: Vec<&str> = jenkinsfile
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("docker build"))
            .collect();
        assert_eq!(
            builds.len(),
            DOCKERFILES.len(),
            "one `docker build` per shipped image, no more and no fewer: {builds:?}"
        );
        for line in builds {
            assert!(
                line.contains(&format!("--platform={TARGET_PLATFORM}")),
                "`{line}` does not name --platform={TARGET_PLATFORM}, so the image it \
                 produces is stamped with whatever architecture the node happens to have"
            );
        }
    }

    #[test]
    fn every_builder_stage_compiles_on_the_machine_it_runs_on() {
        for file in DOCKERFILES {
            let text = read(file);
            let from = text
                .lines()
                .find(|l| l.trim_start().starts_with("FROM") && l.contains("AS build"))
                .unwrap_or_else(|| panic!("{file}: no builder stage"));
            assert!(
                from.contains("--platform=$BUILDPLATFORM"),
                "{file}: `{from}` would run the whole build under emulation on a node of \
                 another architecture, and rustc does not survive that"
            );
            assert!(
                text.contains(TARGET_TRIPLE),
                "{file}: builds no {TARGET_TRIPLE} binary, so the platform this gate \
                 requires of its image is not the platform of what is inside it"
            );
        }
    }
}

/// The fifth place the same invariant is written down, and the one an operator
/// reads out of `kubectl get`: what the rollout counters mean when nothing was
/// counted.
///
/// The shipped `deploy/controller/deployment.yaml` passes no `--cluster`, so
/// `plan_rollout` is handed an empty slice on every real install. While the
/// counters were plain `i32` that produced `clustersReady: 0` forever — the
/// zero value of a struct nobody filled, printed in the column an operator
/// reads to decide whether policy landed, and indistinguishable from a declared
/// fleet that is entirely stuck. Absent and zero now serialise differently, and
/// both halves of that are checked here rather than only in the crate that
/// computes them, because the claim spans three files: the manifest that
/// declares no fleet, the code that answers for one, and the CRD schema that
/// has to accept the answer.
mod rollout_accounting {
    use ferrum_api::RolloutStatus;
    use ferrum_controller::{compile_and_sign, plan_rollout, ClusterAbi};
    use ferrum_ids::{ADMISSION_ABI, AGENT_ABI};
    use ferrum_testkit::prod_restricted;
    use serde_yaml::Value;
    use std::path::{Path, PathBuf};

    /// RFC 8032 §7.1 test-1 seed: fixture only, not a prod key.
    const SK: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    fn repo_path(rel: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel)
    }

    /// Every `command:` and `args:` entry of every container in the controller
    /// Deployment.
    ///
    /// Both keys, in that order, the way `build_closure::collect_containers`
    /// reads them: either can carry a flag, and a reader that took only `args`
    /// would let a `--cluster` moved into `command` past the premise below
    /// while the `--status-dir` calibration still passed out of `args`.
    ///
    /// Flat across containers on purpose: the question is whether this manifest
    /// declares a fleet anywhere, and a `--cluster` on a sidecar would be a
    /// declaration this gate must not walk past.
    fn controller_argv() -> Vec<String> {
        let raw = std::fs::read_to_string(repo_path("deploy/controller/deployment.yaml"))
            .expect("controller deployment");
        let doc: Value = serde_yaml::from_str(&raw).expect("deployment yaml");
        let containers = doc
            .get("spec")
            .and_then(|s| s.get("template"))
            .and_then(|t| t.get("spec"))
            .and_then(|s| s.get("containers"))
            .and_then(Value::as_sequence)
            .expect("controller pod spec has containers");
        let mut argv = Vec::new();
        for container in containers {
            for key in ["command", "args"] {
                let Some(items) = container.get(key).and_then(Value::as_sequence) else {
                    continue;
                };
                argv.extend(
                    items
                        .iter()
                        .map(|item| item.as_str().expect("argv entries are strings").to_string()),
                );
            }
        }
        argv
    }

    /// `status.rollout.<name>` in **every** served version of `crd`, by version
    /// name.
    ///
    /// Not `versions[0]`. An operator uses the version they are served, so a
    /// second version that dropped `nullable` would be the one in the cluster
    /// while a reader stopping at the first still said the schema was right.
    fn rollout_properties(crd: &str, name: &str) -> Vec<(String, Value)> {
        let root: Value = serde_yaml::from_str(crd).expect("crd yaml");
        let versions = root
            .get("spec")
            .and_then(|s| s.get("versions"))
            .and_then(Value::as_sequence)
            .expect("crd serves versions");
        let out: Vec<(String, Value)> = versions
            .iter()
            .filter_map(|version| {
                let property = version
                    .get("schema")
                    .and_then(|s| s.get("openAPIV3Schema"))
                    .and_then(|s| s.get("properties"))
                    .and_then(|p| p.get("status"))
                    .and_then(|s| s.get("properties"))
                    .and_then(|p| p.get("rollout"))
                    .and_then(|r| r.get("properties"))
                    .and_then(|p| p.get(name))?;
                Some((
                    version
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("<unnamed>")
                        .to_string(),
                    property.clone(),
                ))
            })
            .collect();
        assert!(
            !out.is_empty(),
            "no served version declares status.rollout.{name}, so the assertions on it would \
             run over nothing"
        );
        out
    }

    #[test]
    fn the_shipped_controller_declares_no_fleet_so_its_rollout_counts_are_absent_not_zero() {
        let argv = controller_argv();
        assert!(
            !argv.is_empty(),
            "the controller container passes no args at all, so this gate read the wrong \
             manifest and its premise is decided by nothing"
        );
        assert!(
            argv.iter().any(|a| a == "--status-dir"),
            "the flag this reader is calibrated on is gone from {argv:?}"
        );
        let declared: Vec<&String> = argv
            .iter()
            .filter(|a| *a == "--cluster" || a.starts_with("--cluster="))
            .collect();
        assert!(
            declared.is_empty(),
            "deploy/controller/deployment.yaml now declares a fleet: {declared:?}. That is \
             the repair this branch was waiting for, not a break — but the rollout counters \
             stop being absent on a real install the day it lands, so rewrite the line in \
             docs/MVP-1-BOUNDARY.md that says they are, and delete this half of the gate."
        );

        // Given that premise, what the operator reads. `None` and `Some(0)` are
        // the two answers this gate exists to keep apart, so both are asserted
        // through the serialised form the API server actually receives.
        let bundle = compile_and_sign(&prod_restricted().spec, &SK).expect("sign");
        let nobody = plan_rollout(&bundle, None, &[]);
        assert_eq!(nobody.status, RolloutStatus::default());
        assert_eq!(
            serde_json::to_value(&nobody.status).expect("json"),
            serde_json::json!({ "clustersReady": null, "clustersDegraded": null }),
            "an uncounted rollout must travel as an explicit null: the status write is a \
             merge patch, and an omitted key leaves a stale count from an earlier version \
             standing forever"
        );

        let stuck = plan_rollout(
            &bundle,
            None,
            &[ClusterAbi {
                name: "current".into(),
                agent_abi: AGENT_ABI.saturating_sub(1),
                admission_abi: ADMISSION_ABI,
            }],
        );
        assert_eq!(
            serde_json::to_value(&stuck.status).expect("json"),
            serde_json::json!({ "clustersReady": 0, "clustersDegraded": 1 }),
            "a declared fleet that is entirely stuck is a counted zero and must keep saying \
             so; if this reports null the two states have collapsed again, the other way"
        );
    }

    #[test]
    fn both_rollout_counts_are_nullable_in_every_crd_that_carries_them() {
        for (kind, crd) in [
            ("ClusterSecurityPolicy", super::CRD_CLUSTER_SECURITY_POLICY),
            ("SecurityPolicy", super::CRD_SECURITY_POLICY),
        ] {
            for name in ["clustersReady", "clustersDegraded"] {
                for (version, property) in rollout_properties(crd, name) {
                    assert_eq!(
                        property.get("type").and_then(Value::as_str),
                        Some("integer"),
                        "{kind}/{version}.status.rollout.{name} is not an integer any more, so \
                         this gate is reading something else"
                    );
                    assert_eq!(
                        property.get("nullable").and_then(Value::as_bool),
                        Some(true),
                        "{kind}/{version}.status.rollout.{name} is not nullable, and the \
                         controller's own writes are not what needs it: those are JSON merge \
                         patches, where `null` is a delete directive that never reaches schema \
                         validation. What needs it is every other way this field is written — \
                         an update, a server-side apply, an operator's `kubectl apply` of a \
                         whole object — each of which sends `null` as a value a structural \
                         schema refuses unless it is nullable. Removing this line would not \
                         break the controller today, which is exactly why it has to be checked \
                         rather than left to be noticed."
                    );
                }
            }
        }
    }
}

/// Публичный воркфлоу Actions исполняет те же команды, что и одноимённые
/// стадии `Jenkinsfile`, и ни одной датапейсной.
///
/// Два CI, гоняющие похожее, — это два вердикта об одном дереве, и «зелено»
/// перестаёт что-либо значить в тот день, когда они расходятся. Расхождение
/// при этом не выглядит как поломка: воркфлоу остаётся зелёным, просто мерит
/// не то. Поэтому тела шагов сверяются побуквенно, а не «по духу», и сверка
/// живёт здесь, а не в ревью.
///
/// Вторая половина — про то, чего в воркфлоу быть не должно. Раннер
/// `ubuntu-latest` не даёт ни tracefs, ни `CAP_BPF`/`CAP_PERFMON`, ни писуемой
/// cgroup2; шаг с именем `BPF attach`, зелёный на такой машине, — гейт,
/// умеющий себя пропустить, и он опаснее отсутствующего, потому что читается
/// как исполненный.
///
/// Чего гейт не делает: он не утверждает, что воркфлоу хоть раз исполнялся на
/// GitHub. Как и `Jenkinsfile::<стадия>` в границе, он говорит только про
/// содержимое поставляемого файла.
mod actions_parity {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    /// Стадии `Jenkinsfile`, которые обязаны быть в публичном воркфлоу с тем
    /// же телом. Это ровно userspace: группа `Build` без `BPF ELF` и группа
    /// `Checks` целиком.
    const MIRRORED: [&str; 11] = [
        "Format",
        "Clippy",
        "Test",
        "Crate boundary",
        "Validate policies",
        "Security: policy invariants",
        "Security: MVP acceptance",
        "Security: metrics contract",
        "Security: admission latency",
        "Security: event contract",
        "Security: supply chain",
    ];

    /// Стадии, которых в публичном воркфлоу быть не может: первым шести нужно
    /// настоящее ядро, остальным — docker CLI ноды.
    const NOT_MIRRORED: [&str; 10] = [
        "BPF ELF",
        "BPF attach",
        "BPF join",
        "BPF join mutations",
        "Datapath tracefs",
        "Datapath cgroup",
        "Agent image",
        "Admission image",
        "Controller image",
        "SAST (semgrep)",
    ];

    /// Шаги воркфлоу, у которых стадии-близнеца в `Jenkinsfile` нет и не
    /// должно быть.
    ///
    /// Ровно один сюжет на сегодня: установка чарта в kind. Датапейс живёт на
    /// Jenkins, потому что раннеру не дают ядра; установка живёт здесь по
    /// зеркальной причине — на ноде Jenkins нет kind, и стадия там была бы
    /// либо всегда красной, либо под `when`, то есть тем самым гейтом, умеющим
    /// себя пропустить.
    ///
    /// Список нужен не ради этих трёх строк, а ради направления, которого до
    /// него не было: пока каждый шаг обязан быть либо зеркальным, либо
    /// названным здесь, шаг, тихо дописанный в один из двух CI, роняет гейт.
    /// Без этого расхождение двух CI видно только тому, кто читает оба файла
    /// рядом.
    const WORKFLOW_ONLY: [&str; 3] = ["Install: images", "Install: cluster", "Install: gate"];

    const WORKFLOW: &str = ".github/workflows/ci.yml";

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .canonicalize()
            .expect("workspace root")
    }

    fn read(rel: &str) -> String {
        let path = repo_root().join(rel);
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
    }

    /// Тело шелл-блока стадии, значащими строками.
    ///
    /// Отступ не сравнивается ни здесь, ни в воркфлоу: в Groovy он один, в
    /// блочном скаляре YAML другой, а шеллу он безразличен — heredoc в этих
    /// телах нет. Комментарии остаются: они и есть половина того, что должно
    /// доехать до второго CI.
    fn jenkins_stage_body(jenkinsfile: &str, stage: &str) -> Vec<String> {
        let head = format!("stage('{stage}')");
        let at = jenkinsfile
            .find(&head)
            .unwrap_or_else(|| panic!("Jenkinsfile has no {head}: the stage was renamed"));
        let rest = &jenkinsfile[at..];
        let quote = "'''";
        let opener = format!("sh {quote}");
        let open = rest
            .find(&opener)
            .unwrap_or_else(|| panic!("{head} carries no shell body"))
            + opener.len();
        let close = rest[open..]
            .find(quote)
            .unwrap_or_else(|| panic!("{head}: unterminated shell body"));
        significant(&rest[open..open + close])
    }

    fn significant(text: &str) -> Vec<String> {
        text.lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect()
    }

    /// Тело шага воркфлоу с этим именем, значащими строками.
    ///
    /// Скрипт кончается там, где кончается блочный скаляр YAML, — на первой
    /// значащей строке с отступом не больше, чем у `run:`. Не на следующем
    /// `- name:`: последний шаг джобы кончается её концом, и по такому правилу
    /// в него утекала бы вся следующая джоба.
    ///
    /// В результат попадает всё, что в скаляре есть. Именно всё: сравнение с
    /// телом стадии — на равенство, поэтому лишняя команда, дописанная в шаг,
    /// роняет гейт так же, как выпавшая.
    fn workflow_step_body(workflow: &str, name: &str) -> Vec<String> {
        let head = format!("- name: \"{name}\"");
        let lines: Vec<&str> = workflow.lines().collect();
        let at = lines
            .iter()
            .position(|line| line.trim() == head)
            .unwrap_or_else(|| panic!("{WORKFLOW} has no step {head}"));
        let run = lines.get(at + 1).copied().unwrap_or_default();
        assert_eq!(
            run.trim(),
            "run: |",
            "step {head}: the line after the name must be `run: |` — this gate reads the script \
             that follows it and nothing else"
        );
        let indent = |line: &str| line.len() - line.trim_start().len();
        let opened = indent(run);
        let script: Vec<&str> = lines[at + 2..]
            .iter()
            .copied()
            .take_while(|line| line.trim().is_empty() || indent(line) > opened)
            .collect();
        significant(&script.join("\n"))
    }

    #[test]
    fn every_mirrored_stage_runs_the_same_script_here_and_in_jenkins() {
        let jenkinsfile = read("Jenkinsfile");
        let workflow = read(WORKFLOW);
        for stage in MIRRORED {
            let expected = jenkins_stage_body(&jenkinsfile, stage);
            assert!(
                expected.len() > 1,
                "Jenkinsfile::{stage} has {} significant lines: this gate would compare almost \
                 nothing",
                expected.len()
            );
            let actual = workflow_step_body(&workflow, stage);
            assert_eq!(
                actual, expected,
                "{WORKFLOW} step {stage:?} and Jenkinsfile::{stage} run different scripts. Two \
                 CIs measuring different things return two verdicts about one tree, and the \
                 weaker one is the one that gets read. Change both or neither."
            );
        }
    }

    /// Контроль на сравнение: команда, изменённая в одном из двух файлов,
    /// обязана быть падением.
    ///
    /// Без него равенство выше проходило бы и на компараторе, который всегда
    /// говорит «совпало» — например, если бы разбор тела возвращал пустой
    /// список на любом входе.
    #[test]
    fn the_comparison_notices_a_script_that_drifted() {
        let jenkinsfile = read("Jenkinsfile");
        let workflow = read(WORKFLOW);
        let intact = jenkins_stage_body(&jenkinsfile, "Format");
        assert_eq!(intact, workflow_step_body(&workflow, "Format"));

        let softened = jenkinsfile.replace(
            "cargo fmt --all -- --check",
            "cargo fmt --all -- --check ; true",
        );
        assert_ne!(
            softened, jenkinsfile,
            "the line this control mutates is gone from the Jenkinsfile, so the control mutates \
             nothing"
        );
        assert_ne!(
            jenkins_stage_body(&softened, "Format"),
            intact,
            "a softened command in Jenkinsfile::Format read as the same body: the comparison \
             above cannot detect drift and proves nothing"
        );

        let dropped = jenkinsfile.replace("rustup component add rustfmt\n", "");
        assert_ne!(dropped, jenkinsfile);
        assert_ne!(
            jenkins_stage_body(&dropped, "Format"),
            intact,
            "a deleted command read as the same body"
        );
    }

    #[test]
    fn the_public_workflow_claims_no_stage_it_cannot_execute() {
        let jenkinsfile = read("Jenkinsfile");
        let workflow = read(WORKFLOW);
        for stage in NOT_MIRRORED {
            assert!(
                jenkinsfile.contains(&format!("stage('{stage}')")),
                "Jenkinsfile has no stage('{stage}'), so this list names something that no \
                 longer exists and the check below is about nothing"
            );
            assert!(
                !workflow.contains(&format!("- name: \"{stage}\"")),
                "{WORKFLOW} carries a step named {stage:?}. That stage needs a real kernel or \
                 the node's docker CLI; a green step of that name on a hosted runner is a gate \
                 that skipped itself and reads as one that ran."
            );
        }
    }

    /// Каждый шаг воркфлоу либо зеркалит стадию, либо назван таким, у которого
    /// близнеца нет.
    ///
    /// Обратное направление к `every_mirrored_stage_runs_the_same_script_here_and_in_jenkins`.
    /// Тот требует, чтобы названное совпадало, и ничего не говорит про шаг,
    /// которого в списке нет: до этой проверки в публичный CI можно было
    /// дописать что угодно, и два вердикта об одном дереве расходились бы
    /// молча — ровно то направление, в котором гниют документы этого
    /// репозитория.
    #[test]
    fn every_step_here_is_mirrored_or_named_as_workflow_only() {
        let workflow = read(WORKFLOW);
        let known: BTreeSet<&str> = MIRRORED.into_iter().chain(WORKFLOW_ONLY).collect();
        let mut seen = BTreeSet::new();
        for line in workflow.lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix("- name: \"") else {
                continue;
            };
            let name = rest.trim_end_matches('"');
            assert!(
                known.contains(name),
                "{WORKFLOW} has a step {name:?} that neither mirrors a \
                 Jenkinsfile stage nor is named in WORKFLOW_ONLY. A step that \
                 belongs to one CI and not the other is fine; a step nobody \
                 wrote down as belonging to one CI is how the two verdicts \
                 drift apart in silence."
            );
            seen.insert(name.to_string());
        }
        for name in WORKFLOW_ONLY {
            assert!(
                seen.contains(name),
                "WORKFLOW_ONLY names {name:?}, and {WORKFLOW} has no such step: \
                 the entry excuses nothing"
            );
        }
    }

    #[test]
    fn no_step_in_the_public_workflow_can_skip_itself() {
        let workflow = read(WORKFLOW);
        let softeners = ["continue-on-error", "if:"];
        for (number, line) in workflow.lines().enumerate() {
            let line = line.trim();
            // Комментарии воркфлоу называют эти конструкции затем, чтобы
            // сказать, что их здесь нет.
            if line.starts_with('#') {
                continue;
            }
            let number = number + 1;
            for softener in softeners {
                assert!(
                    !line.starts_with(softener),
                    "{WORKFLOW}:{number}: `{softener}` makes a red gate a green run — a step \
                     that can skip itself reports success for having done nothing"
                );
            }
            assert!(
                !line.contains("|| true"),
                "{WORKFLOW}:{number}: `|| true` swallows the exit code the whole stage is for"
            );
        }
    }
}

/// Поставка: что релизный воркфлоу публикует, чем подписывает и совпадает ли
/// это с тем, что дерево просит кластер скачать.
///
/// Продукт, который проверяет подпись bundle, а сам едет неподписанным,
/// требует от получателя ровно того доверия, от которого отучает. Файл
/// `.github/workflows/release.yml` закрывает эту половину; чего он не
/// закрывает — того, что запуск был, — не закрывает и этот модуль, и в границе
/// про него написано то же, что про `ci.yml`: поставленный файл не прогон.
///
/// Что здесь держится и почему именно это:
///
///  * **множество образов**. Три места называют образы — `deploy/**`,
///    `Jenkinsfile` и этот воркфлоу, — и расхождение любого из них тихое:
///    манифест, тянущий репозиторий, который релиз не публикует, — это
///    `ImagePullBackOff` у получателя и зелёный прогон у нас;
///  * **домены подписи**. `ferrum-crypto` подписывает bundle Ed25519-seed'ом в
///    контексте `BUNDLE_SIGNATURE_CONTEXT`. Образ подписывается эфемерным
///    ключом Fulcio. Общего ключа у них нет и быть не должно, а самый простой
///    способ его завести — вписать в релиз долгоживущий `--key`;
///  * **процедура проверки**. Инструкция получателю — часть поставки, и
///    расходится она молча: команда, называющая идентичность, которой Fulcio не
///    выпишет, не пройдёт ни у кого, а красным от этого не станет ничего.
mod release_supply_chain {
    use serde_yaml::Value;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    const WORKFLOW: &str = ".github/workflows/release.yml";
    const README: &str = "README.md";

    /// Раздел README, который описывает процедуру получателю.
    const DELIVERY_HEADING: &str = "## Поставка";

    /// Издатель OIDC-токена, под который Fulcio выписывает сертификат
    /// GitHub-воркфлоу. Единственное его значение для Actions; получатель обязан
    /// называть именно его, иначе проверка примет подпись кого угодно с любым
    /// другим провайдером.
    const ISSUER: &str = "https://token.actions.githubusercontent.com";

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .canonicalize()
            .expect("workspace root")
    }

    fn read(rel: &str) -> String {
        let path = repo_root().join(rel);
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
    }

    fn workflow() -> Value {
        serde_yaml::from_str(&read(WORKFLOW)).expect("release workflow is not valid YAML")
    }

    fn job<'a>(workflow: &'a Value, name: &str) -> &'a Value {
        workflow
            .get("jobs")
            .and_then(|jobs| jobs.get(name))
            .unwrap_or_else(|| panic!("{WORKFLOW} has no job {name:?}"))
    }

    /// Тело `run` шага, чьё имя начинается с `prefix`.
    ///
    /// По префиксу, а не по равенству: имя шага несёт `${{ matrix.crate }}`, и
    /// сравнение с полным именем читало бы шаблон, а не имя.
    fn step_script(job: &Value, prefix: &str) -> String {
        let steps = job
            .get("steps")
            .and_then(Value::as_sequence)
            .unwrap_or_else(|| panic!("{WORKFLOW}: a job has no steps"));
        let mut found: Vec<String> = steps
            .iter()
            .filter(|step| {
                step.get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name.starts_with(prefix))
            })
            .filter_map(|step| step.get("run").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        assert_eq!(
            found.len(),
            1,
            "{WORKFLOW}: expected exactly one step whose name starts with {prefix:?} and carries \
             a script; found {}",
            found.len()
        );
        found.remove(0)
    }

    /// Репозитории образов, которые публикует релиз.
    ///
    /// Собираются из двух половин файла, а не из одной строки: имя строится в
    /// скрипте (`image="<префикс>${{ matrix.crate }}"`), а перебирается
    /// матрицей. Читать только матрицу значило бы не заметить смену префикса,
    /// читать только скрипт — не заметить исчезнувший образ.
    fn published_repos() -> BTreeSet<String> {
        let workflow = workflow();
        let publish = job(&workflow, "publish");
        let script = step_script(publish, "Publish ");
        assert!(
            script.contains(r#"docker push "$image:$tag""#),
            "{WORKFLOW}: the publish step no longer pushes `$image:$tag`, so nothing below can \
             say what this release puts in a registry"
        );
        let marker = "image=";
        let line = script
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with(marker))
            .unwrap_or_else(|| panic!("{WORKFLOW}: the publish step assigns no `image=`"));
        let prefix = line
            .trim_start_matches(marker)
            .trim_matches('"')
            .strip_suffix("${{ matrix.crate }}")
            .unwrap_or_else(|| {
                panic!(
                    "{WORKFLOW}: `image=` is {line:?}; this gate reads a fixed prefix followed by \
                     the matrix crate, and a name built any other way cannot be compared with \
                     deploy/**"
                )
            })
            .to_string();

        let entries = publish
            .get("strategy")
            .and_then(|strategy| strategy.get("matrix"))
            .and_then(|matrix| matrix.get("include"))
            .and_then(Value::as_sequence)
            .unwrap_or_else(|| panic!("{WORKFLOW}: the publish job has no matrix include"));
        let repos: BTreeSet<String> = entries
            .iter()
            .map(|entry| {
                let name = entry
                    .get("crate")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("{WORKFLOW}: a matrix entry names no crate"));
                format!("{prefix}{name}")
            })
            .collect();
        assert!(
            !repos.is_empty(),
            "{WORKFLOW}: the publish matrix is empty, so this gate sees nothing published and \
             every comparison below is satisfied by finding nothing"
        );
        repos
    }

    fn yaml_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap_or_else(|err| panic!("{}: {err}", dir.display()))
        {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                yaml_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "yaml") {
                out.push(path);
            }
        }
    }

    fn collect_images(node: &Value, out: &mut Vec<String>) {
        match node {
            Value::Mapping(map) => {
                if let Some(Value::String(image)) = map.get(Value::from("image")) {
                    out.push(image.clone());
                }
                for (_, value) in map.iter() {
                    collect_images(value, out);
                }
            }
            Value::Sequence(items) => items.iter().for_each(|item| collect_images(item, out)),
            _ => {}
        }
    }

    /// `repo:tag` из каждого контейнера в `deploy/`, как манифест его пишет.
    fn deploy_images() -> Vec<String> {
        let root = repo_root();
        let mut files = Vec::new();
        yaml_files(&root.join("deploy"), &mut files);
        files.sort();
        let mut out = Vec::new();
        for path in files {
            let raw = std::fs::read_to_string(&path).expect("manifest");
            for document in raw.split("\n---") {
                let Ok(value) = serde_yaml::from_str::<Value>(document) else {
                    continue;
                };
                collect_images(&value, &mut out);
            }
        }
        assert!(
            !out.is_empty(),
            "no container under deploy/ names an image, so this gate cannot see what the cluster \
             is asked to pull and proves nothing"
        );
        out
    }

    fn repo_of(reference: &str) -> String {
        let last = reference.rfind('/').map_or(0, |i| i + 1);
        match reference[last..].find(':') {
            Some(colon) => reference[..last + colon].to_string(),
            None => reference.to_string(),
        }
    }

    fn tag_of(reference: &str) -> String {
        reference[repo_of(reference).len()..]
            .trim_start_matches(':')
            .to_string()
    }

    /// Репозитории, которые собирает `Jenkinsfile`, по строкам `-t`.
    fn jenkins_repos() -> BTreeSet<String> {
        let jenkinsfile = read("Jenkinsfile");
        let out: BTreeSet<String> = jenkinsfile
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .filter_map(|line| line.split("-t \"").nth(1))
            // До закрывающей кавычки, и только то, что вообще может быть
            // ссылкой на образ: `-t` встречается в этом файле и у `nsenter`,
            // где за ним стоит pid.
            .filter_map(|rest| rest.split('"').next())
            .filter(|reference| reference.contains('/') && reference.contains(':'))
            .map(repo_of)
            .collect();
        assert!(
            !out.is_empty(),
            "no `docker build -t \"…\"` in the Jenkinsfile: this gate cannot see what the \
             pipeline produces and proves nothing"
        );
        out
    }

    /// Три места называют образ, и все три обязаны называть один и тот же.
    ///
    /// Не подмножество, а равенство. Образ, который релиз публикует, а манифест
    /// не ставит, — тег, который никто не тянет; образ, который манифест
    /// ставит, а релиз не публикует, — `ImagePullBackOff` у получателя, зелёный
    /// прогон у нас и молчание с обеих сторон.
    #[test]
    fn the_release_publishes_exactly_the_images_this_tree_installs() {
        let published = published_repos();
        let installed: BTreeSet<String> = deploy_images().iter().map(|i| repo_of(i)).collect();
        let built = jenkins_repos();
        assert_eq!(
            published, installed,
            "the images the release publishes and the images deploy/** installs are different \
             sets. One of them is a reference nobody can resolve."
        );
        assert_eq!(
            published, built,
            "the images the release publishes and the images the Jenkinsfile builds are \
             different sets: two pipelines producing two different products out of one tree"
        );
    }

    /// Тег, который закрепляют манифесты, — тот, который релиз способен
    /// выпустить.
    ///
    /// Это вторая половина замыкания образов, и раньше она была открыта по
    /// причине, которой больше нет: ничто в дереве не публиковало, поэтому тег,
    /// придуманный CI, жил в локальном сторе одного узла, а сравнивать его с
    /// закреплённым в манифесте было не с чем. Теперь публикует релизный
    /// воркфлоу, и публикует он имя git-тега, — значит вопрос «может ли этот
    /// манифест вообще разрешиться» стал проверяемым.
    ///
    /// Чего этот тест по-прежнему **не** утверждает: что образ опубликован.
    /// Воркфлоу в дереве — не запуск, ровно как `Jenkinsfile::<стадия>` в
    /// границе не значит «зелено в CI». Здесь проверяется, что закреплённый тег
    /// принадлежит множеству, которое релиз выпускает, а не что кто-то нажал
    /// кнопку.
    ///
    /// `Jenkinsfile` при этом по-прежнему не публикует, и это отдельная
    /// посылка: его `dev-$BUILD_NUMBER` — имена, живущие в локальном сторе
    /// ноды, и манифест, закреплённый на таком имени, был бы дефектом, а не
    /// починкой.
    #[test]
    fn the_tag_the_manifests_pin_is_one_the_release_can_publish() {
        let jenkinsfile = read("Jenkinsfile");
        assert!(
            !jenkinsfile.contains("docker push") && !jenkinsfile.contains("docker image push"),
            "a Jenkins stage now publishes an image. Its tags are `dev-$BUILD_NUMBER`, which no \
             manifest can pin without being rewritten every build; if publication has moved \
             there, the manifests and this gate have to move with it."
        );

        let workflow = workflow();
        let triggers = workflow
            .as_mapping()
            .expect("workflow mapping")
            .iter()
            // `on` — булев литерал YAML 1.1, и разные парсеры дают разный ключ.
            // Ключ ищется по написанию, а не по типу.
            .find(|(key, _)| matches!(key, Value::Bool(true)) || key.as_str() == Some("on"))
            .map(|(_, value)| value)
            .unwrap_or_else(|| panic!("{WORKFLOW} declares no `on:`"));
        let patterns: Vec<String> = triggers
            .get("push")
            .and_then(|push| push.get("tags"))
            .and_then(Value::as_sequence)
            .unwrap_or_else(|| panic!("{WORKFLOW} is not triggered by a tag push"))
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        assert!(
            !patterns.is_empty(),
            "{WORKFLOW}: the tag filter is empty, so this gate matches nothing and passes for it"
        );

        let script = step_script(job(&workflow, "publish"), "Publish ");
        assert!(
            script.contains(r#"tag="$GITHUB_REF_NAME""#),
            "{WORKFLOW}: the publish step no longer tags with the git tag that triggered it. A \
             tag the run invents is one no manifest can pin, which is the state this gate was \
             written to leave."
        );

        for image in deploy_images() {
            let tag = tag_of(&image);
            assert!(
                !tag.is_empty() && tag != "latest",
                "{image} names a floating tag on the plane that decides admission: `latest` is \
                 whatever was pushed last"
            );
            assert!(
                patterns.iter().any(|pattern| tag_matches(pattern, &tag)),
                "{image} pins the tag {tag:?}, and no trigger of {WORKFLOW} ({patterns:?}) \
                 publishes it. The manifest asks the cluster for something this repository has \
                 no way of producing."
            );
        }
    }

    /// Глоб-фильтр тегов GitHub Actions, в том объёме, который здесь нужен:
    /// `*` — любая последовательность без `/`, `[…]` — класс символов, `+`
    /// после класса — один символ класса или больше, всё прочее — литерал.
    ///
    /// Свой, а не regex-crate: `ferrum-testkit` не заводит зависимость ради
    /// одного сравнения, объём замкнут, а сам сопоставитель проверен
    /// `the_tag_filter_reader_accepts_and_refuses_the_right_tags`.
    fn tag_matches(pattern: &str, tag: &str) -> bool {
        fn in_class(class: &[u8], c: u8) -> bool {
            let mut i = 0;
            while i < class.len() {
                if i + 2 < class.len() && class[i + 1] == b'-' {
                    if c >= class[i] && c <= class[i + 2] {
                        return true;
                    }
                    i += 3;
                } else {
                    if class[i] == c {
                        return true;
                    }
                    i += 1;
                }
            }
            false
        }
        fn go(pattern: &[u8], tag: &[u8]) -> bool {
            let Some(head) = pattern.first().copied() else {
                return tag.is_empty();
            };
            match head {
                b'*' => (0..=tag.len()).any(|take| {
                    tag[..take].iter().all(|c| *c != b'/') && go(&pattern[1..], &tag[take..])
                }),
                b'[' => {
                    let Some(close) = pattern.iter().position(|c| *c == b']') else {
                        return false;
                    };
                    let class = &pattern[1..close];
                    let mut rest = &pattern[close + 1..];
                    let mut most = 1;
                    if rest.first() == Some(&b'+') {
                        rest = &rest[1..];
                        most = tag.len();
                    }
                    (1..=most).any(|take| {
                        take <= tag.len()
                            && tag[..take].iter().all(|c| in_class(class, *c))
                            && go(rest, &tag[take..])
                    })
                }
                literal => tag.first() == Some(&literal) && go(&pattern[1..], &tag[1..]),
            }
        }
        go(pattern.as_bytes(), tag.as_bytes())
    }

    /// Читатель фильтра — на входах, ответ на которых известен.
    ///
    /// Без него «тег манифеста публикуется релизом» одинаково верно и для
    /// сопоставителя, который говорит «да» на всё, а ровно такой получается из
    /// опечатки в разборе класса.
    #[test]
    fn the_tag_filter_reader_accepts_and_refuses_the_right_tags() {
        let semver = "v[0-9]+.[0-9]+.[0-9]+";
        assert!(tag_matches(semver, "v0.1.0"));
        assert!(tag_matches(semver, "v12.30.4"));
        assert!(!tag_matches(semver, "v0.1"));
        assert!(!tag_matches(semver, "0.1.0"));
        assert!(!tag_matches(semver, "v0.1.0-rc1"));
        assert!(!tag_matches(semver, "latest"));
        assert!(tag_matches("v*", "v0.1.0"));
        assert!(!tag_matches("v*", "w0.1.0"));
        assert!(!tag_matches("v*", "v0.1/0"));
    }

    /// Каждый опубликованный образ подписан, и подпись стоит на digest.
    ///
    /// Подпись по тегу — это подпись под тем, что по этому тегу лежало в момент
    /// подписи. Тег переставляется, и назавтра проверка проходит на другом
    /// образе; digest — единственное имя, которое этого не умеет.
    ///
    /// SBOM здесь же и по той же причине: файл, приложенный к релизу, связан с
    /// образом только словом того, кто его приложил. `cosign attest`
    /// подписывает предикат той же идентичностью и цепляет его к digest, и
    /// только эта половина проверяема на стороне получателя.
    #[test]
    fn every_published_image_is_signed_and_carries_an_attested_sbom() {
        let workflow = workflow();
        let script = step_script(job(&workflow, "publish"), "Publish ");
        for required in [
            r#"digest="$(docker inspect --format '{{index .RepoDigests 0}}' "$image:$tag")""#,
            r#"cosign sign --yes "$digest""#,
            r#"syft "$digest" -o "spdx-json=$sbom""#,
            r#"cosign attest --yes --type spdxjson --predicate "$sbom" "$digest""#,
        ] {
            assert!(
                script.contains(required),
                "{WORKFLOW}: the publish step does not run `{required}`. An image published \
                 without it is one the consumer cannot tell from any other image wearing the \
                 same tag."
            );
        }
        for line in script.lines().map(str::trim) {
            if line.starts_with('#') {
                continue;
            }
            for command in ["cosign sign", "cosign attest", "cosign verify", "syft "] {
                assert!(
                    !(line.starts_with(command) && line.contains("$image:$tag")),
                    "{WORKFLOW}: `{line}` names the image by tag. A tag is repointable, so the \
                     signature would outlive the bytes it was made over."
                );
            }
        }

        // Релиз несёт SBOM каждого образа, а не какого-нибудь. Проверяется
        // числом, потому что «загрузили что нашли» — это ровно тот отказ,
        // который выглядит успехом.
        let count = job(&workflow, "publish")
            .get("strategy")
            .and_then(|strategy| strategy.get("matrix"))
            .and_then(|matrix| matrix.get("include"))
            .and_then(Value::as_sequence)
            .expect("matrix include")
            .len();
        let release = step_script(job(&workflow, "release"), "Attach SBOMs");
        assert!(
            release.contains(&format!(r#"if [ "$count" -ne {count} ]; then"#)),
            "{WORKFLOW}: the release step does not require exactly {count} SBOMs — one per \
             published image. A release carrying two of three says nothing about the third, and \
             nothing there would go red."
        );
    }

    /// Подпись образа не берёт ключ ниоткуда, и в частности не берёт его у
    /// подписи bundle.
    ///
    /// Домены разные по построению: bundle подписывается Ed25519-seed'ом в
    /// контексте `BUNDLE_SIGNATURE_CONTEXT` и живёт в Secret кластера, образ —
    /// эфемерным ключом Fulcio, выданным на один запуск под OIDC. Единственный
    /// способ их смешать — завести в релизе долгоживущий ключ, поэтому здесь
    /// проверяется отсутствие всякого `--key` и всякого имени, которым в этом
    /// дереве зовут ключевой материал bundle.
    ///
    /// Отсутствие само по себе доказывает мало: его же даёт опечатка в списке.
    /// Поэтому вторая половина — положительный контроль: `id-token: write`
    /// обязан стоять (без него keyless не существует), а имена доменов обязаны
    /// быть настоящими именами из `ferrum-crypto`.
    #[test]
    fn the_release_signs_keyless_and_never_touches_the_bundle_signing_domain() {
        let workflow = workflow();
        let permissions = job(&workflow, "publish")
            .get("permissions")
            .and_then(Value::as_mapping)
            .unwrap_or_else(|| panic!("{WORKFLOW}: the publish job declares no permissions"));
        for (key, expected) in [("id-token", "write"), ("packages", "write")] {
            assert_eq!(
                permissions.get(Value::from(key)).and_then(Value::as_str),
                Some(expected),
                "{WORKFLOW}: the publish job needs `{key}: {expected}` — without id-token there \
                 is no OIDC token for Fulcio and no keyless signature at all"
            );
        }

        for (source, domain) in [
            (
                "crates/ferrum-crypto/src/lib.rs",
                "BUNDLE_SIGNATURE_CONTEXT",
            ),
            ("crates/ferrum-crypto/src/mtls.rs", "KEY_BIND_MSG"),
        ] {
            assert!(
                read(source).contains(domain),
                "{source} no longer names {domain}, so the check below forbids a string that \
                 means nothing and proves nothing"
            );
        }

        let text = read(WORKFLOW);
        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            // Комментарии файла называют эти вещи затем, чтобы сказать, что их
            // здесь нет.
            if line.starts_with('#') {
                continue;
            }
            let number = number + 1;
            for forbidden in [
                "COSIGN_PRIVATE_KEY",
                "COSIGN_PASSWORD",
                "cosign generate-key-pair",
                "--key ",
                "--seed-file",
                "BUNDLE_SIGNATURE_CONTEXT",
                "KEY_BIND_MSG",
                "ferrumctl sign",
            ] {
                assert!(
                    !line.contains(forbidden),
                    "{WORKFLOW}:{number}: `{forbidden}`. The image domain signs with an \
                     ephemeral Fulcio key that dies with the job; a long-lived key here is a \
                     secret to store, rotate and lose, and if it is the bundle's, the key a \
                     cluster trusts for policy is a key that lives in CI."
                );
            }
        }
    }

    /// Ни один шаг релиза не может себя пропустить.
    ///
    /// Тот же запрет, что у публичного CI, и здесь он строже по последствиям:
    /// шаг подписи, пропустивший себя, оставляет в ghcr неподписанный образ под
    /// зелёным значком — ровно то, что получатель прочтёт как подписанное.
    #[test]
    fn no_step_in_the_release_workflow_can_skip_itself() {
        let text = read(WORKFLOW);
        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let number = number + 1;
            for softener in ["continue-on-error", "if:"] {
                assert!(
                    !line.starts_with(softener),
                    "{WORKFLOW}:{number}: `{softener}` makes a red gate a green run"
                );
            }
            assert!(
                !line.contains("|| true"),
                "{WORKFLOW}:{number}: `|| true` swallows the exit code the step is for"
            );
        }
    }

    /// Инструкция получателю — та же процедура, которую релиз исполняет на
    /// себе.
    ///
    /// Инструкция расходится с воркфлоу молча: `cosign verify` с
    /// идентичностью, которой Fulcio не выпишет, не проходит ни у кого, и
    /// красным от этого не становится ничего. Поэтому идентичность в README
    /// собирается здесь из пути файла воркфлоу и сверяется на равенство: файл
    /// переименован — строка в README стала ложью, и это падение, а не вопрос
    /// прилежания автора строки.
    #[test]
    fn the_documented_verification_is_the_one_the_release_performs() {
        let readme = read(README);
        let at = readme
            .find(DELIVERY_HEADING)
            .unwrap_or_else(|| panic!("{README} has no {DELIVERY_HEADING:?} section"));
        let section = &readme[at..];
        let section = match section[DELIVERY_HEADING.len()..].find("\n## ") {
            Some(end) => &section[..DELIVERY_HEADING.len() + end],
            None => section,
        };

        let identity = format!("https://github.com/onixus/Ferrum/{WORKFLOW}@refs/tags/$TAG");
        assert!(
            section.contains(&identity),
            "{README} § {DELIVERY_HEADING} does not tell the consumer to verify against \
             {identity:?}. That string is the subject Fulcio puts in the certificate for this \
             workflow; any other one either fails for everybody or accepts a signature made by \
             something else."
        );
        assert!(
            section.contains(ISSUER),
            "{README} § {DELIVERY_HEADING} names no OIDC issuer. Without \
             --certificate-oidc-issuer the identity above can be asserted by any provider."
        );
        for command in [
            "cosign verify",
            "cosign verify-attestation --type spdxjson",
            "cargo audit bin",
        ] {
            assert!(
                section.contains(command),
                "{README} § {DELIVERY_HEADING} does not document `{command}`, which is half of \
                 what the release produces: a signature nobody is told to check is not delivery"
            );
        }

        // Тег в инструкции — тот, который закреплён в манифестах. Иначе
        // получатель проверяет один образ, а ставит другой.
        let pinned: BTreeSet<String> = deploy_images().iter().map(|i| tag_of(i)).collect();
        assert_eq!(
            pinned.len(),
            1,
            "deploy/** pins more than one tag ({pinned:?}); the README procedure names one"
        );
        let pinned = pinned.into_iter().next().expect("one tag");
        assert!(
            section.contains(&format!("TAG={pinned}")),
            "{README} § {DELIVERY_HEADING} does not set TAG={pinned}, the tag deploy/** pins. A \
             procedure verifying one tag while the manifests install another checks an image the \
             cluster will not run."
        );
        for repo in published_repos() {
            assert!(
                section.contains(&repo),
                "{README} § {DELIVERY_HEADING} says nothing about {repo}, which the release \
                 publishes. An image with no documented verification ships unverified."
            );
        }
    }

    /// Бинарь в каждом образе несёт список своих зависимостей.
    ///
    /// Образ на `scratch` — это один статический ELF, и SBOM по нему без
    /// `cargo-auditable` перечисляет ровно ничего: syft видит файл и не видит
    /// ни одного crate. Такой SBOM хуже отсутствующего — он приложен к релизу и
    /// читается как ответ на вопрос «что внутри».
    ///
    /// Обе половины: линкует `cargo auditable build`, и получившийся бинарь
    /// проверен на секцию `.dep-v0` в том же Dockerfile. Первая — намерение,
    /// вторая — результат, и без второй тихо проходит любая сборка, из которой
    /// инструмент выпал.
    #[test]
    fn every_shipped_binary_carries_the_dependency_list_its_sbom_is_made_of() {
        for (dockerfile, binary) in [
            ("Dockerfile", "ferrum-agent"),
            ("Dockerfile.admission", "ferrum-admission"),
            ("Dockerfile.controller", "ferrum-controller"),
        ] {
            let text = read(dockerfile);
            assert!(
                text.contains("cargo auditable build --release --locked"),
                "{dockerfile} links with plain `cargo build`: the binary it ships carries no \
                 dependency list, and the SBOM of the image would list no crate at all"
            );
            assert!(
                !text.contains("    cargo build --release --locked"),
                "{dockerfile} still carries a plain `cargo build --release --locked` line; the \
                 binary that reaches the image must be the auditable one"
            );
            assert!(
                text.contains(&format!("readelf -SW /{binary} | grep -q '\\.dep-v0'")),
                "{dockerfile} does not check /{binary} for the .dep-v0 section. The cargo line \
                 above is an intention; this is the only place the result is visible."
            );
            assert!(
                text.contains(
                    "cargo install --locked \"cargo-auditable@${CARGO_AUDITABLE_VERSION}\""
                ),
                "{dockerfile} installs cargo-auditable without a pinned version, in a file whose \
                 whole subject is provenance"
            );
        }
    }
}

/// Первый релиз: версия, тег и файлы, которые про них говорят.
///
/// `release_supply_chain` выше держит подпись и происхождение образа — то, что
/// получатель проверяет, уже имея артефакт. Здесь другая половина: артефакта
/// ещё нет, и единственное, что может разойтись до его появления, — четыре
/// написания одной и той же версии. Она стоит в `[workspace.package]`, в теге,
/// который ставит человек, в фильтре триггера `release.yml` и в `image:`
/// каждого манифеста `deploy/**`. Три из четырёх лежат в дереве, четвёртое
/// выводится из первого по правилу `v` + версия, и разъехаться они могут молча:
/// `cargo` не читает `deploy/**`, `deploy/**` не читает `Cargo.toml`, а фильтр
/// тега не читает ни того, ни другого. Разъехавшись, они дают ровно тот отказ,
/// от которого написан `every_image_a_manifest_names_is_built_by_the_pipeline`,
/// — `ImagePullBackOff` на плоскости, решающей admission, — только теперь не по
/// имени образа, а по его тегу.
///
/// Ни один тест здесь не утверждает, что релиз состоялся. Тега `v0.1.0` в этом
/// репозитории нет, и гейт, читающий дерево, узнать о нём не может: он читает
/// файлы, а не `git tag` и не реестр.
mod first_release {
    use std::path::{Path, PathBuf};

    const README: &str = "README.md";
    const SECURITY: &str = "SECURITY.md";
    const MANIFEST: &str = "Cargo.toml";
    const WORKFLOW: &str = ".github/workflows/release.yml";

    /// Приватный канал GitHub, единственный, который у этого репозитория есть.
    const ADVISORY_URL: &str = "https://github.com/onixus/Ferrum/security/advisories/new";

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .canonicalize()
            .expect("workspace root")
    }

    fn read(rel: &str) -> String {
        let path = repo_root().join(rel);
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
    }

    /// Версия из `[workspace.package]` корневого манифеста.
    ///
    /// Читается именно эта секция, а не первое `version =` в файле: в
    /// `[workspace.dependencies]` их два десятка, и `version` любого из них
    /// прошёл бы вместо версии продукта.
    fn workspace_version() -> String {
        let manifest = read(MANIFEST);
        let mut in_section = false;
        for line in manifest.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                in_section = line == "[workspace.package]";
                continue;
            }
            if !in_section {
                continue;
            }
            if let Some(rest) = line.strip_prefix("version") {
                let value = rest
                    .trim_start()
                    .strip_prefix('=')
                    .unwrap_or_else(|| {
                        panic!("{MANIFEST}: [workspace.package] version line is {line:?}")
                    })
                    .trim()
                    .trim_matches('"');
                assert!(
                    !value.is_empty(),
                    "{MANIFEST}: [workspace.package] declares an empty version"
                );
                return value.to_string();
            }
        }
        panic!(
            "{MANIFEST} has no version in [workspace.package]. Every crate here inherits its \
             version from there; without it there is no single version this tree carries, and \
             nothing below can be compared with a tag."
        );
    }

    /// Имя git-тега, которым выпускается эта версия.
    fn release_tag() -> String {
        format!("v{}", workspace_version())
    }

    /// Манифесты crate вместе с именами их каталогов, отсортированные, чтобы
    /// сообщение об ошибке не плавало от прогона к прогону.
    fn crate_manifests() -> Vec<(String, String)> {
        let crates = repo_root().join("crates");
        let mut dirs: Vec<PathBuf> = std::fs::read_dir(&crates)
            .expect("crates/")
            .map(|entry| entry.expect("directory entry").path())
            .filter(|path| path.join(MANIFEST).is_file())
            .collect();
        dirs.sort();
        let out: Vec<(String, String)> = dirs
            .iter()
            .map(|dir| {
                let name = dir
                    .file_name()
                    .expect("crate directory name")
                    .to_string_lossy()
                    .to_string();
                let text = std::fs::read_to_string(dir.join(MANIFEST))
                    .unwrap_or_else(|err| panic!("{}/{MANIFEST}: {err}", dir.display()));
                (name, text)
            })
            .collect();
        assert!(
            !out.is_empty(),
            "no crate manifest was found under crates/, so this gate sees no version at all and \
             every comparison below is satisfied by finding nothing"
        );
        out
    }

    /// Все `image:` под `deploy/`, вместе с файлом, который их называет.
    ///
    /// Свой обход, а не `release_supply_chain::deploy_images`: там путь до файла
    /// теряется, а сообщение «версия разъехалась» без имени файла заставляет
    /// искать его руками по четырём манифестам.
    fn deploy_image_references() -> Vec<(String, String)> {
        let root = repo_root();
        let mut files = Vec::new();
        collect_yaml(&root.join("deploy"), &mut files);
        files.sort();
        let mut out = Vec::new();
        for path in files {
            let raw = std::fs::read_to_string(&path).expect("manifest");
            let shown = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            for line in raw.lines() {
                let trimmed = line.trim();
                let Some(rest) = trimmed.strip_prefix("image:") else {
                    continue;
                };
                let image = rest.trim().trim_matches('"').trim_matches('\'');
                if image.is_empty() {
                    continue;
                }
                out.push((shown.clone(), image.to_string()));
            }
        }
        out
    }

    fn collect_yaml(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap_or_else(|err| panic!("{}: {err}", dir.display()))
        {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                collect_yaml(&path, out);
            } else if path.extension().is_some_and(|e| e == "yaml") {
                out.push(path);
            }
        }
    }

    /// Одна версия на дерево, и она — та, которую называет тег.
    ///
    /// Тег ставит человек, а не воркфлоу, поэтому вывести его из файла нельзя;
    /// вывести можно правило, по которому он строится, и проверить, что все
    /// написания версии в дереве этому правилу отвечают. `deploy/**` закрепляет
    /// `v0.1.0`, `[workspace.package]` несёт `0.1.0`, и разница между ними —
    /// одна буква, которую до этого теста не проверял никто.
    ///
    /// `release_supply_chain::the_tag_the_manifests_pin_is_one_the_release_can_publish`
    /// проверяет другое и меньшее: что закреплённый тег вообще попадает в фильтр
    /// триггера. Под `v9.9.9` в манифестах он проходит — фильтр такой тег
    /// пропускает, — а собрано из этого дерева будет `0.1.0`.
    #[test]
    fn the_version_this_workspace_carries_is_the_tag_its_manifests_pin() {
        let tag = release_tag();
        let readme = read(README);
        assert!(
            readme.contains(&tag),
            "{README} never names {tag}, the tag this tree's version produces. The section \
             describing the first release has to name the version it releases, or it describes \
             some other one."
        );

        let mut seen = 0usize;
        for (path, image) in deploy_image_references() {
            let Some(colon) = image.rfind(':') else {
                panic!(
                    "{path} names the image {image:?} with no tag at all: the cluster would be \
                     asked for `latest`, which is whatever was pushed last"
                );
            };
            let (repo, pinned) = image.split_at(colon);
            let pinned = &pinned[1..];
            if !repo.starts_with("ghcr.io/onixus/") {
                continue;
            }
            seen += 1;
            assert_eq!(
                pinned,
                tag,
                "{path} pins {image:?}, but this workspace carries version {} and releases it as \
                 {tag}. One of the two was bumped without the other, and the cluster would be \
                 asked for an image no tag of this repository produces.",
                workspace_version()
            );
        }
        assert!(
            seen > 0,
            "no manifest under deploy/ names an image in ghcr.io/onixus/, so this gate compared \
             nothing and passed for it"
        );
    }

    /// Ни один crate не объявляет собственную версию.
    ///
    /// Тег один, а версий было бы восемнадцать. Crate, отставший на своей
    /// строке, поедет в образ под тегом, который называет чужую версию, и
    /// узнать об этом можно будет только развернув образ: `cargo` на такое
    /// расхождение не жалуется — своя версия у члена workspace совершенно
    /// законна.
    #[test]
    fn every_crate_takes_its_version_from_the_workspace() {
        for (name, manifest) in crate_manifests() {
            let mut in_package = false;
            let mut declared: Option<String> = None;
            for line in manifest.lines() {
                let line = line.trim();
                if line.starts_with('[') {
                    in_package = line == "[package]";
                    continue;
                }
                if !in_package {
                    continue;
                }
                if line.starts_with("version.workspace") {
                    declared = Some(String::new());
                    break;
                }
                if line.starts_with("version") {
                    declared = Some(line.to_string());
                    break;
                }
            }
            match declared {
                Some(line) if line.is_empty() => {}
                Some(line) => panic!(
                    "crates/{name}/{MANIFEST} declares its own version ({line}). This tree \
                     releases one tag for all of them; a crate carrying a different number ships \
                     inside an image whose tag says otherwise, and nothing but this test looks."
                ),
                None => panic!(
                    "crates/{name}/{MANIFEST} declares no version in [package] at all, so what \
                     the tag {} names for this crate is undefined",
                    release_tag()
                ),
            }
        }
    }

    /// Раздел про первый релиз называет каждый образ, который релиз публикует.
    ///
    /// Иначе появившийся четвёртый образ выйдет под тем же тегом и не будет
    /// назван нигде, кроме воркфлоу: получатель, читающий README, проверит три
    /// подписи из четырёх и решит, что проверил всё.
    #[test]
    fn the_first_release_section_names_every_image_that_release_publishes() {
        let readme = read(README);
        let heading = "### Первый релиз";
        let start = readme.find(heading).unwrap_or_else(|| {
            panic!(
                "{README} has no {heading:?} section. What a tag produces would then be named \
                 nowhere but the workflow file, which is not where a recipient looks."
            )
        });
        let section = &readme[start..];
        let end = section[heading.len()..]
            .find("\n## ")
            .map_or(section.len(), |offset| offset + heading.len());
        let section = &section[..end];

        let workflow = read(WORKFLOW);
        let mut crates: Vec<&str> = workflow
            .lines()
            .filter_map(|line| line.trim().strip_prefix("- crate: "))
            .map(str::trim)
            .collect();
        crates.sort();
        assert!(
            !crates.is_empty(),
            "{WORKFLOW} publishes no image this gate can see, so the section was compared \
             against nothing"
        );
        for name in crates {
            assert!(
                section.contains(name),
                "{README}: the first-release section does not name {name:?}, which {WORKFLOW} \
                 publishes under this tag. A release describing fewer artefacts than it produces \
                 teaches the recipient to verify fewer."
            );
        }
    }

    /// SECURITY.md называет канал, который у этого репозитория есть, и не
    /// заводит ни одного, которого нет.
    ///
    /// Выдуманный канал раскрытия хуже отсутствующего: адрес, который никто не
    /// читает, и отпечаток, которого нет ни у одного ключа, превращают
    /// сообщение об обходе enforcement в письмо в никуда, а отправитель считает
    /// себя сообщившим. Поэтому проверяются обе стороны: приватный advisory
    /// назван, а почты и PGP в файле нет вовсе.
    #[test]
    fn the_security_policy_names_a_channel_this_repository_actually_has() {
        let text = read(SECURITY);
        assert!(
            text.contains(ADVISORY_URL),
            "{SECURITY} does not name {ADVISORY_URL}. GitHub private vulnerability reporting is \
             the only confidential channel this repository has; a policy without it sends the \
             reporter to a public issue."
        );

        assert!(
            !text.contains("BEGIN PGP"),
            "{SECURITY} carries a PGP block. This project publishes no key; a block here is a \
             key nobody holds, and everything encrypted to it is lost."
        );
        for (index, line) in text.lines().enumerate() {
            let number = index + 1;
            if let Some(word) = line.split_whitespace().find(|word| {
                let word = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
                word.len() == 40 && word.chars().all(|c| c.is_ascii_hexdigit())
            }) {
                panic!(
                    "{SECURITY}:{number}: {word:?} reads as a key fingerprint. This project has \
                     no key and no fingerprint to publish, and one written here would be a trust \
                     anchor nothing in this tree can back."
                );
            }
            if let Some(word) = line.split_whitespace().find(|word| {
                let word = word.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '@');
                match word.split_once('@') {
                    Some((user, host)) => {
                        !user.is_empty() && host.contains('.') && !host.ends_with('.')
                    }
                    None => false,
                }
            }) {
                panic!(
                    "{SECURITY}:{number}: {word:?} reads as an e-mail address. No mailbox for \
                     this project is confirmed, and a reporting address nobody reads is worse \
                     than none: the reporter believes they have reported."
                );
            }
        }
    }

    /// SECURITY.md поддерживает ту версию, которую это дерево несёт.
    ///
    /// Политика, называющая поддерживаемой линию, которой в дереве нет, — это
    /// занижение и завышение сразу: сообщивший против `main` не знает, примут ли
    /// его, а сообщивший против несуществующей `0.2.x` считает себя покрытым.
    #[test]
    fn the_security_policy_supports_the_version_this_tree_carries() {
        let text = read(SECURITY);
        let version = workspace_version();
        let (major, rest) = version
            .split_once('.')
            .unwrap_or_else(|| panic!("{MANIFEST}: version {version:?} has no minor component"));
        let minor = rest.split('.').next().expect("minor component");
        let line = format!("{major}.{minor}.x");
        assert!(
            text.contains(&line),
            "{SECURITY} says nothing about {line}, the line this tree builds. A reporter cannot \
             tell whether the version they are running is one this project answers for."
        );
        assert!(
            text.contains("main"),
            "{SECURITY} does not say whether `main` is supported. Until the first tag exists it \
             is the only thing anybody can be running."
        );
    }
}

/// Устанавливаемость, читающая текст — и говорящая об этом вслух.
///
/// `install_gate.rs` ставит `deploy` в настоящий apiserver и ждёт, пока
/// workload'ы поднимутся; вот там утверждение про установку. Здесь — только
/// про файлы, и разница ровно та, на которой прошлый цикл поймал это дерево:
/// два CRD из семи проходили каждый читающий текст гейт и отвергались
/// apiserver целиком. Поэтому ни один тест ниже не называется
/// «устанавливается».
///
/// Чего эта половина всё-таки не даёт сделать:
///
///  * забыть манифест. Файл в `deploy/`, который не ставит ни один корень и не
///    назван исключением с причиной, — это объект, который получатель не
///    применит и о котором ничего не покраснеет;
///  * унаследовать respond. `optional-respond.yaml` меняет DaemonSet на тот,
///    что несёт `hostPID` и `CAP_KILL`; попасть он должен ровно одним способом
///    — руками набранным `kubectl apply -f`;
///  * применить нерендеренный вебхук. В шаблоне стоит
///    `caBundle: REPLACE_WITH_PEM_CA_BUNDLE_BASE64`, а `failurePolicy: Fail`
///    начинает отказывать в Pod'ах в момент появления объекта: установка,
///    затянувшая его за собой, — это отказ всему кластеру;
///  * подменить умолчания на удобные. Значения по умолчанию — это то, что
///    ставится одной командой, и держатся они здесь, а не в values-файле,
///    которого нет.
mod kustomize_roots {
    use serde::Deserialize;
    use serde_yaml::Value;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    const KUSTOMIZATION: &str = "kustomization.yaml";
    /// Корень, который ставит `kubectl apply -k deploy`.
    const DEFAULT_INSTALL: &str = "deploy";
    /// Корень агента: отдельный, и `deploy/README` объясняет почему.
    const AGENT_INSTALL: &str = "deploy/agent";
    const CRD_INSTALL: &str = "docs/crd";
    const MIRRORED_OVERLAY: &str = "overlays/mirrored-registry";
    const POLICY: &str = "policies/examples/prod-restricted.yaml";

    /// Манифесты `deploy/`, которые не ставит ни один корень, и причина у
    /// каждого.
    ///
    /// Список, а не прозаический комментарий: файл может выпасть из установки
    /// по недосмотру, и единственная разница между недосмотром и решением —
    /// написанная причина. Короткая строка причины ниже — падение.
    const NOT_INSTALLED_BY_ANY_ROOT: [(&str, &str); 2] = [
        (
            "deploy/admission/validatingwebhookconfiguration.tmpl.yaml",
            "шаблон, а не манифест: в нём стоит \
             `caBundle: REPLACE_WITH_PEM_CA_BUNDLE_BASE64`, и CA, который его \
             заменит, не существует, пока не отработал `ferrumctl \
             gen-webhook-pki`. Применённый как есть, он ставит вебхук, до \
             которого apiserver не дозвонится, а с `failurePolicy: Fail` это \
             отказ в каждом Pod'е вне ferrum/kube-system. Отрендеренный файл \
             применяется руками и последним — deploy/admission/README, шаг 3",
        ),
        (
            "deploy/agent/optional-respond.yaml",
            "не часть базовой установки по построению: этот файл заменяет \
             DaemonSet на тот, что несёт hostPID и CAP_KILL, то есть \
             превращает kill из записанного решения в действие. Такое \
             включается набранным `kubectl apply -f`, а не наследуется из \
             overlay, который кто-то однажды выбрал",
        ),
    ];

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .canonicalize()
            .expect("workspace root")
    }

    fn read_yaml(path: &Path) -> Value {
        let text =
            std::fs::read_to_string(path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
        serde_yaml::from_str(&text).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
    }

    /// Путь относительно корня репозитория, слэшами и без `./`.
    fn rel(path: &Path) -> String {
        path.strip_prefix(repo_root())
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/")
    }

    /// Корень kustomize: то, что в нём написано, без интерпретации.
    struct Root {
        dir: PathBuf,
        doc: Value,
    }

    impl Root {
        fn open(rel_dir: &str) -> Root {
            let dir = repo_root().join(rel_dir);
            let file = dir.join(KUSTOMIZATION);
            assert!(
                file.is_file(),
                "{rel_dir} is not a kustomization root: no {KUSTOMIZATION} in it"
            );
            Root {
                doc: read_yaml(&file),
                dir,
            }
        }

        fn strings(&self, key: &str) -> Vec<String> {
            self.doc
                .get(key)
                .and_then(Value::as_sequence)
                .map(|seq| {
                    seq.iter()
                        .map(|v| {
                            v.as_str()
                                .unwrap_or_else(|| {
                                    panic!(
                                        "{}/{KUSTOMIZATION}: {key} holds a non-string",
                                        rel(&self.dir)
                                    )
                                })
                                .to_string()
                        })
                        .collect()
                })
                .unwrap_or_default()
        }

        fn keys(&self) -> BTreeSet<String> {
            self.doc
                .as_mapping()
                .expect("kustomization is a mapping")
                .keys()
                .map(|k| k.as_str().unwrap_or_default().to_string())
                .collect()
        }
    }

    /// Всё, что корень в итоге ставит: файлы манифестов, разрешённые
    /// рекурсивно через вложенные корни.
    ///
    /// Разрешение, а не чтение одного файла: `deploy/kustomization.yaml` не
    /// называет ни одного манифеста напрямую, и гейт, читающий только его,
    /// не увидел бы ничего.
    fn installed_files(rel_dir: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let mut seen = BTreeSet::new();
        collect(rel_dir, &mut out, &mut seen);
        out
    }

    fn collect(rel_dir: &str, out: &mut BTreeSet<String>, seen: &mut BTreeSet<String>) {
        if !seen.insert(rel_dir.to_string()) {
            return;
        }
        let root = Root::open(rel_dir);
        for entry in root.strings("resources") {
            let path = root
                .dir
                .join(&entry)
                .canonicalize()
                .unwrap_or_else(|err| panic!("{rel_dir}: resource {entry:?}: {err}"));
            if path.is_dir() {
                collect(&rel(&path), out, seen);
            } else {
                assert!(
                    out.insert(rel(&path)),
                    "{rel_dir}: {entry:?} is installed twice by this root"
                );
            }
        }
    }

    /// Каждый корень kustomize в дереве. Найденные, а не перечисленные: корень,
    /// добавленный и не вписанный сюда, — ровно то, что проверки ниже должны
    /// увидеть.
    fn every_root() -> Vec<String> {
        let mut out = Vec::new();
        walk(&repo_root(), &mut |path: &Path| {
            if path.file_name().and_then(|n| n.to_str()) == Some(KUSTOMIZATION) {
                out.push(rel(path.parent().expect("file has a parent")));
            }
        });
        out.sort();
        assert!(
            out.len() >= 4,
            "found {} kustomization roots; this tree has at least four \
             (deploy, deploy/agent, docs/crd, overlays/mirrored-registry) and \
             the walk that found fewer is reading the wrong directory",
            out.len()
        );
        out
    }

    fn walk(dir: &Path, visit: &mut impl FnMut(&Path)) {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') || name == "target" {
                continue;
            }
            if path.is_dir() {
                walk(&path, visit);
            } else {
                visit(&path);
            }
        }
    }

    fn yaml_files_under(rel_dir: &str) -> Vec<String> {
        let mut out = Vec::new();
        walk(&repo_root().join(rel_dir), &mut |path: &Path| {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if name == KUSTOMIZATION {
                return;
            }
            if name.ends_with(".yaml") || name.ends_with(".yml") {
                out.push(rel(path));
            }
        });
        out.sort();
        out
    }

    /// Документы одного файла: манифесты этого дерева многодокументные.
    fn documents(rel_path: &str) -> Vec<Value> {
        let path = repo_root().join(rel_path);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{rel_path}: {err}"));
        serde_yaml::Deserializer::from_str(&text)
            .map(|doc| Value::deserialize(doc).unwrap_or_else(|err| panic!("{rel_path}: {err}")))
            .filter(|doc| !doc.is_null())
            .collect()
    }

    /// Все объекты, которые ставит корень.
    fn installed_objects(rel_dir: &str) -> Vec<(String, Value)> {
        installed_files(rel_dir)
            .into_iter()
            .flat_map(|file| {
                documents(&file)
                    .into_iter()
                    .map(move |doc| (file.clone(), doc))
            })
            .collect()
    }

    fn pod_specs(objects: &[(String, Value)]) -> Vec<(String, &Value)> {
        objects
            .iter()
            .filter_map(|(file, doc)| {
                doc.get("spec")
                    .and_then(|s| s.get("template"))
                    .and_then(|t| t.get("spec"))
                    .map(|spec| (file.clone(), spec))
            })
            .collect()
    }

    fn containers(pod: &Value) -> Vec<&Value> {
        pod.get("containers")
            .and_then(Value::as_sequence)
            .map(|s| s.iter().collect())
            .unwrap_or_default()
    }

    /// Реестр из ссылки на образ: всё до первого `/`.
    fn registry_of(reference: &str) -> String {
        reference
            .split('/')
            .next()
            .expect("split yields one element")
            .to_string()
    }

    /// Ссылка без тега и без digest.
    fn repo_of(reference: &str) -> String {
        let without_digest = reference.split('@').next().unwrap_or(reference);
        match without_digest.rsplit_once(':') {
            Some((repo, _)) => repo.to_string(),
            None => without_digest.to_string(),
        }
    }

    fn images_installed_by(rel_dir: &str) -> BTreeSet<String> {
        let objects = installed_objects(rel_dir);
        let mut out = BTreeSet::new();
        for (_, pod) in pod_specs(&objects) {
            for container in containers(pod) {
                if let Some(image) = container.get("image").and_then(Value::as_str) {
                    out.insert(image.to_string());
                }
            }
        }
        out
    }

    /// Каждый манифест `deploy/` ставится ровно одним корнем — или назван
    /// неустанавливаемым, с причиной.
    ///
    /// Направление, в котором дерево гниёт молча: манифест добавляют, корень
    /// не трогают, `kubectl apply -k deploy` его не ставит, и не краснеет
    /// ничего — получатель просто не получает объект. Обратное направление
    /// (корень называет несуществующий файл) ловит сам kustomize, и оно
    /// шумное.
    #[test]
    fn every_manifest_in_the_deploy_tree_is_installed_by_a_root_or_excused() {
        let installed: BTreeSet<String> = installed_files(DEFAULT_INSTALL)
            .into_iter()
            .chain(installed_files(AGENT_INSTALL))
            .collect();
        let excused: BTreeMap<&str, &str> = NOT_INSTALLED_BY_ANY_ROOT.into_iter().collect();

        for (file, reason) in &excused {
            assert!(
                repo_root().join(file).is_file(),
                "{file} is excused from every kustomization root, and it does not \
                 exist: the entry is about nothing"
            );
            assert!(
                reason.len() > 40,
                "{file} is excused by {reason:?}, which is not a reason"
            );
            assert!(
                !installed.contains(*file),
                "{file} is both installed by a kustomization root and listed as \
                 not installed by any. If it became installable, delete the \
                 entry; if it did not, delete the resource."
            );
        }

        for file in yaml_files_under(DEFAULT_INSTALL) {
            assert!(
                installed.contains(&file) || excused.contains_key(file.as_str()),
                "{file} is a manifest no kustomization root installs and no entry \
                 in NOT_INSTALLED_BY_ANY_ROOT excuses. `kubectl apply -k deploy` \
                 does not deliver it, and nothing in this tree would go red for \
                 that — the receiver simply would not have the object."
            );
        }
    }

    /// Корень CRD ставит каждый CRD, который это дерево поставляет.
    ///
    /// Не три, которые смотрит контроллер, и не «те, что вспомнили». Не
    /// установленный CRD — это тип, которого apiserver не знает: объект,
    /// который оператор пишет, отвергается как неизвестный, и ни в одном файле
    /// нет строки о том, что тип оставили снаружи намеренно.
    #[test]
    fn the_crd_kustomization_installs_every_crd_this_repository_ships() {
        let shipped: BTreeSet<String> = yaml_files_under(CRD_INSTALL).into_iter().collect();
        let installed = installed_files(CRD_INSTALL);
        assert!(
            shipped.len() >= 7,
            "found {} CRD files under {CRD_INSTALL}; the catalogue has seven, so \
             this walk is reading the wrong directory",
            shipped.len()
        );
        assert_eq!(
            installed, shipped,
            "{CRD_INSTALL}/{KUSTOMIZATION} and the files beside it disagree. A CRD \
             this repository ships and this root does not install is a type the \
             API server never learns."
        );
    }

    /// Ни один корень не тянет respond и ни один не тянет нерендеренный вебхук.
    ///
    /// Проверяется по всем корням дерева, а не по двум ожидаемым: смысл в том,
    /// что этих двух файлов нельзя получить *никак*, кроме набранного руками
    /// `kubectl apply -f`. Корень, добавленный завтра, попадает сюда сам.
    ///
    /// Плюс запрет на `secretGenerator`: seed подписи и serving-ключ — не
    /// манифесты, и генератор для них либо кладёт ключ в git, либо выпускает
    /// новый на каждый apply.
    #[test]
    fn no_kustomization_root_installs_the_respond_variant_or_the_unrendered_webhook() {
        for root in every_root() {
            let installed = installed_files(&root);
            for (file, _) in NOT_INSTALLED_BY_ANY_ROOT {
                assert!(
                    !installed.contains(file),
                    "kustomization root {root} installs {file}. \
                     `optional-respond.yaml` hands the agent hostPID and \
                     CAP_KILL, and the webhook template hands the API server a \
                     caBundle placeholder under failurePolicy: Fail. Neither may \
                     arrive as a consequence of choosing an overlay."
                );
            }
            let keys = Root::open(&root).keys();
            for forbidden in ["secretGenerator", "helmCharts"] {
                assert!(
                    !keys.contains(forbidden),
                    "kustomization root {root} carries `{forbidden}`. A generated \
                     Secret is either a key in git or a new key on every apply, \
                     and a chart pulled at install time is the supply chain this \
                     product exists to refuse."
                );
            }
        }
    }

    /// Умолчания — restricted, а не удобные.
    ///
    /// «Значения по умолчанию» здесь буквально то, что ставится одной командой:
    /// values-файла нет, и второй копии этой позиции тоже. Каждое утверждение
    /// ниже — про объекты, которые вернул разбор корня `deploy`, а не про
    /// конкретный файл, так что послабление, приехавшее новым манифестом,
    /// падает здесь так же, как правка старого.
    #[test]
    fn the_default_install_is_the_restricted_one() {
        let objects = installed_objects(DEFAULT_INSTALL);
        let pods = pod_specs(&objects);
        assert_eq!(
            pods.len(),
            2,
            "the default install has {} workloads; it is supposed to be exactly \
             two — the controller and the webhook. A third one appearing here \
             has to be argued for, and the agent is not it (deploy/README says \
             why it is a root of its own).",
            pods.len()
        );

        for (file, pod) in &pods {
            for field in ["hostPID", "hostIPC", "hostNetwork"] {
                assert!(
                    pod.get(field).is_none(),
                    "{file}: the default install sets {field}. \
                     `policies/examples/prod-restricted.yaml` denies all three \
                     (`admit.deny`), so this install would be refused by the \
                     policy it ships with."
                );
            }
            let security = pod
                .get("securityContext")
                .unwrap_or_else(|| panic!("{file}: workload has no pod securityContext"));
            assert_eq!(
                security.get("runAsNonRoot").and_then(Value::as_bool),
                Some(true),
                "{file}: the default install does not require runAsNonRoot"
            );
            assert_eq!(
                security
                    .get("seccompProfile")
                    .and_then(|p| p.get("type"))
                    .and_then(Value::as_str),
                Some("RuntimeDefault"),
                "{file}: the default install does not set the RuntimeDefault \
                 seccomp profile"
            );

            let containers = containers(pod);
            assert!(!containers.is_empty(), "{file}: workload has no containers");
            for container in containers {
                let name = container
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("<unnamed>");
                let sc = container
                    .get("securityContext")
                    .unwrap_or_else(|| panic!("{file}: container {name} has no securityContext"));
                assert_eq!(
                    sc.get("readOnlyRootFilesystem").and_then(Value::as_bool),
                    Some(true),
                    "{file}: container {name} has a writable root filesystem in \
                     the default install"
                );
                assert_eq!(
                    sc.get("allowPrivilegeEscalation").and_then(Value::as_bool),
                    Some(false),
                    "{file}: container {name} allows privilege escalation in the \
                     default install"
                );
                assert_ne!(
                    sc.get("privileged").and_then(Value::as_bool),
                    Some(true),
                    "{file}: container {name} is privileged in the default install"
                );
                let dropped: BTreeSet<&str> = sc
                    .get("capabilities")
                    .and_then(|c| c.get("drop"))
                    .and_then(Value::as_sequence)
                    .map(|s| s.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                assert!(
                    dropped.contains("ALL"),
                    "{file}: container {name} does not drop ALL capabilities"
                );
                let added: BTreeSet<&str> = sc
                    .get("capabilities")
                    .and_then(|c| c.get("add"))
                    .and_then(Value::as_sequence)
                    .map(|s| s.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                assert!(
                    added.is_empty(),
                    "{file}: container {name} adds {added:?} in the default \
                     install. The control plane needs no capability at all; the \
                     one component that does (the agent, BPF and PERFMON) is a \
                     root of its own."
                );

                let args: Vec<&str> = container
                    .get("args")
                    .and_then(Value::as_sequence)
                    .map(|s| s.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                if let Some(at) = args.iter().position(|a| *a == "--policy-name") {
                    assert_eq!(
                        args.get(at + 1),
                        Some(&"prod-restricted"),
                        "{file}: container {name} is installed against a policy \
                         that is not prod-restricted"
                    );
                }
            }
        }

        // Один экземпляр вебхука под failurePolicy=Fail — это отказ всему
        // кластеру при первом же вытеснении, а не «менее доступно».
        let replicas = objects
            .iter()
            .find(|(_, doc)| {
                doc.get("kind").and_then(Value::as_str) == Some("Deployment")
                    && doc
                        .get("metadata")
                        .and_then(|m| m.get("name"))
                        .and_then(Value::as_str)
                        == Some("ferrum-admission")
            })
            .and_then(|(_, doc)| doc.get("spec"))
            .and_then(|spec| spec.get("replicas"))
            .and_then(Value::as_u64)
            .expect("the default install carries a ferrum-admission Deployment");
        assert!(
            replicas >= 2,
            "the default install runs {replicas} webhook replica(s) under \
             failurePolicy=Fail: a single eviction is then a cluster-wide outage"
        );

        // Respond не только не ставится файлом — его identity не связана.
        for (file, doc) in &objects {
            if doc.get("kind").and_then(Value::as_str) == Some("ClusterRoleBinding") {
                let name = doc
                    .get("metadata")
                    .and_then(|m| m.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                assert_ne!(
                    name, "ferrum-agent-respond",
                    "{file}: the default install binds the respond ServiceAccount"
                );
            }
        }
    }

    /// Overlay для зеркала меняет имена образов и больше ничего.
    ///
    /// Overlay, который «заодно» правит что-то ещё, — это вторая копия
    /// установки, расходящаяся с первой молча: гейты этого дерева читают
    /// `deploy/**`, и то, что дописано в overlay, не читает ни один.
    #[test]
    fn the_mirrored_overlay_changes_image_names_and_nothing_else() {
        let overlay = Root::open(MIRRORED_OVERLAY);
        assert_eq!(
            overlay.keys(),
            ["apiVersion", "images", "kind", "resources"]
                .into_iter()
                .map(str::to_string)
                .collect::<BTreeSet<String>>(),
            "{MIRRORED_OVERLAY}/{KUSTOMIZATION} carries a key beyond the image \
             rewrite. Anything else here is a second copy of the install that no \
             gate in this tree reads."
        );
        assert_eq!(
            overlay.strings("resources"),
            vec![format!("../../{DEFAULT_INSTALL}")],
            "{MIRRORED_OVERLAY} is an overlay over something other than the \
             default install"
        );

        let entries = overlay
            .doc
            .get("images")
            .and_then(Value::as_sequence)
            .expect("the overlay carries an images list");
        let mut rewritten = BTreeSet::new();
        for entry in entries {
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .expect("image entry names an image");
            assert!(
                entry.get("newName").and_then(Value::as_str).is_some(),
                "{MIRRORED_OVERLAY}: entry for {name} rewrites no registry"
            );
            for forbidden in ["newTag", "digest"] {
                assert!(
                    entry.get(forbidden).is_none(),
                    "{MIRRORED_OVERLAY}: entry for {name} sets `{forbidden}`. The \
                     tag is pinned once, in the manifests, and joined to the \
                     release that can publish it by \
                     `the_tag_the_manifests_pin_is_one_the_release_can_publish`. \
                     A second pin here is a second thing to forget."
                );
            }
            rewritten.insert(name.to_string());
        }

        let installed: BTreeSet<String> = images_installed_by(DEFAULT_INSTALL)
            .iter()
            .map(|image| repo_of(image))
            .collect();
        assert_eq!(
            rewritten, installed,
            "{MIRRORED_OVERLAY} rewrites a different set of images than the \
             default install pulls. An entry matching nothing is silently \
             ignored by kustomize, so an image left out of this list is an image \
             that goes on being pulled from the internet in a contour that has \
             none."
        );
    }

    /// Overlay переносит установку в тот реестр, который разрешает
    /// поставляемая политика — а база стоит вне него.
    ///
    /// Обе половины утверждения нужны. Без первой overlay мог бы указывать
    /// куда угодно; без второй он был бы декорацией — если бы база уже стояла
    /// в разрешённом реестре, переносить было бы нечего, и незамеченным
    /// осталось бы то, что установка по умолчанию тянет образы из интернета.
    #[test]
    fn the_mirrored_overlay_moves_the_install_into_the_registry_the_shipped_policy_allows() {
        let policy = documents(POLICY);
        let allowed: BTreeSet<String> = policy
            .first()
            .and_then(|doc| doc.get("spec"))
            .and_then(|spec| spec.get("selector"))
            .and_then(|sel| sel.get("image"))
            .and_then(|img| img.get("registriesAllow"))
            .and_then(Value::as_sequence)
            .map(|seq| {
                seq.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .expect("prod-restricted names the registries it allows");
        assert!(
            !allowed.is_empty(),
            "{POLICY} allows no registry at all, so nothing below is a comparison"
        );

        for image in images_installed_by(DEFAULT_INSTALL) {
            assert!(
                !allowed.contains(&registry_of(&image)),
                "the default install pulls {image}, which {POLICY} already \
                 allows. That would make {MIRRORED_OVERLAY} decoration — it \
                 exists because the shipped install comes from the internet and \
                 the shipped policy does not permit that registry."
            );
        }

        let overlay = Root::open(MIRRORED_OVERLAY);
        let entries = overlay
            .doc
            .get("images")
            .and_then(Value::as_sequence)
            .expect("the overlay carries an images list");
        for entry in entries {
            let new_name = entry
                .get("newName")
                .and_then(Value::as_str)
                .expect("entry rewrites a registry");
            assert!(
                allowed.contains(&registry_of(new_name)),
                "{MIRRORED_OVERLAY} rewrites an image to {new_name}, whose \
                 registry {POLICY} does not allow. The overlay's whole job is to \
                 make the install and the policy agree."
            );
        }
    }
}

/// Вебхук с `failurePolicy: Fail` — единственная точка отказа кластера, и
/// доступность здесь свойство поставляемых манифестов, а не эксплуатации.
///
/// Что читает этот модуль: реплик больше одной, вытеснение не может забрать
/// обе, реплики предпочитают разные узлы, а исключение из-под вебхука решается
/// меткой, которую namespace не может выдать себе сам. Каждое из четырёх — то,
/// чего нет в коде и нельзя проверить прогоном: это текст, который применит
/// оператор.
mod high_availability {
    use serde_yaml::Value;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    const DEPLOYMENT: &str = "deploy/admission/deployment.yaml";
    const PDB: &str = "deploy/admission/pdb.yaml";
    const WEBHOOK_TMPL: &str = "deploy/admission/validatingwebhookconfiguration.tmpl.yaml";
    const ADMISSION_ROOT: &str = "deploy/admission/kustomization.yaml";
    /// Метка, по которой Deployment собирает свои Pod'ы. Всё в этом модуле —
    /// про то, что PDB и anti-affinity говорят о тех же Pod'ах.
    const APP_LABEL: &str = "app.kubernetes.io/name";
    const APP_NAME: &str = "ferrum-admission";
    /// Ключ, который apiserver проставляет и контролирует на каждом namespace
    /// с 1.21. Единственный, по которому исключение не может быть выдано
    /// самому себе.
    const OWNED_LABEL: &str = "kubernetes.io/metadata.name";

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .canonicalize()
            .expect("workspace root")
    }

    fn read(rel: &str) -> Value {
        let path = repo_root().join(rel);
        let text =
            std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
        serde_yaml::from_str(&text).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
    }

    fn pod_spec(deployment: &Value) -> &Value {
        deployment
            .get("spec")
            .and_then(|s| s.get("template"))
            .and_then(|t| t.get("spec"))
            .expect("the webhook Deployment carries a pod template")
    }

    /// Реплик больше одной, и вытеснение не может забрать их все разом.
    ///
    /// Две половины, и по отдельности каждая бесполезна. Две реплики без
    /// бюджета — это две реплики, которые `kubectl drain` одного узла снимает
    /// одной командой, а с `failurePolicy: Fail` пауза между «сняли» и
    /// «поднялись» — это отказ в создании Pod'ов по всему кластеру. Бюджет без
    /// второй реплики — это запрет на любое вытеснение вообще: drain повисает
    /// навсегда, и обновление узлов кластера останавливается на этом объекте.
    /// Поэтому число реплик и число из бюджета читаются вместе, а не порознь.
    #[test]
    fn the_webhook_is_a_pair_that_a_drain_cannot_take_at_once() {
        let deployment = read(DEPLOYMENT);
        let replicas = deployment
            .get("spec")
            .and_then(|s| s.get("replicas"))
            .and_then(Value::as_u64)
            .expect("the webhook Deployment states its replica count");
        assert!(
            replicas >= 2,
            "{DEPLOYMENT} runs {replicas} replica(s) under failurePolicy=Fail: одно вытеснение — \
             отказ всему кластеру"
        );

        let pdb = read(PDB);
        assert_eq!(
            pdb.get("kind").and_then(Value::as_str),
            Some("PodDisruptionBudget"),
            "{PDB} is not a PodDisruptionBudget"
        );
        assert_eq!(
            pdb.get("metadata")
                .and_then(|m| m.get("namespace"))
                .and_then(Value::as_str),
            deployment
                .get("metadata")
                .and_then(|m| m.get("namespace"))
                .and_then(Value::as_str),
            "{PDB} is in a different namespace from {DEPLOYMENT}, so it governs no Pod of it"
        );

        // Селектор бюджета обязан выбирать те Pod'ы, что поднимает Deployment.
        // Бюджет с чужим селектором — объект, который применяется, ничего не
        // защищает и читается как защита.
        let selector = pdb
            .get("spec")
            .and_then(|s| s.get("selector"))
            .and_then(|s| s.get("matchLabels"))
            .and_then(Value::as_mapping)
            .expect("{PDB} selects Pods by matchLabels");
        let template_labels = deployment
            .get("spec")
            .and_then(|s| s.get("template"))
            .and_then(|t| t.get("metadata"))
            .and_then(|m| m.get("labels"))
            .and_then(Value::as_mapping)
            .expect("the pod template carries labels");
        for (key, want) in selector {
            assert_eq!(
                template_labels.get(key),
                Some(want),
                "{PDB} selects on {key:?}={want:?}, which the Pods {DEPLOYMENT} creates do not \
                 carry: the budget governs nothing"
            );
        }
        assert_eq!(
            selector.get(Value::from(APP_LABEL)),
            Some(&Value::from(APP_NAME)),
            "{PDB} does not select the webhook by {APP_LABEL}"
        );

        let spec = pdb.get("spec").expect("pdb spec");
        let max_unavailable = spec.get("maxUnavailable").and_then(Value::as_u64);
        let min_available = spec.get("minAvailable").and_then(Value::as_u64);
        match (max_unavailable, min_available) {
            (Some(max), None) => {
                assert!(
                    max >= 1,
                    "{PDB} allows {max} unavailable: every voluntary eviction is refused, and a \
                     node drain hangs on this object forever"
                );
                assert!(
                    max < replicas,
                    "{PDB} allows {max} of {replicas} replicas unavailable at once, which is all \
                     of them: the budget permits exactly the outage it exists to prevent"
                );
            }
            (None, Some(min)) => {
                assert!(
                    min >= 1,
                    "{PDB} requires {min} available, so a drain may take every replica"
                );
                assert!(
                    min < replicas,
                    "{PDB} requires {min} of {replicas} available: no eviction is ever permitted \
                     and a node drain hangs on this object forever"
                );
            }
            _ => panic!(
                "{PDB} states neither exactly one of maxUnavailable and minAvailable; the API \
                 rejects both together and decides nothing with neither"
            ),
        }

        // И бюджет обязан ставиться тем же корнем, что и Deployment: правило,
        // приезжающее отдельным apply, — правило, которого нет у половины
        // установок.
        let root = read(ADMISSION_ROOT);
        let resources: BTreeSet<String> = root
            .get("resources")
            .and_then(Value::as_sequence)
            .expect("the admission root lists resources")
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        assert!(
            resources.contains("pdb.yaml") && resources.contains("deployment.yaml"),
            "{ADMISSION_ROOT} installs {resources:?}: the budget and the Deployment it governs \
             must arrive together"
        );
    }

    /// Реплики предпочитают разные узлы, и предпочтение не умеет оставить одну
    /// висеть.
    ///
    /// Бюджет выше — про добровольные вытеснения; узел, который умер, никого не
    /// спрашивает, и против этого работает только anti-affinity. Но требование
    /// `required` на одноузловом кластере оставляет вторую реплику в Pending
    /// навсегда — а именно одноузловой кластер поднимает `install_gate.rs` и
    /// публичный воркфлоу, то есть поставлялась бы установка, не поднимающаяся
    /// на том кластере, которым её же и проверяют. Поэтому здесь проверяется
    /// обратное обычному: правило есть **и** оно мягкое.
    #[test]
    fn the_two_replicas_prefer_different_nodes_and_the_preference_cannot_strand_one() {
        let deployment = read(DEPLOYMENT);
        let anti = pod_spec(&deployment)
            .get("affinity")
            .and_then(|a| a.get("podAntiAffinity"))
            .expect(
                "the webhook Deployment declares no podAntiAffinity: two replicas the scheduler \
                 is free to put on one node are two replicas one node failure takes",
            );
        assert!(
            anti.get("requiredDuringSchedulingIgnoredDuringExecution")
                .is_none(),
            "{DEPLOYMENT} requires anti-affinity. On a single-node cluster — which is what kind \
             is, and what install_gate.rs and the public workflow install into — the second \
             replica stays Pending forever, so the shipped install would be one that does not \
             come up on the cluster its own gate uses."
        );
        let preferred = anti
            .get("preferredDuringSchedulingIgnoredDuringExecution")
            .and_then(Value::as_sequence)
            .expect("the anti-affinity is stated as a preference");
        let term = preferred
            .iter()
            .find(|t| {
                t.get("podAffinityTerm")
                    .and_then(|t| t.get("topologyKey"))
                    .and_then(Value::as_str)
                    == Some("kubernetes.io/hostname")
            })
            .expect(
                "no anti-affinity term over kubernetes.io/hostname: a preference over some other \
                 topology says nothing about two replicas on one node",
            );
        assert_eq!(
            term.get("weight").and_then(Value::as_u64),
            Some(100),
            "the anti-affinity carries less than the full weight, so any other preference can \
             outvote it and the two replicas land together anyway"
        );
        let labels = term
            .get("podAffinityTerm")
            .and_then(|t| t.get("labelSelector"))
            .and_then(|s| s.get("matchLabels"))
            .and_then(Value::as_mapping)
            .expect("the term selects the Pods it is about");
        assert_eq!(
            labels.get(Value::from(APP_LABEL)),
            Some(&Value::from(APP_NAME)),
            "the anti-affinity term selects Pods other than this webhook's, so the scheduler is \
             separating the wrong thing"
        );
    }

    /// Из-под вебхука исключены ровно два namespace, и решает это метка,
    /// которую apiserver проставляет сам.
    ///
    /// Исключения нужны: с `failurePolicy: Fail` вебхук, гейтящий namespace
    /// собственных Pod'ов и namespace плоскости управления кластера, нельзя
    /// перезапустить после того, как он перестал отвечать. Но ключ, по
    /// которому исключение решается, — это и есть политика: любой
    /// `ferrum.io/*`-опт-аут был бы исключением, которое namespace выдаёт себе
    /// сам, а в продукте про enforcement это вся политика целиком.
    #[test]
    fn the_webhook_exemption_is_decided_by_a_label_the_api_server_owns() {
        let webhook = read(WEBHOOK_TMPL);
        let hook = webhook
            .get("webhooks")
            .and_then(Value::as_sequence)
            .and_then(|w| w.first())
            .expect("the template carries a webhook");
        let selector = hook
            .get("namespaceSelector")
            .expect("the webhook states a namespaceSelector");
        assert!(
            selector.get("matchLabels").is_none(),
            "{WEBHOOK_TMPL} exempts by matchLabels: an equality selector cannot say NotIn, so \
             this either gates nothing or gates one namespace"
        );
        let expressions = selector
            .get("matchExpressions")
            .and_then(Value::as_sequence)
            .expect("the selector is stated as matchExpressions");
        let mut exempt: BTreeSet<String> = BTreeSet::new();
        for expr in expressions {
            let key = expr
                .get("key")
                .and_then(Value::as_str)
                .expect("expression names a key");
            assert_eq!(
                key, OWNED_LABEL,
                "{WEBHOOK_TMPL} decides the exemption on {key:?}. Only {OWNED_LABEL} is set and \
                 enforced by the API server; on any other key a namespace exempts itself from \
                 the policy by labelling itself."
            );
            assert_eq!(
                expr.get("operator").and_then(Value::as_str),
                Some("NotIn"),
                "the exemption is not stated as NotIn, so it is a list of namespaces the webhook \
                 *does* gate — everything else in the cluster is then ungated"
            );
            exempt.extend(
                expr.get("values")
                    .and_then(Value::as_sequence)
                    .expect("NotIn carries values")
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string),
            );
        }
        assert!(
            exempt.contains("kube-system"),
            "{WEBHOOK_TMPL} gates kube-system. With failurePolicy=Fail that is a cluster whose \
             control plane cannot restart while this webhook is down; exempt {exempt:?} does not \
             include it"
        );
        assert!(
            exempt.contains("ferrum"),
            "{WEBHOOK_TMPL} gates the namespace holding this webhook's own Pods, so a cold \
             cluster deadlocks on the replica that has not started yet; exempt is {exempt:?}"
        );
        // И ровно эти два: каждый лишний — namespace, в котором политика не
        // действует и об этом знает только этот файл.
        assert_eq!(
            exempt,
            ["ferrum", "kube-system"]
                .into_iter()
                .map(str::to_string)
                .collect::<BTreeSet<String>>(),
            "the webhook exempts more than the two namespaces it must: every extra one is a \
             namespace where the shipped policy does not apply and nothing else in this tree \
             says so"
        );
    }

    /// У каждого ресурса, который вебхук регистрирует, есть scope, известный
    /// коду, который его решает.
    ///
    /// Это шов, на котором сломался issue #17. `namespaceSelector` выше не
    /// применяется apiserver к ресурсам уровня кластера, значит для них
    /// решение целиком за `ferrum-admission`, и он обязан знать, что у такого
    /// объекта нет namespace, а не спрашивать кеш меток о пустой строке.
    /// Ресурс, дописанный в `rules` и не разобранный здесь, — второй заход на
    /// ту же ошибку, поэтому таблица ниже полная, а незнакомый ресурс — падение.
    #[test]
    fn every_resource_the_webhook_registers_has_a_scope_this_crate_knows() {
        /// resource → (Kind, cluster-scoped?). Полная, а не «то, что
        /// встретилось»: в этом и смысл.
        const SCOPES: [(&str, &str, bool); 6] = [
            ("pods", "Pod", false),
            ("roles", "Role", false),
            ("rolebindings", "RoleBinding", false),
            ("clusterroles", "ClusterRole", true),
            ("clusterrolebindings", "ClusterRoleBinding", true),
            ("namespaces", "Namespace", true),
        ];

        let webhook = read(WEBHOOK_TMPL);
        let hook = webhook
            .get("webhooks")
            .and_then(Value::as_sequence)
            .and_then(|w| w.first())
            .expect("the template carries a webhook");
        let mut registered: BTreeSet<String> = BTreeSet::new();
        for rule in hook
            .get("rules")
            .and_then(Value::as_sequence)
            .expect("the webhook carries rules")
        {
            registered.extend(
                rule.get("resources")
                    .and_then(Value::as_sequence)
                    .expect("a rule names resources")
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string),
            );
        }
        assert!(
            !registered.is_empty(),
            "{WEBHOOK_TMPL} registers no resource at all, so nothing below is about anything"
        );

        for resource in &registered {
            let (_, kind, cluster_scoped) = SCOPES
                .iter()
                .find(|(name, _, _)| name == resource)
                .unwrap_or_else(|| {
                    panic!(
                        "{WEBHOOK_TMPL} registers {resource:?}, whose scope this gate does not \
                         know. Decide it here and in ferrum_admission::CLUSTER_SCOPED_KINDS \
                         together: a cluster-scoped resource reaching a policy that carries a \
                         namespaceSelector is what denied every ClusterRoleBinding in the \
                         cluster until issue #20, and a namespaced one wrongly listed as \
                         cluster-scoped would skip the namespace selector entirely."
                    )
                });
            assert_eq!(
                ferrum_admission::CLUSTER_SCOPED_KINDS.contains(kind),
                *cluster_scoped,
                "{WEBHOOK_TMPL} registers {resource:?} ({kind}), which this gate calls \
                 cluster-scoped={cluster_scoped} and ferrum_admission::CLUSTER_SCOPED_KINDS \
                 disagrees with. One of the two is wrong, and while they disagree the webhook \
                 either asks a label cache about an object with no namespace or applies no \
                 namespace selector to an object that has one."
            );
        }

        // Обратное направление: `Namespace` намеренно не в списке crate, и это
        // держится только тем, что вебхук его не регистрирует. Зарегистрирует —
        // и `cluster_scoped_kind` начнёт отвечать «нет» на объект, у которого
        // метки namespace есть, но лежат на нём самом.
        if registered.contains("namespaces") {
            panic!(
                "{WEBHOOK_TMPL} now registers `namespaces`. For a Namespace object the labels a \
                 namespaceSelector asks about are the object's own — a third case that neither \
                 cluster_scoped_kind nor program_applies decides today. Decide it before this \
                 rule ships."
            );
        }
    }
}
