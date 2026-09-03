//! What the shipped policy actually hands the kernel.
//!
//! `ferrum-ebpf` builds rule shapes by hand in its own unit tests, because
//! that crate may not carry `serde_yaml` and so cannot read the policy this
//! product ships. That is exactly the gap the prefilter gate next door was
//! written to close, and this file closes it for the kernel rule set: both
//! crates are in scope here, so the assertions are made against the real
//! `policies/examples/prod-restricted.yaml`, compiled by the real compiler.
//!
//! It exists because a claim about this was wrong once. The first reading of
//! the LSM work said the §D acceptance case, «`exec` + `/bin/sh` → kill»,
//! could not reach the kernel because it names a path. It does not name a
//! path: `no-shell` matches `commIn` and `containerOnly`, both of which the
//! hook can answer. A sentence in a document said otherwise for a day; this
//! file is what makes the same mistake a red build instead.

use ferrum_api::{PolicyMode, RuntimeAction};
use ferrum_ebpf::{
    compile_kernel_rules, kernel_verdict, KernelRuleSet, ACTION_ALLOW, ACTION_KILL, COMM_LEN,
};

fn shipped_policy() -> ferrum_api::ClusterSecurityPolicy {
    let yaml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../policies/examples/prod-restricted.yaml"
    ));
    serde_yaml::from_str(yaml).expect("prod-restricted yaml")
}

/// The shipped policy with the two attributes that refuse it in kernel taken
/// off: `mode: audit` and the namespace selector.
///
/// Both refusals are correct, and both are asserted on their own below. This
/// helper exists so the *rules* can be measured at all — without it every
/// assertion about what the kernel would enforce would be made against an
/// empty set, and would pass for the wrong reason forever.
fn shipped_policy_made_enforceable() -> ferrum_api::ClusterSecurityPolicy {
    let mut policy = shipped_policy();
    policy.spec.mode = PolicyMode::Enforce;
    policy.spec.selector = Default::default();
    policy
}

fn kernel_set_of(policy: &ferrum_api::ClusterSecurityPolicy) -> KernelRuleSet {
    let bundle =
        ferrum_compiler::compile_cluster_policy(&policy.spec).expect("prod-restricted compiles");
    let compiled = ferrum_ebpf::parse_febp(&bundle.ebpf_spec).expect("FEBP decodes");
    compile_kernel_rules(&compiled)
}

fn comm(name: &str) -> [u8; COMM_LEN] {
    let mut out = [0u8; COMM_LEN];
    out[..name.len()].copy_from_slice(name.as_bytes());
    out
}

/// As shipped, `prod-restricted` hands the kernel nothing — and that is
/// correct, not a gap.
///
/// It ships `mode: audit`. An auditing policy must not refuse a syscall, so
/// the whole set is refused with the mode as the reason. Pinned here because
/// the alternative — a kernel that prevents under a policy whose operator
/// asked only to be told — is the worst failure this feature could have.
#[test]
fn the_shipped_policy_as_shipped_enforces_nothing_in_kernel_and_says_why() {
    let policy = shipped_policy();
    assert_eq!(
        policy.spec.mode,
        PolicyMode::Audit,
        "prod-restricted no longer ships mode: audit; this test is about that value"
    );
    let set = kernel_set_of(&policy);
    let reason = set
        .refused
        .as_deref()
        .expect("an auditing policy must not reach the kernel rule set");
    assert!(reason.contains("enforce"), "{reason}");
    assert!(set.is_empty());
}

/// And in enforce it is still refused, for the second reason: it selects.
///
/// This is the bound on the whole feature as it stands, stated where it will
/// be read rather than left to be discovered on a cluster. The kernel has no
/// pod identity, so a selected policy enforced there would refuse execs in
/// workloads it never selected. Until the agent publishes the *selected*
/// cgroups — it already resolves them, the map does not exist yet — a policy
/// with any selector prevents nothing in kernel and detects exactly as before.
#[test]
fn a_selected_policy_still_prevents_nothing_in_kernel_and_that_is_the_current_bound() {
    let mut policy = shipped_policy();
    policy.spec.mode = PolicyMode::Enforce;
    assert!(
        !policy
            .spec
            .selector
            .namespace_selector
            .match_expressions
            .is_empty(),
        "prod-restricted no longer selects a namespace; this test is about that selector"
    );
    let set = kernel_set_of(&policy);
    let reason = set
        .refused
        .as_deref()
        .expect("a selected policy must not be enforced against every container");
    assert!(reason.contains("селектор"), "{reason}");
    assert!(set.is_empty());
}

/// Made enforceable, the shipped policy reaches the kernel, and the §D shell
/// case is the part that reaches it.
#[test]
fn the_shipped_policy_hands_the_shell_rule_to_the_kernel_and_the_socket_rule_stays_behind() {
    let set = kernel_set_of(&shipped_policy_made_enforceable());
    assert!(
        !set.is_refused(),
        "the shipped policy is refused wholesale: {:?}",
        set.refused
    );

    // `no-shell` names five comms, and a slot carries one, so five slots.
    assert_eq!(
        set.len(),
        5,
        "the shipped policy produced {} slots, expected the five comms of no-shell: {set:#?}",
        set.len()
    );

    // Every one of them kills, in a container, and never the agent itself.
    for slot in &set.rules {
        assert_eq!(slot.action, ACTION_KILL);
        assert!(slot.container_only(), "a shell slot lost containerOnly");
        assert!(slot.comm_len > 0, "a shell slot lost its comm predicate");
    }

    // And the ones that stay behind stay behind for a written reason.
    let excluded: Vec<&str> = set.excluded.iter().map(|e| e.rule.as_str()).collect();
    assert_eq!(
        excluded,
        ["no-runtime-sock", "no-module"],
        "the set of rules the kernel cannot decide changed: {:#?}",
        set.excluded
    );
    assert!(
        set.excluded[0].reason.contains("путь"),
        "no-runtime-sock is excluded for its pathSuffix, and the reason should say so: {}",
        set.excluded[0].reason
    );
}

/// The acceptance case itself, decided by the function the kernel walks.
///
/// Not "a rule that looks like the acceptance case" — the rule the shipped
/// policy carries, compiled by the shipped compiler, matched by the shipped
/// matcher. The three shells §D names decide kill in a container; the same
/// names outside one decide nothing, which is `containerOnly` doing its job
/// and is why the node's own shells are not refused.
#[test]
fn the_acceptance_shell_is_refused_in_a_container_and_untouched_outside_one() {
    let set = kernel_set_of(&shipped_policy_made_enforceable());

    for shell in ["sh", "bash", "ash", "dash", "zsh"] {
        assert_eq!(
            kernel_verdict(&set.rules, &comm(shell), true, false),
            ACTION_KILL,
            "{shell} in a container is not refused by the kernel set"
        );
        assert_eq!(
            kernel_verdict(&set.rules, &comm(shell), false, false),
            ACTION_ALLOW,
            "{shell} outside a container was refused; containerOnly is not being honoured, and \
             the node's own shells would stop working"
        );
        // `no-shell` carries no `notAgentSelf`, so the agent is not exempt
        // from it — and the kernel must not invent an exemption the policy
        // does not grant. This is the userspace answer too, which is the
        // whole point of the two matchers being one function.
        assert_eq!(
            kernel_verdict(&set.rules, &comm(shell), true, true),
            ACTION_KILL,
            "{shell} run by the agent was exempted by a rule that grants no exemption"
        );
    }

    // A name that merely starts with one of them is not one of them.
    for other in ["shred", "bashful", "cat"] {
        assert_eq!(
            kernel_verdict(&set.rules, &comm(other), true, false),
            ACTION_ALLOW,
            "{other} was refused by a rule that names only shells"
        );
    }
}

/// `defaultAction: audit` — what the shipped policy carries — must not refuse
/// the whole set, and a default that would itself refuse an exec must.
///
/// This is the condition that was wrong first time round: refusing on any
/// non-`allow` default refused the shipped policy entirely, which would have
/// left the kernel enforcing nothing on every cluster while every test built
/// on a hand-made `allow` policy stayed green.
#[test]
fn an_auditing_default_does_not_refuse_the_set_and_a_killing_one_does() {
    let mut policy = shipped_policy_made_enforceable();
    assert_eq!(
        policy.spec.runtime.default_action,
        RuntimeAction::Audit,
        "prod-restricted no longer ships defaultAction: audit; this test is about that value"
    );
    assert!(!kernel_set_of(&policy).is_refused());

    policy.spec.runtime.default_action = RuntimeAction::Allow;
    assert!(!kernel_set_of(&policy).is_refused());

    // The other half is defence in depth rather than a live path: a killing
    // default cannot be authored at all — the compiler calls it kill-all and
    // refuses it — so the refusal in `compile_kernel_rules` is the second
    // lock on a door the first one already holds. Asserted here so that if
    // the compiler ever stops refusing, this stays the thing that does.
    policy.spec.runtime.default_action = RuntimeAction::Kill;
    let err = ferrum_compiler::compile_cluster_policy(&policy.spec)
        .expect_err("a killing default is kill-all and must not compile");
    assert!(err.to_string().contains("kill-all"), "{err}");
}
