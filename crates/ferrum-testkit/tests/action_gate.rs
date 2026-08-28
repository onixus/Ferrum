//! Drift gate between the three copies of "which runtime action may be
//! signed": `ferrum-policy` (advisory), the encoder in `ferrum-compiler`, and
//! the loader in `ferrum-ebpf`.
//!
//! `deploy_gate.rs` holds the same question for the CEL copy on the CRDs. This
//! file holds it for the two copies that run after the API server is out of
//! the picture — the ones that decide what a *signed* bundle may carry, and so
//! the ones that face a bundle an older or foreign compiler produced.
//!
//! Both sides are derived, never remembered: the sets come from asking each
//! copy about one probe per `RuntimeAction`, so a verdict that moves on either
//! side fails here until the other follows.

#[allow(dead_code)]
mod common;

use common::febp::Writer;
use common::{respond_agent, signed_bundle, temp_lkg, SK};
use ferrum_agent::encode_fsig;
use ferrum_api::{
    ClusterSecurityPolicySpec, RuntimeAction, RuntimeMatch, RuntimeRule, RuntimeSpec,
};
use ferrum_compiler::{bundle_digest_material, compile_cluster_policy};
use ferrum_crypto::{public_key_from_secret, sign_bundle};
use ferrum_ebpf::{parse_febp, parse_febp_with, Action, DeadRules, Mode, EBPF_MAGIC};
use ferrum_ids::{Digest, ADMISSION_ABI, AGENT_ABI};
use ferrum_policy::validate_cluster_policy;
use std::collections::BTreeSet;

/// Every `RuntimeAction` the API type can carry, mirrored by every `Action` the
/// wire can carry. Neither enum is reflective; what keeps the two lists
/// complete and aligned is `the_two_action_enums_are_the_same_set` below.
const RUNTIME_ACTIONS: [RuntimeAction; 5] = [
    RuntimeAction::Allow,
    RuntimeAction::Audit,
    RuntimeAction::Deny,
    RuntimeAction::Kill,
    RuntimeAction::Isolate,
];

const WIRE_ACTIONS: [Action; 5] = [
    Action::Allow,
    Action::Audit,
    Action::Deny,
    Action::Kill,
    Action::Isolate,
];

/// The wire spelling, from serde rather than retyped.
fn action_name(action: RuntimeAction) -> String {
    serde_yaml::to_value(action)
        .expect("RuntimeAction serializes")
        .as_str()
        .expect("RuntimeAction is a scalar")
        .to_string()
}

/// A rule carrying `action`, with a match. Anything refused here is refused on
/// the verb alone — no match can rescue it.
fn matched_rule_spec(action: RuntimeAction) -> ClusterSecurityPolicySpec {
    ClusterSecurityPolicySpec {
        runtime: RuntimeSpec {
            rules: vec![RuntimeRule {
                id: "probe".into(),
                // execve/execveat travel as a pair; naming one alone fails a
                // different invariant and would poison the set.
                syscalls: vec!["execve".into(), "execveat".into()],
                match_on: RuntimeMatch {
                    comm_in: vec!["sh".into()],
                    ..Default::default()
                },
                action,
            }],
            ..Default::default()
        },
        ..Default::default()
    }
}

/// The same rule with every match predicate empty: the kill-all shape.
fn matchless_rule_spec(action: RuntimeAction) -> ClusterSecurityPolicySpec {
    ClusterSecurityPolicySpec {
        runtime: RuntimeSpec {
            rules: vec![RuntimeRule {
                id: "probe".into(),
                syscalls: vec![],
                match_on: RuntimeMatch::default(),
                action,
            }],
            ..Default::default()
        },
        ..Default::default()
    }
}

fn default_action_spec(action: RuntimeAction) -> ClusterSecurityPolicySpec {
    ClusterSecurityPolicySpec {
        runtime: RuntimeSpec {
            default_action: action,
            rules: vec![],
        },
        ..Default::default()
    }
}

fn accepted_by(
    probe: fn(RuntimeAction) -> ClusterSecurityPolicySpec,
    ask: fn(&ClusterSecurityPolicySpec) -> bool,
) -> BTreeSet<String> {
    RUNTIME_ACTIONS
        .iter()
        .copied()
        .filter(|action| ask(&probe(*action)))
        .map(action_name)
        .collect()
}

fn policy_accepts(spec: &ClusterSecurityPolicySpec) -> bool {
    validate_cluster_policy(spec).is_ok()
}

fn compiler_accepts(spec: &ClusterSecurityPolicySpec) -> bool {
    compile_cluster_policy(spec).is_ok()
}

/// The invariant copy and the encoder must accept the same specs, in both
/// directions and on all three shapes the action gates split on. One direction
/// alone is not enough: an encoder that refused everything would satisfy
/// "refuses whatever the validator refuses" and ship no policy at all.
#[test]
fn the_encoder_accepts_exactly_what_ferrum_policy_accepts() {
    for (shape, probe) in [
        (
            "rule action, with a match",
            matched_rule_spec as fn(RuntimeAction) -> ClusterSecurityPolicySpec,
        ),
        ("rule action, no match", matchless_rule_spec),
        ("defaultAction", default_action_spec),
    ] {
        let by_policy = accepted_by(probe, policy_accepts);
        let by_compiler = accepted_by(probe, compiler_accepts);
        // A vacuous comparison would pass with the invariant deleted from both.
        assert!(
            !by_policy.is_empty(),
            "{shape}: ferrum-policy accepts nothing at all"
        );
        assert!(
            by_policy.len() < RUNTIME_ACTIONS.len(),
            "{shape}: ferrum-policy refuses nothing at all"
        );
        assert_eq!(
            by_policy, by_compiler,
            "{shape}: the encoder and ferrum-policy disagree about which actions may be signed"
        );
    }

    // The shapes are genuinely different questions, or the loop above proves
    // one thing three times: a match rescues `kill` on a rule and nothing
    // rescues it as a default.
    assert!(accepted_by(matched_rule_spec, policy_accepts).contains("kill"));
    assert!(!accepted_by(matchless_rule_spec, policy_accepts).contains("kill"));
    assert!(!accepted_by(default_action_spec, policy_accepts).contains("kill"));
}

/// A hand-encoded FEBP: one rule with `action`, and `default_action`, both
/// chosen by the caller. `matched` decides whether the rule carries any
/// predicate at all, which is what the rule-level kill-all gate turns on.
fn febp(default_action: Action, rule_action: Action, matched: bool) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(&EBPF_MAGIC);
    w.u32(AGENT_ABI);
    w.u8(Mode::Enforce.as_u8());
    w.bool(false);
    w.i32(0);
    w.u8(default_action.as_u8());
    for _ in 0..4 {
        w.empty_label_selector();
    }
    w.str_list(&[]);
    w.bool(false);
    w.u16(1);
    w.str("probe");
    if matched {
        w.str_list(&["execve", "execveat"]);
    } else {
        w.str_list(&[]);
    }
    w.u8(rule_action.as_u8());
    if matched {
        w.str_list(&["sh"]);
    } else {
        w.str_list(&[]);
    }
    w.bool(false);
    w.str_list(&[]);
    w.str_list(&[]);
    w.bool(false);
    w.finish()
}

/// That FEBP inside a real FRMB envelope, signed with the trust root the
/// replay agents pin. Admission program and wasm come from a real compile, so
/// only the eBPF half is hand-made — exactly the shape an older controller
/// would put on the wire.
fn signed(spec: Vec<u8>) -> (Vec<u8>, Digest) {
    let compiled = compile_cluster_policy(&ferrum_testkit::prod_restricted().spec)
        .expect("compile prod-restricted");
    let material = bundle_digest_material(
        AGENT_ABI,
        ADMISSION_ABI,
        &compiled.admission_program,
        &spec,
        &compiled.wasm,
    )
    .expect("frmb material");
    let digest = ferrum_crypto::bundle_digest(&material);
    let pk = public_key_from_secret(&SK).expect("public key");
    let sig = sign_bundle(&material, &SK).expect("sign");
    let fsig = encode_fsig(&material, &sig, &pk).expect("fsig");
    (fsig, digest)
}

fn loader_accepts_default(action: Action) -> bool {
    parse_febp(&febp(action, Action::Audit, true)).is_ok()
}

fn loader_accepts_matchless_rule(action: Action) -> bool {
    parse_febp(&febp(Action::Audit, action, false)).is_ok()
}

fn wire_accepted(ask: fn(Action) -> bool) -> BTreeSet<String> {
    WIRE_ACTIONS
        .iter()
        .copied()
        .filter(|a| ask(*a))
        .map(|a| a.as_str().to_string())
        .collect()
}

#[test]
fn the_two_action_enums_are_the_same_set() {
    let declared: BTreeSet<String> = RUNTIME_ACTIONS.iter().copied().map(action_name).collect();
    let wire: BTreeSet<String> = WIRE_ACTIONS
        .iter()
        .copied()
        .map(|a| a.as_str().to_string())
        .collect();
    assert_eq!(
        declared, wire,
        "RuntimeAction and the wire Action disagree; every derived set below is then partial"
    );
}

/// What the loader refuses, derived, against what the encoder refuses, also
/// derived — and the difference between them asserted rather than assumed.
///
/// The loader is deliberately the more permissive of the two, on exactly one
/// axis: an action that is merely *not executed* (`deny`) still loads, because
/// a bundle carrying one is what an older controller signs during a rolling
/// upgrade, and refusing it whole would stop that node taking any update at
/// all. An action that would *kill* does not load, on a rule or as the
/// default, because that is the kill-all `AGENTS.md` forbids and no operator
/// can walk it back. If either half of that difference moves, this fails.
#[test]
fn the_loader_refuses_every_kill_all_and_keeps_the_inert_deny() {
    let compiler_defaults = accepted_by(default_action_spec, compiler_accepts);
    let loader_defaults = wire_accepted(loader_accepts_default);
    assert_eq!(
        &loader_defaults - &compiler_defaults,
        BTreeSet::from(["deny".to_string()]),
        "the loader may be more permissive than the encoder about a defaultAction only for deny"
    );
    assert!(
        (&compiler_defaults - &loader_defaults).is_empty(),
        "the loader accepts less than the encoder as a defaultAction: {compiler_defaults:?} vs {loader_defaults:?}"
    );
    assert!(
        !loader_defaults.contains("kill") && !loader_defaults.contains("isolate"),
        "a kill-all defaultAction loads: {loader_defaults:?}"
    );

    let compiler_rules = accepted_by(matchless_rule_spec, compiler_accepts);
    let loader_rules = wire_accepted(loader_accepts_matchless_rule);
    assert_eq!(
        &loader_rules - &compiler_rules,
        BTreeSet::from(["deny".to_string()]),
        "the loader may be more permissive than the encoder about a matchless rule only for deny"
    );
    assert!(
        !loader_rules.contains("kill") && !loader_rules.contains("isolate"),
        "a kill-all rule loads: {loader_rules:?}"
    );

    // The rule gate turns on the match, the default gate cannot: there is no
    // match to add. `kill` is the one verb that shows the difference.
    assert!(parse_febp(&febp(Action::Audit, Action::Kill, true)).is_ok());
}

/// `DeadRules::Drop` must not reach the kill-all gate. Dropping is admissible
/// only for a rule no record can match; a kill-all default matches every
/// record, so "drop it and fall through to allow" would be precisely the
/// fail-open the last-known-good path exists to prevent.
#[test]
fn a_kill_all_default_refuses_the_snapshot_on_the_restore_path_too() {
    let spec = febp(Action::Kill, Action::Audit, true);
    for dead in [DeadRules::Reject, DeadRules::Drop] {
        let err = parse_febp_with(&spec, dead)
            .expect_err("a kill-all default is refused whole on both paths");
        let msg = err.to_string();
        assert!(msg.contains("kill-all"), "{dead:?}: {msg}");
        assert!(msg.contains("defaultAction"), "{dead:?}: {msg}");
    }
}

/// The live path, end to end: a signed FEBP whose only defect is
/// `default_action = Kill` — the bundle an older compiler, or one with the
/// encoder's gate missing, would sign. It must not install, and the policy
/// already running must survive its refusal.
#[test]
fn a_signed_kill_all_default_does_not_install_and_keeps_last_known_good() {
    let lkg = temp_lkg();
    let mut agent = respond_agent(Some(lkg.clone()));
    let (good_fsig, good_digest) = signed_bundle();
    let installed = agent
        .apply_fsig(&good_fsig, Some(&good_digest))
        .expect("the shipped policy installs");
    assert_eq!(installed, good_digest);

    let (fsig, digest) = signed(febp(Action::Kill, Action::Audit, true));
    let err = agent
        .apply_fsig(&fsig, Some(&digest))
        .expect_err("a kill-all default must not install, signature or no signature");
    let msg = err.to_string();
    assert!(msg.contains("kill-all"), "{msg}");

    assert_eq!(
        agent.last_good_digest(),
        Some(&good_digest),
        "the refused bundle replaced the running policy"
    );
    let on_disk = std::fs::read_to_string(lkg.join("digest")).expect("LKG digest on disk");
    assert_eq!(
        on_disk.trim(),
        good_digest.as_str(),
        "the refused bundle was persisted as last-known-good"
    );
    let _ = std::fs::remove_dir_all(&lkg);
}

/// The other side of the asymmetry, on the same live path: `defaultAction:
/// deny` is drift from the same older compiler, and it keeps loading. If this
/// starts failing, a node on a rolling upgrade has been cut off from a control
/// plane that is still serving every other node correctly — the sibling of
/// `a_pre_gate_deny_bundle_loads_and_every_match_is_recorded`.
#[test]
fn a_signed_deny_default_still_installs() {
    let (fsig, digest) = signed(febp(Action::Deny, Action::Audit, true));
    let mut agent = respond_agent(None);
    let installed = agent
        .apply_fsig(&fsig, Some(&digest))
        .expect("a deny defaultAction is inert drift, not a kill-all");
    assert_eq!(installed, digest);
}
