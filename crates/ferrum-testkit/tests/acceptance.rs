//! MVP-1 acceptance (RFC §D): the eight cases run the real offline pipeline —
//! compile `prod-restricted` → sign FSIG → admission/agent public APIs.
//! No cluster, no private helpers of other crates.

use chrono::{DateTime, TimeZone, Utc};
use ferrum_admission::{
    admit, load_bundle, AdmissionSubject, RULE_CLUSTER_ADMIN_BIND, RULE_PRIVILEGED, RULE_UNSIGNED,
};
use ferrum_agent::{apply_role, encode_fsig, Agent, AgentConfig, AgentRole};
use ferrum_api::{PolicyExceptionSpec, PolicyMode};
use ferrum_compiler::{bundle_digest_material, compile_cluster_policy};
use ferrum_crypto::{public_key_from_secret, sign_bundle};
use ferrum_ebpf::{Action, SyscallEvent};
use ferrum_ids::{Digest, ADMISSION_ABI, AGENT_ABI};
use ferrum_testkit::{
    exception_ok, prod_restricted, try_exception_from_yaml, EXCEPTION_WITHOUT_TTL_YAML,
};
use std::path::PathBuf;

/// RFC 8032 §7.1 test-1 seed: fixture only, not a prod key.
const SK: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 27, 12, 0, 0).unwrap()
}

/// compile → sign: FSIG over the FRMB material of `prod-restricted` (enforce).
fn signed_bundle() -> (Vec<u8>, Digest, Vec<u8>) {
    let mut spec = prod_restricted().spec;
    spec.mode = PolicyMode::Enforce;
    let bundle = compile_cluster_policy(&spec).expect("compile prod-restricted");
    let frmb = bundle_digest_material(
        AGENT_ABI,
        ADMISSION_ABI,
        &bundle.admission_program,
        &bundle.ebpf_spec,
        &bundle.wasm,
    )
    .expect("frmb material");
    let pk = public_key_from_secret(&SK).expect("public key");
    let sig = sign_bundle(&frmb, &SK).expect("sign");
    let fsig = encode_fsig(&frmb, &sig, &pk).expect("fsig");
    (fsig, bundle.digest, pk)
}

fn program() -> ferrum_admission::AdmissionProgram {
    let (fsig, _, pk) = signed_bundle();
    load_bundle(&fsig, &pk).expect("verify + parse FADM")
}

/// Matches the prod-restricted selector: pci namespace, allowed registry, digest-pinned.
fn compliant_subject() -> AdmissionSubject {
    let mut subject = AdmissionSubject {
        policy_name: "prod-restricted".into(),
        namespace: "payments".into(),
        image: "registry.internal.example/app@sha256:abc".into(),
        image_signed: true,
        ..Default::default()
    };
    subject
        .namespace_labels
        .insert("ferrum.io/zone".into(), "pci".into());
    subject
}

fn respond_agent(lkg_dir: Option<PathBuf>) -> Agent {
    Agent::new(AgentConfig {
        role: AgentRole::Respond,
        lkg_dir,
        trust_root: public_key_from_secret(&SK).expect("public key"),
        bundle_path: None,
    })
}

fn loaded_agent() -> Agent {
    let (fsig, digest, _) = signed_bundle();
    let mut agent = respond_agent(None);
    let applied = agent.apply_fsig(&fsig, Some(&digest)).expect("apply FSIG");
    assert_eq!(applied, digest);
    agent
}

fn ev<'a>(syscall: &'a str, comm: &'a str, path: &'a str, agent_self: bool) -> SyscallEvent<'a> {
    SyscallEvent {
        syscall,
        comm,
        path,
        in_container: true,
        agent_self,
    }
}

fn temp_lkg() -> PathBuf {
    std::env::temp_dir().join(format!(
        "ferrum-acceptance-lkg-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ))
}

#[test]
fn unsigned_image_is_denied() {
    let program = program();

    let signed = admit(&program, &compliant_subject(), &[], now());
    assert!(signed.allowed, "{:?}", signed.reasons);
    assert!(!signed.fail_closed);

    let mut subject = compliant_subject();
    subject.image_signed = false;
    let decision = admit(&program, &subject, &[], now());
    assert!(!decision.allowed);
    assert!(!decision.fail_closed);
    assert!(decision.rule_ids.iter().any(|r| r == RULE_UNSIGNED));
}

#[test]
fn privileged_pod_is_denied() {
    let program = program();
    let mut subject = compliant_subject();
    subject.privileged = true;
    let decision = admit(&program, &subject, &[], now());
    assert!(!decision.allowed);
    assert!(decision.rule_ids.iter().any(|r| r == RULE_PRIVILEGED));
}

#[test]
fn cluster_admin_bind_is_denied() {
    let program = program();
    let mut subject = compliant_subject();
    subject.cluster_admin_bind = true;
    let decision = admit(&program, &subject, &[], now());
    assert!(!decision.allowed);
    assert!(decision
        .rule_ids
        .iter()
        .any(|r| r == RULE_CLUSTER_ADMIN_BIND));
}

#[test]
fn exception_without_ttl_is_rejected_and_scoped_exception_waives() {
    // API reject: the CRD type cannot even decode a PolicyException without expiresAt.
    let err = try_exception_from_yaml(EXCEPTION_WITHOUT_TTL_YAML)
        .expect_err("missing expiresAt must not decode");
    let msg = err.to_string();
    assert!(
        msg.contains("expiresAt") || msg.contains("expires_at") || msg.contains("missing field"),
        "{msg}"
    );

    // A ticketed, TTL-bounded exception waives exactly its rule, nothing else.
    let mut exception: PolicyExceptionSpec = exception_ok().spec;
    exception.target.namespace = String::new();
    exception.target.rules = vec![RULE_PRIVILEGED.into()];

    let program = program();
    let mut subject = compliant_subject();
    subject.privileged = true;
    let waived = admit(&program, &subject, std::slice::from_ref(&exception), now());
    assert!(waived.allowed, "{:?}", waived.reasons);

    subject.cluster_admin_bind = true;
    let other_rule = admit(&program, &subject, std::slice::from_ref(&exception), now());
    assert!(!other_rule.allowed, "exception must not leak across rules");

    subject.cluster_admin_bind = false;
    let expired = admit(
        &program,
        &subject,
        std::slice::from_ref(&exception),
        exception.expires_at + chrono::Days::new(1),
    );
    assert!(!expired.allowed, "expired exception must not waive");
}

#[test]
fn exec_shell_in_container_is_killed() {
    let agent = loaded_agent();
    let decision = agent.matched_action(&ev("execve", "sh", "/bin/sh", false));
    assert_eq!(decision.action, Action::Kill);
    assert_eq!(decision.rule_id.as_deref(), Some("no-shell"));
    assert_eq!(
        apply_role(AgentRole::Respond, decision.action),
        Action::Kill
    );
    // Observe demotes Kill to Audit; enforcement needs the respond role.
    assert_eq!(
        apply_role(AgentRole::Observe, decision.action),
        Action::Audit
    );

    let mut outside = ev("execve", "sh", "/bin/sh", false);
    outside.in_container = false;
    assert_ne!(agent.matched_action(&outside).action, Action::Kill);
}

#[test]
fn docker_sock_access_is_killed() {
    let agent = loaded_agent();
    let decision = agent.matched_action(&ev("openat", "curl", "/var/run/docker.sock", false));
    assert_eq!(decision.action, Action::Kill);
    assert_eq!(decision.rule_id.as_deref(), Some("no-runtime-sock"));

    let benign = agent.matched_action(&ev("openat", "curl", "/tmp/app.sock", false));
    assert_ne!(benign.action, Action::Kill);
}

#[test]
fn bpf_not_from_agent_is_denied() {
    let agent = loaded_agent();
    let decision = agent.matched_action(&ev("bpf", "loader", "", false));
    assert_eq!(decision.action, Action::Deny);
    assert_eq!(decision.rule_id.as_deref(), Some("no-module"));

    let from_agent = agent.matched_action(&ev("bpf", "ferrum-agent", "", true));
    assert_ne!(from_agent.action, Action::Deny);
    assert_ne!(from_agent.action, Action::Kill);
}

#[test]
fn cp_down_keeps_last_known_good_not_fail_open() {
    let dir = temp_lkg();
    let (fsig, digest, _) = signed_bundle();

    let mut agent = respond_agent(Some(dir.clone()));
    agent.apply_fsig(&fsig, Some(&digest)).expect("apply FSIG");
    assert!(agent.using_last_known_good());

    agent.mark_control_plane_down();
    assert!(agent.control_plane_down());
    assert!(agent.is_degraded());

    // A tampered bundle while CP is down must not swap out last-known-good.
    let mut tampered = fsig.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    agent
        .apply_fsig(&tampered, None)
        .expect_err("tampered FSIG must be rejected");
    assert!(agent.using_last_known_good());
    assert_eq!(agent.last_good_digest(), Some(&digest));
    assert_eq!(
        agent
            .matched_action(&ev("execve", "sh", "/bin/sh", false))
            .action,
        Action::Kill,
        "degraded is not fail-open"
    );

    // Restart during the outage restores the same signed bundle from disk.
    let restarted = respond_agent(Some(dir.clone()));
    assert!(restarted.using_last_known_good());
    assert_eq!(restarted.last_good_digest(), Some(&digest));

    let _ = std::fs::remove_dir_all(&dir);
}
