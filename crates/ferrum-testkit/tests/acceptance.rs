//! MVP-1 acceptance (RFC §D): the eight cases run the real offline pipeline —
//! compile `prod-restricted` → sign FSIG → admission/agent public APIs.
//! No cluster, no private helpers of other crates.

use chrono::{DateTime, TimeZone, Utc};
use ferrum_admission::{
    admit, load_bundle, AdmissionSubject, RULE_CLUSTER_ADMIN_BIND, RULE_PRIVILEGED, RULE_UNSIGNED,
};
use ferrum_agent::{
    apply_role, encode_fsig, Agent, AgentConfig, AgentRole, BUNDLE_DIGEST_KEY, BUNDLE_FSIG_KEY,
    EXCEPTIONS_FSIG_KEY, WAIVED_ACTION,
};
use ferrum_api::{PolicyExceptionSpec, PolicyMode};
use ferrum_compiler::{bundle_digest_material, compile_cluster_policy};
use ferrum_crypto::{public_key_from_secret, sign_bundle};
use ferrum_ebpf::{Action, SyscallEvent};
use ferrum_export::MemorySink;
use ferrum_ids::{Digest, ADMISSION_ABI, AGENT_ABI};
use ferrum_k8smeta::WorkloadIdentity;
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
        policy_name: "prod-restricted".into(),
        ..Default::default()
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

/// Matches the prod-restricted selector (pci zone, pinned registry) in the
/// namespace targeted by the `exception-ok` fixture.
fn payments_identity() -> WorkloadIdentity {
    let mut id = WorkloadIdentity {
        namespace: "payments".into(),
        pod: "web-1".into(),
        container: "app".into(),
        service_account: "web".into(),
        ..Default::default()
    };
    id.namespace_labels
        .insert("ferrum.io/zone".into(), "pci".into());
    id.image = "registry.internal.example/app@sha256:abc".into();
    id.image_digest = "sha256:abc".into();
    id
}

#[test]
fn docker_sock_kill_is_waived_only_in_scope() {
    let mut agent = loaded_agent();
    agent.insert_cgroup(7, payments_identity());
    let mut other = payments_identity();
    other.namespace = "checkout".into();
    agent.insert_cgroup(8, other);

    let mut waiver = exception_ok().spec;
    waiver.target.rules = vec!["no-runtime-sock".into()];
    let expires_at = waiver.expires_at;
    agent.set_exceptions(vec![waiver]);

    let sink = MemorySink::new();
    let sock = ev("openat", "curl", "/var/run/docker.sock", false);

    // In scope: kill demoted to audit, with a distinct audit-trail action
    // carrying the ticket that authorized it.
    let waived = agent.handle_event_at(7, &sock, &sink, now());
    assert_eq!(waived.action, Action::Audit);
    assert_eq!(waived.rule_id.as_deref(), Some("no-runtime-sock"));
    assert_eq!(sink.events()[0].action, WAIVED_ACTION);
    assert_eq!(sink.events()[0].namespace, "payments");
    let exported = serde_json::to_string(&sink.events()[0]).expect("serialize");
    assert!(exported.contains("\"ticket\":\"JIRA-18421\""), "{exported}");
    assert!(
        exported.contains("\"approvedBy\":\"ib-architect\""),
        "{exported}"
    );
    assert_eq!(
        sink.events()[0].waiver.as_ref().map(|w| w.ticket.as_str()),
        Some("JIRA-18421")
    );

    // Same rule outside the exception namespace: still kill, no waiver ref.
    let outside = agent.handle_event_at(8, &sock, &sink, now());
    assert_eq!(outside.action, Action::Kill);
    assert_eq!(sink.events()[1].action, "kill");
    assert!(sink.events()[1].waiver.is_none());

    // The waiver does not outlive expiresAt.
    let expired = agent.handle_event_at(7, &sock, &sink, expires_at + chrono::Days::new(1));
    assert_eq!(expired.action, Action::Kill);

    // Empty target.rules is no-match, not a policy-wide waiver.
    let mut empty_rules = exception_ok().spec;
    empty_rules.target.rules = Vec::new();
    agent.set_exceptions(vec![empty_rules]);
    let no_rules = agent.handle_event_at(7, &sock, &sink, now());
    assert_eq!(no_rules.action, Action::Kill);
}

#[test]
fn only_signed_exceptions_are_accepted_from_the_mount() {
    let dir = temp_lkg();
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let (fsig, digest, _) = signed_bundle();
    std::fs::write(dir.join(BUNDLE_FSIG_KEY), fsig).expect("bundle.fsig");
    std::fs::write(dir.join(BUNDLE_DIGEST_KEY), digest.as_str().as_bytes()).expect("digest");

    let mut waiver = exception_ok().spec;
    waiver.target.rules = vec!["no-runtime-sock".into()];
    let json = serde_json::to_vec(&[waiver]).expect("encode");

    // Plain JSON (the old exceptions.json contract, unsigned) never yields waivers.
    std::fs::write(dir.join(EXCEPTIONS_FSIG_KEY), &json).expect("plain json");
    let mut agent = respond_agent(None);
    agent.apply_path(&dir).expect("bundle from mount");
    agent
        .reload_exceptions_path(&dir)
        .expect_err("unsigned exceptions must be rejected");
    assert_eq!(agent.exceptions_reload_failed_total(), 1);
    agent.insert_cgroup(7, payments_identity());
    let sock = ev("openat", "curl", "/var/run/docker.sock", false);
    assert_eq!(
        agent
            .handle_event_at(7, &sock, &MemorySink::new(), now())
            .action,
        Action::Kill,
        "no waiver without a signature"
    );

    // Same payload in an FSIG envelope under the pinned key: waiver applies.
    let sig = sign_bundle(&json, &SK).expect("sign exceptions");
    let pk = public_key_from_secret(&SK).expect("public key");
    let sealed = encode_fsig(&json, &sig, &pk).expect("exceptions.fsig");
    std::fs::write(dir.join(EXCEPTIONS_FSIG_KEY), &sealed).expect("exceptions.fsig");
    assert_eq!(agent.reload_exceptions_path(&dir).expect("signed"), 1);
    let sink = MemorySink::new();
    let waived = agent.handle_event_at(7, &sock, &sink, now());
    assert_eq!(waived.action, Action::Audit);
    assert_eq!(sink.events()[0].action, WAIVED_ACTION);
    assert_eq!(
        sink.events()[0].waiver.as_ref().map(|w| w.ticket.as_str()),
        Some("JIRA-18421")
    );

    // Tampered envelope drops every waiver: fail-closed back to kill.
    let mut tampered = sealed;
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    std::fs::write(dir.join(EXCEPTIONS_FSIG_KEY), &tampered).expect("tampered");
    agent
        .reload_exceptions_path(&dir)
        .expect_err("tampered exceptions must be rejected");
    assert_eq!(agent.exceptions_reload_failed_total(), 2);
    assert_eq!(
        agent
            .handle_event_at(7, &sock, &MemorySink::new(), now())
            .action,
        Action::Kill
    );

    let _ = std::fs::remove_dir_all(&dir);
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

/// The FSIG codec exists in four copies (controller, agent, admission, CLI)
/// because the crate boundary forbids a shared runtime dependency. This is the
/// gate that catches drift: bytes the controller actually publishes must be
/// accepted by both consumers of the waiver channel.
#[test]
fn controller_signed_exceptions_are_accepted_by_agent_and_admission() {
    let mut waiver = exception_ok().spec;
    waiver.target.rules = vec!["no-runtime-sock".into()];
    let specs = vec![waiver];

    // Produced by the control plane, not by a test-local encoder.
    let sealed = ferrum_controller::exceptions_fsig(&specs, &SK).expect("controller signs");
    assert_eq!(
        ferrum_controller::EXCEPTIONS_FSIG_KEY,
        EXCEPTIONS_FSIG_KEY,
        "controller and agent must agree on the Secret key"
    );
    let trust_root = public_key_from_secret(&SK).expect("public key");

    // Admission verifies the same envelope against its pinned trust root.
    let payload = ferrum_admission::verify_exceptions_fsig(&sealed, &trust_root)
        .expect("admission accepts controller bytes");
    let decoded: Vec<PolicyExceptionSpec> =
        serde_json::from_slice(&payload).expect("payload is the spec array");
    assert_eq!(decoded, specs);

    // The agent takes it from the mount and the waiver demotes the kill.
    let dir = temp_lkg();
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let (fsig, digest, _) = signed_bundle();
    std::fs::write(dir.join(BUNDLE_FSIG_KEY), fsig).expect("bundle.fsig");
    std::fs::write(dir.join(BUNDLE_DIGEST_KEY), digest.as_str().as_bytes()).expect("digest");
    std::fs::write(dir.join(EXCEPTIONS_FSIG_KEY), &sealed).expect("exceptions.fsig");

    let mut agent = respond_agent(None);
    agent.apply_path(&dir).expect("bundle from mount");
    assert_eq!(
        agent.reload_exceptions_path(&dir).expect("agent accepts"),
        1
    );
    agent.insert_cgroup(7, payments_identity());
    let sink = MemorySink::new();
    let sock = ev("openat", "curl", "/var/run/docker.sock", false);
    assert_eq!(
        agent.handle_event_at(7, &sock, &sink, now()).action,
        Action::Audit
    );
    assert_eq!(sink.events()[0].action, WAIVED_ACTION);

    let _ = std::fs::remove_dir_all(&dir);
}
