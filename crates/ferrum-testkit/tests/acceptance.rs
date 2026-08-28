//! MVP-1 acceptance (RFC §D): the eight cases run the real offline pipeline —
//! compile `prod-restricted` → sign FSIG → admission/agent public APIs.
//! No cluster, no private helpers of other crates.

use chrono::{DateTime, TimeZone, Utc};
use ferrum_admission::{
    admit, load_bundle, AdmissionSubject, RULE_ADDED_CAPABILITIES, RULE_CLUSTER_ADMIN_BIND,
    RULE_PRIVILEGED, RULE_UNSIGNED,
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
    exception_ok, prod_restricted, try_exception_from_yaml, AcceptanceCase,
    EXCEPTION_WITHOUT_TTL_YAML,
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
    subject.namespace_labels = Some(
        [("ferrum.io/zone".to_string(), "pci".to_string())]
            .into_iter()
            .collect(),
    );
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
        path_truncated: false,
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

/// Which test carries which §D case, checked against the shared case list
/// rather than against prose. The entries are the real test functions, so a
/// case whose test is renamed away stops compiling, and a case added to
/// `AcceptanceCase` fails this gate until something here covers it. The
/// functions are not called: `#[test]` already runs each exactly once.
#[test]
fn every_acceptance_case_has_a_test() {
    let covered: [(AcceptanceCase, fn()); 8] = [
        (AcceptanceCase::UnsignedDeny, unsigned_image_is_denied),
        (AcceptanceCase::PrivilegedDeny, privileged_pod_is_denied),
        (
            AcceptanceCase::ClusterAdminBindDeny,
            cluster_admin_bind_is_denied,
        ),
        (
            AcceptanceCase::ExceptionWithoutTtlReject,
            exception_without_ttl_is_rejected_and_scoped_exception_waives,
        ),
        (
            AcceptanceCase::ExecShellKill,
            exec_shell_in_container_is_killed,
        ),
        (AcceptanceCase::DockerSockKill, docker_sock_access_is_killed),
        (
            AcceptanceCase::BpfNotFromAgentDeny,
            bpf_not_from_agent_is_denied,
        ),
        (
            AcceptanceCase::ControlPlaneDownLkg,
            cp_down_keeps_last_known_good_not_fail_open,
        ),
    ];
    for case in AcceptanceCase::ALL {
        assert_eq!(
            covered.iter().filter(|(c, _)| c == case).count(),
            1,
            "no acceptance test registered for §D case: {}",
            case.label()
        );
    }
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
    // The join read them off a listed namespace; without this the identity
    // says "never observed" and the selector cannot be resolved.
    id.namespace_labels_observed = true;
    id.service_account_labels_observed = true;
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

/// §D `bpf()` not from the agent → deny, and which layer carries the deny.
///
/// Admission carries it: it refuses the pod that could load a module before it
/// runs at all (`admit.deny` privileged / SYS_MODULE, asserted here and in the
/// admission cases above). The runtime plane cannot: its tracepoint fires
/// after the syscall has already returned, so a runtime `deny` would be a
/// verdict decided and never executed — a permanent export stream of denials
/// that never happened. What this plane can honestly execute is the audit
/// record naming the caller, and `ferrum-policy` now refuses to compile the
/// dishonest version.
#[test]
fn bpf_not_from_agent_is_denied() {
    // The deny half, before the syscall exists to observe.
    let program = program();
    let mut privileged_loader = compliant_subject();
    privileged_loader.privileged = true;
    privileged_loader.added_capabilities = vec!["SYS_MODULE".into()];
    let denied = admit(&program, &privileged_loader, &[], now());
    assert!(!denied.allowed);
    assert!(denied.rule_ids.iter().any(|r| r == RULE_PRIVILEGED));
    assert!(denied.rule_ids.iter().any(|r| r == RULE_ADDED_CAPABILITIES));

    // The runtime half: the caller is named, and the record does not claim a
    // reaction that never ran.
    let agent = loaded_agent();
    let decision = agent.matched_action(&ev("bpf", "loader", "", false));
    assert_eq!(decision.action, Action::Audit);
    assert_eq!(decision.rule_id.as_deref(), Some("no-module"));

    let from_agent = agent.matched_action(&ev("bpf", "ferrum-agent", "", true));
    assert_eq!(
        from_agent.rule_id, None,
        "the agent's own bpf() is not a hit"
    );
    assert_ne!(from_agent.action, Action::Deny);
    assert_ne!(from_agent.action, Action::Kill);

    agent.insert_cgroup(7, payments_identity());
    let refused_before = agent.respond_refused_total();
    let sink = MemorySink::new();
    let exported = agent.handle_event_at(7, &ev("bpf", "loader", "", false), &sink, now());
    assert_eq!(exported.action, Action::Audit);

    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "audit");
    assert_eq!(events[0].rule.as_str(), "no-module");
    assert_eq!(events[0].comm, "loader");
    assert!(
        !events[0].executed,
        "an audit record executes nothing, and must not claim otherwise"
    );
    assert_eq!(
        events[0].respond_error, None,
        "nothing was refused: there was nothing to execute"
    );
    assert_eq!(
        agent.respond_refused_total(),
        refused_before,
        "a rule the plane can execute must not feed the refusal counter"
    );
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

    // The fourth copy. `ferrumctl` is the offline half of the same channel —
    // it is what an operator runs to look at bytes a cluster is serving — and
    // until this line the row in docs/MVP-1-BOUNDARY.md said "four copies"
    // while the test under it exercised three. A codec copy that nothing
    // compares is the drift this test exists to catch, one crate over.
    let (cli_key, cli_sig, cli_raw) =
        ferrum_cli::fsig::decode_fsig(&sealed).expect("ferrumctl decodes controller bytes");
    assert_eq!(cli_raw, payload, "the CLI reads a different payload");
    assert_eq!(
        cli_key, trust_root,
        "the CLI reads a different embedded key"
    );
    assert_eq!(cli_sig.len(), 64, "an Ed25519 signature is 64 bytes");

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

/// One namespace, two planes, one answer.
///
/// `ferrum-ebpf/src/eval.rs` has carried the sentence "admission fails closed on
/// exactly this condition; the runtime plane must not diverge" in a comment
/// since the selector was written, and nothing executed it. It was also false:
/// admission raised `Integrity` and the runtime raised `LabelsUnknown` for a
/// namespace that had been listed and simply carries no labels, so both planes
/// treated "seen, and it has none" as "never seen" — admission denying the Pod
/// and the agent flagging every record on the node, forever, on any cluster
/// with one unlabelled namespace.
///
/// The gate runs the shipped `prod-restricted` selector (`ferrum.io/zone In
/// [pci, secrets]`) against both planes for the same namespace in both states,
/// and requires the pair of answers to agree: listed-without-labels is a
/// non-match on both sides, never-listed is fail-closed on both sides.
#[test]
fn both_planes_answer_an_unlabelled_namespace_the_same_way() {
    use ferrum_admission::{LabelSource, StaticLabels};
    use ferrum_ebpf::{parse_febp, selector_match, SelectorMatch};
    use ferrum_k8smeta::source::{ContainerRecord, PodCache, PodMetadataSource};
    use ferrum_k8smeta::{LabelObject, PodRecord};
    use std::collections::BTreeMap;

    let mut spec = prod_restricted().spec;
    spec.mode = PolicyMode::Enforce;
    let bundle = compile_cluster_policy(&spec).expect("compile prod-restricted");
    let ebpf = parse_febp(&bundle.ebpf_spec).expect("parse FEBP");
    assert!(
        !ebpf.selector.namespace_selector.is_empty(),
        "the fixture must carry a namespace selector, or this gate asserts nothing"
    );
    let admission = program();

    /// The runtime plane's answer for a pod in `namespace`, with the label
    /// caches told what they listed. `None` for the namespace means the list
    /// never named it.
    fn runtime(namespace: &str, namespace_labels: Option<BTreeMap<String, String>>) -> PodRecord {
        let mut cache = PodCache::new("node-a");
        cache.upsert(PodRecord {
            uid: "uid-1".into(),
            namespace: namespace.into(),
            name: "web-1".into(),
            node_name: "node-a".into(),
            service_account: "web".into(),
            resource_version: "1".into(),
            labels: BTreeMap::new(),
            namespace_labels: BTreeMap::new(),
            service_account_labels: BTreeMap::new(),
            namespace_labels_observed: false,
            service_account_labels_observed: false,
            containers: vec![ContainerRecord {
                name: "app".into(),
                id: "a".repeat(64),
                image: "registry.internal.example/app@sha256:abc".into(),
                image_digest: "sha256:abc".into(),
            }],
        });
        cache.mark_applied_at(std::time::Instant::now());
        let mut listed = Vec::new();
        if let Some(labels) = namespace_labels {
            listed.push(LabelObject {
                namespace: String::new(),
                name: namespace.to_string(),
                labels,
                resource_version: "1".into(),
            });
        }
        cache
            .namespaces_mut()
            .try_replace_all(listed)
            .expect("namespace list fits");
        cache
            .service_accounts_mut()
            .try_replace_all(vec![LabelObject {
                namespace: namespace.to_string(),
                name: "web".into(),
                labels: BTreeMap::new(),
                resource_version: "1".into(),
            }])
            .expect("serviceaccount list fits");
        cache.snapshot().expect("snapshot").remove(0)
    }

    // A warm cache that listed `plain` and found no labels on it.
    let listed_unlabelled = StaticLabels::default()
        .with_namespace("plain", BTreeMap::new())
        .with_service_account("plain", "default", BTreeMap::new())
        .warm();
    // Privileged, so "allowed" can only mean the policy did not apply: a
    // compliant Pod would be allowed either way and would prove nothing.
    let mut subject = compliant_subject();
    subject.namespace = "plain".into();
    subject.privileged = true;
    subject.namespace_labels = listed_unlabelled.namespace_labels("plain");
    subject.service_account_labels = listed_unlabelled.service_account_labels("plain", "default");
    assert_eq!(
        subject.namespace_labels,
        Some(BTreeMap::new()),
        "a listed namespace with no labels is observed and empty"
    );
    let decision = admit(&admission, &subject, &[], now());
    assert!(
        decision.allowed && !decision.fail_closed,
        "admission must answer a listed unlabelled namespace with a selector miss, not an \
         integrity failure: {:?}",
        decision.reasons
    );

    let pod = runtime("plain", Some(BTreeMap::new()));
    assert!(pod.namespace_labels_observed);
    assert_eq!(
        selector_match(&ebpf.selector, &pod.identity(&pod.containers[0])),
        SelectorMatch::NoMatch,
        "the runtime plane must answer the same namespace the same way"
    );

    // The same namespace, never listed. Both planes fail closed, and this is
    // the half that must not be weakened by fixing the half above.
    let never_listed = StaticLabels::default().warm();
    let mut unseen = compliant_subject();
    unseen.namespace = "plain".into();
    unseen.privileged = true;
    unseen.namespace_labels = never_listed.namespace_labels("plain");
    unseen.service_account_labels = never_listed.service_account_labels("plain", "default");
    assert_eq!(unseen.namespace_labels, None);
    let decision = admit(&admission, &unseen, &[], now());
    assert!(
        !decision.allowed && decision.fail_closed,
        "a namespace nothing ever listed is still an integrity failure: {:?}",
        decision.reasons
    );
    assert!(
        decision
            .reasons
            .iter()
            .any(|r| r.contains("never observed")),
        "the deny must name what was not known: {:?}",
        decision.reasons
    );

    let pod = runtime("plain", None);
    assert!(!pod.namespace_labels_observed);
    assert_eq!(
        selector_match(&ebpf.selector, &pod.identity(&pod.containers[0])),
        SelectorMatch::LabelsUnknown,
        "the runtime plane must fail closed on the same namespace admission fails closed on"
    );
}
