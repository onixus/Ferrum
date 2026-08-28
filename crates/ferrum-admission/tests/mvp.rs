//! MVP admit cases. Compiler is a test-only fixture source, not a runtime dep.

mod common;

use chrono::{DateTime, Days, TimeZone, Utc};
use ferrum_admission::{
    admit, admit_bytes, admit_digest, admit_signed, parse_program, AdmissionSubject, Patch,
    ADMISSION_ABI, RULE_ADDED_CAPABILITIES, RULE_CLUSTER_ADMIN_BIND, RULE_HOST_PATH, RULE_HOST_PID,
    RULE_LATEST_TAG, RULE_PRIVILEGED, RULE_RUN_AS_ROOT, RULE_UNSIGNED,
};
use ferrum_api::{
    AdmitDeny, AdmitMutate, AdmitSpec, ClusterSecurityPolicy, ClusterSecurityPolicySpec,
    ExceptionTarget, FailurePolicy, PolicyExceptionSpec, PolicyMode, PssProfile,
    SecurityPolicySpec, SupplySpec, TrustRoot,
};
use ferrum_compiler::{bundle_digest_material, compile_cluster_policy};
use ferrum_crypto::{public_key_from_secret, sign_bundle};
use ferrum_ids::{Digest, AGENT_ABI};

const FIXTURE_ED25519_PK: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 26, 12, 0, 0).unwrap()
}

fn compile(spec: ClusterSecurityPolicySpec) -> Vec<u8> {
    let bundle = compile_cluster_policy(&spec).expect("compile fixture");
    match parse_program(&bundle.admission_program) {
        Ok(parsed) if public_keys_match(&parsed.supply.trust_roots, &spec.supply.trust_roots) => {
            bundle.admission_program
        }
        _ => common::encode_cluster(&spec),
    }
}

fn compile_namespaced(spec: SecurityPolicySpec) -> Vec<u8> {
    let bundle = ferrum_compiler::compile_namespaced_policy(&spec).expect("compile namespaced");
    match parse_program(&bundle.admission_program) {
        Ok(parsed) if public_keys_match(&parsed.supply.trust_roots, &spec.supply.trust_roots) => {
            bundle.admission_program
        }
        _ => common::encode_namespaced(&spec),
    }
}

fn public_keys_match(got: &[TrustRoot], want: &[TrustRoot]) -> bool {
    got.len() == want.len()
        && got
            .iter()
            .zip(want)
            .all(|(g, w)| g.public_keys == w.public_keys)
}

fn trust_roots() -> Vec<TrustRoot> {
    vec![TrustRoot {
        name: "org-cosign".into(),
        keyless_issuer_allow: vec!["https://token.actions.githubusercontent.com".into()],
        public_keys: vec![FIXTURE_ED25519_PK.into()],
    }]
}

fn enforce_spec() -> ClusterSecurityPolicySpec {
    ClusterSecurityPolicySpec {
        mode: PolicyMode::Enforce,
        supply: SupplySpec {
            require_signed: true,
            deny_unsigned: true,
            deny_latest_tag: true,
            trust_roots: trust_roots(),
        },
        admit: AdmitSpec {
            failure_policy: FailurePolicy::Fail,
            pss: PssProfile::Restricted,
            deny: AdmitDeny {
                privileged: true,
                host_pid: true,
                host_ipc: true,
                host_network: true,
                host_path: true,
                allow_privilege_escalation: true,
                run_as_root: true,
                wildcards_rbac: true,
                cluster_admin_bind: true,
                added_capabilities: vec!["SYS_ADMIN".into()],
            },
            mutate: AdmitMutate {
                inject_seccomp_runtime_default: true,
                drop_all_capabilities: true,
                read_only_root_filesystem: true,
            },
        },
        ..Default::default()
    }
}

fn compliant() -> AdmissionSubject {
    AdmissionSubject {
        policy_name: "prod-restricted".into(),
        image: "registry.internal.example/app@sha256:abc".into(),
        image_signed: true,
        ..Default::default()
    }
}

fn pss_empty_deny(pss: PssProfile, mode: PolicyMode) -> ClusterSecurityPolicySpec {
    ClusterSecurityPolicySpec {
        mode,
        supply: SupplySpec {
            require_signed: true,
            deny_unsigned: true,
            trust_roots: trust_roots(),
            ..Default::default()
        },
        admit: AdmitSpec {
            failure_policy: FailurePolicy::Fail,
            pss,
            deny: AdmitDeny::default(),
            mutate: AdmitMutate::default(),
        },
        ..Default::default()
    }
}

fn live_exception(namespace: &str, policy: &str, rule: &str) -> PolicyExceptionSpec {
    PolicyExceptionSpec {
        ticket: "JIRA-18421".into(),
        requested_by: "sre".into(),
        approved_by: "ib".into(),
        reason: "temporary debug sidecar after incident".into(),
        expires_at: now() + Days::new(7),
        mode: PolicyMode::Audit,
        four_eyes: true,
        target: ExceptionTarget {
            namespace: namespace.into(),
            policies: vec![policy.into()],
            rules: vec![rule.into()],
        },
    }
}

#[test]
fn privileged_enforce_denies() {
    let program = compile(enforce_spec());
    let mut subject = compliant();
    subject.privileged = true;
    let decision = admit_bytes(&program, &subject, &[], now());
    assert!(!decision.allowed);
    assert!(!decision.fail_closed);
    assert!(decision.rule_ids.iter().any(|r| r == RULE_PRIVILEGED));
}

#[test]
fn observe_mode_does_not_deny_privileged() {
    let mut spec = enforce_spec();
    spec.mode = PolicyMode::Observe;
    let program = compile(spec);
    let mut subject = compliant();
    subject.privileged = true;
    let decision = admit_bytes(&program, &subject, &[], now());
    assert!(decision.allowed);
    assert!(!decision.fail_closed);
    assert!(decision.rule_ids.iter().any(|r| r == RULE_PRIVILEGED));
}

#[test]
fn audit_mode_does_not_deny_privileged() {
    let mut spec = enforce_spec();
    spec.mode = PolicyMode::Audit;
    let program = compile(spec);
    let mut subject = compliant();
    subject.privileged = true;
    let decision = admit_bytes(&program, &subject, &[], now());
    assert!(decision.allowed);
    assert!(decision.rule_ids.iter().any(|r| r == RULE_PRIVILEGED));
}

#[test]
fn unsigned_image_denies_when_deny_unsigned() {
    let program = compile(enforce_spec());
    let mut subject = compliant();
    subject.image_signed = false;
    let decision = admit_bytes(&program, &subject, &[], now());
    assert!(!decision.allowed);
    assert!(decision.rule_ids.iter().any(|r| r == RULE_UNSIGNED));
}

#[test]
fn latest_tag_denies_when_deny_latest_tag() {
    let program = compile(enforce_spec());
    let mut subject = compliant();
    subject.image = "registry.internal.example/app:latest".into();
    let decision = admit_bytes(&program, &subject, &[], now());
    assert!(!decision.allowed);
    assert!(decision.rule_ids.iter().any(|r| r == RULE_LATEST_TAG));
}

#[test]
fn cluster_admin_bind_denies() {
    let program = compile(enforce_spec());
    let mut subject = compliant();
    subject.cluster_admin_bind = true;
    let decision = admit_bytes(&program, &subject, &[], now());
    assert!(!decision.allowed);
    assert!(decision
        .rule_ids
        .iter()
        .any(|r| r == RULE_CLUSTER_ADMIN_BIND));
}

#[test]
fn compliant_pod_allowed_with_mutations() {
    let program = compile(enforce_spec());
    let decision = admit_bytes(&program, &compliant(), &[], now());
    assert!(decision.allowed);
    assert!(!decision.fail_closed);
    assert!(decision.rule_ids.is_empty());
    assert_eq!(
        decision.patches,
        vec![
            Patch::InjectSeccompRuntimeDefault,
            Patch::DropAllCapabilities,
            Patch::ReadOnlyRootFilesystem,
        ]
    );
}

#[test]
fn invalid_bundle_denies_fail_closed() {
    for bytes in [&b""[..], &b"XXXX"[..], &b"FADM"[..], &b"not-a-program"[..]] {
        let decision = admit_bytes(bytes, &compliant(), &[], now());
        assert!(!decision.allowed, "bytes={bytes:?}");
        assert!(decision.fail_closed, "bytes={bytes:?}");
    }
}

#[test]
fn abi_mismatch_denies_fail_closed() {
    let mut program = compile(enforce_spec());
    program[4..8].copy_from_slice(&0xFFFFu32.to_le_bytes());
    let decision = admit_bytes(&program, &compliant(), &[], now());
    assert!(!decision.allowed);
    assert!(decision.fail_closed);
    match parse_program(&program) {
        Err(_) => {}
        Ok(_) => panic!("unknown ABI must not parse"),
    }
}

#[test]
fn truncated_and_trailing_bytes_deny() {
    let program = compile(enforce_spec());
    let truncated = &program[..program.len().saturating_sub(4)];
    let trunc = admit_bytes(truncated, &compliant(), &[], now());
    assert!(!trunc.allowed);
    assert!(trunc.fail_closed);

    let mut trailing = program.clone();
    trailing.extend_from_slice(&[0xFF, 0x00]);
    let extra = admit_bytes(&trailing, &compliant(), &[], now());
    assert!(!extra.allowed);
    assert!(extra.fail_closed);
}

#[test]
fn bad_signature_denies_fail_closed() {
    let program = compile(enforce_spec());
    let secret = [0x11u8; 32];
    let public = public_key_from_secret(&secret).expect("public");
    let mut sig = sign_bundle(&program, &secret).expect("sign");
    sig[0] ^= 0x01;
    let decision = admit_signed(&program, &sig, &public, &compliant(), &[], now());
    assert!(!decision.allowed);
    assert!(decision.fail_closed);
}

#[test]
fn empty_signature_denies_fail_closed() {
    let program = compile(enforce_spec());
    let secret = [0x11u8; 32];
    let public = public_key_from_secret(&secret).expect("public");
    let decision = admit_signed(&program, &[], &public, &compliant(), &[], now());
    assert!(!decision.allowed);
    assert!(decision.fail_closed);
}

#[test]
fn digest_mismatch_denies_fail_closed() {
    let program = compile(enforce_spec());
    let expected = Digest::new("00".repeat(32));
    let decision = admit_digest(&program, &expected, &compliant(), &[], now());
    assert!(!decision.allowed);
    assert!(decision.fail_closed);
}

#[test]
fn valid_signature_and_digest_allow_compliant() {
    let program = compile(enforce_spec());
    let secret = [0x11u8; 32];
    let public = public_key_from_secret(&secret).expect("public");
    let sig = sign_bundle(&program, &secret).expect("sign");
    let signed = admit_signed(&program, &sig, &public, &compliant(), &[], now());
    assert!(signed.allowed);
    assert!(!signed.fail_closed);

    let digest = ferrum_crypto::bundle_digest(&program);
    let hashed = admit_digest(&program, &digest, &compliant(), &[], now());
    assert!(hashed.allowed);
}

#[test]
fn in_scope_exception_waives_privileged_before_expiry() {
    let program = compile(enforce_spec());
    let mut subject = compliant();
    subject.privileged = true;
    let exceptions = [live_exception("", "prod-restricted", RULE_PRIVILEGED)];
    let decision = admit_bytes(&program, &subject, &exceptions, now());
    assert!(decision.allowed);
    assert!(!decision.rule_ids.iter().any(|r| r == RULE_PRIVILEGED));
}

#[test]
fn expired_exception_does_not_waive() {
    let program = compile(enforce_spec());
    let mut subject = compliant();
    subject.privileged = true;
    let mut ex = live_exception("", "prod-restricted", RULE_PRIVILEGED);
    ex.expires_at = now() - Days::new(1);
    let decision = admit_bytes(&program, &subject, &[ex], now());
    assert!(!decision.allowed);
}

#[test]
fn empty_target_exception_does_not_waive() {
    let program = compile(enforce_spec());
    let mut subject = compliant();
    subject.privileged = true;
    let mut ex = live_exception("", "prod-restricted", RULE_PRIVILEGED);
    ex.target = ExceptionTarget::default();
    let decision = admit_bytes(&program, &subject, &[ex], now());
    assert!(!decision.allowed);
}

#[test]
fn namespaced_exception_does_not_waive_cluster_hit() {
    let program = compile(enforce_spec());
    let mut subject = compliant();
    subject.namespace = "payments".into();
    subject.privileged = true;
    let exceptions = [live_exception(
        "payments",
        "prod-restricted",
        RULE_PRIVILEGED,
    )];
    let decision = admit_bytes(&program, &subject, &exceptions, now());
    assert!(!decision.allowed);
}

#[test]
fn namespaced_ignore_does_not_fail_open() {
    let spec = SecurityPolicySpec {
        mode: PolicyMode::Enforce,
        supply: SupplySpec {
            deny_unsigned: true,
            trust_roots: trust_roots(),
            ..Default::default()
        },
        admit: AdmitSpec {
            failure_policy: FailurePolicy::Fail,
            deny: AdmitDeny {
                privileged: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let mut program = compile_namespaced(spec);
    // failurePolicy is at offset 14 (FADM + abi + mode + disabled + i32).
    assert_eq!(program[14], 0);
    program[14] = 1;
    let parsed = parse_program(&program).expect("Ignore byte still parses");
    assert_eq!(parsed.admit.failure_policy, FailurePolicy::Ignore);
    assert_eq!(parsed.effective_failure_policy(true), FailurePolicy::Fail);

    let mut subject = compliant();
    subject.policy_namespace = "payments".into();
    subject.namespace = "payments".into();
    subject.privileged = true;
    let decision = admit(&parsed, &subject, &[], now());
    assert!(!decision.allowed);
    assert_eq!(decision.failure_policy, FailurePolicy::Fail);
}

#[test]
fn cluster_ignore_is_break_glass_not_integrity_bypass() {
    let mut spec = enforce_spec();
    spec.admit.failure_policy = FailurePolicy::Ignore;
    let program = compile(spec);
    let parsed = parse_program(&program).expect("cluster Ignore parses");
    assert_eq!(
        parsed.effective_failure_policy(false),
        FailurePolicy::Ignore
    );
    let mut garbage = program;
    garbage[0] = b'X';
    let decision = admit_bytes(&garbage, &compliant(), &[], now());
    assert!(!decision.allowed);
    assert!(decision.fail_closed);
    assert_eq!(decision.failure_policy, FailurePolicy::Fail);
}

#[test]
fn implicit_latest_and_hostpid_and_caps_deny() {
    let program = compile(enforce_spec());
    let mut latest = compliant();
    latest.image = "nginx".into();
    let decision = admit_bytes(&program, &latest, &[], now());
    assert!(!decision.allowed);
    assert!(decision.rule_ids.iter().any(|r| r == RULE_LATEST_TAG));

    let mut host = compliant();
    host.host_pid = true;
    let decision = admit_bytes(&program, &host, &[], now());
    assert!(!decision.allowed);
    assert!(decision.rule_ids.iter().any(|r| r == RULE_HOST_PID));

    let mut caps = compliant();
    caps.added_capabilities = vec!["SYS_ADMIN".into()];
    let decision = admit_bytes(&program, &caps, &[], now());
    assert!(!decision.allowed);
    assert!(decision
        .rule_ids
        .iter()
        .any(|r| r == RULE_ADDED_CAPABILITIES));
}

#[test]
fn selector_miss_does_not_apply_policy() {
    let mut spec = enforce_spec();
    spec.selector
        .workload_selector
        .match_labels
        .insert("app".into(), "payments".into());
    let program = compile(spec);
    let mut subject = compliant();
    subject.privileged = true;
    let decision = admit_bytes(&program, &subject, &[], now());
    assert!(decision.allowed);
    assert!(decision.rule_ids.is_empty());
}

#[test]
fn signed_frmb_bundle_evaluates() {
    let spec = enforce_spec();
    let compiled = compile_cluster_policy(&spec).expect("compile");
    let fadm = compile(spec);
    let raw = bundle_digest_material(
        AGENT_ABI,
        ADMISSION_ABI,
        &fadm,
        &compiled.ebpf_spec,
        &compiled.wasm,
    )
    .expect("material");
    let secret = [0x11u8; 32];
    let public = public_key_from_secret(&secret).expect("public");
    let sig = sign_bundle(&raw, &secret).expect("sign");
    let allowed = admit_signed(&raw, &sig, &public, &compliant(), &[], now());
    assert!(allowed.allowed);

    let mut privileged = compliant();
    privileged.privileged = true;
    let denied = admit_signed(&raw, &sig, &public, &privileged, &[], now());
    assert!(!denied.allowed);
}

#[test]
fn empty_expected_digest_denies() {
    let program = compile(enforce_spec());
    let decision = admit_digest(&program, &Digest::new(""), &compliant(), &[], now());
    assert!(!decision.allowed);
    assert!(decision.fail_closed);
}

#[test]
fn require_signed_without_public_keys_denies_even_if_marked_signed() {
    let mut spec = enforce_spec();
    spec.supply.trust_roots[0].public_keys.clear();
    let program = common::encode_cluster(&spec);
    let parsed = parse_program(&program).expect("keyless-only program still parses");
    assert!(parsed.supply.trust_roots[0].public_keys.is_empty());
    let decision = admit(&parsed, &compliant(), &[], now());
    assert!(!decision.allowed);
    assert!(decision.rule_ids.iter().any(|r| r == RULE_UNSIGNED));
}

#[test]
fn parser_reads_public_keys_after_keyless_issuers() {
    let program = compile(enforce_spec());
    let parsed = parse_program(&program).expect("parse");
    assert_eq!(
        parsed.supply.trust_roots[0].keyless_issuer_allow,
        vec!["https://token.actions.githubusercontent.com"]
    );
    assert_eq!(
        parsed.supply.trust_roots[0].public_keys,
        vec![FIXTURE_ED25519_PK]
    );
}

#[test]
fn pss_restricted_empty_deny_privileged() {
    let program = compile(pss_empty_deny(PssProfile::Restricted, PolicyMode::Enforce));
    let mut subject = compliant();
    subject.privileged = true;
    let decision = admit_bytes(&program, &subject, &[], now());
    assert!(!decision.allowed);
    assert!(!decision.fail_closed);
    assert!(decision.rule_ids.iter().any(|r| r == RULE_PRIVILEGED));
}

#[test]
fn pss_restricted_empty_deny_run_as_root() {
    let program = compile(pss_empty_deny(PssProfile::Restricted, PolicyMode::Enforce));
    let mut subject = compliant();
    subject.run_as_root = true;
    let decision = admit_bytes(&program, &subject, &[], now());
    assert!(!decision.allowed);
    assert!(decision.rule_ids.iter().any(|r| r == RULE_RUN_AS_ROOT));
}

#[test]
fn pss_restricted_empty_deny_host_path() {
    let program = compile(pss_empty_deny(PssProfile::Restricted, PolicyMode::Enforce));
    let mut subject = compliant();
    subject.host_path = true;
    let decision = admit_bytes(&program, &subject, &[], now());
    assert!(!decision.allowed);
    assert!(decision.rule_ids.iter().any(|r| r == RULE_HOST_PATH));
}

#[test]
fn pss_restricted_empty_deny_capabilities() {
    let program = compile(pss_empty_deny(PssProfile::Restricted, PolicyMode::Enforce));
    let mut sys_admin = compliant();
    sys_admin.added_capabilities = vec!["SYS_ADMIN".into()];
    let denied = admit_bytes(&program, &sys_admin, &[], now());
    assert!(!denied.allowed);
    assert!(denied.rule_ids.iter().any(|r| r == RULE_ADDED_CAPABILITIES));

    let mut net_bind = compliant();
    net_bind.added_capabilities = vec!["NET_BIND_SERVICE".into()];
    let allowed = admit_bytes(&program, &net_bind, &[], now());
    assert!(allowed.allowed);
    assert!(!allowed.fail_closed);
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
fn pss_baseline_empty_deny_host_pid_and_host_path() {
    let program = compile(pss_empty_deny(PssProfile::Baseline, PolicyMode::Enforce));
    let mut host_pid = compliant();
    host_pid.host_pid = true;
    let denied = admit_bytes(&program, &host_pid, &[], now());
    assert!(!denied.allowed);
    assert!(denied.rule_ids.iter().any(|r| r == RULE_HOST_PID));

    let mut host_path = compliant();
    host_path.host_path = true;
    let denied_path = admit_bytes(&program, &host_path, &[], now());
    assert!(!denied_path.allowed);
    assert!(denied_path.rule_ids.iter().any(|r| r == RULE_HOST_PATH));
    assert!(denied_path.patches.is_empty());
}

#[test]
fn pss_baseline_empty_deny_capabilities() {
    let program = compile(pss_empty_deny(PssProfile::Baseline, PolicyMode::Enforce));
    let mut sys_admin = compliant();
    sys_admin.added_capabilities = vec!["SYS_ADMIN".into()];
    let denied = admit_bytes(&program, &sys_admin, &[], now());
    assert!(!denied.allowed);
    assert!(denied.rule_ids.iter().any(|r| r == RULE_ADDED_CAPABILITIES));

    let mut chown = compliant();
    chown.added_capabilities = vec!["CHOWN".into()];
    let allowed = admit_bytes(&program, &chown, &[], now());
    assert!(allowed.allowed);
    assert!(allowed.rule_ids.is_empty());
    assert!(allowed.patches.is_empty());
}

#[test]
fn pss_privileged_empty_deny_allows_privileged() {
    let program = compile(pss_empty_deny(PssProfile::Privileged, PolicyMode::Enforce));
    let mut subject = compliant();
    subject.privileged = true;
    let decision = admit_bytes(&program, &subject, &[], now());
    assert!(decision.allowed);
    assert!(decision.rule_ids.is_empty());
}

#[test]
fn pss_restricted_observe_and_audit_do_not_fail_request() {
    for mode in [PolicyMode::Observe, PolicyMode::Audit] {
        let program = compile(pss_empty_deny(PssProfile::Restricted, mode));
        let mut subject = compliant();
        subject.privileged = true;
        let decision = admit_bytes(&program, &subject, &[], now());
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
fn prod_restricted_example_audit_records_privileged() {
    let yaml = include_str!("../../../policies/examples/prod-restricted.yaml");
    let mut obj: ClusterSecurityPolicy = serde_yaml::from_str(yaml).expect("example yaml");
    if obj.spec.supply.trust_roots[0].public_keys.is_empty() {
        obj.spec.supply.trust_roots[0]
            .public_keys
            .push(FIXTURE_ED25519_PK.into());
    }
    let program = compile(obj.spec);
    assert_eq!(&program[..4], ferrum_admission::ADMISSION_MAGIC);
    assert_eq!(&program[4..8], &ADMISSION_ABI.to_le_bytes());
    let parsed = parse_program(&program).expect("prod-restricted FADM");
    assert_eq!(parsed.supply.trust_roots[0].public_keys[0].len(), 64);
    let mut subject = compliant();
    subject.namespace_labels = Some(
        [("ferrum.io/zone".to_string(), "pci".to_string())]
            .into_iter()
            .collect(),
    );
    subject.privileged = true;
    let decision = admit_bytes(&program, &subject, &[], now());
    assert!(decision.allowed);
    assert_eq!(decision.mode, PolicyMode::Audit);
    assert!(decision.rule_ids.iter().any(|r| r == RULE_PRIVILEGED));
}
