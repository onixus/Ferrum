//! AdmissionReview webhook: MVP deny/allow, FSIG fail-closed, exceptions.

mod common;

use chrono::{DateTime, Days, TimeZone, Utc};
use ferrum_admission::{
    encode_fsig, handle_review_bytes, load_bundle, load_path, load_source, parse_program,
    poll_bundle_file, poll_exceptions_file, AdmissionProgram, ReviewConfig, WebhookState,
    ADMISSION_ABI, BUNDLE_DIGEST_KEY, BUNDLE_FSIG_KEY, EXCEPTIONS_FSIG_KEY,
    IMAGE_SIGNATURE_ANNOTATION, RULE_CLUSTER_ADMIN_BIND, RULE_PRIVILEGED, RULE_UNSIGNED,
};
use ferrum_admission::{ClusterLabels, StaticLabels};
use ferrum_api::{
    AdmitDeny, AdmitMutate, AdmitSpec, ClusterSecurityPolicy, ClusterSecurityPolicySpec,
    ExceptionTarget, FailurePolicy, PolicyExceptionSpec, PolicyMode, PssProfile, SupplySpec,
    TrustRoot,
};
use ferrum_common::FerrumError;
use ferrum_compiler::{bundle_digest_material, compile_cluster_policy};
use ferrum_crypto::{public_key_from_secret, sign_bundle};
use ferrum_ids::AGENT_ABI;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};

const SK: [u8; 32] = [0x11; 32];
const SK_OTHER: [u8; 32] = [0x22; 32];
const IMAGE: &str = "registry.internal.example/app@sha256:abc";

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 26, 12, 0, 0).unwrap()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn b64_encode(data: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < data.len() {
        let rem = data.len() - i;
        let b0 = data[i];
        let b1 = if rem > 1 { data[i + 1] } else { 0 };
        let b2 = if rem > 2 { data[i + 2] } else { 0 };
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        if rem > 1 {
            out.push(B64[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if rem > 2 {
            out.push(B64[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

fn b64_decode(s: &str) -> Vec<u8> {
    fn val(b: u8) -> u8 {
        match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => 0,
        }
    }
    let s = s.trim();
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i + 3 < b.len() {
        let n = (u32::from(val(b[i])) << 18)
            | (u32::from(val(b[i + 1])) << 12)
            | (u32::from(val(b[i + 2])) << 6)
            | u32::from(val(b[i + 3]));
        out.push((n >> 16) as u8);
        if b[i + 2] != b'=' {
            out.push((n >> 8) as u8);
        }
        if b[i + 3] != b'=' {
            out.push(n as u8);
        }
        i += 4;
    }
    out
}

fn pk_hex(sk: &[u8; 32]) -> String {
    hex_encode(&public_key_from_secret(sk).expect("pk"))
}

fn compile(spec: ClusterSecurityPolicySpec) -> Vec<u8> {
    let bundle = compile_cluster_policy(&spec).expect("compile fixture");
    match parse_program(&bundle.admission_program) {
        Ok(parsed)
            if parsed.supply.trust_roots.first().map(|r| &r.public_keys)
                == spec.supply.trust_roots.first().map(|r| &r.public_keys) =>
        {
            bundle.admission_program
        }
        _ => common::encode_cluster(&spec),
    }
}

fn enforce_spec(mode: PolicyMode, pk_hex: String) -> ClusterSecurityPolicySpec {
    ClusterSecurityPolicySpec {
        mode,
        supply: SupplySpec {
            require_signed: true,
            deny_unsigned: true,
            deny_latest_tag: true,
            trust_roots: vec![TrustRoot {
                name: "org-cosign".into(),
                public_keys: vec![pk_hex],
                ..Default::default()
            }],
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

fn make_signed(spec: ClusterSecurityPolicySpec, sk: &[u8; 32]) -> (Vec<u8>, Vec<u8>, String) {
    let fadm = compile(spec);
    let raw = bundle_digest_material(AGENT_ABI, ADMISSION_ABI, &fadm, b"", b"").expect("frmb");
    let pk = public_key_from_secret(sk).expect("pk");
    let sig = sign_bundle(&raw, sk).expect("sign");
    let fsig = encode_fsig(&raw, &sig, &pk).expect("fsig");
    let digest = ferrum_crypto::bundle_digest(&raw);
    (fsig, pk, digest.as_str().to_string())
}

fn make_fsig(spec: ClusterSecurityPolicySpec, sk: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let (fsig, pk, _) = make_signed(spec, sk);
    (fsig, pk)
}

fn controller_secret(fsig: &[u8], digest_hex: Option<&str>) -> Vec<u8> {
    let mut data = serde_json::Map::new();
    data.insert(BUNDLE_FSIG_KEY.into(), json!(b64_encode(fsig)));
    if let Some(digest_hex) = digest_hex {
        data.insert(
            BUNDLE_DIGEST_KEY.into(),
            json!(b64_encode(digest_hex.as_bytes())),
        );
    }
    serde_json::to_vec(&json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "ferrum-bundle-prod-restricted",
            "namespace": "ferrum"
        },
        "type": "Opaque",
        "data": data
    }))
    .expect("secret json")
}

fn assert_integrity<T: std::fmt::Debug>(result: Result<T, FerrumError>) {
    match result {
        Err(FerrumError::Integrity(_)) => {}
        other => panic!("expected Integrity, got {other:?}"),
    }
}

fn webhook_state(fsig: &[u8], pk: &[u8]) -> WebhookState {
    WebhookState::new(
        load_ok(fsig, pk),
        pk.to_vec(),
        vec![],
        ReviewConfig::default(),
    )
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ferrum-admission-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn write_secret_dir(dir: &std::path::Path, fsig: &[u8], digest: &str) {
    std::fs::write(dir.join(BUNDLE_FSIG_KEY), fsig).expect("bundle.fsig");
    std::fs::write(dir.join(BUNDLE_DIGEST_KEY), digest.as_bytes()).expect("digest");
}

fn load_ok(fsig: &[u8], pk: &[u8]) -> AdmissionProgram {
    load_bundle(fsig, pk).expect("verified bundle")
}

fn image_annotations(image: &str, sk: &[u8; 32]) -> Value {
    let sig = sign_bundle(image.as_bytes(), sk).expect("image sig");
    json!({ IMAGE_SIGNATURE_ANNOTATION: hex_encode(&sig) })
}

fn pod(image: &str, annotations: Value, privileged: bool) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "app",
            "namespace": "default",
            "annotations": annotations
        },
        "spec": {
            "containers": [{
                "name": "app",
                "image": image,
                "securityContext": {
                    "privileged": privileged,
                    "allowPrivilegeEscalation": false,
                    "runAsNonRoot": true
                }
            }]
        }
    })
}

fn cluster_admin_bind() -> Value {
    json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": "break-glass"},
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": "cluster-admin"
        },
        "subjects": [{"kind": "User", "name": "alice"}]
    })
}

fn review(object: Value, uid: &str) -> Vec<u8> {
    let ns = object
        .pointer("/metadata/namespace")
        .cloned()
        .unwrap_or(json!(""));
    serde_json::to_vec(&json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": uid,
            "namespace": ns,
            "operation": "CREATE",
            "object": object
        }
    }))
    .expect("review json")
}

fn admit_review(
    body: &[u8],
    program: Option<&AdmissionProgram>,
    exceptions: &[PolicyExceptionSpec],
) -> Value {
    let reply = handle_review_bytes(body, program, exceptions, now());
    assert_eq!(reply.status, 200, "expected HTTP 200 AdmissionReview");
    serde_json::from_slice(&reply.body).expect("response json")
}

fn live_exception(policy: &str, rule: &str) -> PolicyExceptionSpec {
    PolicyExceptionSpec {
        ticket: "JIRA-18421".into(),
        requested_by: "sre".into(),
        approved_by: "ib".into(),
        reason: "temporary debug sidecar after incident".into(),
        expires_at: now() + Days::new(7),
        mode: PolicyMode::Audit,
        four_eyes: true,
        target: ExceptionTarget {
            namespace: String::new(),
            policies: vec![policy.into()],
            rules: vec![rule.into()],
        },
    }
}

fn enforce_program() -> (AdmissionProgram, Vec<u8>) {
    let (fsig, pk) = make_fsig(enforce_spec(PolicyMode::Enforce, pk_hex(&SK)), &SK);
    (load_ok(&fsig, &pk), pk)
}

#[test]
fn unsigned_image_deny() {
    let (program, _) = enforce_program();
    let obj = pod(IMAGE, json!({}), false);
    let resp = admit_review(&review(obj, "uid-unsigned"), Some(&program), &[]);
    assert_eq!(resp["response"]["uid"], "uid-unsigned");
    assert_eq!(resp["response"]["allowed"], false);
    let msg = resp["response"]["status"]["message"]
        .as_str()
        .unwrap_or_default();
    assert!(
        msg.contains("unsigned") || msg.contains(RULE_UNSIGNED),
        "{msg}"
    );
}

#[test]
fn privileged_deny() {
    let (program, _) = enforce_program();
    let obj = pod(IMAGE, image_annotations(IMAGE, &SK), true);
    let resp = admit_review(&review(obj, "uid-priv"), Some(&program), &[]);
    assert_eq!(resp["response"]["allowed"], false);
    let msg = resp["response"]["status"]["message"]
        .as_str()
        .unwrap_or_default();
    assert!(
        msg.contains("privileged") || msg.contains(RULE_PRIVILEGED),
        "{msg}"
    );
}

#[test]
fn cluster_admin_bind_deny() {
    let (program, _) = enforce_program();
    let resp = admit_review(
        &review(cluster_admin_bind(), "uid-admin"),
        Some(&program),
        &[],
    );
    assert_eq!(resp["response"]["allowed"], false);
    let msg = resp["response"]["status"]["message"]
        .as_str()
        .unwrap_or_default();
    assert!(
        msg.contains("cluster-admin") || msg.contains(RULE_CLUSTER_ADMIN_BIND),
        "{msg}"
    );
}

#[test]
fn compliant_signed_digested_image_allow_with_enforce_patches() {
    let (program, _) = enforce_program();
    let obj = pod(IMAGE, image_annotations(IMAGE, &SK), false);
    let resp = admit_review(&review(obj, "uid-ok"), Some(&program), &[]);
    assert_eq!(resp["response"]["allowed"], true);
    assert_eq!(resp["response"]["patchType"], "JSONPatch");
    let patch_b64 = resp["response"]["patch"].as_str().expect("patch");
    let raw = b64_decode(patch_b64);
    let ops: Value = serde_json::from_slice(&raw).expect("rfc6902 json");
    let arr = ops.as_array().expect("patch array");
    assert!(!arr.is_empty());
    assert!(arr
        .iter()
        .all(|op| op.get("op").and_then(Value::as_str) == Some("add")
            && op.get("path").and_then(Value::as_str).is_some()));
    let paths: Vec<&str> = arr
        .iter()
        .filter_map(|op| op.get("path").and_then(Value::as_str))
        .collect();
    assert!(
        paths.iter().any(|p| p.contains("seccompProfile")),
        "{paths:?}"
    );
    assert!(
        paths.iter().any(|p| p.contains("capabilities")),
        "{paths:?}"
    );
    assert!(
        paths.iter().any(|p| p.contains("readOnlyRootFilesystem")),
        "{paths:?}"
    );
}

#[test]
fn truncated_and_wrong_key_fsig_fail_closed() {
    let (fsig, pk) = make_fsig(enforce_spec(PolicyMode::Enforce, pk_hex(&SK)), &SK);
    let body = review(pod(IMAGE, image_annotations(IMAGE, &SK), false), "uid-fsig");

    let truncated = &fsig[..fsig.len().saturating_sub(4)];
    let trunc_load = load_bundle(truncated, &pk);
    assert!(trunc_load.is_err(), "truncated FSIG must not load");
    let trunc_resp = admit_review(&body, trunc_load.as_ref().ok(), &[]);
    assert_eq!(trunc_resp["response"]["allowed"], false);
    assert_eq!(trunc_resp["response"]["uid"], "uid-fsig");

    let other = public_key_from_secret(&SK_OTHER).expect("other pk");
    let wrong = load_bundle(&fsig, &other);
    assert!(wrong.is_err(), "wrong-key FSIG must not load");
    let wrong_resp = admit_review(&body, wrong.as_ref().ok(), &[]);
    assert_eq!(wrong_resp["response"]["allowed"], false);
    assert!(wrong_resp["response"].get("patch").is_none());
}

#[test]
fn observe_privileged_allowed_no_patches() {
    let (fsig, pk) = make_fsig(enforce_spec(PolicyMode::Observe, pk_hex(&SK)), &SK);
    let program = load_ok(&fsig, &pk);
    let obj = pod(IMAGE, image_annotations(IMAGE, &SK), true);
    let resp = admit_review(&review(obj, "uid-obs"), Some(&program), &[]);
    assert_eq!(resp["response"]["allowed"], true);
    assert!(resp["response"].get("patch").is_none());
    assert!(resp["response"].get("patchType").is_none());
}

#[test]
fn garbage_body_deny() {
    let (program, _) = enforce_program();
    let reply = handle_review_bytes(b"{{{{not json", Some(&program), &[], now());
    assert_eq!(reply.status, 400);

    let reply = handle_review_bytes(
        b"{\"request\":{\"uid\":\"x\",\"object\":\"nope\"}}",
        Some(&program),
        &[],
        now(),
    );
    assert_eq!(reply.status, 200);
    let resp: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(resp["response"]["allowed"], false);
    assert_eq!(resp["response"]["uid"], "x");
}

#[test]
fn in_scope_exception_waives_only_that_rule() {
    let (program, _) = enforce_program();
    let obj = pod(IMAGE, image_annotations(IMAGE, &SK), true);
    let body = review(obj.clone(), "uid-ex");
    let exceptions = [live_exception("prod-restricted", RULE_PRIVILEGED)];

    let leaked = handle_review_bytes(&body, Some(&program), &exceptions, now());
    assert_eq!(leaked.status, 200);
    let leaked: Value = serde_json::from_slice(&leaked.body).unwrap();
    assert_eq!(
        leaked["response"]["allowed"], false,
        "empty policy_name must not copy exception targets"
    );

    let cfg = ReviewConfig {
        policy_name: "prod-restricted".into(),
        policy_namespace: String::new(),
        ..Default::default()
    };
    let waived = cfg.handle_bytes(&body, Some(&program), &exceptions, now());
    assert_eq!(waived.status, 200);
    let waived: Value = serde_json::from_slice(&waived.body).unwrap();
    assert_eq!(waived["response"]["allowed"], true);

    let wrong_rule = cfg.handle_bytes(
        &body,
        Some(&program),
        &[live_exception("prod-restricted", RULE_UNSIGNED)],
        now(),
    );
    let wrong_rule: Value = serde_json::from_slice(&wrong_rule.body).unwrap();
    assert_eq!(wrong_rule["response"]["allowed"], false);

    let other = ReviewConfig {
        policy_name: "other-policy".into(),
        policy_namespace: String::new(),
        ..Default::default()
    };
    let other = other.handle_bytes(&body, Some(&program), &exceptions, now());
    let other: Value = serde_json::from_slice(&other.body).unwrap();
    assert_eq!(
        other["response"]["allowed"], false,
        "exception must not waive a different policy"
    );
}

#[test]
fn prod_restricted_namespace_selector_without_labels_fail_closed() {
    let yaml = include_str!("../../../policies/examples/prod-restricted.yaml");
    let mut obj: ClusterSecurityPolicy = serde_yaml::from_str(yaml).expect("example yaml");
    obj.spec.supply.trust_roots[0].public_keys = vec![pk_hex(&SK)];
    let (fsig, pk) = make_fsig(obj.spec, &SK);
    let program = load_ok(&fsig, &pk);
    let pod = pod(IMAGE, image_annotations(IMAGE, &SK), false);
    let reply = handle_review_bytes(&review(pod, "uid-ns"), Some(&program), &[], now());
    assert_eq!(reply.status, 200);
    let resp: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(resp["response"]["allowed"], false);
    assert_eq!(resp["response"]["uid"], "uid-ns");
    let msg = resp["response"]["status"]["message"]
        .as_str()
        .unwrap_or_default();
    assert!(
        msg.contains("namespace") || msg.contains("labels") || msg.contains("fail closed"),
        "{msg}"
    );
}

fn handle_json(state: &WebhookState, body: &[u8]) -> Value {
    let reply = state.handle(body);
    assert_eq!(reply.status, 200, "expected HTTP 200 AdmissionReview");
    serde_json::from_slice(&reply.body).expect("response json")
}

fn deny_msg(resp: &Value) -> String {
    resp["response"]["status"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn controller_secret_json_loads_and_denies_unsigned_pod() {
    let (fsig, pk, digest) = make_signed(enforce_spec(PolicyMode::Enforce, pk_hex(&SK)), &SK);
    let secret = controller_secret(&fsig, Some(&digest));
    let program = load_source(&secret, &pk).expect("controller Secret + trust-root");
    let obj = pod(IMAGE, json!({}), false);
    let resp = admit_review(&review(obj, "uid-secret"), Some(&program), &[]);
    assert_eq!(resp["response"]["allowed"], false);
    let msg = deny_msg(&resp);
    assert!(
        msg.contains("unsigned") || msg.contains(RULE_UNSIGNED),
        "{msg}"
    );
}

#[test]
fn digest_mismatch_truncated_wrong_pin_do_not_swap() {
    let (fsig, pk, _digest) = make_signed(enforce_spec(PolicyMode::Enforce, pk_hex(&SK)), &SK);
    let state = webhook_state(&fsig, &pk);
    let unsigned = review(pod(IMAGE, json!({}), false), "uid-keep");

    assert_integrity(load_source(
        &controller_secret(&fsig, Some(&"00".repeat(32))),
        &pk,
    ));
    assert_integrity(state.try_reload(&controller_secret(&fsig, Some(&"00".repeat(32)))));

    let truncated = &fsig[..fsig.len().saturating_sub(4)];
    assert_integrity(load_source(truncated, &pk));
    assert_integrity(state.try_reload(truncated));

    let other = public_key_from_secret(&SK_OTHER).expect("other pk");
    assert_integrity(load_source(&fsig, &other));
    let (fsig_other, _) = make_fsig(
        enforce_spec(PolicyMode::Enforce, pk_hex(&SK_OTHER)),
        &SK_OTHER,
    );
    assert_integrity(state.try_reload(&fsig_other));

    let resp = handle_json(&state, &unsigned);
    assert_eq!(resp["response"]["allowed"], false);
    let msg = deny_msg(&resp);
    assert!(
        msg.contains("unsigned") || msg.contains(RULE_UNSIGNED),
        "{msg}"
    );
}

#[test]
fn empty_or_missing_bundle_fsig_is_integrity() {
    let pk = public_key_from_secret(&SK).expect("pk");
    let missing = br#"{"apiVersion":"v1","kind":"Secret","data":{}}"#;
    assert_integrity(load_source(missing, &pk));
    let empty = controller_secret(b"", None);
    assert_integrity(load_source(&empty, &pk));
}

#[test]
fn unsigned_frmb_or_fadm_in_secret_is_integrity() {
    let (fsig, pk) = make_fsig(enforce_spec(PolicyMode::Enforce, pk_hex(&SK)), &SK);
    let fadm = compile(enforce_spec(PolicyMode::Enforce, pk_hex(&SK)));
    let frmb = bundle_digest_material(AGENT_ABI, ADMISSION_ABI, &fadm, b"", b"").expect("frmb");
    assert_integrity(load_source(&controller_secret(&fadm, None), &pk));
    assert_integrity(load_source(&controller_secret(&frmb, None), &pk));
    let state = webhook_state(&fsig, &pk);
    assert_integrity(state.try_reload(&controller_secret(&fadm, None)));
    assert_integrity(state.try_reload(&controller_secret(&frmb, None)));
}

#[test]
fn successful_second_fsig_swaps_and_handle_uses_new_program() {
    let (fsig_enforce, pk, _) = make_signed(enforce_spec(PolicyMode::Enforce, pk_hex(&SK)), &SK);
    let (fsig_observe, pk2, digest) =
        make_signed(enforce_spec(PolicyMode::Observe, pk_hex(&SK)), &SK);
    assert_eq!(pk, pk2);
    let state = webhook_state(&fsig_enforce, &pk);
    let body = review(pod(IMAGE, image_annotations(IMAGE, &SK), true), "uid-swap");
    let denied = handle_json(&state, &body);
    assert_eq!(denied["response"]["allowed"], false);

    let loaded = state
        .try_reload(&controller_secret(&fsig_observe, Some(&digest)))
        .expect("second FSIG");
    assert_eq!(loaded.as_str(), digest);
    let allowed = handle_json(&state, &body);
    assert_eq!(
        allowed["response"]["allowed"], true,
        "observe program must apply after swap"
    );
}

#[test]
fn failed_reload_keeps_last_good_mvp_denies() {
    let (fsig, pk, _) = make_signed(enforce_spec(PolicyMode::Enforce, pk_hex(&SK)), &SK);
    let state = webhook_state(&fsig, &pk);
    assert_integrity(state.try_reload(b"not-a-bundle"));
    assert_integrity(state.try_reload(&controller_secret(&fsig, Some(&"00".repeat(32)))));
    assert_integrity(state.try_reload(&fsig[..fsig.len().saturating_sub(8)]));

    let unsigned = handle_json(&state, &review(pod(IMAGE, json!({}), false), "uid-u"));
    assert_eq!(unsigned["response"]["allowed"], false);
    let umsg = deny_msg(&unsigned);
    assert!(
        umsg.contains("unsigned") || umsg.contains(RULE_UNSIGNED),
        "{umsg}"
    );

    let priv_obj = pod(IMAGE, image_annotations(IMAGE, &SK), true);
    let privileged = handle_json(&state, &review(priv_obj, "uid-p"));
    assert_eq!(privileged["response"]["allowed"], false);
    let pmsg = deny_msg(&privileged);
    assert!(
        pmsg.contains("privileged") || pmsg.contains(RULE_PRIVILEGED),
        "{pmsg}"
    );

    let admin = handle_json(&state, &review(cluster_admin_bind(), "uid-a"));
    assert_eq!(admin["response"]["allowed"], false);
    let amsg = deny_msg(&admin);
    assert!(
        amsg.contains("cluster-admin") || amsg.contains(RULE_CLUSTER_ADMIN_BIND),
        "{amsg}"
    );
}

#[test]
fn dir_matching_digest_loads_and_denies_unsigned() {
    let (fsig, pk, digest) = make_signed(enforce_spec(PolicyMode::Enforce, pk_hex(&SK)), &SK);
    let dir = temp_dir("dir-match");
    write_secret_dir(&dir, &fsig, &digest);
    let (program, loaded) = load_path(&dir, &pk).expect("dir + matching digest");
    assert_eq!(loaded.as_str(), digest);
    let resp = admit_review(
        &review(pod(IMAGE, json!({}), false), "uid-dir"),
        Some(&program),
        &[],
    );
    assert_eq!(resp["response"]["allowed"], false);
    let msg = deny_msg(&resp);
    assert!(
        msg.contains("unsigned") || msg.contains(RULE_UNSIGNED),
        "{msg}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dir_mismatched_digest_does_not_swap() {
    let (fsig_enforce, pk, digest) =
        make_signed(enforce_spec(PolicyMode::Enforce, pk_hex(&SK)), &SK);
    let (fsig_observe, _, _) = make_signed(enforce_spec(PolicyMode::Observe, pk_hex(&SK)), &SK);
    let dir = temp_dir("dir-mismatch");
    write_secret_dir(&dir, &fsig_enforce, &digest);
    let (program, _) = load_path(&dir, &pk).expect("initial dir load");
    let state = WebhookState::new(program, pk.clone(), vec![], ReviewConfig::default());
    let body = review(
        pod(IMAGE, image_annotations(IMAGE, &SK), true),
        "uid-dir-mm",
    );
    assert_eq!(handle_json(&state, &body)["response"]["allowed"], false);

    write_secret_dir(&dir, &fsig_observe, &"00".repeat(32));
    assert_integrity(load_path(&dir, &pk));
    assert_integrity(state.try_reload_path(&dir));
    assert_eq!(
        handle_json(&state, &body)["response"]["allowed"],
        false,
        "matching pin + mismatched sibling digest must not swap"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn poll_reloads_on_mtime_len_and_keeps_lkg_if_file_vanishes() {
    let (fsig_enforce, pk, digest_enforce) =
        make_signed(enforce_spec(PolicyMode::Enforce, pk_hex(&SK)), &SK);
    let (fsig_observe, _, digest_observe) =
        make_signed(enforce_spec(PolicyMode::Observe, pk_hex(&SK)), &SK);
    let dir = temp_dir("poll-dir");
    write_secret_dir(&dir, &fsig_enforce, &digest_enforce);
    let state = Arc::new(webhook_state(&fsig_enforce, &pk));
    poll_bundle_file(dir.clone(), Duration::from_millis(50), Arc::clone(&state));
    write_secret_dir(&dir, &fsig_observe, "bad");
    let body = review(pod(IMAGE, image_annotations(IMAGE, &SK), true), "uid-poll");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        handle_json(&state, &body)["response"]["allowed"],
        false,
        "poll must not swap on sibling digest mismatch"
    );
    write_secret_dir(&dir, &fsig_observe, &digest_observe);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let resp = handle_json(&state, &body);
        if resp["response"]["allowed"] == true {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "poll did not swap to observe program"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_file(dir.join(BUNDLE_FSIG_KEY));
    let _ = std::fs::remove_file(dir.join(BUNDLE_DIGEST_KEY));
    std::thread::sleep(Duration::from_millis(150));
    let still = handle_json(&state, &body);
    assert_eq!(
        still["response"]["allowed"], true,
        "vanished file must not clear last-known-good"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn serve_missing_bundle_exits_2() {
    let exe = env!("CARGO_BIN_EXE_ferrum-admission");
    let output = std::process::Command::new(exe)
        .args([
            "serve",
            "--bundle",
            "/no/such/ferrum-bundle",
            "--trust-root",
            &pk_hex(&SK),
            "--listen",
            "127.0.0.1:0",
        ])
        .output()
        .expect("spawn serve");
    assert_eq!(output.status.code(), Some(2));

    let dir = std::env::temp_dir().join(format!(
        "ferrum-admission-empty-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("empty dir");
    let output = std::process::Command::new(exe)
        .args([
            "serve",
            "--bundle",
            dir.to_str().expect("utf8 path"),
            "--trust-root",
            &pk_hex(&SK),
            "--listen",
            "127.0.0.1:0",
        ])
        .output()
        .expect("spawn serve dir");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(output.status.code(), Some(2));
}

/// Exception with wall-clock expiry: `WebhookState::handle` evaluates at
/// real `Utc::now()`, unlike the fixed-clock helpers above.
fn wallclock_exception(
    policy: &str,
    rule: &str,
    expires: DateTime<Utc>,
    ticket: &str,
) -> PolicyExceptionSpec {
    PolicyExceptionSpec {
        ticket: ticket.into(),
        requested_by: "sre".into(),
        approved_by: "ib".into(),
        reason: "temporary debug sidecar after incident".into(),
        expires_at: expires,
        mode: PolicyMode::Audit,
        four_eyes: true,
        target: ExceptionTarget {
            namespace: String::new(),
            policies: vec![policy.into()],
            rules: vec![rule.into()],
        },
    }
}

/// Controller-format `exceptions.fsig`: FSIG envelope over the JSON array,
/// signed with the bundle key.
fn exceptions_fsig_bytes(list: &[PolicyExceptionSpec], sk: &[u8; 32]) -> Vec<u8> {
    let payload = serde_json::to_vec(list).expect("controller-format json");
    let pk = public_key_from_secret(sk).expect("pk");
    let sig = sign_bundle(&payload, sk).expect("sign exceptions");
    encode_fsig(&payload, &sig, &pk).expect("exceptions fsig")
}

fn write_exceptions(dir: &std::path::Path, list: &[PolicyExceptionSpec]) {
    std::fs::write(
        dir.join(EXCEPTIONS_FSIG_KEY),
        exceptions_fsig_bytes(list, &SK),
    )
    .expect("exceptions.fsig");
}

fn wait_decision(state: &WebhookState, body: &[u8], want: bool, why: &str) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let resp = handle_json(state, body);
        if resp["response"]["allowed"] == want {
            return;
        }
        assert!(Instant::now() < deadline, "{why}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn exceptions_mount_rotation_gates_scope_and_ttl() {
    let (fsig, pk) = make_fsig(enforce_spec(PolicyMode::Enforce, pk_hex(&SK)), &SK);
    let cfg = ReviewConfig {
        policy_name: "prod-restricted".into(),
        policy_namespace: String::new(),
        ..Default::default()
    };
    let state = Arc::new(WebhookState::new(
        load_ok(&fsig, &pk),
        pk.clone(),
        vec![],
        cfg,
    ));
    let dir = temp_dir("exceptions-mount");
    poll_exceptions_file(dir.clone(), Duration::from_millis(50), Arc::clone(&state));
    let body = review(pod(IMAGE, image_annotations(IMAGE, &SK), true), "uid-exc");

    // Missing exceptions.json = empty list, not an error.
    assert_eq!(handle_json(&state, &body)["response"]["allowed"], false);

    let live = Utc::now() + Days::new(7);
    write_exceptions(
        &dir,
        &[wallclock_exception(
            "prod-restricted",
            RULE_PRIVILEGED,
            live,
            "JIRA-LIVE-1",
        )],
    );
    wait_decision(
        &state,
        &body,
        true,
        "live in-scope exception must waive privileged deny",
    );

    std::fs::write(dir.join(EXCEPTIONS_FSIG_KEY), b"{{{ not exceptions fsig").expect("garbage");
    wait_decision(
        &state,
        &body,
        false,
        "garbage exceptions.fsig must reset the list to empty, restoring the deny",
    );

    let live_list = [wallclock_exception(
        "prod-restricted",
        RULE_PRIVILEGED,
        live,
        "JIRA-UNSIGNED-2",
    )];
    std::fs::write(
        dir.join(EXCEPTIONS_FSIG_KEY),
        serde_json::to_vec(&live_list.to_vec()).expect("json"),
    )
    .expect("plain json");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        handle_json(&state, &body)["response"]["allowed"],
        false,
        "unsigned plain-JSON exceptions must be rejected, deny stays deny"
    );

    std::fs::write(
        dir.join(EXCEPTIONS_FSIG_KEY),
        exceptions_fsig_bytes(&live_list, &SK_OTHER),
    )
    .expect("foreign-key fsig");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        handle_json(&state, &body)["response"]["allowed"],
        false,
        "exceptions signed with a foreign key must be rejected"
    );

    let mut tampered = exceptions_fsig_bytes(&live_list, &SK);
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    std::fs::write(dir.join(EXCEPTIONS_FSIG_KEY), &tampered).expect("tampered fsig");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        handle_json(&state, &body)["response"]["allowed"],
        false,
        "tampered exceptions payload must be rejected"
    );

    write_exceptions(
        &dir,
        &[wallclock_exception(
            "other-policy",
            RULE_PRIVILEGED,
            live,
            "JIRA-OTHER-22",
        )],
    );
    wait_decision(
        &state,
        &body,
        false,
        "out-of-scope exception must not waive the deny",
    );

    write_exceptions(
        &dir,
        &[wallclock_exception(
            "prod-restricted",
            RULE_PRIVILEGED,
            live,
            "JIRA-LIVE-333",
        )],
    );
    wait_decision(
        &state,
        &body,
        true,
        "rotation back to in-scope must waive again",
    );

    let expired = Utc::now() - Days::new(1);
    write_exceptions(
        &dir,
        &[wallclock_exception(
            "prod-restricted",
            RULE_PRIVILEGED,
            expired,
            "JIRA-EXPIRED-4444",
        )],
    );
    wait_decision(
        &state,
        &body,
        false,
        "expired exception after rotation must deny again",
    );

    write_exceptions(
        &dir,
        &[wallclock_exception(
            "prod-restricted",
            RULE_PRIVILEGED,
            live,
            "JIRA-LIVE-55555",
        )],
    );
    wait_decision(&state, &body, true, "fresh live exception must waive again");

    std::fs::remove_file(dir.join(EXCEPTIONS_FSIG_KEY)).expect("remove");
    wait_decision(
        &state,
        &body,
        false,
        "removed exceptions.fsig must reset to an empty list",
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn exceptions_reload_missing_file_is_empty_and_unverifiable_resets() {
    let (fsig, pk) = make_fsig(enforce_spec(PolicyMode::Enforce, pk_hex(&SK)), &SK);
    let cfg = ReviewConfig {
        policy_name: "prod-restricted".into(),
        policy_namespace: String::new(),
        ..Default::default()
    };
    let live = wallclock_exception(
        "prod-restricted",
        RULE_PRIVILEGED,
        Utc::now() + Days::new(7),
        "JIRA-LIVE-1",
    );
    let state = WebhookState::new(load_ok(&fsig, &pk), pk.clone(), vec![live.clone()], cfg);
    let body = review(pod(IMAGE, image_annotations(IMAGE, &SK), true), "uid-st");
    assert_eq!(handle_json(&state, &body)["response"]["allowed"], true);
    assert_eq!(state.exceptions_resets(), 0);

    assert!(state.try_reload_exceptions(b"{{{ garbage").is_err());
    assert_eq!(
        handle_json(&state, &body)["response"]["allowed"],
        false,
        "unverifiable bytes reset the list to empty, restoring the deny"
    );
    assert_eq!(state.exceptions_resets(), 1);

    let signed = exceptions_fsig_bytes(std::slice::from_ref(&live), &SK);
    let n = state.try_reload_exceptions(&signed).expect("signed list");
    assert_eq!(n, 1);
    assert_eq!(handle_json(&state, &body)["response"]["allowed"], true);

    assert!(state
        .try_reload_exceptions(&serde_json::to_vec(&vec![live.clone()]).expect("json"))
        .is_err());
    assert_eq!(
        handle_json(&state, &body)["response"]["allowed"],
        false,
        "unsigned plain JSON resets to empty; deny stays deny"
    );

    state.try_reload_exceptions(&signed).expect("signed again");
    assert!(state
        .try_reload_exceptions(&exceptions_fsig_bytes(
            std::slice::from_ref(&live),
            &SK_OTHER
        ))
        .is_err());
    assert_eq!(
        handle_json(&state, &body)["response"]["allowed"],
        false,
        "foreign-key envelope resets to empty"
    );

    state.try_reload_exceptions(&signed).expect("signed again");
    let mut tampered = signed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(state.try_reload_exceptions(&tampered).is_err());
    assert_eq!(
        handle_json(&state, &body)["response"]["allowed"],
        false,
        "tampered payload resets to empty"
    );
    assert_eq!(state.exceptions_resets(), 4);

    state.try_reload_exceptions(&signed).expect("signed again");
    let dir = temp_dir("exceptions-missing");
    let n = state
        .try_reload_exceptions_path(&dir)
        .expect("missing file is empty, not an error");
    assert_eq!(n, 0);
    assert_eq!(
        handle_json(&state, &body)["response"]["allowed"],
        false,
        "empty list restores the deny"
    );
    assert_eq!(state.exceptions_resets(), 4, "missing file is not a reset");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cargo_toml_hot_path_keeps_boundary() {
    let toml = include_str!("../Cargo.toml");
    let start = toml.find("[dependencies]").expect("dependencies");
    let section = &toml[start..];
    let end = section[1..]
        .find("\n[")
        .map(|i| i + 1)
        .unwrap_or(section.len());
    let deps = &section[..end];
    for forbidden in ["ferrum-compiler", "kube", "tokio", "serde_yaml", "aya"] {
        let present = deps.lines().any(|line| {
            let line = line.trim();
            !line.starts_with('#') && line.starts_with(forbidden)
        });
        assert!(
            !present,
            "{forbidden} must not be in [dependencies]: {deps}"
        );
    }
}

const ZONE: &str = "ferrum.io/zone";
const TIER: &str = "ferrum.io/tier";

fn labels(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Signed, PSS-clean apart from `privileged`: the policy denies it wherever it
/// applies, and allows it wherever it does not.
fn privileged_pod_in(namespace: &str, service_account: &str) -> Value {
    let mut obj = pod(IMAGE, image_annotations(IMAGE, &SK), true);
    obj["metadata"]["namespace"] = json!(namespace);
    obj["spec"]["serviceAccountName"] = json!(service_account);
    obj
}

fn selected_program(mutate: impl FnOnce(&mut ClusterSecurityPolicySpec)) -> AdmissionProgram {
    let mut spec = enforce_spec(PolicyMode::Enforce, pk_hex(&SK));
    mutate(&mut spec);
    let (fsig, pk) = make_fsig(spec, &SK);
    load_ok(&fsig, &pk)
}

/// A program carrying a cluster selector, written into the *decoded* program
/// rather than into the spec it was compiled from.
///
/// `ferrum_policy::validate_selector` and the compiler's own second gate now
/// refuse to emit a bundle with a `clusterSelector`: nothing on either plane
/// observes cluster labels, so such a policy denies every Pod here and applies
/// to every workload on the runtime plane while holding `DEG_LABELS_UNKNOWN`
/// true. What the two tests below assert is the other half of that decision —
/// the fail-closed floor stays, because these bytes can still arrive: a
/// last-known-good bundle compiled by an older build, or a FADM this tree did
/// not produce. Authorship is refused; parsing and deciding are not.
fn program_with_cluster_selector(key: &str, value: &str) -> AdmissionProgram {
    let mut program = selected_program(|_| {});
    program
        .selector
        .cluster_selector
        .match_labels
        .insert(key.into(), value.into());
    program
}

fn cfg_with(labels: StaticLabels) -> ReviewConfig {
    ReviewConfig {
        policy_name: "prod-restricted".into(),
        labels: Arc::new(labels),
        ..Default::default()
    }
}

fn decide(cfg: &ReviewConfig, program: &AdmissionProgram, object: Value, uid: &str) -> Value {
    let reply = cfg.handle_bytes(&review(object, uid), Some(program), &[], now());
    assert_eq!(reply.status, 200, "expected HTTP 200 AdmissionReview");
    serde_json::from_slice(&reply.body).expect("response json")
}

#[test]
fn warm_cache_applies_a_namespace_selector_to_its_own_namespace_only() {
    let program = selected_program(|spec| {
        spec.selector
            .namespace_selector
            .match_labels
            .insert(ZONE.into(), "pci".into());
    });
    assert!(
        !program.selector.namespace_selector.match_labels.is_empty(),
        "fixture must carry the selector into the bundle"
    );
    let cfg = cfg_with(
        StaticLabels::default()
            .with_namespace("pci-ns", labels(&[(ZONE, "pci")]))
            .with_namespace("public-ns", labels(&[(ZONE, "public")]))
            .warm(),
    );

    let denied = decide(
        &cfg,
        &program,
        privileged_pod_in("pci-ns", "default"),
        "uid-pci",
    );
    assert_eq!(denied["response"]["allowed"], false);
    let msg = deny_msg(&denied);
    assert!(
        msg.contains(RULE_PRIVILEGED) || msg.contains("privileged"),
        "denied by the rule, not by a missing-label fallback: {msg}"
    );

    let allowed = decide(
        &cfg,
        &program,
        privileged_pod_in("public-ns", "default"),
        "uid-public",
    );
    assert_eq!(
        allowed["response"]["allowed"], true,
        "a namespace that does not match the selector is not this policy's business"
    );
}

#[test]
fn warm_cache_keeps_service_account_labels_inside_their_namespace() {
    let program = selected_program(|spec| {
        spec.selector
            .service_account_selector
            .match_labels
            .insert(TIER.into(), "frontend".into());
    });
    let cfg = cfg_with(
        StaticLabels::default()
            .with_service_account("prod", "web-sa", labels(&[(TIER, "frontend")]))
            .with_service_account("dev", "web-sa", labels(&[(TIER, "sandbox")]))
            .warm(),
    );

    let denied = decide(
        &cfg,
        &program,
        privileged_pod_in("prod", "web-sa"),
        "uid-sa-prod",
    );
    assert_eq!(denied["response"]["allowed"], false);

    let allowed = decide(
        &cfg,
        &program,
        privileged_pod_in("dev", "web-sa"),
        "uid-sa-dev",
    );
    assert_eq!(
        allowed["response"]["allowed"], true,
        "same ServiceAccount name in another namespace is a different subject"
    );
}

#[test]
fn cold_cache_denies_a_selected_policy_but_not_an_unselected_one() {
    let selected = selected_program(|spec| {
        spec.selector
            .namespace_selector
            .match_labels
            .insert(ZONE.into(), "pci".into());
    });
    let cold = cfg_with(StaticLabels::default());
    let reply = decide(
        &cold,
        &selected,
        privileged_pod_in("pci-ns", "default"),
        "uid-cold",
    );
    assert_eq!(reply["response"]["allowed"], false);
    let msg = deny_msg(&reply);
    assert!(msg.contains("labels unavailable"), "{msg}");

    // No namespace/SA selector: the cold cache is irrelevant, nothing changes.
    let unselected = selected_program(|_| {});
    let clean = pod(IMAGE, image_annotations(IMAGE, &SK), false);
    let reply = decide(&cold, &unselected, clean, "uid-cold-clean");
    assert_eq!(reply["response"]["allowed"], true);
    let reply = decide(
        &cold,
        &unselected,
        privileged_pod_in("any-ns", "default"),
        "uid-cold-priv",
    );
    assert_eq!(reply["response"]["allowed"], false);
    assert!(deny_msg(&reply).contains(RULE_PRIVILEGED) || deny_msg(&reply).contains("privileged"));
}

#[test]
fn cluster_labels_come_from_the_flag_and_need_no_warm_cache() {
    let program = program_with_cluster_selector("env", "prod");
    let cfg = cfg_with(StaticLabels::cluster(ClusterLabels::stated(labels(&[(
        "env", "prod",
    )]))));
    let reply = decide(
        &cfg,
        &program,
        privileged_pod_in("any-ns", "default"),
        "uid-cluster",
    );
    assert_eq!(reply["response"]["allowed"], false);
    assert!(!deny_msg(&reply).contains("labels unavailable"));

    let elsewhere = cfg_with(StaticLabels::cluster(ClusterLabels::stated(labels(&[(
        "env", "staging",
    )]))));
    let reply = decide(
        &elsewhere,
        &program,
        privileged_pod_in("any-ns", "default"),
        "uid-cluster-2",
    );
    assert_eq!(reply["response"]["allowed"], true);
}

/// A1: the mount the binary cannot survive the absence of must not claim it
/// can. `optional: true` on this Secret produced two replicas in
/// CrashLoopBackOff that a TCP readiness probe still called Ready, under a
/// failurePolicy that denies every Pod in the cluster meanwhile.
#[test]
fn bundle_secret_mount_is_not_optional() {
    let yaml = include_str!("../../../deploy/admission/deployment.yaml");
    let volumes = yaml
        .split_once("\n      volumes:")
        .expect("deployment declares volumes")
        .1;
    let bundle = volumes
        .split_once("- name: bundle")
        .expect("bundle volume")
        .1;
    let bundle_block = bundle.split_once("- name: ").map_or(bundle, |(b, _)| b);
    assert!(
        bundle_block.contains("secretName: ferrum-bundle-"),
        "bundle volume is the controller-written Secret: {bundle_block}"
    );
    for line in bundle_block.lines() {
        let line = line.trim();
        assert!(
            line.starts_with('#') || !line.starts_with("optional:"),
            "the binary exits 2 without a verified bundle, before the poll loop that would \
             pick one up: the mount may not be optional, or the manifest promises a \
             tolerance the process does not have"
        );
    }
}

/// B2, bundle mount: unreadable and deleted must not look alike. Both keep the
/// last-known-good program — that part is right — but only one of them means
/// the poll loop has stopped working, and before this it said nothing at all.
#[test]
fn unreadable_bundle_mount_is_counted_and_a_deleted_one_is_not() {
    let (fsig_enforce, pk, digest_enforce) =
        make_signed(enforce_spec(PolicyMode::Enforce, pk_hex(&SK)), &SK);
    let (fsig_observe, _, digest_observe) =
        make_signed(enforce_spec(PolicyMode::Observe, pk_hex(&SK)), &SK);
    let body = review(pod(IMAGE, image_annotations(IMAGE, &SK), true), "uid-stat");

    // Deleted: the keys leave the mount. Last-known-good stays, silently.
    let gone = temp_dir("bundle-gone");
    write_secret_dir(&gone, &fsig_enforce, &digest_enforce);
    let state = Arc::new(webhook_state(&fsig_enforce, &pk));
    poll_bundle_file(gone.clone(), Duration::from_millis(50), Arc::clone(&state));
    std::fs::remove_file(gone.join(BUNDLE_FSIG_KEY)).expect("remove fsig");
    std::fs::remove_file(gone.join(BUNDLE_DIGEST_KEY)).expect("remove digest");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        handle_json(&state, &body)["response"]["allowed"],
        false,
        "a deleted mount keeps the last-known-good program"
    );
    assert_eq!(
        state.bundle_unreadable(),
        0,
        "an absent key is a Secret being rewritten, not a broken mount"
    );
    let _ = std::fs::remove_dir_all(&gone);

    // Unreadable: bundle.fsig is there and does not stat as a file. Same
    // last-known-good, different observable.
    let broken = temp_dir("bundle-unreadable");
    write_secret_dir(&broken, &fsig_enforce, &digest_enforce);
    let state = Arc::new(webhook_state(&fsig_enforce, &pk));
    poll_bundle_file(
        broken.clone(),
        Duration::from_millis(50),
        Arc::clone(&state),
    );
    std::thread::sleep(Duration::from_millis(150));
    std::fs::remove_file(broken.join(BUNDLE_FSIG_KEY)).expect("remove fsig");
    std::fs::create_dir(broken.join(BUNDLE_FSIG_KEY)).expect("directory in its place");
    let deadline = Instant::now() + Duration::from_secs(3);
    while state.bundle_unreadable() == 0 {
        assert!(
            Instant::now() < deadline,
            "an unreadable bundle mount must be counted, not silently skipped"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        handle_json(&state, &body)["response"]["allowed"],
        false,
        "an unreadable mount keeps the last-known-good program too"
    );

    // And it does not latch: a mount that comes back is picked up, which is
    // the swap the frozen loop could never make.
    std::fs::remove_dir(broken.join(BUNDLE_FSIG_KEY)).expect("remove placeholder dir");
    write_secret_dir(&broken, &fsig_observe, &digest_observe);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if handle_json(&state, &body)["response"]["allowed"] == true {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the poll loop must resume after the mount is readable again"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(state.bundle_unreadable(), 1, "counted once per transition");
    let _ = std::fs::remove_dir_all(&broken);
}

/// M3: keeping the last-known-good across an absent key is the right policy —
/// a Secret mid-rewrite looks exactly like a deleted one — but the arm said
/// nothing and moved nothing. Delete the key for real and the webhook goes on
/// enforcing a program with no source behind it, forever, with no trace: absent
/// collapsed into nothing happened.
#[test]
fn a_bundle_key_that_vanished_is_counted_not_silent() {
    let (fsig, pk, digest) = make_signed(enforce_spec(PolicyMode::Enforce, pk_hex(&SK)), &SK);
    let body = review(
        pod(IMAGE, image_annotations(IMAGE, &SK), true),
        "uid-absent",
    );

    let dir = temp_dir("bundle-absent-counted");
    write_secret_dir(&dir, &fsig, &digest);
    let state = Arc::new(webhook_state(&fsig, &pk));
    poll_bundle_file(dir.clone(), Duration::from_millis(50), Arc::clone(&state));
    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(state.bundle_absent(), 0, "nothing is missing yet");

    std::fs::remove_file(dir.join(BUNDLE_FSIG_KEY)).expect("remove fsig");
    std::fs::remove_file(dir.join(BUNDLE_DIGEST_KEY)).expect("remove digest");
    let deadline = Instant::now() + Duration::from_secs(3);
    while state.bundle_absent() == 0 {
        assert!(
            Instant::now() < deadline,
            "a bundle key that vanished must move something; the webhook is enforcing a \
             program whose source is gone"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        handle_json(&state, &body)["response"]["allowed"],
        false,
        "and the last-known-good still enforces, which is the policy that must not change"
    );
    assert_eq!(
        state.bundle_unreadable(),
        0,
        "an absent key is still not a broken mount"
    );
    // The poll loop dedupes by stat, so this is a transition count, not a tick
    // count: the same missing key does not keep filling the log.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(state.bundle_absent(), 1, "counted once per transition");
    let _ = std::fs::remove_dir_all(&dir);
}

/// B2, exceptions mount: emptying the whole waiver table must not be quieter
/// than failing to reload it. Absent and unreadable both end with no waivers
/// applying, and they are different events.
#[test]
fn absent_and_unreadable_exceptions_mounts_are_counted_apart() {
    let (fsig, pk) = make_fsig(enforce_spec(PolicyMode::Enforce, pk_hex(&SK)), &SK);
    let cfg = ReviewConfig {
        policy_name: "prod-restricted".into(),
        policy_namespace: String::new(),
        ..Default::default()
    };
    let state = Arc::new(WebhookState::new(
        load_ok(&fsig, &pk),
        pk.clone(),
        vec![],
        cfg,
    ));
    let dir = temp_dir("exceptions-stat");
    let live = Utc::now() + Days::new(7);
    write_exceptions(
        &dir,
        &[wallclock_exception(
            "prod-restricted",
            RULE_PRIVILEGED,
            live,
            "JIRA-STAT-1",
        )],
    );
    poll_exceptions_file(dir.clone(), Duration::from_millis(50), Arc::clone(&state));
    let body = review(
        pod(IMAGE, image_annotations(IMAGE, &SK), true),
        "uid-exc-stat",
    );
    wait_decision(&state, &body, true, "live in-scope exception must waive");
    assert_eq!(state.exceptions_resets(), 0);
    let cleared_before = state.exceptions_clears();

    // Unreadable: the key is there and does not stat as a file. It cannot be
    // verified, so the waivers stop applying — as a reload failure, counted.
    std::fs::remove_file(dir.join(EXCEPTIONS_FSIG_KEY)).expect("remove");
    std::fs::create_dir(dir.join(EXCEPTIONS_FSIG_KEY)).expect("directory in its place");
    wait_decision(
        &state,
        &body,
        false,
        "an unreadable exceptions mount must drop the waivers, not keep them",
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    while state.exceptions_resets() == 0 {
        assert!(
            Instant::now() < deadline,
            "an unreadable exceptions mount is a failed reload, and is counted as one"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        state.exceptions_clears(),
        cleared_before,
        "unreadable is not the same event as a Secret that carries no waivers"
    );

    // Absent: the key is gone. Same empty table, the other counter.
    std::fs::remove_dir(dir.join(EXCEPTIONS_FSIG_KEY)).expect("remove dir");
    let deadline = Instant::now() + Duration::from_secs(3);
    while state.exceptions_clears() == cleared_before {
        assert!(
            Instant::now() < deadline,
            "dropping every approved waiver because the key is gone must be counted"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        state.exceptions_resets(),
        1,
        "an absent key is not a failed reload"
    );
    assert_eq!(state.exception_count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// B5: after the first seconds the fixed sentence was wrong. A cache that
/// listed and went stale, and one that owes a relist, are not a cache that has
/// never listed, and the deny reply is the only place the difference can be
/// said.
#[test]
fn cold_stale_and_relist_pending_deny_with_different_causes() {
    let program = selected_program(|spec| {
        spec.selector
            .namespace_selector
            .match_labels
            .insert(ZONE.into(), "pci".into());
    });
    let object = || privileged_pod_in("pci-ns", "default");

    let cold = cfg_with(StaticLabels::default());
    let cold_msg = deny_msg(&decide(&cold, &program, object(), "uid-warm-cold"));

    let stale = cfg_with(StaticLabels::default().stale(Duration::from_secs(7_200)));
    let stale_msg = deny_msg(&decide(&stale, &program, object(), "uid-warm-stale"));

    let relist = cfg_with(StaticLabels::default().relist_pending());
    let relist_msg = deny_msg(&decide(&relist, &program, object(), "uid-warm-relist"));

    for msg in [&cold_msg, &stale_msg, &relist_msg] {
        assert!(msg.contains("labels unavailable"), "{msg}");
    }
    assert!(cold_msg.contains("has not listed yet"), "{cold_msg}");
    assert!(
        stale_msg.contains("7200s") && !stale_msg.contains("has not listed yet"),
        "a stale cache must not be reported as one that never listed: {stale_msg}"
    );
    assert!(
        relist_msg.contains("410 Gone") && !relist_msg.contains("has not listed yet"),
        "a relist obligation must not be reported as a cold start: {relist_msg}"
    );
    assert_ne!(cold_msg, stale_msg);
    assert_ne!(cold_msg, relist_msg);
    assert_ne!(stale_msg, relist_msg);

    // Warmth is only consulted for a policy that needs those labels.
    let unselected = selected_program(|_| {});
    let clean = pod(IMAGE, image_annotations(IMAGE, &SK), false);
    let reply = decide(&stale, &unselected, clean, "uid-warm-unselected");
    assert_eq!(reply["response"]["allowed"], true);
}

/// The `apiserver` feature is what production builds with, and until now no
/// test target enabled it: `WatchedLabels` shipped unexercised. Same denies,
/// driven by real `LabelCache` state instead of a stated flag.
#[cfg(feature = "apiserver")]
mod watched_labels {
    use super::*;
    use ferrum_admission::{LabelSource, LabelWarmth, WatchedLabels};
    use ferrum_k8smeta::{LabelCache, LabelObject};
    use std::sync::RwLock;

    fn cache(objects: Vec<LabelObject>) -> LabelCache {
        let mut cache = LabelCache::new();
        cache.try_replace_all(objects).expect("list");
        cache
    }

    /// Both namespaces carry a zone label: eval fails closed on an *empty*
    /// label map, so "not selected" has to be a label that does not match, not
    /// the absence of one.
    fn pci_namespace() -> Vec<LabelObject> {
        vec![
            LabelObject {
                namespace: String::new(),
                name: "pci-ns".into(),
                labels: labels(&[(ZONE, "pci")]),
                resource_version: "1".into(),
            },
            LabelObject {
                namespace: String::new(),
                name: "other-ns".into(),
                labels: labels(&[(ZONE, "public")]),
                resource_version: "1".into(),
            },
        ]
    }

    fn source(namespaces: LabelCache, service_accounts: LabelCache) -> Arc<WatchedLabels> {
        Arc::new(WatchedLabels::new(
            Arc::new(RwLock::new(namespaces)),
            Arc::new(RwLock::new(service_accounts)),
            ClusterLabels::stated(std::collections::BTreeMap::new()),
        ))
    }

    fn cfg(source: Arc<WatchedLabels>) -> ReviewConfig {
        ReviewConfig {
            policy_name: "prod-restricted".into(),
            labels: source,
            ..Default::default()
        }
    }

    fn ns_selected() -> AdmissionProgram {
        selected_program(|spec| {
            spec.selector
                .namespace_selector
                .match_labels
                .insert(ZONE.into(), "pci".into());
        })
    }

    #[test]
    fn a_warm_watch_decides_and_a_cold_one_denies_with_the_cold_reason() {
        let program = ns_selected();

        let warm = cfg(source(cache(pci_namespace()), cache(vec![])));
        let reply = decide(
            &warm,
            &program,
            privileged_pod_in("pci-ns", "default"),
            "w1",
        );
        assert_eq!(reply["response"]["allowed"], false);
        let msg = deny_msg(&reply);
        assert!(
            !msg.contains("labels unavailable"),
            "a warm watch denies by the rule: {msg}"
        );
        let reply = decide(
            &warm,
            &program,
            privileged_pod_in("other-ns", "default"),
            "w2",
        );
        assert_eq!(
            reply["response"]["allowed"], true,
            "a namespace the selector does not match is not this policy's business"
        );

        // One cache that never listed is enough to hold the whole source cold.
        let half = cfg(source(cache(pci_namespace()), LabelCache::new()));
        let reply = decide(
            &half,
            &program,
            privileged_pod_in("pci-ns", "default"),
            "w3",
        );
        assert_eq!(reply["response"]["allowed"], false);
        assert!(deny_msg(&reply).contains("has not listed yet"));
    }

    #[test]
    fn a_stale_watch_says_stale_and_a_gone_watch_says_relist() {
        let program = ns_selected();

        let mut aged = cache(pci_namespace());
        aged.set_max_age(Duration::from_secs(60));
        aged.mark_fresh_at(Instant::now() - Duration::from_secs(4_000));
        let stale = source(aged, cache(vec![]));
        assert!(matches!(stale.warmth(), LabelWarmth::Stale { .. }));
        let reply = decide(
            &cfg(Arc::clone(&stale)),
            &program,
            privileged_pod_in("pci-ns", "default"),
            "w4",
        );
        assert_eq!(reply["response"]["allowed"], false);
        let stale_msg = deny_msg(&reply);
        assert!(
            !stale_msg.contains("has not listed yet"),
            "the cache listed; it went stale: {stale_msg}"
        );

        let mut gone = cache(pci_namespace());
        gone.raise_relist_pending();
        let relist = source(gone, cache(vec![]));
        assert_eq!(relist.warmth(), LabelWarmth::RelistPending);
        let reply = decide(
            &cfg(relist),
            &program,
            privileged_pod_in("pci-ns", "default"),
            "w5",
        );
        assert_eq!(reply["response"]["allowed"], false);
        let relist_msg = deny_msg(&reply);
        assert!(relist_msg.contains("410 Gone"), "{relist_msg}");
        assert_ne!(stale_msg, relist_msg);
    }
}

/// B: the mirror of this tree's defect class. A cause that is true always
/// decides nothing, and "namespace labels are missing" was true for every
/// namespace that carries no labels, on a cache that had listed it and knew
/// exactly that. The webhook answered an integrity failure where the honest
/// answer is "the selector did not match".
#[test]
fn a_warm_cache_that_listed_an_unlabelled_namespace_does_not_deny_a_selected_policy() {
    let program = selected_program(|spec| {
        spec.selector
            .namespace_selector
            .match_labels
            .insert(ZONE.into(), "pci".into());
    });
    let cfg = cfg_with(
        StaticLabels::default()
            .with_namespace("pci-ns", labels(&[(ZONE, "pci")]))
            .with_namespace("plain-ns", std::collections::BTreeMap::new())
            .warm(),
    );

    let allowed = decide(
        &cfg,
        &program,
        privileged_pod_in("plain-ns", "default"),
        "uid-plain",
    );
    assert_eq!(
        allowed["response"]["allowed"],
        true,
        "a namespace the cache listed and found unlabelled is a selector miss, not an integrity \
         failure: {}",
        deny_msg(&allowed)
    );

    // The same policy still bites where the selector does match, so the row
    // above is not "the selector stopped working".
    let denied = decide(
        &cfg,
        &program,
        privileged_pod_in("pci-ns", "default"),
        "uid-pci",
    );
    assert_eq!(denied["response"]["allowed"], false);
    let msg = deny_msg(&denied);
    assert!(
        msg.contains(RULE_PRIVILEGED) || msg.contains("privileged"),
        "denied by the rule, not by a missing-label fallback: {msg}"
    );
}

/// The half that must not be weakened by the one above: a warm cache is not
/// an omniscient one. A namespace no list ever named is still unknown, and a
/// policy that selects on namespace labels still fails closed there.
#[test]
fn a_namespace_a_warm_cache_never_listed_is_still_a_fail_closed_deny() {
    let program = selected_program(|spec| {
        spec.selector
            .namespace_selector
            .match_labels
            .insert(ZONE.into(), "pci".into());
    });
    let cfg = cfg_with(
        StaticLabels::default()
            .with_namespace("pci-ns", labels(&[(ZONE, "pci")]))
            .warm(),
    );

    let reply = decide(
        &cfg,
        &program,
        privileged_pod_in("ghost-ns", "default"),
        "uid-ghost",
    );
    assert_eq!(reply["response"]["allowed"], false);
    let msg = deny_msg(&reply);
    assert!(
        msg.contains("never observed"),
        "the deny must say the labels were never seen, not that the namespace has none: {msg}"
    );
    assert!(
        !msg.contains(RULE_PRIVILEGED),
        "this is an integrity refusal, not a rule hit: {msg}"
    );

    // Same for a ServiceAccount the cache never listed.
    let sa_program = selected_program(|spec| {
        spec.selector
            .service_account_selector
            .match_labels
            .insert(TIER.into(), "frontend".into());
    });
    let sa_cfg = cfg_with(
        StaticLabels::default()
            .with_service_account("prod", "web-sa", labels(&[(TIER, "frontend")]))
            .warm(),
    );
    let reply = decide(
        &sa_cfg,
        &sa_program,
        privileged_pod_in("prod", "other-sa"),
        "uid-ghost-sa",
    );
    assert_eq!(reply["response"]["allowed"], false);
    assert!(
        deny_msg(&reply).contains("never observed"),
        "{}",
        deny_msg(&reply)
    );
}

/// Cluster labels have no cache behind them, so nothing about a map can say
/// whether the operator stated any: `--cluster-label` absent and
/// `--cluster-label` naming a cluster with no labels both leave it empty. The
/// flag being passed is therefore its own fact, and without it the cluster
/// branch of `require_labels_if_selected` keeps deciding by emptiness — the
/// defect the namespace branch was just fixed for, left standing one selector
/// over.
#[test]
fn a_cluster_selector_without_the_flag_is_unknown_and_not_an_empty_map() {
    let program = program_with_cluster_selector("env", "prod");

    // No flag: unknown, and a policy that selects on it fails closed. A warm
    // namespace cache does not help — it is not where these come from.
    let unstated = cfg_with(StaticLabels::cluster(ClusterLabels::unstated()).warm());
    let reply = decide(
        &unstated,
        &program,
        privileged_pod_in("any-ns", "default"),
        "uid-no-flag",
    );
    assert_eq!(reply["response"]["allowed"], false);
    let msg = deny_msg(&reply);
    assert!(
        msg.contains("cluster") && msg.contains("never observed"),
        "the deny must name the cluster labels as unobserved: {msg}"
    );

    // The flag passed, naming a cluster that carries no labels: observed, so
    // the selector is answered — with a miss, which is a decision, not a
    // refusal.
    let stated_empty = cfg_with(
        StaticLabels::cluster(ClusterLabels::stated(std::collections::BTreeMap::new())).warm(),
    );
    let reply = decide(
        &stated_empty,
        &program,
        privileged_pod_in("any-ns", "default"),
        "uid-stated-empty",
    );
    assert_eq!(
        reply["response"]["allowed"],
        true,
        "an operator who stated a cluster with no labels has been heard: {}",
        deny_msg(&reply)
    );

    // And the flag that does match still applies the policy.
    let stated = cfg_with(StaticLabels::cluster(ClusterLabels::stated(labels(&[(
        "env", "prod",
    )]))));
    let reply = decide(
        &stated,
        &program,
        privileged_pod_in("any-ns", "default"),
        "uid-stated",
    );
    assert_eq!(reply["response"]["allowed"], false);
    assert!(!deny_msg(&reply).contains("never observed"));
}
