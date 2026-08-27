//! AdmissionReview webhook: MVP deny/allow, FSIG fail-closed, exceptions.

mod common;

use chrono::{DateTime, Days, TimeZone, Utc};
use ferrum_admission::{
    encode_fsig, handle_review_bytes, load_bundle, load_path, load_source, parse_program,
    poll_bundle_file, poll_exceptions_file, AdmissionProgram, ReviewConfig, WebhookState,
    ADMISSION_ABI, BUNDLE_DIGEST_KEY, BUNDLE_FSIG_KEY, EXCEPTIONS_JSON_KEY,
    IMAGE_SIGNATURE_ANNOTATION, RULE_CLUSTER_ADMIN_BIND, RULE_PRIVILEGED, RULE_UNSIGNED,
};
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
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
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

fn write_exceptions(dir: &std::path::Path, list: &[PolicyExceptionSpec]) {
    std::fs::write(
        dir.join(EXCEPTIONS_JSON_KEY),
        serde_json::to_vec(list).expect("controller-format json"),
    )
    .expect("exceptions.json");
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

    std::fs::write(dir.join(EXCEPTIONS_JSON_KEY), b"{{{ not exceptions json").expect("garbage");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        handle_json(&state, &body)["response"]["allowed"],
        true,
        "garbage exceptions.json must keep the previous list, not deny-all"
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

    std::fs::remove_file(dir.join(EXCEPTIONS_JSON_KEY)).expect("remove");
    wait_decision(
        &state,
        &body,
        false,
        "removed exceptions.json must reset to an empty list",
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn exceptions_reload_missing_file_is_empty_and_garbage_keeps_previous() {
    let (fsig, pk) = make_fsig(enforce_spec(PolicyMode::Enforce, pk_hex(&SK)), &SK);
    let cfg = ReviewConfig {
        policy_name: "prod-restricted".into(),
        policy_namespace: String::new(),
    };
    let live = wallclock_exception(
        "prod-restricted",
        RULE_PRIVILEGED,
        Utc::now() + Days::new(7),
        "JIRA-LIVE-1",
    );
    let state = WebhookState::new(load_ok(&fsig, &pk), pk.clone(), vec![live], cfg);
    let body = review(pod(IMAGE, image_annotations(IMAGE, &SK), true), "uid-st");
    assert_eq!(handle_json(&state, &body)["response"]["allowed"], true);

    assert!(state.try_reload_exceptions(b"{{{ garbage").is_err());
    assert_eq!(
        handle_json(&state, &body)["response"]["allowed"],
        true,
        "garbage bytes keep the previous list"
    );

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
