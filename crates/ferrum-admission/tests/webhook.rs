//! AdmissionReview webhook: MVP deny/allow, FSIG fail-closed, exceptions.

mod common;

use chrono::{DateTime, Days, TimeZone, Utc};
use ferrum_admission::{
    encode_fsig, handle_review_bytes, load_bundle, parse_program, AdmissionProgram, ReviewConfig,
    ADMISSION_ABI, IMAGE_SIGNATURE_ANNOTATION, RULE_CLUSTER_ADMIN_BIND, RULE_PRIVILEGED,
    RULE_UNSIGNED,
};
use ferrum_api::{
    AdmitDeny, AdmitMutate, AdmitSpec, ClusterSecurityPolicy, ClusterSecurityPolicySpec,
    ExceptionTarget, FailurePolicy, PolicyExceptionSpec, PolicyMode, PssProfile, SupplySpec,
    TrustRoot,
};
use ferrum_compiler::{bundle_digest_material, compile_cluster_policy};
use ferrum_crypto::{public_key_from_secret, sign_bundle};
use ferrum_ids::AGENT_ABI;
use serde_json::{json, Value};

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

fn make_fsig(spec: ClusterSecurityPolicySpec, sk: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let fadm = compile(spec);
    let raw = bundle_digest_material(AGENT_ABI, ADMISSION_ABI, &fadm, b"", b"").expect("frmb");
    let pk = public_key_from_secret(sk).expect("pk");
    let sig = sign_bundle(&raw, sk).expect("sign");
    let fsig = encode_fsig(&raw, &sig, &pk).expect("fsig");
    (fsig, pk)
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
