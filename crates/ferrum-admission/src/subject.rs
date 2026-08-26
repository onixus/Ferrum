//! Map admission `object` JSON to [`AdmissionSubject`]. No kube types, no network.

use ferrum_api::TrustRoot;
use ferrum_common::{FerrumError, Result};
use ferrum_crypto::ED25519_SIGNATURE_LEN;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

use crate::encoding::hex_decode;
use crate::eval::AdmissionSubject;

/// Annotation holding a hex Ed25519 signature over a single image reference.
pub const IMAGE_SIGNATURE_ANNOTATION: &str = "ferrum.io/image-signature";
/// JSON object of image reference → hex signature.
pub const IMAGE_SIGNATURES_ANNOTATION: &str = "ferrum.io/image-signatures";

/// Map a Kubernetes object JSON value. Missing or malformed objects fail closed.
/// `image_signed` is true only when a local Ed25519 signature over the image
/// reference verifies against bundle `supply.trustRoots.publicKeys`.
pub fn subject_from_object(object: &Value, trust_roots: &[TrustRoot]) -> Result<AdmissionSubject> {
    let obj = object.as_object().ok_or_else(|| {
        FerrumError::Integrity("admission object is missing or not a JSON object".into())
    })?;
    let kind = obj
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let meta = optional_object(object, "metadata")?;
    let mut subject = AdmissionSubject {
        kind: kind.clone(),
        namespace: meta
            .and_then(|m| m.get("namespace"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        workload_labels: string_map(meta.and_then(|m| m.get("labels"))),
        ..AdmissionSubject::default()
    };
    match kind.as_str() {
        "Pod" => fill_pod(&mut subject, object, meta, trust_roots)?,
        "Role" | "ClusterRole" => fill_role(&mut subject, object)?,
        "RoleBinding" | "ClusterRoleBinding" => fill_binding(&mut subject, object)?,
        _ => {}
    }
    Ok(subject)
}

fn fill_pod(
    subject: &mut AdmissionSubject,
    object: &Value,
    meta: Option<&Map<String, Value>>,
    trust_roots: &[TrustRoot],
) -> Result<()> {
    let spec = optional_object(object, "spec")?
        .ok_or_else(|| FerrumError::Integrity("Pod spec is missing".into()))?;
    subject.host_pid = spec
        .get("hostPID")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    subject.host_ipc = spec
        .get("hostIPC")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    subject.host_network = spec
        .get("hostNetwork")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    subject.service_account = spec
        .get("serviceAccountName")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    subject.host_path = volumes_host_path(spec.get("volumes"))?;

    let pod_sc = optional_object_from(spec, "securityContext")?;
    let mut containers = Vec::new();
    collect_containers(&mut containers, spec.get("containers"))?;
    collect_containers(&mut containers, spec.get("initContainers"))?;
    collect_containers(&mut containers, spec.get("ephemeralContainers"))?;

    if containers.is_empty() {
        subject.allow_privilege_escalation = true;
        subject.run_as_root = runs_as_root(pod_sc, None);
        subject.image_signed = false;
        return Ok(());
    }

    let mut images = Vec::new();
    let mut caps = Vec::new();
    let mut any_privileged = false;
    let mut any_allow_esc = false;
    let mut any_root = false;
    for c in &containers {
        let csc = optional_object_from(c, "securityContext")?;
        any_privileged |= csc
            .and_then(|sc| sc.get("privileged"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let allow = csc
            .and_then(|sc| sc.get("allowPrivilegeEscalation"))
            .and_then(Value::as_bool)
            .unwrap_or(true);
        any_allow_esc |= allow;
        any_root |= runs_as_root(pod_sc, csc);
        if let Some(add) = csc
            .and_then(|sc| sc.get("capabilities"))
            .and_then(Value::as_object)
            .and_then(|cap| cap.get("add"))
            .and_then(Value::as_array)
        {
            for v in add {
                if let Some(s) = v.as_str() {
                    if !caps.iter().any(|e: &String| e == s) {
                        caps.push(s.to_string());
                    }
                }
            }
        }
        if let Some(img) = c.get("image").and_then(Value::as_str) {
            if !img.is_empty() {
                images.push(img.to_string());
            }
        }
    }
    subject.privileged = any_privileged;
    subject.allow_privilege_escalation = any_allow_esc;
    subject.run_as_root = any_root;
    subject.added_capabilities = caps;

    let annotations = string_map(meta.and_then(|m| m.get("annotations")));
    let keys = verifying_keys(trust_roots);
    let signed_flags: Vec<bool> = images
        .iter()
        .map(|img| image_signature_ok(img, &images, &annotations, &keys))
        .collect();
    subject.image_signed = !images.is_empty() && signed_flags.iter().all(|s| *s);
    subject.image = pick_image(&images, &signed_flags);
    Ok(())
}

fn fill_role(subject: &mut AdmissionSubject, object: &Value) -> Result<()> {
    let spec = match optional_object(object, "spec")? {
        Some(s) => s,
        None => object
            .as_object()
            .ok_or_else(|| FerrumError::Integrity("Role is not an object".into()))?,
    };
    let rules = spec.get("rules").or_else(|| object.get("rules"));
    subject.wildcard_rbac = rules_have_wildcard(rules)?;
    Ok(())
}

fn fill_binding(subject: &mut AdmissionSubject, object: &Value) -> Result<()> {
    let spec = optional_object(object, "spec")?;
    let role_ref = spec
        .and_then(|s| s.get("roleRef"))
        .or_else(|| object.get("roleRef"));
    subject.cluster_admin_bind = is_cluster_admin_ref(role_ref)?;
    Ok(())
}

fn is_cluster_admin_ref(role_ref: Option<&Value>) -> Result<bool> {
    match role_ref {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Object(m)) => {
            let kind = m.get("kind").and_then(Value::as_str).unwrap_or("");
            let name = m.get("name").and_then(Value::as_str).unwrap_or("");
            Ok(kind == "ClusterRole" && name == "cluster-admin")
        }
        Some(_) => Err(FerrumError::Integrity("roleRef is not an object".into())),
    }
}

fn rules_have_wildcard(rules: Option<&Value>) -> Result<bool> {
    match rules {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Array(items)) => {
            for rule in items {
                let obj = rule
                    .as_object()
                    .ok_or_else(|| FerrumError::Integrity("RBAC rule is not an object".into()))?;
                if list_has_star(obj.get("verbs"))?
                    || list_has_star(obj.get("resources"))?
                    || list_has_star(obj.get("apiGroups"))?
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Some(_) => Err(FerrumError::Integrity("rules is not an array".into())),
    }
}

fn list_has_star(v: Option<&Value>) -> Result<bool> {
    match v {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Array(items)) => Ok(items.iter().any(|i| i.as_str() == Some("*"))),
        Some(_) => Err(FerrumError::Integrity("RBAC list is not an array".into())),
    }
}

fn volumes_host_path(volumes: Option<&Value>) -> Result<bool> {
    match volumes {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Array(items)) => {
            for vol in items {
                let obj = vol
                    .as_object()
                    .ok_or_else(|| FerrumError::Integrity("volume is not an object".into()))?;
                if obj.contains_key("hostPath") {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Some(_) => Err(FerrumError::Integrity("volumes is not an array".into())),
    }
}

fn collect_containers<'a>(
    out: &mut Vec<&'a Map<String, Value>>,
    v: Option<&'a Value>,
) -> Result<()> {
    match v {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Array(items)) => {
            for c in items {
                let obj = c
                    .as_object()
                    .ok_or_else(|| FerrumError::Integrity("container is not an object".into()))?;
                out.push(obj);
            }
            Ok(())
        }
        Some(_) => Err(FerrumError::Integrity("containers is not an array".into())),
    }
}

fn runs_as_root(
    pod_sc: Option<&Map<String, Value>>,
    container_sc: Option<&Map<String, Value>>,
) -> bool {
    let run_as_non_root =
        bool_field(container_sc, "runAsNonRoot").or_else(|| bool_field(pod_sc, "runAsNonRoot"));
    if run_as_non_root == Some(true) {
        return false;
    }
    let run_as_user =
        i64_field(container_sc, "runAsUser").or_else(|| i64_field(pod_sc, "runAsUser"));
    match run_as_user {
        Some(uid) => uid == 0,
        None => true,
    }
}

fn bool_field(sc: Option<&Map<String, Value>>, key: &str) -> Option<bool> {
    sc.and_then(|m| m.get(key)).and_then(Value::as_bool)
}

fn i64_field(sc: Option<&Map<String, Value>>, key: &str) -> Option<i64> {
    sc.and_then(|m| m.get(key)).and_then(Value::as_i64)
}

fn optional_object<'a>(v: &'a Value, key: &str) -> Result<Option<&'a Map<String, Value>>> {
    let Some(map) = v.as_object() else {
        return Err(FerrumError::Integrity(
            "admission object is not a JSON object".into(),
        ));
    };
    optional_object_from(map, key)
}

fn optional_object_from<'a>(
    map: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a Map<String, Value>>> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(m)) => Ok(Some(m)),
        Some(_) => Err(FerrumError::Integrity(format!("{key} is not an object"))),
    }
}

fn string_map(v: Option<&Value>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(Value::Object(m)) = v {
        for (k, val) in m {
            if let Some(s) = val.as_str() {
                out.insert(k.clone(), s.to_string());
            }
        }
    }
    out
}

fn verifying_keys(roots: &[TrustRoot]) -> Vec<Vec<u8>> {
    let mut keys = Vec::new();
    for root in roots {
        for hex in &root.public_keys {
            if let Ok(k) = hex_decode(hex) {
                if k.len() == ferrum_crypto::ED25519_PUBLIC_KEY_LEN {
                    keys.push(k);
                }
            }
        }
    }
    keys
}

fn image_signature_ok(
    image: &str,
    all_images: &[String],
    annotations: &BTreeMap<String, String>,
    keys: &[Vec<u8>],
) -> bool {
    if keys.is_empty() {
        return false;
    }
    let unique: Vec<&String> = {
        let mut u = Vec::new();
        for img in all_images {
            if !u.iter().any(|e: &&String| *e == img) {
                u.push(img);
            }
        }
        u
    };
    let sig_hex = signatures_map(annotations).get(image).cloned().or_else(|| {
        if unique.len() == 1 {
            annotations.get(IMAGE_SIGNATURE_ANNOTATION).cloned()
        } else {
            None
        }
    });
    let Some(hex) = sig_hex else {
        return false;
    };
    let Ok(sig) = hex_decode(&hex) else {
        return false;
    };
    if sig.len() != ED25519_SIGNATURE_LEN {
        return false;
    }
    keys.iter()
        .any(|pk| ferrum_crypto::verify_bundle_signature(image.as_bytes(), &sig, pk).is_ok())
}

fn signatures_map(annotations: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(raw) = annotations.get(IMAGE_SIGNATURES_ANNOTATION) {
        if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(raw) {
            for (k, v) in m {
                if let Some(s) = v.as_str() {
                    out.insert(k, s.to_string());
                }
            }
        }
    }
    out
}

fn pick_image(images: &[String], signed: &[bool]) -> String {
    for (img, ok) in images.iter().zip(signed) {
        if !ok {
            return img.clone();
        }
    }
    images
        .iter()
        .find(|i| image_lacks_digest(i))
        .cloned()
        .or_else(|| images.iter().find(|i| image_looks_latest(i)).cloned())
        .or_else(|| images.first().cloned())
        .unwrap_or_default()
}

fn image_lacks_digest(image: &str) -> bool {
    !image.contains('@')
}

fn image_looks_latest(image: &str) -> bool {
    if image.contains('@') {
        return false;
    }
    match image.rsplit_once(':') {
        Some((repo, tag)) if !repo.is_empty() && !tag.is_empty() && !tag.contains('/') => {
            tag == "latest"
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_crypto::{public_key_from_secret, sign_bundle};
    use serde_json::json;

    fn keys_for(sk: &[u8; 32]) -> Vec<TrustRoot> {
        let pk = public_key_from_secret(sk).expect("pk");
        vec![TrustRoot {
            name: "org".into(),
            public_keys: vec![crate::encoding::hex_encode(&pk)],
            ..Default::default()
        }]
    }

    #[test]
    fn missing_object_fails_closed() {
        assert!(subject_from_object(&json!(null), &[]).is_err());
        assert!(subject_from_object(&json!("pod"), &[]).is_err());
        assert!(subject_from_object(&json!([]), &[]).is_err());
    }

    #[test]
    fn unknown_kind_is_benign() {
        let s = subject_from_object(&json!({"kind": "ConfigMap"}), &[]).unwrap();
        assert_eq!(s.kind, "ConfigMap");
        assert!(!s.privileged);
        assert!(!s.cluster_admin_bind);
        assert!(!s.wildcard_rbac);
        assert!(!s.image_signed);
    }

    #[test]
    fn pod_defaults_and_host_path() {
        let obj = json!({
            "kind": "Pod",
            "metadata": {"namespace": "ns", "labels": {"app": "p"}},
            "spec": {
                "hostPID": true,
                "volumes": [{"name": "d", "hostPath": {"path": "/var/run/docker.sock"}}],
                "containers": [{"name": "c", "image": "nginx"}]
            }
        });
        let s = subject_from_object(&obj, &[]).unwrap();
        assert_eq!(s.kind, "Pod");
        assert_eq!(s.namespace, "ns");
        assert_eq!(s.workload_labels.get("app").map(String::as_str), Some("p"));
        assert!(s.host_pid);
        assert!(s.host_path);
        assert!(s.allow_privilege_escalation);
        assert!(s.run_as_root);
        assert!(!s.image_signed);
        assert_eq!(s.image, "nginx");
    }

    #[test]
    fn run_as_non_root_and_explicit_user() {
        let obj = json!({
            "kind": "Pod",
            "spec": {
                "securityContext": {"runAsNonRoot": true},
                "containers": [{
                    "name": "c",
                    "image": "a@sha256:1",
                    "securityContext": {
                        "allowPrivilegeEscalation": false,
                        "runAsUser": 1000
                    }
                }]
            }
        });
        let s = subject_from_object(&obj, &[]).unwrap();
        assert!(!s.run_as_root);
        assert!(!s.allow_privilege_escalation);
    }

    #[test]
    fn run_as_user_zero_is_root() {
        let obj = json!({
            "kind": "Pod",
            "spec": {
                "containers": [{
                    "name": "c",
                    "image": "a@sha256:1",
                    "securityContext": {"runAsUser": 0, "allowPrivilegeEscalation": false}
                }]
            }
        });
        let s = subject_from_object(&obj, &[]).unwrap();
        assert!(s.run_as_root);
    }

    #[test]
    fn missing_annotation_is_unsigned() {
        let sk = [0x11u8; 32];
        let obj = json!({
            "kind": "Pod",
            "spec": {
                "containers": [{
                    "name": "c",
                    "image": "registry.internal.example/app@sha256:abc",
                    "securityContext": {"allowPrivilegeEscalation": false, "runAsNonRoot": true}
                }]
            }
        });
        let s = subject_from_object(&obj, &keys_for(&sk)).unwrap();
        assert!(!s.image_signed);
    }

    #[test]
    fn local_image_signature_verifies() {
        let sk = [0x11u8; 32];
        let image = "registry.internal.example/app@sha256:abc";
        let sig = sign_bundle(image.as_bytes(), &sk).unwrap();
        let obj = json!({
            "kind": "Pod",
            "metadata": {
                "annotations": {
                    IMAGE_SIGNATURE_ANNOTATION: crate::encoding::hex_encode(&sig)
                }
            },
            "spec": {
                "containers": [{
                    "name": "c",
                    "image": image,
                    "securityContext": {"allowPrivilegeEscalation": false, "runAsNonRoot": true}
                }]
            }
        });
        let s = subject_from_object(&obj, &keys_for(&sk)).unwrap();
        assert!(s.image_signed);
        assert_eq!(s.image, image);
    }

    #[test]
    fn cluster_admin_bind_and_wildcard_role() {
        let bind = json!({
            "kind": "ClusterRoleBinding",
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"}
        });
        let s = subject_from_object(&bind, &[]).unwrap();
        assert!(s.cluster_admin_bind);

        let role = json!({
            "kind": "Role",
            "rules": [{"apiGroups": ["*"], "resources": ["pods"], "verbs": ["get"]}]
        });
        let s = subject_from_object(&role, &[]).unwrap();
        assert!(s.wildcard_rbac);
    }

    #[test]
    fn init_and_ephemeral_privileged() {
        let obj = json!({
            "kind": "Pod",
            "spec": {
                "containers": [{"name": "c", "image": "a:1", "securityContext": {"allowPrivilegeEscalation": false, "runAsNonRoot": true}}],
                "initContainers": [{"name": "i", "image": "a:1", "securityContext": {"privileged": true, "allowPrivilegeEscalation": false, "runAsNonRoot": true}}],
                "ephemeralContainers": [{"name": "e", "image": "a:1", "securityContext": {"capabilities": {"add": ["SYS_ADMIN"]}, "allowPrivilegeEscalation": false, "runAsNonRoot": true}}]
            }
        });
        let s = subject_from_object(&obj, &[]).unwrap();
        assert!(s.privileged);
        assert!(s.added_capabilities.iter().any(|c| c == "SYS_ADMIN"));
        assert!(!s.allow_privilege_escalation);
        assert!(!s.run_as_root);
    }
}
