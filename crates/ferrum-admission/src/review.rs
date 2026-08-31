//! admission.k8s.io/v1 AdmissionReview. Fail closed; Cluster Ignore is not an integrity bypass.

use chrono::{DateTime, Utc};
use ferrum_api::{LabelSelector, PolicyExceptionSpec, PolicyMode};
use serde_json::{json, Map, Value};
use std::sync::Arc;

use crate::encoding::b64_encode;
use crate::eval::{admit, AdmissionDecision, Patch};
use crate::labels::{ColdLabels, LabelSource};
use crate::program::AdmissionProgram;
use crate::subject::subject_from_object;

/// A Pod that names no ServiceAccount runs as this one, so that is the key to
/// look labels up under.
const DEFAULT_SERVICE_ACCOUNT: &str = "default";

/// Policy identity for exception scope. Empty namespace is cluster-scoped.
/// `policy_name` is never inferred from exception targets.
#[derive(Debug, Clone)]
pub struct ReviewConfig {
    pub policy_name: String,
    pub policy_namespace: String,
    /// Namespace/ServiceAccount/cluster labels. Defaults to a cold source, so
    /// a webhook that was never given one denies every selected policy.
    pub labels: Arc<dyn LabelSource>,
}

impl Default for ReviewConfig {
    fn default() -> Self {
        Self {
            policy_name: String::new(),
            policy_namespace: String::new(),
            labels: Arc::new(ColdLabels::default()),
        }
    }
}

/// HTTP status + AdmissionReview (or error) body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewReply {
    pub status: u16,
    pub body: Vec<u8>,
    /// The verdict this reply carries, as a field rather than as something a
    /// caller re-parses out of `body`.
    ///
    /// It exists because the webhook now counts its own decisions, and the
    /// alternative was a second JSON parse of the response on the request
    /// path — a parse whose failure mode is a deny silently counted as an
    /// allow. A 400 is `false` here: the API server under `failurePolicy: Fail`
    /// treats it as a refusal, so counting it as an allow would put the one
    /// case an operator most needs to see on the wrong side of the graph.
    pub allowed: bool,
}

impl ReviewConfig {
    /// Evaluate an AdmissionReview body. `program = None` is fail-closed.
    pub fn handle_bytes(
        &self,
        body: &[u8],
        program: Option<&AdmissionProgram>,
        exceptions: &[PolicyExceptionSpec],
        now: DateTime<Utc>,
    ) -> ReviewReply {
        handle_with(self, body, program, exceptions, now)
    }
}

/// Fail-closed AdmissionReview. Unrecoverable uid → HTTP 400, not 200 with empty uid.
pub fn handle_review_bytes(
    body: &[u8],
    program: Option<&AdmissionProgram>,
    exceptions: &[PolicyExceptionSpec],
    now: DateTime<Utc>,
) -> ReviewReply {
    ReviewConfig::default().handle_bytes(body, program, exceptions, now)
}

fn handle_with(
    cfg: &ReviewConfig,
    body: &[u8],
    program: Option<&AdmissionProgram>,
    exceptions: &[PolicyExceptionSpec],
    now: DateTime<Utc>,
) -> ReviewReply {
    if body.is_empty() {
        return http_400("empty admission review body");
    }
    let parsed = match serde_json::from_slice::<Value>(body) {
        Ok(v) => v,
        Err(_) => return http_400("admission review is not JSON"),
    };
    // Echo uid before any other check. Missing uid is HTTP 400 so Ignore
    // cannot treat a 200 empty-uid response as a processed review.
    let uid = parsed
        .pointer("/request/uid")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if uid.is_empty() {
        return ReviewReply {
            status: 400,
            body: encode_response("", false, None, "admission request uid is required"),
            allowed: false,
        };
    }

    let Some(request) = parsed.get("request").and_then(Value::as_object) else {
        return ok_deny(&uid, "admission request is missing");
    };

    let Some(program) = program else {
        return ok_deny(&uid, "policy bundle missing, invalid, or unverifiable");
    };

    let object = match request.get("object") {
        None | Some(Value::Null) => {
            return ok_deny(&uid, "admission object is missing");
        }
        Some(o) => o,
    };

    let mut subject = match subject_from_object(object, &program.supply.trust_roots) {
        Ok(s) => s,
        Err(err) => {
            return ok_deny(&uid, &err.to_string());
        }
    };
    if subject.namespace.is_empty() {
        if let Some(ns) = request.get("namespace").and_then(Value::as_str) {
            subject.namespace = ns.to_string();
        }
    }
    subject.policy_name = cfg.policy_name.clone();
    subject.policy_namespace = cfg.policy_namespace.clone();

    // A cold cache denies only what it would actually decide: a policy with no
    // namespace/ServiceAccount selector never needed those labels. Sample the
    // warmth once and carry its cause into the reply: this message is the only
    // channel admission has, and it reaches the human running kubectl at the
    // moment of the deny.
    let warmth = cfg.labels.warmth();
    if !warmth.is_warm() && watched_labels_selected(program) {
        return ok_deny(
            &uid,
            &format!("namespace labels unavailable: {}", warmth.reason()),
        );
    }
    // The source answers "observed, and here they are" or "never observed";
    // the subject carries that answer through to `require_labels_if_selected`
    // instead of handing it an empty map for both.
    subject.namespace_labels = cfg.labels.namespace_labels(&subject.namespace);
    let service_account = if subject.service_account.is_empty() {
        DEFAULT_SERVICE_ACCOUNT
    } else {
        subject.service_account.as_str()
    };
    subject.service_account_labels = cfg
        .labels
        .service_account_labels(&subject.namespace, service_account);
    subject.cluster_labels = cfg.labels.cluster_labels();

    let decision = admit(program, &subject, exceptions, now);
    decision_response(&uid, object, &decision)
}

/// Cluster labels come from a flag, not from the watch, so a cluster selector
/// alone does not depend on the cache being warm.
fn watched_labels_selected(program: &AdmissionProgram) -> bool {
    selector_nonempty(&program.selector.namespace_selector)
        || selector_nonempty(&program.selector.service_account_selector)
}

fn selector_nonempty(selector: &LabelSelector) -> bool {
    !selector.match_labels.is_empty() || !selector.match_expressions.is_empty()
}

fn http_400(message: &str) -> ReviewReply {
    ReviewReply {
        status: 400,
        body: serde_json::to_vec(&json!({"error": message}))
            .unwrap_or_else(|_| br#"{"error":"bad request"}"#.to_vec()),
        allowed: false,
    }
}

fn ok_deny(uid: &str, message: &str) -> ReviewReply {
    ReviewReply {
        status: 200,
        body: encode_response(uid, false, None, message),
        allowed: false,
    }
}

fn decision_response(uid: &str, object: &Value, decision: &AdmissionDecision) -> ReviewReply {
    // Cluster Ignore is break-glass for webhook availability, never integrity.
    if decision.fail_closed {
        let msg = decision
            .reasons
            .first()
            .cloned()
            .unwrap_or_else(|| "policy bundle failed closed".into());
        return ok_deny(uid, &msg);
    }
    if !decision.allowed {
        let msg = if decision.reasons.is_empty() {
            "denied by policy".into()
        } else {
            decision.reasons.join("; ")
        };
        return ok_deny(uid, &msg);
    }
    // observe/audit never patch. Enforce patches are JSON Patch when allowed.
    let patch = if decision.mode == PolicyMode::Enforce
        && !decision.patches.is_empty()
        && object.get("kind").and_then(Value::as_str) == Some("Pod")
    {
        let ops = rfc6902_patches(&decision.patches, object);
        if ops.is_empty() {
            None
        } else {
            Some(Value::Array(ops))
        }
    } else {
        None
    };
    ReviewReply {
        status: 200,
        body: encode_response(uid, true, patch.as_ref(), ""),
        allowed: true,
    }
}

fn encode_response(uid: &str, allowed: bool, patch: Option<&Value>, message: &str) -> Vec<u8> {
    let mut response = Map::new();
    response.insert("uid".into(), json!(uid));
    response.insert("allowed".into(), json!(allowed));
    if let Some(patch) = patch {
        let bytes = serde_json::to_vec(patch).unwrap_or_else(|_| b"[]".to_vec());
        response.insert("patchType".into(), json!("JSONPatch"));
        response.insert("patch".into(), json!(b64_encode(&bytes)));
    }
    if !allowed {
        response.insert("status".into(), json!({"code": 403, "message": message}));
    }
    let body = json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": Value::Object(response),
    });
    serde_json::to_vec(&body).unwrap_or_else(|_| {
        b"{\"apiVersion\":\"admission.k8s.io/v1\",\"kind\":\"AdmissionReview\",\"response\":{\"uid\":\"\",\"allowed\":false}}"
            .to_vec()
    })
}

fn rfc6902_patches(patches: &[Patch], object: &Value) -> Vec<Value> {
    let mut ops = Vec::new();
    let container_paths = container_paths(object);
    if patches.contains(&Patch::InjectSeccompRuntimeDefault) {
        add_nested(
            &mut ops,
            object,
            "/spec/securityContext/seccompProfile",
            json!({"type": "RuntimeDefault"}),
        );
        for path in &container_paths {
            add_nested(
                &mut ops,
                object,
                &format!("{path}/securityContext/seccompProfile"),
                json!({"type": "RuntimeDefault"}),
            );
        }
    }
    if patches.contains(&Patch::DropAllCapabilities) {
        for path in &container_paths {
            add_nested(
                &mut ops,
                object,
                &format!("{path}/securityContext/capabilities/drop"),
                json!(["ALL"]),
            );
        }
    }
    if patches.contains(&Patch::ReadOnlyRootFilesystem) {
        for path in &container_paths {
            add_nested(
                &mut ops,
                object,
                &format!("{path}/securityContext/readOnlyRootFilesystem"),
                json!(true),
            );
        }
    }
    ops
}

fn container_paths(object: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    for key in ["containers", "initContainers", "ephemeralContainers"] {
        if let Some(arr) = object
            .pointer(&format!("/spec/{key}"))
            .and_then(Value::as_array)
        {
            for i in 0..arr.len() {
                paths.push(format!("/spec/{key}/{i}"));
            }
        }
    }
    paths
}

fn add_nested(ops: &mut Vec<Value>, object: &Value, path: &str, value: Value) {
    if object.pointer(path).is_some() {
        ops.push(json!({"op": "add", "path": path, "value": value}));
        return;
    }
    let Some((parent, key)) = split_pointer(path) else {
        ops.push(json!({"op": "add", "path": path, "value": value}));
        return;
    };
    if object.pointer(parent).is_some() {
        ops.push(json!({"op": "add", "path": path, "value": value}));
        return;
    }
    let mut obj = Map::new();
    obj.insert(key.to_string(), value);
    add_nested(ops, object, parent, Value::Object(obj));
}

fn split_pointer(path: &str) -> Option<(&str, &str)> {
    let trimmed = path.strip_prefix('/')?;
    let idx = trimmed.rfind('/')?;
    let parent = &path[..idx + 1];
    let parent = parent.strip_suffix('/').unwrap_or(parent);
    let key = &trimmed[idx + 1..];
    if parent.is_empty() {
        Some(("/", key))
    } else {
        Some((parent, key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_and_missing_uid_are_http_400() {
        let reply = handle_review_bytes(b"not-json", None, &[], Utc::now());
        assert_eq!(reply.status, 400);

        let reply = handle_review_bytes(&[], None, &[], Utc::now());
        assert_eq!(reply.status, 400);

        let reply = handle_review_bytes(
            br#"{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{}}"#,
            None,
            &[],
            Utc::now(),
        );
        assert_eq!(reply.status, 400);
        let v: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(v["response"]["allowed"], false);
        assert_eq!(v["response"]["uid"], "");
    }

    #[test]
    fn uid_is_echoed_on_http_200_before_other_checks() {
        let reply = handle_review_bytes(
            br#"{"request":{"uid":"keep-me","object":null}}"#,
            None,
            &[],
            Utc::now(),
        );
        assert_eq!(reply.status, 200);
        let v: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(v["response"]["uid"], "keep-me");
        assert_eq!(v["response"]["allowed"], false);
    }

    #[test]
    fn split_pointer_parent() {
        assert_eq!(
            split_pointer("/spec/containers/0/securityContext"),
            Some(("/spec/containers/0", "securityContext"))
        );
    }
}
