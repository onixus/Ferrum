//! Status PATCH and signed bundle Secret. Failed compile never writes a Secret.

use crate::bundle::{encode_fsig_envelope, verify_signed_bundle, SignedBundle};
use crate::{compile_status_err, ReconcileOutcome};
use ferrum_api::{PolicyExceptionSpec, PolicyStatus};
use ferrum_common::{FerrumError, Result};
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::ByteString;
use kube::api::{Api, ListParams, Patch, PatchParams, PostParams};
use kube::Client;
use std::collections::BTreeMap;

pub const DEFAULT_NAMESPACE: &str = "ferrum";
pub const BUNDLE_SECRET_PREFIX: &str = "ferrum-bundle-";
pub const BUNDLE_FSIG_KEY: &str = "bundle.fsig";
pub const BUNDLE_DIGEST_KEY: &str = "digest";
/// Live exceptions ride in the same Secret as the FSIG so admission reads both
/// from one mount. The list is signed with the bundle key into an FSIG
/// envelope: a writer with Secret access must not be able to add or strip
/// exceptions (that would disable Kill/Deny without the signing key). Eval
/// still re-checks scope and expiresAt on every request.
pub const EXCEPTIONS_FSIG_KEY: &str = "exceptions.fsig";
/// Legacy unsigned key. No longer written; the patch nulls it out so a stale
/// unsigned list cannot linger next to the signed one.
pub const EXCEPTIONS_JSON_KEY: &str = "exceptions.json";

/// Secrets carry owner labels; `upsert_secret` refuses to overwrite a Secret
/// whose labels name a different owner, so any residual name collision
/// (hyphens make ns/name concatenation ambiguous) fails closed instead of
/// silently replacing another policy's bundle.
pub const MANAGED_BY_KEY: &str = "app.kubernetes.io/managed-by";
pub const MANAGED_BY_VALUE: &str = "ferrum-controller";
pub const POLICY_LABEL_KEY: &str = "ferrum.io/policy";
pub const POLICY_NAMESPACE_LABEL_KEY: &str = "ferrum.io/policy-namespace";
/// Label value for cluster-scoped policies; a real namespace can never be it
/// (RFC 1123 labels cannot contain a dot).
pub const CLUSTER_SCOPE_VALUE: &str = "cluster.scope";

pub fn secret_name(policy_name: &str) -> String {
    format!("{BUNDLE_SECRET_PREFIX}cluster-{policy_name}")
}

/// Namespaced SecurityPolicy bundles get their own Secret in a `ns-` name
/// space distinct from the `cluster-` one.
pub fn namespaced_secret_name(policy_name: &str, policy_namespace: &str) -> String {
    format!("{BUNDLE_SECRET_PREFIX}ns-{policy_namespace}-{policy_name}")
}

pub fn cluster_secret_labels(policy_name: &str) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert(MANAGED_BY_KEY.into(), MANAGED_BY_VALUE.into());
    labels.insert(POLICY_LABEL_KEY.into(), policy_name.into());
    labels.insert(
        POLICY_NAMESPACE_LABEL_KEY.into(),
        CLUSTER_SCOPE_VALUE.into(),
    );
    labels
}

pub fn namespaced_secret_labels(
    policy_name: &str,
    policy_namespace: &str,
) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert(MANAGED_BY_KEY.into(), MANAGED_BY_VALUE.into());
    labels.insert(POLICY_LABEL_KEY.into(), policy_name.into());
    labels.insert(POLICY_NAMESPACE_LABEL_KEY.into(), policy_namespace.into());
    labels
}

/// A live Secret may be overwritten only when its owner labels match the
/// planned ones exactly. Anything else — foreign Secret, other policy, other
/// scope — is Integrity, not a merge.
pub fn ensure_secret_ownership(live: &Secret, planned: &Secret) -> Result<()> {
    let planned_labels = planned.metadata.labels.clone().unwrap_or_default();
    let live_labels = live.metadata.labels.clone().unwrap_or_default();
    for key in [MANAGED_BY_KEY, POLICY_LABEL_KEY, POLICY_NAMESPACE_LABEL_KEY] {
        if live_labels.get(key) != planned_labels.get(key) {
            let name = live.metadata.name.as_deref().unwrap_or("<unnamed>");
            return Err(FerrumError::Integrity(format!(
                "secret {name} is owned by another policy ({key} mismatch); refusing to overwrite"
            )));
        }
    }
    Ok(())
}

/// Exceptions relevant to one policy's Secret: an explicit `target.policies`
/// list must name the policy; an empty list stays global. Scope and TTL are
/// still re-checked by eval on every request.
pub fn exceptions_for_policy(
    specs: &[PolicyExceptionSpec],
    policy_name: &str,
) -> Vec<PolicyExceptionSpec> {
    specs
        .iter()
        .filter(|s| {
            s.target.policies.is_empty() || s.target.policies.iter().any(|p| p == policy_name)
        })
        .cloned()
        .collect()
}

pub fn exceptions_json(specs: &[PolicyExceptionSpec]) -> Result<Vec<u8>> {
    serde_json::to_vec(specs)
        .map_err(|e| FerrumError::Validation(format!("exceptions encode: {e}")))
}

/// Sign the JSON exception array into the same FSIG envelope as bundle.fsig,
/// with the same bundle-signing key.
pub fn exceptions_fsig(specs: &[PolicyExceptionSpec], secret_key: &[u8]) -> Result<Vec<u8>> {
    let payload = exceptions_json(specs)?;
    let signature = ferrum_crypto::sign_bundle(&payload, secret_key)?;
    let public_key = ferrum_crypto::public_key_from_secret(secret_key)?;
    encode_fsig_envelope(&public_key, &signature, &payload)
}

/// Merge-patch body that sets only `exceptions.fsig` and deletes the legacy
/// unsigned `exceptions.json` (null removes a key in a JSON merge patch);
/// bundle.fsig and digest keys of the target Secret are left intact.
pub fn exceptions_secret_patch(
    specs: &[PolicyExceptionSpec],
    secret_key: &[u8],
) -> Result<serde_json::Value> {
    let fsig = exceptions_fsig(specs, secret_key)?;
    let fsig_b64 = serde_json::to_value(ByteString(fsig))
        .map_err(|e| FerrumError::Validation(format!("exceptions.fsig encode: {e}")))?;
    Ok(serde_json::json!({
        "data": {
            EXCEPTIONS_FSIG_KEY: fsig_b64,
            EXCEPTIONS_JSON_KEY: serde_json::Value::Null,
        }
    }))
}

/// Push the current live exception list into every bundle Secret we own —
/// selected by owner label, never by name prefix — scoping each Secret's
/// `exceptions.fsig` to the exceptions that target its policy.
pub async fn persist_exceptions(
    client: &Client,
    namespace: &str,
    secret_key: &[u8],
    specs: &[PolicyExceptionSpec],
) -> Result<()> {
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let selector = format!("{MANAGED_BY_KEY}={MANAGED_BY_VALUE}");
    let list = api
        .list(&ListParams::default().labels(&selector))
        .await
        .map_err(|e| FerrumError::Degraded(format!("secret list {namespace}: {e}")))?;
    for secret in list.items {
        let Some(name) = secret.metadata.name.as_deref() else {
            continue;
        };
        let Some(policy) = secret
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(POLICY_LABEL_KEY))
        else {
            continue;
        };
        let patch = exceptions_secret_patch(&exceptions_for_policy(specs, policy), secret_key)?;
        api.patch(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
            .map_err(|e| FerrumError::Degraded(format!("secret patch {name}: {e}")))?;
    }
    Ok(())
}

pub(crate) async fn patch_secret_exceptions(
    client: &Client,
    namespace: &str,
    secret_name: &str,
    secret_key: &[u8],
    specs: &[PolicyExceptionSpec],
) -> Result<()> {
    let patch = exceptions_secret_patch(specs, secret_key)?;
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    api.patch(secret_name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(|e| FerrumError::Degraded(format!("secret patch {secret_name}: {e}")))?;
    Ok(())
}

pub fn status_patch(status: &PolicyStatus) -> serde_json::Value {
    serde_json::json!({ "status": status })
}

/// Encode FSIG only after verifying against the configured trust-root.
pub fn bundle_secret(
    policy_name: &str,
    namespace: &str,
    bundle: &SignedBundle,
    trust_root: &[u8],
) -> Result<Secret> {
    bundle_secret_named(
        &secret_name(policy_name),
        namespace,
        cluster_secret_labels(policy_name),
        bundle,
        trust_root,
    )
}

pub fn bundle_secret_named(
    secret_name: &str,
    namespace: &str,
    labels: BTreeMap<String, String>,
    bundle: &SignedBundle,
    trust_root: &[u8],
) -> Result<Secret> {
    verify_signed_bundle(bundle, trust_root)?;
    let fsig = bundle.encode()?;
    let mut data = BTreeMap::new();
    data.insert(BUNDLE_FSIG_KEY.to_string(), ByteString(fsig));
    data.insert(
        BUNDLE_DIGEST_KEY.to_string(),
        ByteString(bundle.digest.as_str().as_bytes().to_vec()),
    );
    Ok(Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels),
            ..ObjectMeta::default()
        },
        type_: Some("Opaque".into()),
        data: Some(data),
        ..Secret::default()
    })
}

/// Live Secret must verify against the trust-root and match `expected_digest`.
pub fn live_secret_matches(secret: &Secret, trust_root: &[u8], expected_digest: &str) -> bool {
    if expected_digest.is_empty() {
        return false;
    }
    let Some(data) = secret.data.as_ref() else {
        return false;
    };
    if let Some(stored) = data.get(BUNDLE_DIGEST_KEY) {
        match std::str::from_utf8(&stored.0) {
            Ok(s) if s == expected_digest => {}
            _ => return false,
        }
    }
    let Some(fsig) = data.get(BUNDLE_FSIG_KEY) else {
        return false;
    };
    let Ok(bundle) = SignedBundle::decode(&fsig.0) else {
        return false;
    };
    match verify_signed_bundle(&bundle, trust_root) {
        Ok(digest) => digest.as_str() == expected_digest,
        Err(_) => false,
    }
}

pub(crate) async fn load_bundle_secret(
    client: &Client,
    namespace: &str,
    secret_name: &str,
) -> Result<Option<Secret>> {
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    api.get_opt(secret_name)
        .await
        .map_err(|e| FerrumError::Degraded(format!("secret get {secret_name}: {e}")))
}

#[derive(Debug, Clone)]
pub struct ApplyPlan {
    pub status: serde_json::Value,
    pub secret: Option<Secret>,
}

/// Applied → status + Secret. Failed / unverifiable → status only, empty digest.
pub fn plan_apply(
    policy_name: &str,
    namespace: &str,
    outcome: &ReconcileOutcome,
    trust_root: &[u8],
) -> ApplyPlan {
    plan_apply_named(
        &secret_name(policy_name),
        namespace,
        cluster_secret_labels(policy_name),
        outcome,
        trust_root,
    )
}

/// Namespaced SecurityPolicy plan: same shape, `ns-` Secret name space.
pub fn plan_apply_namespaced(
    policy_name: &str,
    policy_namespace: &str,
    secret_namespace: &str,
    outcome: &ReconcileOutcome,
    trust_root: &[u8],
) -> ApplyPlan {
    plan_apply_named(
        &namespaced_secret_name(policy_name, policy_namespace),
        secret_namespace,
        namespaced_secret_labels(policy_name, policy_namespace),
        outcome,
        trust_root,
    )
}

pub fn plan_apply_named(
    secret_name: &str,
    namespace: &str,
    labels: BTreeMap<String, String>,
    outcome: &ReconcileOutcome,
    trust_root: &[u8],
) -> ApplyPlan {
    match outcome {
        ReconcileOutcome::Applied(applied) => {
            match bundle_secret_named(secret_name, namespace, labels, &applied.bundle, trust_root) {
                Ok(secret) => ApplyPlan {
                    status: status_patch(&applied.status),
                    secret: Some(secret),
                },
                Err(err) => ApplyPlan {
                    status: status_patch(&PolicyStatus {
                        observed_generation: applied.status.observed_generation,
                        compile: compile_status_err(&err),
                        rollout: Default::default(),
                    }),
                    secret: None,
                },
            }
        }
        ReconcileOutcome::Failed(status) => ApplyPlan {
            status: status_patch(status),
            secret: None,
        },
    }
}

pub async fn persist(
    client: &Client,
    policy_name: &str,
    namespace: &str,
    plan: &ApplyPlan,
) -> Result<()> {
    persist_dynamic(
        client,
        &crate::watch::cluster_security_policy_resource(),
        None,
        policy_name,
        namespace,
        plan,
    )
    .await
}

/// Upsert the plan Secret (in `secret_namespace`), then PATCH the object status
/// via the given ApiResource; `object_namespace = None` means cluster-scoped.
pub(crate) async fn persist_dynamic(
    client: &Client,
    resource: &kube::api::ApiResource,
    object_namespace: Option<&str>,
    object_name: &str,
    secret_namespace: &str,
    plan: &ApplyPlan,
) -> Result<()> {
    if let Some(secret) = &plan.secret {
        upsert_secret(client, secret_namespace, secret).await?;
    }
    patch_status_dynamic(
        client,
        resource,
        object_namespace,
        object_name,
        &plan.status,
    )
    .await
}

async fn upsert_secret(client: &Client, namespace: &str, secret: &Secret) -> Result<()> {
    let name =
        secret.metadata.name.as_deref().ok_or_else(|| {
            FerrumError::Validation("bundle Secret metadata.name is missing".into())
        })?;
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let live = api
        .get_opt(name)
        .await
        .map_err(|e| FerrumError::Degraded(format!("secret get {name}: {e}")))?;
    if let Some(live) = live {
        ensure_secret_ownership(&live, secret)?;
        api.patch(name, &PatchParams::default(), &Patch::Merge(secret))
            .await
            .map_err(|e| FerrumError::Degraded(format!("secret patch {name}: {e}")))?;
    } else {
        api.create(&PostParams::default(), secret)
            .await
            .map_err(|e| FerrumError::Degraded(format!("secret create {name}: {e}")))?;
    }
    Ok(())
}

pub(crate) async fn patch_status_dynamic(
    client: &Client,
    resource: &kube::api::ApiResource,
    namespace: Option<&str>,
    name: &str,
    patch: &serde_json::Value,
) -> Result<()> {
    let api: Api<kube::api::DynamicObject> = match namespace {
        Some(ns) => Api::namespaced_with(client.clone(), ns, resource),
        None => Api::all_with(client.clone(), resource),
    };
    api.patch_status(name, &PatchParams::default(), &Patch::Merge(patch.clone()))
        .await
        .map_err(|e| FerrumError::Degraded(format!("status patch {name}: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::SignedBundle;
    use crate::{compile_and_sign, reconcile, ClusterAbi, ReconcileInput};
    use ferrum_api::{
        ClusterSecurityPolicy, ClusterSecurityPolicySpec, PolicyLibrarySpec, RuntimeAction,
        RuntimeSpec,
    };
    use ferrum_crypto::ED25519_SECRET_KEY_LEN;
    use ferrum_ids::AGENT_ABI;

    const RFC8032_SK: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    fn prod_restricted() -> ClusterSecurityPolicySpec {
        let yaml = include_str!("../../../policies/examples/prod-restricted.yaml");
        let obj: ClusterSecurityPolicy = serde_yaml::from_str(yaml).expect("example yaml");
        obj.spec
    }

    fn pk() -> Vec<u8> {
        ferrum_crypto::public_key_from_secret(&RFC8032_SK).expect("pk")
    }

    #[test]
    fn applied_plan_writes_verifiable_fsig_secret() {
        let spec = prod_restricted();
        let outcome = reconcile(ReconcileInput {
            spec: &spec,
            observed_generation: 9,
            secret_key: &RFC8032_SK,
            library: None,
            clusters: &[],
            runtime_profile: None,
        });
        let plan = plan_apply("prod-restricted", DEFAULT_NAMESPACE, &outcome, &pk());
        let secret = plan.secret.expect("Secret on Applied");
        assert_eq!(
            secret.metadata.name.as_deref(),
            Some("ferrum-bundle-cluster-prod-restricted")
        );
        let labels = secret.metadata.labels.as_ref().expect("owner labels");
        assert_eq!(
            labels.get(MANAGED_BY_KEY).map(String::as_str),
            Some(MANAGED_BY_VALUE)
        );
        assert_eq!(
            labels.get(POLICY_LABEL_KEY).map(String::as_str),
            Some("prod-restricted")
        );
        assert_eq!(
            labels.get(POLICY_NAMESPACE_LABEL_KEY).map(String::as_str),
            Some(CLUSTER_SCOPE_VALUE)
        );
        assert_eq!(
            secret.metadata.namespace.as_deref(),
            Some(DEFAULT_NAMESPACE)
        );
        let data = secret.data.as_ref().expect("data");
        let fsig = &data.get(BUNDLE_FSIG_KEY).expect("bundle.fsig").0;
        assert_eq!(&fsig[..4], &crate::SIGNED_MAGIC);
        let decoded = SignedBundle::decode(fsig).expect("decode FSIG");
        let digest = verify_signed_bundle(&decoded, &pk()).expect("trust-root verifies");
        assert_eq!(digest.as_str().len(), 64);
        assert_eq!(
            plan.status["status"]["compile"]["ready"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            plan.status["status"]["compile"]["bundleDigest"]
                .as_str()
                .expect("digest")
                .len(),
            64
        );
        assert_eq!(plan.status["status"]["observedGeneration"], 9);
    }

    #[test]
    fn failed_kill_all_has_empty_digest_and_no_secret() {
        let spec = ClusterSecurityPolicySpec {
            runtime: RuntimeSpec {
                default_action: RuntimeAction::Kill,
                rules: vec![],
            },
            ..Default::default()
        };
        let outcome = reconcile(ReconcileInput {
            spec: &spec,
            observed_generation: 3,
            secret_key: &RFC8032_SK,
            library: None,
            clusters: &[],
            runtime_profile: None,
        });
        assert!(matches!(outcome, ReconcileOutcome::Failed(_)));
        let plan = plan_apply("kill-all", DEFAULT_NAMESPACE, &outcome, &pk());
        assert!(plan.secret.is_none());
        assert_eq!(
            plan.status["status"]["compile"]["ready"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            plan.status["status"]["compile"]["bundleDigest"]
                .as_str()
                .expect("empty"),
            ""
        );
    }

    #[test]
    fn wrong_trust_root_does_not_write_secret() {
        let spec = prod_restricted();
        let signed = compile_and_sign(&spec, &RFC8032_SK).expect("sign");
        let mut other = RFC8032_SK;
        other[0] ^= 1;
        let wrong = ferrum_crypto::public_key_from_secret(&other).expect("other pk");
        match bundle_secret("prod-restricted", DEFAULT_NAMESPACE, &signed, &wrong) {
            Err(FerrumError::Integrity(_)) => {}
            other => panic!("expected Integrity, got {other:?}"),
        }
        let outcome = reconcile(ReconcileInput {
            spec: &spec,
            observed_generation: 1,
            secret_key: &RFC8032_SK,
            library: None,
            clusters: &[],
            runtime_profile: None,
        });
        let plan = plan_apply("prod-restricted", DEFAULT_NAMESPACE, &outcome, &wrong);
        assert!(plan.secret.is_none());
        assert_eq!(
            plan.status["status"]["compile"]["ready"],
            serde_json::Value::Bool(false)
        );
    }

    #[test]
    fn all_zero_seed_plan_has_no_secret() {
        let spec = prod_restricted();
        let outcome = reconcile(ReconcileInput {
            spec: &spec,
            observed_generation: 1,
            secret_key: &[0u8; ED25519_SECRET_KEY_LEN],
            library: None,
            clusters: &[],
            runtime_profile: None,
        });
        let plan = plan_apply("prod-restricted", DEFAULT_NAMESPACE, &outcome, &pk());
        assert!(plan.secret.is_none());
        assert!(matches!(outcome, ReconcileOutcome::Failed(_)));
    }

    #[test]
    fn library_min_abi_keep_lkg_still_may_write_bundle() {
        let spec = prod_restricted();
        let lib = PolicyLibrarySpec {
            source: "cli".into(),
            digest: String::new(),
            min_agent_abi: AGENT_ABI.saturating_add(1),
            min_admission_abi: 0,
        };
        let clusters = [ClusterAbi {
            name: "old".into(),
            agent_abi: AGENT_ABI,
            admission_abi: AGENT_ABI,
        }];
        let outcome = reconcile(ReconcileInput {
            spec: &spec,
            observed_generation: 1,
            secret_key: &RFC8032_SK,
            library: Some(&lib),
            clusters: &clusters,
            runtime_profile: None,
        });
        match &outcome {
            ReconcileOutcome::Applied(a) => {
                assert!(a.deliver.is_empty());
                assert_eq!(a.keep_lkg, vec!["old".to_string()]);
                assert_eq!(a.status.rollout.clusters_degraded, 1);
            }
            ReconcileOutcome::Failed(s) => panic!("{}", s.compile.message),
        }
        let plan = plan_apply("prod-restricted", DEFAULT_NAMESPACE, &outcome, &pk());
        assert!(plan.secret.is_some());
    }

    fn live_exception() -> PolicyExceptionSpec {
        let expires = chrono::Utc::now() + chrono::Days::new(7);
        PolicyExceptionSpec {
            ticket: "JIRA-18421".into(),
            requested_by: "sre".into(),
            approved_by: "ib".into(),
            reason: "temporary debug sidecar".into(),
            expires_at: expires,
            mode: Default::default(),
            four_eyes: true,
            target: ferrum_api::ExceptionTarget {
                namespace: "payments".into(),
                policies: vec!["prod-restricted".into()],
                rules: vec!["no-shell".into()],
            },
        }
    }

    fn b64_decode(s: &str) -> Vec<u8> {
        serde_json::from_value::<ByteString>(serde_json::Value::String(s.to_string()))
            .expect("base64")
            .0
    }

    #[test]
    fn exceptions_patch_signs_fsig_and_nulls_legacy_json_key() {
        let spec = live_exception();
        let patch = exceptions_secret_patch(&[spec.clone()], &RFC8032_SK).expect("patch");
        let data = patch["data"].as_object().expect("data");
        assert_eq!(data.len(), 2);
        assert!(
            data.get(EXCEPTIONS_JSON_KEY).expect("legacy key").is_null(),
            "merge patch must delete the unsigned exceptions.json"
        );
        assert!(!data.contains_key(BUNDLE_FSIG_KEY));
        assert!(!data.contains_key(BUNDLE_DIGEST_KEY));
        let fsig = b64_decode(
            data.get(EXCEPTIONS_FSIG_KEY)
                .and_then(|v| v.as_str())
                .expect("exceptions.fsig base64"),
        );
        assert_eq!(&fsig[..4], &crate::SIGNED_MAGIC);
        let payload = crate::bundle::verify_fsig_envelope(&fsig, &pk()).expect("trust root");
        let decoded: Vec<PolicyExceptionSpec> = serde_json::from_slice(&payload).expect("decode");
        assert_eq!(decoded, vec![spec]);
    }

    #[test]
    fn exceptions_fsig_rejects_wrong_root_and_tampered_payload() {
        let fsig = exceptions_fsig(&[live_exception()], &RFC8032_SK).expect("fsig");
        crate::bundle::verify_fsig_envelope(&fsig, &pk()).expect("bundle trust root verifies");

        let mut other = RFC8032_SK;
        other[0] ^= 1;
        let wrong = ferrum_crypto::public_key_from_secret(&other).expect("other pk");
        match crate::bundle::verify_fsig_envelope(&fsig, &wrong) {
            Err(FerrumError::Integrity(_)) => {}
            res => panic!("expected Integrity, got {res:?}"),
        }

        let mut tampered = fsig.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        match crate::bundle::verify_fsig_envelope(&tampered, &pk()) {
            Err(FerrumError::Integrity(_)) => {}
            res => panic!("expected Integrity, got {res:?}"),
        }

        match exceptions_fsig(&[live_exception()], &[0u8; ED25519_SECRET_KEY_LEN]) {
            Err(_) => {}
            Ok(_) => panic!("all-zero seed must not sign exceptions"),
        }
    }

    #[test]
    fn per_policy_scoping_survives_signing() {
        let spec = live_exception();
        let scoped = exceptions_for_policy(&[spec.clone()], "prod-restricted");
        let fsig = exceptions_fsig(&scoped, &RFC8032_SK).expect("fsig");
        let payload = crate::bundle::verify_fsig_envelope(&fsig, &pk()).expect("verify");
        let decoded: Vec<PolicyExceptionSpec> = serde_json::from_slice(&payload).expect("decode");
        assert_eq!(decoded, vec![spec]);

        let other = exceptions_for_policy(&decoded, "other-policy");
        let fsig = exceptions_fsig(&other, &RFC8032_SK).expect("fsig empty");
        let payload = crate::bundle::verify_fsig_envelope(&fsig, &pk()).expect("verify empty");
        assert_eq!(payload, b"[]");
    }

    #[test]
    fn namespaced_secret_name_has_namespace_suffix() {
        assert_eq!(
            namespaced_secret_name("prod-restricted", "payments"),
            "ferrum-bundle-ns-payments-prod-restricted"
        );
        assert_ne!(
            namespaced_secret_name("p", "a"),
            namespaced_secret_name("p", "b")
        );
    }

    #[test]
    fn cluster_and_namespaced_secret_names_never_collide() {
        // SecurityPolicy foo in ns bar vs ClusterSecurityPolicy foo-bar: the
        // old scheme collapsed both to the same name.
        assert_ne!(namespaced_secret_name("foo", "bar"), secret_name("foo-bar"));
        assert_eq!(secret_name("foo-bar"), "ferrum-bundle-cluster-foo-bar");
        assert_eq!(
            namespaced_secret_name("foo", "bar"),
            "ferrum-bundle-ns-bar-foo"
        );
    }

    #[test]
    fn foreign_secret_is_not_overwritten() {
        let planned_labels = cluster_secret_labels("prod-restricted");
        let planned = Secret {
            metadata: ObjectMeta {
                name: Some("ferrum-bundle-cluster-prod-restricted".into()),
                labels: Some(planned_labels),
                ..ObjectMeta::default()
            },
            ..Secret::default()
        };
        // Unlabeled live Secret (pre-existing or foreign) is refused.
        let unlabeled = Secret {
            metadata: ObjectMeta {
                name: Some("ferrum-bundle-cluster-prod-restricted".into()),
                ..ObjectMeta::default()
            },
            ..Secret::default()
        };
        match ensure_secret_ownership(&unlabeled, &planned) {
            Err(FerrumError::Integrity(_)) => {}
            other => panic!("expected Integrity, got {other:?}"),
        }
        // A Secret owned by a different policy is refused.
        let other_policy = Secret {
            metadata: ObjectMeta {
                labels: Some(namespaced_secret_labels("prod-restricted", "payments")),
                ..ObjectMeta::default()
            },
            ..Secret::default()
        };
        assert!(ensure_secret_ownership(&other_policy, &planned).is_err());
        // Same owner labels round-trip fine.
        let same = Secret {
            metadata: ObjectMeta {
                labels: Some(cluster_secret_labels("prod-restricted")),
                ..ObjectMeta::default()
            },
            ..Secret::default()
        };
        assert!(ensure_secret_ownership(&same, &planned).is_ok());
    }

    #[test]
    fn exceptions_filtered_by_target_policies() {
        let expires = chrono::Utc::now() + chrono::Days::new(7);
        let mut scoped = PolicyExceptionSpec {
            ticket: "JIRA-1".into(),
            requested_by: "sre".into(),
            approved_by: "ib".into(),
            reason: "temporary debug sidecar".into(),
            expires_at: expires,
            mode: Default::default(),
            four_eyes: true,
            target: ferrum_api::ExceptionTarget {
                namespace: "payments".into(),
                policies: vec!["prod-restricted".into()],
                rules: vec!["no-shell".into()],
            },
        };
        let global = PolicyExceptionSpec {
            target: ferrum_api::ExceptionTarget {
                namespace: "payments".into(),
                policies: vec![],
                rules: vec![],
            },
            ..scoped.clone()
        };
        scoped.ticket = "JIRA-2".into();
        let specs = vec![scoped.clone(), global.clone()];
        let for_prod = exceptions_for_policy(&specs, "prod-restricted");
        assert_eq!(for_prod, vec![scoped, global.clone()]);
        let for_other = exceptions_for_policy(&specs, "other-policy");
        assert_eq!(for_other, vec![global]);
    }
}
