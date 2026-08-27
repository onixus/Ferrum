//! Status PATCH and signed bundle Secret. Failed compile never writes a Secret.

use crate::bundle::{verify_signed_bundle, SignedBundle};
use crate::{compile_status_err, ReconcileOutcome};
use ferrum_api::PolicyStatus;
use ferrum_common::{FerrumError, Result};
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::ByteString;
use kube::api::{Api, Patch, PatchParams, PostParams};
use kube::Client;
use std::collections::BTreeMap;

pub const DEFAULT_NAMESPACE: &str = "ferrum";
pub const BUNDLE_FSIG_KEY: &str = "bundle.fsig";
pub const BUNDLE_DIGEST_KEY: &str = "digest";

pub fn secret_name(policy_name: &str) -> String {
    format!("ferrum-bundle-{policy_name}")
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
            name: Some(secret_name(policy_name)),
            namespace: Some(namespace.to_string()),
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
    policy_name: &str,
) -> Result<Option<Secret>> {
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let name = secret_name(policy_name);
    api.get_opt(&name)
        .await
        .map_err(|e| FerrumError::Degraded(format!("secret get {name}: {e}")))
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
    match outcome {
        ReconcileOutcome::Applied(applied) => {
            match bundle_secret(policy_name, namespace, &applied.bundle, trust_root) {
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
    if let Some(secret) = &plan.secret {
        upsert_secret(client, namespace, secret).await?;
    }
    patch_policy_status(client, policy_name, &plan.status).await
}

async fn upsert_secret(client: &Client, namespace: &str, secret: &Secret) -> Result<()> {
    let name =
        secret.metadata.name.as_deref().ok_or_else(|| {
            FerrumError::Validation("bundle Secret metadata.name is missing".into())
        })?;
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let exists = api
        .get_opt(name)
        .await
        .map_err(|e| FerrumError::Degraded(format!("secret get {name}: {e}")))?
        .is_some();
    if exists {
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

async fn patch_policy_status(
    client: &Client,
    policy_name: &str,
    patch: &serde_json::Value,
) -> Result<()> {
    let api: Api<kube::api::DynamicObject> = Api::all_with(
        client.clone(),
        &crate::watch::cluster_security_policy_resource(),
    );
    api.patch_status(
        policy_name,
        &PatchParams::default(),
        &Patch::Merge(patch.clone()),
    )
    .await
    .map_err(|e| FerrumError::Degraded(format!("status patch {policy_name}: {e}")))?;
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
            Some("ferrum-bundle-prod-restricted")
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
}
