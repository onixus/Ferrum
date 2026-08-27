//! Watch ClusterSecurityPolicy as DynamicObject. Not kube::runtime::Controller.

use crate::apply::{live_secret_matches, load_bundle_secret, persist, plan_apply, ApplyPlan};
use crate::{compile_status_err, reconcile, ObservedPolicy, ReconcileInput, WatchConfig};
use ferrum_api::{ClusterSecurityPolicySpec, PolicyStatus, RolloutStatus};
use ferrum_common::{FerrumError, Result};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ApiResource, DynamicObject, GroupVersionKind};
use kube::runtime::{watcher, WatchStreamExt};
use kube::Client;

pub fn cluster_security_policy_gvk() -> GroupVersionKind {
    GroupVersionKind::gvk(
        ferrum_api::GROUP,
        ferrum_api::VERSION,
        "ClusterSecurityPolicy",
    )
}

pub fn cluster_security_policy_resource() -> ApiResource {
    ApiResource::from_gvk(&cluster_security_policy_gvk())
}

pub fn observe_policy(obj: &DynamicObject) -> Result<ObservedPolicy> {
    let name = obj
        .metadata
        .name
        .clone()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| {
            FerrumError::Validation("ClusterSecurityPolicy metadata.name is missing".into())
        })?;
    let generation = obj.metadata.generation.unwrap_or(0);
    let resource_version = obj.metadata.resource_version.clone().unwrap_or_default();
    let spec = decode_spec(obj)?;
    Ok(ObservedPolicy {
        name,
        generation,
        resource_version,
        spec,
    })
}

fn decode_spec(obj: &DynamicObject) -> Result<ClusterSecurityPolicySpec> {
    let spec_val = match &obj.data {
        serde_json::Value::Object(map) => map.get("spec"),
        _ => None,
    };
    match spec_val {
        None | Some(serde_json::Value::Null) => Err(FerrumError::Validation(
            "ClusterSecurityPolicy spec is missing".into(),
        )),
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|e| FerrumError::Validation(format!("ClusterSecurityPolicy spec: {e}"))),
    }
}

fn status_compile(obj: &DynamicObject) -> (Option<i64>, bool, String) {
    let Some(status) = obj.data.get("status") else {
        return (None, false, String::new());
    };
    let observed = status.get("observedGeneration").and_then(|v| v.as_i64());
    let compile = status.get("compile");
    let ready = compile
        .and_then(|c| c.get("ready"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let digest = compile
        .and_then(|c| c.get("bundleDigest"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    (observed, ready, digest)
}

/// Skip Applied only when this generation is ready **and** the live Secret verifies.
/// Failed compile never skips as success, even if a leftover Secret exists.
pub(crate) fn should_skip_applied(
    generation: i64,
    observed_generation: Option<i64>,
    compile_ready: bool,
    expected_digest: &str,
    secret: Option<&Secret>,
    trust_root: &[u8],
) -> bool {
    if observed_generation != Some(generation) || !compile_ready || expected_digest.is_empty() {
        return false;
    }
    match secret {
        Some(secret) => live_secret_matches(secret, trust_root, expected_digest),
        None => false,
    }
}

fn failed_status_already_recorded(obj: &DynamicObject, generation: i64, plan: &ApplyPlan) -> bool {
    if plan.secret.is_some() {
        return false;
    }
    let plan_ready = plan.status["status"]["compile"]["ready"]
        .as_bool()
        .unwrap_or(true);
    if plan_ready {
        return false;
    }
    let (og, ready, digest) = status_compile(obj);
    og == Some(generation) && !ready && digest.is_empty()
}

pub async fn run_watch(cfg: WatchConfig) -> Result<()> {
    let client = Client::try_default()
        .await
        .map_err(|e| FerrumError::Degraded(format!("kube client: {e}")))?;
    let api: Api<DynamicObject> =
        Api::all_with(client.clone(), &cluster_security_policy_resource());
    let mut stream = std::pin::pin!(watcher(api, watcher::Config::default()).applied_objects());
    while let Some(event) = stream.next().await {
        match event {
            Ok(obj) => {
                if let Err(err) = reconcile_object(&client, &cfg, obj).await {
                    eprintln!("ferrum-controller: {err}");
                }
            }
            Err(err) => eprintln!("ferrum-controller watch: {err}"),
        }
    }
    Err(FerrumError::Degraded(
        "ClusterSecurityPolicy watch ended".into(),
    ))
}

async fn reconcile_object(client: &Client, cfg: &WatchConfig, obj: DynamicObject) -> Result<()> {
    let name = match obj.metadata.name.as_deref() {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => {
            return Err(FerrumError::Validation(
                "ClusterSecurityPolicy metadata.name is missing".into(),
            ));
        }
    };
    let generation = obj.metadata.generation.unwrap_or(0);
    let (og, ready, digest) = status_compile(&obj);
    if ready {
        let secret = load_bundle_secret(client, &cfg.namespace, &name).await?;
        if should_skip_applied(
            generation,
            og,
            ready,
            &digest,
            secret.as_ref(),
            &cfg.trust_root,
        ) {
            return Ok(());
        }
    }
    let plan = match observe_policy(&obj) {
        Ok(observed) => {
            let outcome = reconcile(ReconcileInput {
                spec: &observed.spec,
                observed_generation: observed.generation,
                secret_key: &cfg.secret_key,
                library: cfg.library.as_ref(),
                clusters: &cfg.clusters,
                runtime_profile: None,
            });
            plan_apply(&observed.name, &cfg.namespace, &outcome, &cfg.trust_root)
        }
        Err(err) => plan_apply(
            &name,
            &cfg.namespace,
            &crate::ReconcileOutcome::Failed(PolicyStatus {
                observed_generation: generation,
                compile: compile_status_err(&err),
                rollout: RolloutStatus::default(),
            }),
            &cfg.trust_root,
        ),
    };
    if failed_status_already_recorded(&obj, generation, &plan) {
        return Ok(());
    }
    persist(client, &name, &cfg.namespace, &plan).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::{bundle_secret, plan_apply, DEFAULT_NAMESPACE};
    use crate::{reconcile, ClusterAbi, ReconcileInput, ReconcileOutcome};
    use ferrum_api::{
        ClusterSecurityPolicy, ClusterSecurityPolicySpec, PolicyLibrarySpec, RuntimeAction,
        RuntimeSpec,
    };
    use ferrum_crypto::ED25519_SECRET_KEY_LEN;
    use ferrum_ids::{ADMISSION_ABI, AGENT_ABI};

    const RFC8032_SK: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    fn pk() -> Vec<u8> {
        ferrum_crypto::public_key_from_secret(&RFC8032_SK).expect("pk")
    }

    fn prod_restricted() -> ClusterSecurityPolicy {
        let yaml = include_str!("../../../policies/examples/prod-restricted.yaml");
        serde_yaml::from_str(yaml).expect("example yaml")
    }

    fn dynamic_from_spec(
        name: &str,
        generation: i64,
        spec: &ClusterSecurityPolicySpec,
    ) -> DynamicObject {
        let v = serde_json::json!({
            "apiVersion": "ferrum.io/v1",
            "kind": "ClusterSecurityPolicy",
            "metadata": {
                "name": name,
                "generation": generation,
                "resourceVersion": "42",
            },
            "spec": spec,
        });
        serde_json::from_value(v).expect("DynamicObject")
    }

    #[test]
    fn gvk_is_cluster_security_policy() {
        let gvk = cluster_security_policy_gvk();
        assert_eq!(gvk.group, "ferrum.io");
        assert_eq!(gvk.version, "v1");
        assert_eq!(gvk.kind, "ClusterSecurityPolicy");
        let ar = cluster_security_policy_resource();
        assert_eq!(ar.plural, "clustersecuritypolicies");
        assert_eq!(ar.api_version, "ferrum.io/v1");
    }

    #[test]
    fn prod_restricted_dynamic_object_json_ready_digest_fsig() {
        let policy = prod_restricted();
        let obj = dynamic_from_spec(&policy.metadata.name, 11, &policy.spec);
        let observed = observe_policy(&obj).expect("observe");
        assert_eq!(observed.name, "prod-restricted");
        assert_eq!(observed.generation, 11);
        assert_eq!(observed.resource_version, "42");
        let outcome = reconcile(ReconcileInput {
            spec: &observed.spec,
            observed_generation: observed.generation,
            secret_key: &RFC8032_SK,
            library: None,
            clusters: &[],
            runtime_profile: None,
        });
        let applied = match &outcome {
            ReconcileOutcome::Applied(a) => a,
            ReconcileOutcome::Failed(s) => panic!("{}", s.compile.message),
        };
        assert!(applied.status.compile.ready);
        assert_eq!(applied.status.compile.bundle_digest.len(), 64);
        assert_eq!(applied.status.observed_generation, 11);
        crate::verify_signed_bundle(&applied.bundle, &pk()).expect("verify");
        let plan = plan_apply(&observed.name, DEFAULT_NAMESPACE, &outcome, &pk());
        let secret = plan.secret.expect("FSIG Secret");
        let fsig = &secret
            .data
            .as_ref()
            .expect("data")
            .get("bundle.fsig")
            .expect("bundle.fsig")
            .0;
        let decoded = crate::SignedBundle::decode(fsig).expect("decode");
        let digest = crate::verify_signed_bundle(&decoded, &pk()).expect("fsig verifies");
        assert_eq!(digest.as_str().len(), 64);
        assert_eq!(digest, applied.bundle.digest);
    }

    #[test]
    fn observed_generation_comes_from_metadata() {
        let policy = prod_restricted();
        let obj = dynamic_from_spec("prod-restricted", 7, &policy.spec);
        let observed = observe_policy(&obj).expect("observe");
        assert_eq!(observed.generation, 7);
        let outcome = reconcile(ReconcileInput {
            spec: &observed.spec,
            observed_generation: observed.generation,
            secret_key: &RFC8032_SK,
            library: None,
            clusters: &[],
            runtime_profile: None,
        });
        match outcome {
            ReconcileOutcome::Applied(a) => {
                assert_eq!(a.status.observed_generation, 7);
            }
            ReconcileOutcome::Failed(s) => panic!("{}", s.compile.message),
        }
    }

    #[test]
    fn missing_spec_is_validation_no_secret() {
        let v = serde_json::json!({
            "apiVersion": "ferrum.io/v1",
            "kind": "ClusterSecurityPolicy",
            "metadata": { "name": "bare", "generation": 1 },
        });
        let obj: DynamicObject = serde_json::from_value(v).expect("obj");
        match observe_policy(&obj) {
            Err(FerrumError::Validation(msg)) => {
                assert!(msg.contains("spec"), "{msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
        let failed = ReconcileOutcome::Failed(PolicyStatus {
            observed_generation: 1,
            compile: compile_status_err(&FerrumError::Validation(
                "ClusterSecurityPolicy spec is missing".into(),
            )),
            rollout: RolloutStatus::default(),
        });
        let plan = plan_apply("bare", DEFAULT_NAMESPACE, &failed, &pk());
        assert!(plan.secret.is_none());
        assert_eq!(
            plan.status["status"]["compile"]["bundleDigest"]
                .as_str()
                .expect("empty"),
            ""
        );
    }

    #[test]
    fn default_action_kill_empty_rules_failed_no_secret() {
        let spec = ClusterSecurityPolicySpec {
            runtime: RuntimeSpec {
                default_action: RuntimeAction::Kill,
                rules: vec![],
            },
            ..Default::default()
        };
        let obj = dynamic_from_spec("kill-all", 2, &spec);
        let observed = observe_policy(&obj).expect("spec present");
        let outcome = reconcile(ReconcileInput {
            spec: &observed.spec,
            observed_generation: observed.generation,
            secret_key: &RFC8032_SK,
            library: None,
            clusters: &[],
            runtime_profile: None,
        });
        assert!(matches!(outcome, ReconcileOutcome::Failed(_)));
        let plan = plan_apply(&observed.name, DEFAULT_NAMESPACE, &outcome, &pk());
        assert!(plan.secret.is_none());
        assert_eq!(plan.status["status"]["observedGeneration"], 2);
        assert_eq!(
            plan.status["status"]["compile"]["ready"],
            serde_json::Value::Bool(false)
        );
    }

    #[test]
    fn min_agent_abi_gate_keeps_lkg() {
        let policy = prod_restricted();
        let obj = dynamic_from_spec("prod-restricted", 1, &policy.spec);
        let observed = observe_policy(&obj).expect("observe");
        let lib = PolicyLibrarySpec {
            source: "cli".into(),
            digest: String::new(),
            min_agent_abi: AGENT_ABI.saturating_add(1),
            min_admission_abi: ADMISSION_ABI,
        };
        let clusters = [ClusterAbi {
            name: "current".into(),
            agent_abi: AGENT_ABI,
            admission_abi: ADMISSION_ABI,
        }];
        let outcome = reconcile(ReconcileInput {
            spec: &observed.spec,
            observed_generation: observed.generation,
            secret_key: &RFC8032_SK,
            library: Some(&lib),
            clusters: &clusters,
            runtime_profile: None,
        });
        match outcome {
            ReconcileOutcome::Applied(a) => {
                assert!(a.deliver.is_empty());
                assert_eq!(a.keep_lkg, vec!["current".to_string()]);
                assert_eq!(a.status.rollout.clusters_ready, 0);
                assert_eq!(a.status.rollout.clusters_degraded, 1);
            }
            ReconcileOutcome::Failed(s) => panic!("{}", s.compile.message),
        }
    }

    #[test]
    fn all_zero_seed_from_dynamic_object_has_no_bundle() {
        let policy = prod_restricted();
        let obj = dynamic_from_spec("prod-restricted", 1, &policy.spec);
        let observed = observe_policy(&obj).expect("observe");
        let outcome = reconcile(ReconcileInput {
            spec: &observed.spec,
            observed_generation: observed.generation,
            secret_key: &[0u8; ED25519_SECRET_KEY_LEN],
            library: None,
            clusters: &[],
            runtime_profile: None,
        });
        match &outcome {
            ReconcileOutcome::Failed(s) => {
                assert!(!s.compile.ready);
                assert!(s.compile.bundle_digest.is_empty());
            }
            ReconcileOutcome::Applied(_) => panic!("all-zero seed must not produce a bundle"),
        }
        let plan = plan_apply(&observed.name, DEFAULT_NAMESPACE, &outcome, &pk());
        assert!(plan.secret.is_none());
    }

    #[test]
    fn generation_match_alone_does_not_skip() {
        assert!(!should_skip_applied(4, Some(4), false, "", None, &pk()));
        assert!(!should_skip_applied(4, Some(4), true, "ab", None, &pk()));
    }

    #[test]
    fn failed_compile_does_not_skip_even_with_leftover_secret() {
        let policy = prod_restricted();
        let signed = crate::compile_and_sign(&policy.spec, &RFC8032_SK).expect("sign");
        let secret =
            bundle_secret("prod-restricted", DEFAULT_NAMESPACE, &signed, &pk()).expect("secret");
        assert!(!should_skip_applied(
            1,
            Some(1),
            false,
            "",
            Some(&secret),
            &pk()
        ));
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "ferrum.io/v1",
            "kind": "ClusterSecurityPolicy",
            "metadata": { "name": "prod-restricted", "generation": 1 },
            "spec": policy.spec,
            "status": {
                "observedGeneration": 1,
                "compile": { "ready": false, "bundleDigest": "", "compilerVersion": "0.1.0", "message": "err" },
                "rollout": { "clustersReady": 0, "clustersDegraded": 0 }
            }
        }))
        .expect("obj");
        let failed = ReconcileOutcome::Failed(PolicyStatus {
            observed_generation: 1,
            compile: compile_status_err(&FerrumError::Validation("still bad".into())),
            rollout: RolloutStatus::default(),
        });
        let plan = plan_apply("prod-restricted", DEFAULT_NAMESPACE, &failed, &pk());
        assert!(plan.secret.is_none());
        assert!(failed_status_already_recorded(&obj, 1, &plan));
        assert!(!should_skip_applied(
            1,
            Some(1),
            false,
            "",
            Some(&secret),
            &pk()
        ));
    }

    #[test]
    fn applied_skips_only_when_live_secret_verifies() {
        let policy = prod_restricted();
        let outcome = reconcile(ReconcileInput {
            spec: &policy.spec,
            observed_generation: 7,
            secret_key: &RFC8032_SK,
            library: None,
            clusters: &[],
            runtime_profile: None,
        });
        let applied = match &outcome {
            ReconcileOutcome::Applied(a) => a,
            ReconcileOutcome::Failed(s) => panic!("{}", s.compile.message),
        };
        let digest = applied.status.compile.bundle_digest.as_str();
        let secret = bundle_secret("prod-restricted", DEFAULT_NAMESPACE, &applied.bundle, &pk())
            .expect("secret");
        assert!(should_skip_applied(
            7,
            Some(7),
            true,
            digest,
            Some(&secret),
            &pk()
        ));
        assert!(!should_skip_applied(7, Some(7), true, digest, None, &pk()));
        assert!(!should_skip_applied(
            8,
            Some(7),
            true,
            digest,
            Some(&secret),
            &pk()
        ));

        let mut tampered = secret.clone();
        let fsig = tampered
            .data
            .as_mut()
            .expect("data")
            .get_mut("bundle.fsig")
            .expect("fsig");
        let last = fsig.0.len() - 1;
        fsig.0[last] ^= 0x01;
        assert!(!should_skip_applied(
            7,
            Some(7),
            true,
            digest,
            Some(&tampered),
            &pk()
        ));

        let mut wrong_digest = RFC8032_SK;
        wrong_digest[0] ^= 1;
        let wrong_pk = ferrum_crypto::public_key_from_secret(&wrong_digest).expect("pk");
        assert!(!should_skip_applied(
            7,
            Some(7),
            true,
            digest,
            Some(&secret),
            &wrong_pk
        ));
    }

    #[test]
    fn failed_status_elision_is_not_applied_skip() {
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "ferrum.io/v1",
            "kind": "ClusterSecurityPolicy",
            "metadata": { "name": "bare", "generation": 2 },
            "status": {
                "observedGeneration": 2,
                "compile": { "ready": false, "bundleDigest": "" }
            }
        }))
        .expect("obj");
        let failed = ReconcileOutcome::Failed(PolicyStatus {
            observed_generation: 2,
            compile: compile_status_err(&FerrumError::Validation("missing spec".into())),
            rollout: RolloutStatus::default(),
        });
        let plan = plan_apply("bare", DEFAULT_NAMESPACE, &failed, &pk());
        assert!(failed_status_already_recorded(&obj, 2, &plan));
        assert!(!should_skip_applied(2, Some(2), false, "", None, &pk()));
    }
}
