//! Control plane: compile + sign + rollout. `reconcile` is kube-free.
//! Live watch is opt-in via `run`. No datapath, no CAP_BPF.

#![deny(unsafe_code)]

mod apply;
mod bundle;
mod key;
mod watch;

pub use apply::{
    bundle_secret, bundle_secret_named, exceptions_json, exceptions_secret_patch,
    namespaced_secret_name, persist_exceptions, plan_apply, plan_apply_named,
    plan_apply_namespaced, secret_name, status_patch, ApplyPlan, DEFAULT_NAMESPACE,
    EXCEPTIONS_JSON_KEY,
};
pub use bundle::{verify_signed_bundle, SignedBundle, SIGNED_FORMAT, SIGNED_MAGIC};
pub use key::{
    hex_decode, hex_encode, load_seed, load_seed_file, parse_public_key_hex, parse_seed_bytes,
    parse_seed_hex, SEED_ENV, SEED_FILE_ENV,
};
pub use watch::{
    cluster_security_policy_gvk, cluster_security_policy_resource, observe_exception,
    observe_namespaced_policy, observe_policy, policy_exception_gvk, policy_exception_resource,
    run_watch, security_policy_gvk, security_policy_resource,
};

use bundle::parse_framb_abis;
use ferrum_api::{
    ClusterSecurityPolicySpec, CompileStatus, PolicyExceptionSpec, PolicyExceptionStatus,
    PolicyLibrarySpec, PolicyMode, PolicyStatus, RolloutStatus, RuntimeProfileSpec,
    RuntimeProfileStatus, SecurityPolicySpec,
};
use ferrum_common::{FerrumError, Result};
use ferrum_compiler::CompiledBundle;
use ferrum_ids::{ADMISSION_ABI, AGENT_ABI};

/// Workspace version of the compiler that produced `CompileStatus.compilerVersion`.
pub const COMPILER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Compile `spec`, sign the FRMB digest material, never an unsigned bundle.
pub fn compile_and_sign(
    spec: &ClusterSecurityPolicySpec,
    secret_key: &[u8],
) -> Result<SignedBundle> {
    let compiled = ferrum_compiler::compile_cluster_policy(spec)?;
    sign_compiled(&compiled, secret_key)
}

/// Namespaced SecurityPolicy compile+sign. `compile_namespaced_policy` already
/// enforces the failurePolicy=Ignore ban before any bundle exists.
pub fn compile_and_sign_namespaced(
    spec: &SecurityPolicySpec,
    secret_key: &[u8],
) -> Result<SignedBundle> {
    let compiled = ferrum_compiler::compile_namespaced_policy(spec)?;
    sign_compiled(&compiled, secret_key)
}

fn sign_compiled(compiled: &CompiledBundle, secret_key: &[u8]) -> Result<SignedBundle> {
    let raw = ferrum_compiler::bundle_digest_material(
        AGENT_ABI,
        ADMISSION_ABI,
        &compiled.admission_program,
        &compiled.ebpf_spec,
        &compiled.wasm,
    )?;
    let digest = ferrum_crypto::bundle_digest(&raw);
    if digest.as_str() != compiled.digest.as_str() {
        return Err(FerrumError::Integrity(
            "compiled digest does not match FRMB material".into(),
        ));
    }
    let signature = ferrum_crypto::sign_bundle(&raw, secret_key)?;
    let public_key = ferrum_crypto::public_key_from_secret(secret_key)?;
    let (min_agent_abi, min_admission_abi) = parse_framb_abis(&raw)?;
    Ok(SignedBundle {
        raw,
        signature,
        public_key,
        digest,
        min_agent_abi,
        min_admission_abi,
    })
}

pub fn compile_status_ok(bundle: &SignedBundle) -> CompileStatus {
    CompileStatus {
        ready: true,
        bundle_digest: bundle.digest.as_str().to_string(),
        compiler_version: COMPILER_VERSION.to_string(),
        message: "compiled and signed".into(),
    }
}

pub fn compile_status_err(err: &FerrumError) -> CompileStatus {
    CompileStatus {
        ready: false,
        bundle_digest: String::new(),
        compiler_version: COMPILER_VERSION.to_string(),
        message: err.to_string(),
    }
}

/// Reported ABI of one fleet member. Incompatible peers keep last-known-good.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterAbi {
    pub name: String,
    pub agent_abi: u32,
    pub admission_abi: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolloutPlan {
    pub status: RolloutStatus,
    pub deliver: Vec<String>,
    pub keep_lkg: Vec<String>,
}

/// `minAgentAbi` / `minAdmissionAbi` are gates: peer ABI must be >= effective min.
pub fn effective_min_abi(bundle: &SignedBundle, library: Option<&PolicyLibrarySpec>) -> (u32, u32) {
    let lib_agent = library.map(|l| l.min_agent_abi).unwrap_or(0);
    let lib_admission = library.map(|l| l.min_admission_abi).unwrap_or(0);
    (
        bundle.min_agent_abi.max(lib_agent),
        bundle.min_admission_abi.max(lib_admission),
    )
}

pub fn abi_compatible(peer_abi: u32, min_abi: u32) -> bool {
    peer_abi >= min_abi
}

/// Incompatible ABI → `keep_lkg`, not a force-load.
pub fn plan_rollout(
    bundle: &SignedBundle,
    library: Option<&PolicyLibrarySpec>,
    clusters: &[ClusterAbi],
) -> RolloutPlan {
    let (min_agent, min_admission) = effective_min_abi(bundle, library);
    let mut deliver = Vec::new();
    let mut keep_lkg = Vec::new();
    for cluster in clusters {
        if abi_compatible(cluster.agent_abi, min_agent)
            && abi_compatible(cluster.admission_abi, min_admission)
        {
            deliver.push(cluster.name.clone());
        } else {
            keep_lkg.push(cluster.name.clone());
        }
    }
    RolloutPlan {
        status: RolloutStatus {
            clusters_ready: count_i32(deliver.len()),
            clusters_degraded: count_i32(keep_lkg.len()),
        },
        deliver,
        keep_lkg,
    }
}

fn count_i32(n: usize) -> i32 {
    i32::try_from(n).expect("rollout cluster count fits i32")
}

/// RuntimeProfile never writes PolicyMode. Promote is a human spec edit.
pub fn retain_policy_mode(
    spec_mode: PolicyMode,
    _profile: Option<&RuntimeProfileSpec>,
) -> PolicyMode {
    spec_mode
}

/// Observe-only status. `readyForPromote` stays false: no telemetry, no auto-enforce.
pub fn runtime_profile_status(_profile: &RuntimeProfileSpec) -> RuntimeProfileStatus {
    RuntimeProfileStatus {
        ready_for_promote: false,
        drift_count: 0,
    }
}

/// ClusterSecurityPolicy fields read from a DynamicObject. Not a kube type.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservedPolicy {
    pub name: String,
    pub generation: i64,
    pub resource_version: String,
    pub spec: ClusterSecurityPolicySpec,
}

/// Namespaced SecurityPolicy fields read from a DynamicObject.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservedNamespacedPolicy {
    pub name: String,
    pub namespace: String,
    pub generation: i64,
    pub resource_version: String,
    pub spec: SecurityPolicySpec,
}

/// PolicyException fields read from a DynamicObject.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservedException {
    pub name: String,
    pub namespace: String,
    pub spec: PolicyExceptionSpec,
}

/// Live-watch inputs. Cluster list is CLI/static — kubeconfigSecretRef is never opened.
#[derive(Debug, Clone)]
pub struct WatchConfig {
    pub namespace: String,
    pub secret_key: Vec<u8>,
    pub trust_root: Vec<u8>,
    pub library: Option<PolicyLibrarySpec>,
    pub clusters: Vec<ClusterAbi>,
}

pub struct ReconcileInput<'a> {
    pub spec: &'a ClusterSecurityPolicySpec,
    pub observed_generation: i64,
    pub secret_key: &'a [u8],
    pub library: Option<&'a PolicyLibrarySpec>,
    pub clusters: &'a [ClusterAbi],
    pub runtime_profile: Option<&'a RuntimeProfileSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileApplied {
    pub bundle: SignedBundle,
    pub status: PolicyStatus,
    pub mode: PolicyMode,
    pub profile_status: Option<RuntimeProfileStatus>,
    pub deliver: Vec<String>,
    pub keep_lkg: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReconcileOutcome {
    Applied(ReconcileApplied),
    Failed(PolicyStatus),
}

/// Compile+sign and account rollout. Does not use a kube client.
pub fn reconcile(input: ReconcileInput<'_>) -> ReconcileOutcome {
    match compile_and_sign(input.spec, input.secret_key) {
        Ok(bundle) => {
            let plan = plan_rollout(&bundle, input.library, input.clusters);
            let status = PolicyStatus {
                observed_generation: input.observed_generation,
                compile: compile_status_ok(&bundle),
                rollout: plan.status,
            };
            ReconcileOutcome::Applied(ReconcileApplied {
                bundle,
                status,
                mode: retain_policy_mode(input.spec.mode, input.runtime_profile),
                profile_status: input.runtime_profile.map(runtime_profile_status),
                deliver: plan.deliver,
                keep_lkg: plan.keep_lkg,
            })
        }
        Err(err) => ReconcileOutcome::Failed(PolicyStatus {
            observed_generation: input.observed_generation,
            compile: compile_status_err(&err),
            rollout: RolloutStatus::default(),
        }),
    }
}

pub struct NamespacedReconcileInput<'a> {
    pub spec: &'a SecurityPolicySpec,
    pub observed_generation: i64,
    pub secret_key: &'a [u8],
    pub library: Option<&'a PolicyLibrarySpec>,
    pub clusters: &'a [ClusterAbi],
}

/// Namespaced twin of `reconcile`. failurePolicy=Ignore fails here, before any
/// Secret is planned — the reject lands in status, never in a bundle.
pub fn reconcile_namespaced(input: NamespacedReconcileInput<'_>) -> ReconcileOutcome {
    match compile_and_sign_namespaced(input.spec, input.secret_key) {
        Ok(bundle) => {
            let plan = plan_rollout(&bundle, input.library, input.clusters);
            let status = PolicyStatus {
                observed_generation: input.observed_generation,
                compile: compile_status_ok(&bundle),
                rollout: plan.status,
            };
            ReconcileOutcome::Applied(ReconcileApplied {
                bundle,
                status,
                mode: input.spec.mode,
                profile_status: None,
                deliver: plan.deliver,
                keep_lkg: plan.keep_lkg,
            })
        }
        Err(err) => ReconcileOutcome::Failed(PolicyStatus {
            observed_generation: input.observed_generation,
            compile: compile_status_err(&err),
            rollout: RolloutStatus::default(),
        }),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExceptionReconcile {
    pub status: PolicyExceptionStatus,
    /// Present only for exceptions that pass ferrum-policy invariants;
    /// only these are serialized into `exceptions.json`.
    pub live: Option<PolicyExceptionSpec>,
}

/// Gate one PolicyException through ferrum-policy invariants (mandatory
/// expiresAt, <= 90 days, non-empty scope). Rejects go to status only.
pub fn reconcile_exception(spec: &PolicyExceptionSpec) -> ExceptionReconcile {
    match ferrum_policy::validate_exception(spec) {
        Ok(()) => ExceptionReconcile {
            status: PolicyExceptionStatus {
                active: true,
                message: "exception is live".into(),
            },
            live: Some(spec.clone()),
        },
        Err(err) => ExceptionReconcile {
            status: PolicyExceptionStatus {
                active: false,
                message: err.to_string(),
            },
            live: None,
        },
    }
}

pub fn exception_status_patch(status: &PolicyExceptionStatus) -> serde_json::Value {
    serde_json::json!({ "status": status })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_api::{
        ClusterSecurityPolicy, PolicyLibrarySpec, RuntimeAction, RuntimeProfileSpec, RuntimeSpec,
    };
    use ferrum_crypto::{ED25519_PUBLIC_KEY_LEN, ED25519_SECRET_KEY_LEN, ED25519_SIGNATURE_LEN};
    use ferrum_testkit::spec_from_yaml;

    /// RFC 8032 §7.1 test 1 secret seed.
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

    fn observe_spec() -> ClusterSecurityPolicySpec {
        spec_from_yaml(
            r#"
mode: observe
priority: 10
supply:
  requireSigned: true
  denyUnsigned: true
  trustRoots:
    - name: org
      publicKeys:
        - "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
admit:
  deny:
    privileged: true
runtime:
  defaultAction: audit
  rules:
    - id: no-shell
      syscalls: [execve]
      match:
        commIn: [sh]
      action: kill
"#,
        )
    }

    fn library(min_agent: u32, min_admission: u32) -> PolicyLibrarySpec {
        PolicyLibrarySpec {
            source: "test".into(),
            digest: String::new(),
            min_agent_abi: min_agent,
            min_admission_abi: min_admission,
        }
    }

    fn profile() -> RuntimeProfileSpec {
        RuntimeProfileSpec {
            source_policy: "prod-restricted".into(),
            window: "7d".into(),
        }
    }

    fn applied(outcome: ReconcileOutcome) -> ReconcileApplied {
        match outcome {
            ReconcileOutcome::Applied(a) => a,
            ReconcileOutcome::Failed(s) => panic!("reconcile failed: {}", s.compile.message),
        }
    }

    fn failed(outcome: ReconcileOutcome) -> PolicyStatus {
        match outcome {
            ReconcileOutcome::Failed(s) => s,
            ReconcileOutcome::Applied(_) => panic!("expected compile failure"),
        }
    }

    #[test]
    fn prod_restricted_compile_sign_matches_compiler_digest() {
        let spec = prod_restricted();
        let compiled = ferrum_compiler::compile_cluster_policy(&spec).expect("compile");
        let signed = compile_and_sign(&spec, &RFC8032_SK).expect("sign");

        let material = ferrum_compiler::bundle_digest_material(
            AGENT_ABI,
            ADMISSION_ABI,
            &compiled.admission_program,
            &compiled.ebpf_spec,
            &compiled.wasm,
        )
        .expect("material");
        assert_eq!(signed.raw, material);
        assert_eq!(signed.digest, compiled.digest);
        assert_eq!(signed.digest, ferrum_crypto::bundle_digest(&material));
        assert_eq!(signed.min_agent_abi, AGENT_ABI);
        assert_eq!(signed.min_admission_abi, ADMISSION_ABI);
        assert_eq!(signed.signature.len(), ED25519_SIGNATURE_LEN);
        assert_eq!(signed.public_key.len(), ED25519_PUBLIC_KEY_LEN);

        let pk = ferrum_crypto::public_key_from_secret(&RFC8032_SK).expect("pk");
        let digest = verify_signed_bundle(&signed, &pk).expect("verify");
        assert_eq!(digest, signed.digest);
        assert_eq!(&signed.raw[..4], &ferrum_compiler::BUNDLE_MAGIC);
    }

    #[test]
    fn signed_bundle_roundtrip_and_wrong_key_fails() {
        let signed = compile_and_sign(&prod_restricted(), &RFC8032_SK).expect("sign");
        let encoded = signed.encode().expect("encode");
        assert_eq!(&encoded[..4], &SIGNED_MAGIC);
        let decoded = SignedBundle::decode(&encoded).expect("decode");
        assert_eq!(decoded, signed);

        let pk = ferrum_crypto::public_key_from_secret(&RFC8032_SK).expect("pk");
        verify_signed_bundle(&decoded, &pk).expect("trust root verifies");

        let mut other_sk = RFC8032_SK;
        other_sk[0] ^= 0x01;
        let wrong_pk = ferrum_crypto::public_key_from_secret(&other_sk).expect("wrong pk");
        match verify_signed_bundle(&decoded, &wrong_pk) {
            Err(FerrumError::Integrity(_)) => {}
            other => panic!("expected Integrity, got {other:?}"),
        }
    }

    #[test]
    fn decode_does_not_trust_embedded_key() {
        let signed = compile_and_sign(&prod_restricted(), &RFC8032_SK).expect("sign");
        let pk = ferrum_crypto::public_key_from_secret(&RFC8032_SK).expect("pk");
        assert_eq!(signed.public_key, pk);
        verify_signed_bundle(&signed, &pk).expect("configured root");
    }

    #[test]
    fn compile_status_records_digest() {
        let signed = compile_and_sign(&prod_restricted(), &RFC8032_SK).expect("sign");
        let st = compile_status_ok(&signed);
        assert!(st.ready);
        assert_eq!(st.bundle_digest, signed.digest.as_str());
        assert_eq!(st.bundle_digest.len(), 64);
        assert_eq!(st.compiler_version, COMPILER_VERSION);
        assert!(!st.message.is_empty());
    }

    #[test]
    fn incompatible_abi_keeps_lkg_and_records_degraded() {
        let spec = prod_restricted();
        let lib = library(AGENT_ABI, ADMISSION_ABI);
        let clusters = [
            ClusterAbi {
                name: "ready".into(),
                agent_abi: AGENT_ABI,
                admission_abi: ADMISSION_ABI,
            },
            ClusterAbi {
                name: "old-agent".into(),
                agent_abi: AGENT_ABI.saturating_sub(1),
                admission_abi: ADMISSION_ABI,
            },
        ];
        let out = applied(reconcile(ReconcileInput {
            spec: &spec,
            observed_generation: 7,
            secret_key: &RFC8032_SK,
            library: Some(&lib),
            clusters: &clusters,
            runtime_profile: None,
        }));
        assert!(out.status.compile.ready);
        assert_eq!(out.status.observed_generation, 7);
        assert_eq!(out.status.rollout.clusters_ready, 1);
        assert_eq!(out.status.rollout.clusters_degraded, 1);
        assert_eq!(out.deliver, vec!["ready".to_string()]);
        assert_eq!(out.keep_lkg, vec!["old-agent".to_string()]);
        assert!(!out.deliver.contains(&"old-agent".to_string()));
    }

    #[test]
    fn library_min_abi_is_a_gate() {
        let spec = prod_restricted();
        let signed = compile_and_sign(&spec, &RFC8032_SK).expect("sign");
        assert_eq!(signed.min_agent_abi, AGENT_ABI);

        let lib = library(AGENT_ABI.saturating_add(1), ADMISSION_ABI);
        let clusters = [ClusterAbi {
            name: "current".into(),
            agent_abi: AGENT_ABI,
            admission_abi: ADMISSION_ABI,
        }];
        let plan = plan_rollout(&signed, Some(&lib), &clusters);
        assert!(plan.deliver.is_empty());
        assert_eq!(plan.keep_lkg, vec!["current".to_string()]);
        assert_eq!(plan.status.clusters_ready, 0);
        assert_eq!(plan.status.clusters_degraded, 1);

        let (min_agent, _) = effective_min_abi(&signed, Some(&lib));
        assert_eq!(min_agent, AGENT_ABI.saturating_add(1));
        assert!(!abi_compatible(AGENT_ABI, min_agent));
    }

    #[test]
    fn compatible_clusters_are_ready() {
        let spec = prod_restricted();
        let lib = library(AGENT_ABI, ADMISSION_ABI);
        let clusters = [
            ClusterAbi {
                name: "a".into(),
                agent_abi: AGENT_ABI,
                admission_abi: ADMISSION_ABI,
            },
            ClusterAbi {
                name: "b".into(),
                agent_abi: AGENT_ABI.saturating_add(1),
                admission_abi: ADMISSION_ABI.saturating_add(1),
            },
        ];
        let out = applied(reconcile(ReconcileInput {
            spec: &spec,
            observed_generation: 1,
            secret_key: &RFC8032_SK,
            library: Some(&lib),
            clusters: &clusters,
            runtime_profile: None,
        }));
        assert_eq!(out.status.rollout.clusters_ready, 2);
        assert_eq!(out.status.rollout.clusters_degraded, 0);
        assert!(out.keep_lkg.is_empty());
        assert_eq!(out.deliver, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn runtime_profile_does_not_auto_enforce() {
        let spec = observe_spec();
        assert_eq!(spec.mode, PolicyMode::Observe);
        let p = profile();
        let out = applied(reconcile(ReconcileInput {
            spec: &spec,
            observed_generation: 1,
            secret_key: &RFC8032_SK,
            library: None,
            clusters: &[],
            runtime_profile: Some(&p),
        }));
        assert_eq!(out.mode, PolicyMode::Observe);
        assert_ne!(out.mode, PolicyMode::Enforce);
        let profile_status = out.profile_status.expect("profile status");
        assert!(!profile_status.ready_for_promote);
        assert_eq!(
            retain_policy_mode(PolicyMode::Audit, Some(&p)),
            PolicyMode::Audit
        );
        assert_eq!(
            retain_policy_mode(PolicyMode::Observe, Some(&p)),
            PolicyMode::Observe
        );
    }

    #[test]
    fn invalid_policy_records_not_ready_without_bundle() {
        let spec = ClusterSecurityPolicySpec {
            runtime: RuntimeSpec {
                default_action: RuntimeAction::Kill,
                rules: vec![],
            },
            ..Default::default()
        };
        let status = failed(reconcile(ReconcileInput {
            spec: &spec,
            observed_generation: 3,
            secret_key: &RFC8032_SK,
            library: None,
            clusters: &[],
            runtime_profile: None,
        }));
        assert_eq!(status.observed_generation, 3);
        assert!(!status.compile.ready);
        assert!(status.compile.bundle_digest.is_empty());
        assert!(!status.compile.message.is_empty());
        assert_eq!(status.compile.compiler_version, COMPILER_VERSION);
        assert_eq!(status.rollout, RolloutStatus::default());
        assert!(compile_and_sign(&spec, &RFC8032_SK).is_err());
    }

    #[test]
    fn all_zero_seed_does_not_produce_a_bundle() {
        let spec = prod_restricted();
        match compile_and_sign(&spec, &[0u8; ED25519_SECRET_KEY_LEN]) {
            Err(FerrumError::Integrity(_)) => {}
            other => panic!("expected Integrity, got {other:?}"),
        }
        let status = failed(reconcile(ReconcileInput {
            spec: &spec,
            observed_generation: 1,
            secret_key: &[0u8; ED25519_SECRET_KEY_LEN],
            library: None,
            clusters: &[],
            runtime_profile: None,
        }));
        assert!(!status.compile.ready);
        assert!(status.compile.bundle_digest.is_empty());
    }

    #[test]
    fn testkit_reconcile_observe_policy() {
        let spec = observe_spec();
        let lib = library(AGENT_ABI, ADMISSION_ABI);
        let clusters = [ClusterAbi {
            name: "c1".into(),
            agent_abi: AGENT_ABI,
            admission_abi: ADMISSION_ABI,
        }];
        let p = profile();
        let out = applied(reconcile(ReconcileInput {
            spec: &spec,
            observed_generation: 2,
            secret_key: &RFC8032_SK,
            library: Some(&lib),
            clusters: &clusters,
            runtime_profile: Some(&p),
        }));
        assert_eq!(out.mode, PolicyMode::Observe);
        assert!(out.status.compile.ready);
        assert_eq!(out.status.compile.bundle_digest, out.bundle.digest.as_str());
        assert_eq!(out.status.rollout.clusters_ready, 1);
        assert_eq!(out.deliver, vec!["c1".to_string()]);
        assert!(!out.profile_status.expect("profile").ready_for_promote);
    }

    #[test]
    fn decode_rejects_empty_signature_payload() {
        let mut bytes = Vec::from(SIGNED_MAGIC);
        bytes.extend_from_slice(&SIGNED_FORMAT.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        match SignedBundle::decode(&bytes) {
            Err(FerrumError::Integrity(msg)) => {
                assert!(msg.contains("unsigned") || msg.contains("empty"));
            }
            other => panic!("expected Integrity, got {other:?}"),
        }
    }

    #[test]
    fn cargo_lock_has_no_kube_derive() {
        let crate_toml = include_str!("../Cargo.toml");
        assert!(
            !crate_toml.contains("kube-derive"),
            "ferrum-controller must not depend on kube-derive"
        );
        assert!(
            !crate_toml.contains("\"derive\""),
            "kube derive feature must stay off"
        );
        let lock = include_str!("../../../Cargo.lock");
        assert!(
            !lock.contains("name = \"kube-derive\""),
            "Cargo.lock must not include kube-derive"
        );
        let api_toml = include_str!("../../ferrum-api/Cargo.toml");
        assert!(
            !api_toml.contains("kube-derive"),
            "ferrum-api must not depend on kube-derive"
        );
    }
}
