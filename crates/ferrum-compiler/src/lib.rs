//! Offline PolicyBundle compile. Not a webhook, not a cluster client.
//!
//! Digest material (little-endian):
//! `FRMB` | u32 format=1 | u32 minAgentAbi | u32 minAdmissionAbi
//! | u32 len | admission_program | u32 len | ebpf_spec | u32 len | wasm
//!
//! `digest` is `ferrum_crypto::bundle_digest` of that concatenation.
//! Signing is the controller's job. Incompatible minAgentAbi / minAdmissionAbi
//! means the agent keeps last-known-good.

#![deny(unsafe_code)]

mod encode;

use encode::Effects;
use ferrum_api::{ClusterSecurityPolicySpec, RuntimeAction, SecurityPolicySpec};
use ferrum_common::{FerrumError, Result};
use ferrum_ids::Digest;
use ferrum_policy::{validate_cluster_policy, validate_namespaced_policy};

pub const BUNDLE_MAGIC: [u8; 4] = *b"FRMB";
pub const BUNDLE_FORMAT: u32 = 1;
pub const ADMISSION_MAGIC: [u8; 4] = encode::ADMISSION_MAGIC;
pub const EBPF_MAGIC: [u8; 4] = encode::EBPF_MAGIC;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledBundle {
    pub digest: Digest,
    pub admission_program: Vec<u8>,
    pub ebpf_spec: Vec<u8>,
    pub wasm: Vec<u8>,
}

pub fn compile_cluster_policy(spec: &ClusterSecurityPolicySpec) -> Result<CompiledBundle> {
    validate_cluster_policy(spec)?;
    emit_bundle(Effects::from(spec))
}

pub fn compile_namespaced_policy(spec: &SecurityPolicySpec) -> Result<CompiledBundle> {
    validate_namespaced_policy(spec)?;
    emit_bundle(Effects::from(spec))
}

fn emit_bundle(fx: Effects<'_>) -> Result<CompiledBundle> {
    if matches!(
        fx.runtime.default_action,
        RuntimeAction::Kill | RuntimeAction::Isolate
    ) {
        return Err(FerrumError::Validation(
            "runtime.defaultAction Kill/Isolate — это kill-all, не политика".into(),
        ));
    }
    reject_unobservable_syscalls(&fx)?;
    let admission_program = encode::encode_admission(&fx)?;
    let ebpf_spec = encode::encode_ebpf(&fx)?;
    let wasm = ferrum_wasm_abi::placeholder_module().to_vec();
    let material = bundle_digest_material(
        ferrum_ids::AGENT_ABI,
        ferrum_ids::ADMISSION_ABI,
        &admission_program,
        &ebpf_spec,
        &wasm,
    )?;
    Ok(CompiledBundle {
        digest: ferrum_crypto::bundle_digest(&material),
        admission_program,
        ebpf_spec,
        wasm,
    })
}

/// Second gate on the same invariant as `ferrum_policy::validate_rule_syscalls`.
/// The validator is advisory — a bundle can be produced by anything that calls
/// the compiler — so the encoder refuses to emit a rule the datapath can never
/// observe. A signed bundle that cannot fire is worse than a rejected compile.
fn reject_unobservable_syscalls(fx: &Effects<'_>) -> Result<()> {
    for rule in &fx.runtime.rules {
        for syscall in &rule.syscalls {
            let name = syscall.trim();
            if !ferrum_ids::is_datapath_syscall(name) {
                return Err(FerrumError::Compile(format!(
                    "rule '{}': syscall '{name}' is not hooked by the datapath; the rule can never fire. Observed: {}",
                    rule.id,
                    ferrum_ids::DATAPATH_SYSCALLS.join(", ")
                )));
            }
        }
        for restricted in ferrum_ids::ARCH_RESTRICTED_SYSCALLS {
            let Some(companion) = restricted.portable_companion else {
                continue;
            };
            if rule.syscalls.iter().any(|s| s.trim() == restricted.syscall)
                && !rule.syscalls.iter().any(|s| s.trim() == companion)
            {
                return Err(FerrumError::Compile(format!(
                    "rule '{}': syscall '{}' exists only on {}; one signed bundle serves the whole cluster, so add '{companion}' or the rule is dead on the other nodes",
                    rule.id,
                    restricted.syscall,
                    restricted.arches.join(", ")
                )));
            }
        }
    }
    Ok(())
}

/// Canonical bytes hashed into `CompiledBundle.digest`.
pub fn bundle_digest_material(
    min_agent_abi: u32,
    min_admission_abi: u32,
    admission_program: &[u8],
    ebpf_spec: &[u8],
    wasm: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(
        4 + 4 + 4 + 4 + 4 + admission_program.len() + 4 + ebpf_spec.len() + 4 + wasm.len(),
    );
    out.extend_from_slice(&BUNDLE_MAGIC);
    out.extend_from_slice(&BUNDLE_FORMAT.to_le_bytes());
    out.extend_from_slice(&min_agent_abi.to_le_bytes());
    out.extend_from_slice(&min_admission_abi.to_le_bytes());
    append_len_prefixed(&mut out, admission_program, "admission_program")?;
    append_len_prefixed(&mut out, ebpf_spec, "ebpf_spec")?;
    append_len_prefixed(&mut out, wasm, "wasm")?;
    Ok(out)
}

fn append_len_prefixed(out: &mut Vec<u8>, blob: &[u8], name: &str) -> Result<()> {
    let len = u32::try_from(blob.len())
        .map_err(|_| FerrumError::Compile(format!("{name} exceeds u32 length")))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(blob);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_api::{
        AdmitDeny, AdmitSpec, ClusterSecurityPolicy, FailurePolicy, PolicyMode, PssProfile,
        RuntimeAction, RuntimeMatch, RuntimeRule, RuntimeSpec, SecurityPolicySpec, SupplySpec,
        TrustRoot,
    };
    use ferrum_common::FerrumError;

    fn prod_restricted() -> ClusterSecurityPolicySpec {
        let yaml = include_str!("../../../policies/examples/prod-restricted.yaml");
        let obj: ClusterSecurityPolicy = serde_yaml::from_str(yaml).expect("example yaml");
        obj.spec
    }

    fn assert_validation_no_bundle(result: Result<CompiledBundle>) {
        match result {
            Err(FerrumError::Validation(_)) => {}
            Err(other) => panic!("expected Validation, got {other:?}"),
            Ok(_) => panic!("invalid spec must not produce a bundle"),
        }
    }

    fn assert_sha256_hex(digest: &Digest) {
        let s = digest.as_str();
        assert_eq!(s.len(), 64);
        assert!(s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    }

    #[test]
    fn wasm_abi_matches_ids() {
        assert_eq!(ferrum_wasm_abi::ABI_VERSION, ferrum_ids::AGENT_ABI);
        assert_eq!(ferrum_wasm_abi::ABI_VERSION, ferrum_ids::ADMISSION_ABI);
    }

    #[test]
    fn prod_restricted_compiles_digest_stable() {
        let spec = prod_restricted();
        let first = compile_cluster_policy(&spec).expect("compile");
        let second = compile_cluster_policy(&spec).expect("compile again");
        assert_eq!(first, second);
        assert_sha256_hex(&first.digest);

        assert_eq!(&first.admission_program[..4], &ADMISSION_MAGIC);
        assert_eq!(&first.ebpf_spec[..4], &EBPF_MAGIC);
        assert_eq!(
            &first.wasm,
            ferrum_wasm_abi::placeholder_module().as_slice()
        );
        assert_eq!(
            &first.admission_program[4..8],
            &ferrum_ids::ADMISSION_ABI.to_le_bytes()
        );
        assert_eq!(&first.ebpf_spec[4..8], &ferrum_ids::AGENT_ABI.to_le_bytes());
        assert_eq!(
            &first.wasm[4..8],
            &ferrum_wasm_abi::ABI_VERSION.to_le_bytes()
        );

        let material = bundle_digest_material(
            ferrum_ids::AGENT_ABI,
            ferrum_ids::ADMISSION_ABI,
            &first.admission_program,
            &first.ebpf_spec,
            &first.wasm,
        )
        .expect("material");
        assert_eq!(&material[..4], &BUNDLE_MAGIC);
        assert_eq!(&material[4..8], &BUNDLE_FORMAT.to_le_bytes());
        assert_eq!(&material[8..12], &ferrum_ids::AGENT_ABI.to_le_bytes());
        assert_eq!(&material[12..16], &ferrum_ids::ADMISSION_ABI.to_le_bytes());
        assert_eq!(ferrum_crypto::bundle_digest(&material), first.digest);
    }

    #[test]
    fn prod_restricted_encodes_mvp_admit_and_runtime() {
        let spec = prod_restricted();
        let bundle = compile_cluster_policy(&spec).expect("compile");
        let admit = encode::decode_admission(&bundle.admission_program).expect("admit");
        let ebpf = encode::decode_ebpf(&bundle.ebpf_spec).expect("ebpf");

        assert_eq!(admit.abi, ferrum_ids::ADMISSION_ABI);
        assert_eq!(admit.mode, PolicyMode::Audit);
        assert_eq!(admit.priority, 100);
        assert!(admit.supply.require_signed);
        assert!(admit.supply.deny_unsigned);
        assert!(admit.supply.deny_latest_tag);
        assert_eq!(admit.supply.trust_roots[0].name, "org-cosign");
        assert_eq!(
            admit.supply.trust_roots[0].public_keys,
            vec!["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]
        );
        assert_eq!(admit.admit.failure_policy, FailurePolicy::Fail);
        assert_eq!(admit.admit.pss, PssProfile::Restricted);
        assert!(admit.admit.deny.privileged);
        assert!(admit.admit.deny.host_pid);
        assert!(admit.admit.deny.cluster_admin_bind);
        assert_eq!(
            admit.admit.deny.added_capabilities,
            vec!["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE"]
        );
        assert!(admit.admit.mutate.drop_all_capabilities);
        assert_eq!(
            admit.selector.image.registries_allow,
            vec!["registry.internal.example"]
        );
        assert!(admit.selector.image.require_digest);

        assert_eq!(ebpf.abi, ferrum_ids::AGENT_ABI);
        assert_eq!(ebpf.mode, PolicyMode::Audit);
        assert_eq!(ebpf.priority, admit.priority);
        assert_eq!(ebpf.selector, admit.selector);
        assert_eq!(
            ebpf.selector.namespace_selector.match_expressions[0].key,
            "ferrum.io/zone"
        );
        assert_eq!(
            ebpf.selector.namespace_selector.match_expressions[0].values,
            vec!["pci", "secrets"]
        );
        assert_eq!(ebpf.runtime.default_action, RuntimeAction::Audit);
        assert_eq!(ebpf.runtime.rules.len(), 3);
        assert_eq!(ebpf.runtime.rules[0].id, "no-shell");
        assert_eq!(ebpf.runtime.rules[0].action, RuntimeAction::Kill);
        assert_eq!(
            ebpf.runtime.rules[0].match_on.comm_in,
            vec!["sh", "bash", "ash", "dash", "zsh"]
        );
        assert_eq!(ebpf.runtime.rules[1].id, "no-runtime-sock");
        assert_eq!(
            ebpf.runtime.rules[1].match_on.path_suffix,
            vec!["docker.sock", "containerd.sock", "crio.sock"]
        );
        assert_eq!(ebpf.runtime.rules[2].id, "no-module");
        assert_eq!(ebpf.runtime.rules[2].action, RuntimeAction::Deny);
        assert!(ebpf.runtime.rules[2].match_on.not_agent_self);
    }

    #[test]
    fn default_action_kill_empty_rules_does_not_compile() {
        for default_action in [RuntimeAction::Kill, RuntimeAction::Isolate] {
            let spec = ClusterSecurityPolicySpec {
                runtime: RuntimeSpec {
                    default_action,
                    rules: vec![],
                },
                ..Default::default()
            };
            assert_validation_no_bundle(compile_cluster_policy(&spec));
        }
    }

    #[test]
    fn kill_all_does_not_compile() {
        let spec = ClusterSecurityPolicySpec {
            runtime: RuntimeSpec {
                rules: vec![RuntimeRule {
                    id: "oops".into(),
                    syscalls: vec![],
                    match_on: RuntimeMatch::default(),
                    action: RuntimeAction::Kill,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_validation_no_bundle(compile_cluster_policy(&spec));
    }

    fn syscall_rule_spec(syscalls: &[&str]) -> ClusterSecurityPolicySpec {
        ClusterSecurityPolicySpec {
            runtime: RuntimeSpec {
                rules: vec![RuntimeRule {
                    id: "probe".into(),
                    syscalls: syscalls.iter().map(|s| (*s).to_string()).collect(),
                    match_on: RuntimeMatch {
                        comm_in: vec!["gdb".into()],
                        ..Default::default()
                    },
                    action: RuntimeAction::Kill,
                }],
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn unobservable_syscall_does_not_compile() {
        // The validator refuses first; the compiler's own gate has to hold on
        // its own, so assert it directly as well.
        assert!(compile_cluster_policy(&syscall_rule_spec(&["ptrace"])).is_err());
        let spec = syscall_rule_spec(&["ptrace"]);
        let fx = Effects::from(&spec);
        match reject_unobservable_syscalls(&fx) {
            Err(FerrumError::Compile(msg)) => {
                assert!(msg.contains("probe") && msg.contains("ptrace"), "{msg}");
            }
            other => panic!("expected Compile, got {other:?}"),
        }
    }

    #[test]
    fn open_without_openat_does_not_compile() {
        assert!(compile_cluster_policy(&syscall_rule_spec(&["open"])).is_err());
        let spec = syscall_rule_spec(&["open"]);
        let fx = Effects::from(&spec);
        match reject_unobservable_syscalls(&fx) {
            Err(FerrumError::Compile(msg)) => assert!(msg.contains("openat"), "{msg}"),
            other => panic!("expected Compile, got {other:?}"),
        }
        compile_cluster_policy(&syscall_rule_spec(&["open", "openat"])).expect("portable pair");
    }

    #[test]
    fn unsigned_without_trust_roots_does_not_compile() {
        for supply in [
            SupplySpec {
                require_signed: true,
                ..Default::default()
            },
            SupplySpec {
                deny_unsigned: true,
                ..Default::default()
            },
        ] {
            let spec = ClusterSecurityPolicySpec {
                supply,
                ..Default::default()
            };
            assert_validation_no_bundle(compile_cluster_policy(&spec));
        }
    }

    #[test]
    fn namespaced_ignore_does_not_compile() {
        let spec = SecurityPolicySpec {
            admit: AdmitSpec {
                failure_policy: FailurePolicy::Ignore,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_validation_no_bundle(compile_namespaced_policy(&spec));
    }

    #[test]
    fn namespaced_policy_compiles() {
        let spec = SecurityPolicySpec {
            supply: SupplySpec {
                deny_unsigned: true,
                trust_roots: vec![TrustRoot {
                    name: "org".into(),
                    keyless_issuer_allow: vec![],
                    public_keys: vec![
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                    ],
                }],
                ..Default::default()
            },
            admit: AdmitSpec {
                deny: AdmitDeny {
                    privileged: true,
                    cluster_admin_bind: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            runtime: RuntimeSpec {
                rules: vec![RuntimeRule {
                    id: "no-shell".into(),
                    syscalls: vec!["execve".into()],
                    match_on: RuntimeMatch {
                        comm_in: vec!["sh".into()],
                        ..Default::default()
                    },
                    action: RuntimeAction::Kill,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let bundle = compile_namespaced_policy(&spec).expect("compile");
        assert_sha256_hex(&bundle.digest);
        let admit = encode::decode_admission(&bundle.admission_program).expect("admit");
        assert!(admit.admit.deny.privileged);
        assert!(admit.admit.deny.cluster_admin_bind);
    }

    #[test]
    fn incompatible_abi_changes_digest() {
        let spec = prod_restricted();
        let bundle = compile_cluster_policy(&spec).expect("compile");
        let other = bundle_digest_material(
            ferrum_ids::AGENT_ABI.saturating_add(1),
            ferrum_ids::ADMISSION_ABI,
            &bundle.admission_program,
            &bundle.ebpf_spec,
            &bundle.wasm,
        )
        .expect("material");
        assert_ne!(ferrum_crypto::bundle_digest(&other), bundle.digest);
    }
}
