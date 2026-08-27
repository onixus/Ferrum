//! Offline fixtures. Decode the same YAML the CRD will serve.
//! Not a cluster client and not kube-bench.

use ferrum_api::{
    AdmitDeny, AdmitSpec, ClusterSecurityPolicy, ClusterSecurityPolicySpec, ComplianceSnapshot,
    FerrumCluster, PolicyException, PolicyLibrary, PssProfile, RuntimeAction, RuntimeMatch,
    RuntimeProfile, RuntimeRule, RuntimeSpec, SecurityPolicy, SupplySpec, TrustRoot,
};
use serde::de::DeserializeOwned;

pub const PROD_RESTRICTED_YAML: &str =
    include_str!("../../../policies/examples/prod-restricted.yaml");
pub const EXCEPTION_OK_YAML: &str = include_str!("../../../policies/examples/exception-ok.yaml");
pub const EXCEPTION_BAD_NO_TICKET_YAML: &str =
    include_str!("../../../policies/examples/exception-bad-no-ticket.yaml");
pub const POLICY_LIBRARY_YAML: &str =
    include_str!("../../../policies/examples/policy-library.yaml");
pub const RUNTIME_PROFILE_YAML: &str =
    include_str!("../../../policies/examples/runtime-profile.yaml");
pub const FERRUM_CLUSTER_YAML: &str =
    include_str!("../../../policies/examples/ferrum-cluster.yaml");
pub const COMPLIANCE_SNAPSHOT_YAML: &str =
    include_str!("../../../policies/examples/compliance-snapshot.yaml");
/// Negative fixture: a runtime rule naming a syscall the datapath never hooks.
/// It must fail validation; the CI stage runs `ferrumctl validate` on the same
/// file so the gate cannot exist only in a unit test.
pub const RUNTIME_UNOBSERVABLE_SYSCALL_YAML: &str =
    include_str!("../../../policies/examples/runtime-unobservable-syscall.yaml");
pub const RUNTIME_ARCH_SPLIT_SYSCALL_YAML: &str =
    include_str!("../../../policies/examples/runtime-arch-split-syscall.yaml");
/// Negative fixture: a runtime rule whose action the runtime plane cannot
/// execute. Same CI stage, same reason: the gate must exist where a policy
/// author meets it, not only in a unit test.
pub const RUNTIME_UNEXECUTABLE_ACTION_YAML: &str =
    include_str!("../../../policies/examples/runtime-unexecutable-action.yaml");

/// RFC §D: `expiresAt` is omitted on purpose so the API rejects the object.
pub const EXCEPTION_WITHOUT_TTL_YAML: &str = include_str!("../fixtures/exception-without-ttl.yaml");
/// RFC §D: CP down keeps last-known-good (`Degraded=true`, digest set), not fail-open.
pub const CP_DOWN_LKG_YAML: &str = include_str!("../fixtures/cp-down-lkg.yaml");

/// Fixture Ed25519 public key: 32-byte hex, not a prod key.
pub const FIXTURE_ED25519_PK: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

pub fn spec_from_yaml(yaml: &str) -> ClusterSecurityPolicySpec {
    decode(yaml)
}

pub fn cluster_policy_from_yaml(yaml: &str) -> ClusterSecurityPolicy {
    decode(yaml)
}

pub fn security_policy_from_yaml(yaml: &str) -> SecurityPolicy {
    decode(yaml)
}

pub fn exception_from_yaml(yaml: &str) -> PolicyException {
    decode(yaml)
}

pub fn policy_library_from_yaml(yaml: &str) -> PolicyLibrary {
    decode(yaml)
}

pub fn runtime_profile_from_yaml(yaml: &str) -> RuntimeProfile {
    decode(yaml)
}

pub fn ferrum_cluster_from_yaml(yaml: &str) -> FerrumCluster {
    decode(yaml)
}

pub fn compliance_snapshot_from_yaml(yaml: &str) -> ComplianceSnapshot {
    decode(yaml)
}

pub fn prod_restricted() -> ClusterSecurityPolicy {
    cluster_policy_from_yaml(PROD_RESTRICTED_YAML)
}

pub fn exception_ok() -> PolicyException {
    exception_from_yaml(EXCEPTION_OK_YAML)
}

pub fn exception_bad_no_ticket() -> PolicyException {
    exception_from_yaml(EXCEPTION_BAD_NO_TICKET_YAML)
}

pub fn policy_library() -> PolicyLibrary {
    policy_library_from_yaml(POLICY_LIBRARY_YAML)
}

pub fn runtime_profile() -> RuntimeProfile {
    runtime_profile_from_yaml(RUNTIME_PROFILE_YAML)
}

pub fn ferrum_cluster() -> FerrumCluster {
    ferrum_cluster_from_yaml(FERRUM_CLUSTER_YAML)
}

pub fn runtime_unobservable_syscall() -> ClusterSecurityPolicy {
    cluster_policy_from_yaml(RUNTIME_UNOBSERVABLE_SYSCALL_YAML)
}

pub fn runtime_arch_split_syscall() -> ClusterSecurityPolicy {
    cluster_policy_from_yaml(RUNTIME_ARCH_SPLIT_SYSCALL_YAML)
}

pub fn runtime_unexecutable_action() -> ClusterSecurityPolicy {
    cluster_policy_from_yaml(RUNTIME_UNEXECUTABLE_ACTION_YAML)
}

pub fn compliance_snapshot() -> ComplianceSnapshot {
    compliance_snapshot_from_yaml(COMPLIANCE_SNAPSHOT_YAML)
}

pub fn cp_down_last_known_good() -> FerrumCluster {
    ferrum_cluster_from_yaml(CP_DOWN_LKG_YAML)
}

pub fn try_exception_from_yaml(yaml: &str) -> Result<PolicyException, serde_yaml::Error> {
    serde_yaml::from_str(yaml)
}

fn decode<T: DeserializeOwned>(yaml: &str) -> T {
    serde_yaml::from_str(yaml).expect("fixture yaml")
}

/// Which plane decides a case. Nothing that never reaches the ring can be
/// replayed, so the split is what lets the replay harness gate its own subset
/// without hand-copying it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptancePlane {
    Admission,
    Runtime,
}

/// Declares the §D case list once and derives everything from it. A variant
/// that exists but is not in `ALL` is unrepresentable: both come from the same
/// invocation, so a case cannot be added to the enum and forgotten by a gate.
macro_rules! acceptance_cases {
    ($($variant:ident => ($plane:ident, $label:literal),)+) => {
        /// The RFC §D MVP-1 acceptance cases, as one source both the
        /// acceptance suite and the replay harness gate themselves against.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum AcceptanceCase {
            $($variant,)+
        }

        impl AcceptanceCase {
            pub const ALL: &'static [AcceptanceCase] = &[$(AcceptanceCase::$variant,)+];

            pub fn plane(self) -> AcceptancePlane {
                match self {
                    $(AcceptanceCase::$variant => AcceptancePlane::$plane,)+
                }
            }

            pub fn label(self) -> &'static str {
                match self {
                    $(AcceptanceCase::$variant => $label,)+
                }
            }
        }
    };
}

acceptance_cases! {
    UnsignedDeny => (Admission, "unsigned image -> deny"),
    PrivilegedDeny => (Admission, "privileged -> deny"),
    ClusterAdminBindDeny => (Admission, "cluster-admin bind -> deny"),
    ExceptionWithoutTtlReject => (Admission, "exception without TTL -> API reject"),
    ExecShellKill => (Runtime, "kubectl exec + /bin/sh -> kill"),
    DockerSockKill => (Runtime, "docker.sock -> kill"),
    BpfNotFromAgentDeny => (Runtime, "bpf() not from the agent -> deny"),
    ControlPlaneDownLkg => (Runtime, "CP down -> last-known-good"),
}

impl AcceptanceCase {
    /// The subset a ring record can carry, i.e. what the replay harness must
    /// cover. The admission cases produce no record and cannot be replayed.
    pub fn runtime() -> Vec<AcceptanceCase> {
        Self::ALL
            .iter()
            .copied()
            .filter(|c| c.plane() == AcceptancePlane::Runtime)
            .collect()
    }
}

fn fixture_trust_roots() -> Vec<TrustRoot> {
    vec![TrustRoot {
        name: "org-cosign".into(),
        keyless_issuer_allow: vec!["https://token.actions.githubusercontent.com".into()],
        public_keys: vec![FIXTURE_ED25519_PK.into()],
    }]
}

/// RFC §D: unsigned image → deny.
pub fn unsigned_deny() -> ClusterSecurityPolicySpec {
    ClusterSecurityPolicySpec {
        supply: SupplySpec {
            require_signed: true,
            deny_unsigned: true,
            trust_roots: fixture_trust_roots(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// RFC §D: privileged → deny.
pub fn privileged_deny() -> ClusterSecurityPolicySpec {
    ClusterSecurityPolicySpec {
        admit: AdmitSpec {
            pss: PssProfile::Restricted,
            deny: AdmitDeny {
                privileged: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

/// RFC §D: cluster-admin bind → deny.
pub fn cluster_admin_bind_deny() -> ClusterSecurityPolicySpec {
    ClusterSecurityPolicySpec {
        admit: AdmitSpec {
            deny: AdmitDeny {
                cluster_admin_bind: true,
                wildcards_rbac: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

/// RFC §D: `kubectl exec` + `/bin/sh` → kill.
pub fn exec_sh_kill() -> ClusterSecurityPolicySpec {
    ClusterSecurityPolicySpec {
        runtime: RuntimeSpec {
            rules: vec![RuntimeRule {
                id: "no-shell".into(),
                syscalls: vec!["execve".into(), "execveat".into()],
                match_on: RuntimeMatch {
                    comm_in: vec![
                        "sh".into(),
                        "bash".into(),
                        "ash".into(),
                        "dash".into(),
                        "zsh".into(),
                    ],
                    container_only: true,
                    ..Default::default()
                },
                action: RuntimeAction::Kill,
            }],
            ..Default::default()
        },
        ..Default::default()
    }
}

/// RFC §D: docker.sock → kill.
pub fn docker_sock_kill() -> ClusterSecurityPolicySpec {
    ClusterSecurityPolicySpec {
        runtime: RuntimeSpec {
            rules: vec![RuntimeRule {
                id: "no-runtime-sock".into(),
                syscalls: vec![],
                match_on: RuntimeMatch {
                    path_suffix: vec![
                        "docker.sock".into(),
                        "containerd.sock".into(),
                        "crio.sock".into(),
                    ],
                    container_only: true,
                    ..Default::default()
                },
                action: RuntimeAction::Kill,
            }],
            ..Default::default()
        },
        ..Default::default()
    }
}

/// RFC §D: `bpf()` not from the agent. The deny is admission's (`admit.deny`
/// carries SYS_MODULE and privileged); what the runtime plane can execute is
/// the audit record that names the caller, because a tracepoint fires after
/// the syscall has already run.
pub fn bpf_not_from_agent_audit() -> ClusterSecurityPolicySpec {
    ClusterSecurityPolicySpec {
        runtime: RuntimeSpec {
            rules: vec![RuntimeRule {
                id: "no-module".into(),
                syscalls: vec!["init_module".into(), "finit_module".into(), "bpf".into()],
                match_on: RuntimeMatch {
                    not_agent_self: true,
                    ..Default::default()
                },
                action: RuntimeAction::Audit,
            }],
            ..Default::default()
        },
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_api::{FailurePolicy, PolicyMode};

    #[test]
    fn prod_restricted_decodes_as_crd() {
        let obj = prod_restricted();
        assert_eq!(obj.api_version, "ferrum.io/v1");
        assert_eq!(obj.kind, "ClusterSecurityPolicy");
        assert_eq!(obj.metadata.name, "prod-restricted");
        assert_eq!(obj.spec.mode, PolicyMode::Audit);
        assert!(obj.spec.supply.require_signed);
        assert!(obj.spec.supply.deny_unsigned);
        assert_eq!(obj.spec.supply.trust_roots[0].name, "org-cosign");
        assert_eq!(
            obj.spec.supply.trust_roots[0].public_keys[0],
            FIXTURE_ED25519_PK
        );
        assert_eq!(obj.spec.admit.failure_policy, FailurePolicy::Fail);
        assert_eq!(obj.spec.admit.pss, PssProfile::Restricted);
        assert!(obj.spec.admit.deny.privileged);
        assert!(obj.spec.admit.deny.cluster_admin_bind);
        assert_eq!(obj.spec.runtime.rules[0].id, "no-shell");
        assert_eq!(obj.spec.runtime.rules[0].action, RuntimeAction::Kill);
        assert_eq!(
            obj.spec.runtime.rules[1].match_on.path_suffix,
            vec!["docker.sock", "containerd.sock", "crio.sock"]
        );
        assert!(
            obj.spec.runtime.rules[1].match_on.container_only,
            "the node's own containerd opens these sockets; without containerOnly              every one of those opens is exported as a kill that never happened"
        );
        assert_eq!(obj.spec.runtime.rules[2].id, "no-module");
        assert!(obj.spec.runtime.rules[2]
            .syscalls
            .iter()
            .any(|s| s == "bpf"));
        assert!(obj.spec.runtime.rules[2].match_on.not_agent_self);
        assert_eq!(obj.spec.runtime.rules[2].action, RuntimeAction::Audit);
    }

    #[test]
    fn exception_examples_decode_as_crd() {
        let ok = exception_ok();
        assert_eq!(ok.kind, "PolicyException");
        assert_eq!(ok.spec.ticket, "JIRA-18421");
        assert_eq!(ok.spec.target.namespace, "payments");
        assert_eq!(ok.spec.target.policies, vec!["prod-restricted"]);
        assert_eq!(ok.spec.target.rules, vec!["no-shell"]);

        let bad = exception_bad_no_ticket();
        assert!(bad.spec.ticket.is_empty());
        assert_eq!(bad.spec.reason, "asap");
    }

    #[test]
    fn remaining_kinds_decode_as_crd() {
        let lib = policy_library();
        assert_eq!(lib.kind, "PolicyLibrary");
        assert!(!lib.spec.source.trim().is_empty());
        assert_eq!(lib.spec.digest.len(), 64);

        let profile = runtime_profile();
        assert_eq!(profile.kind, "RuntimeProfile");
        assert_eq!(profile.spec.source_policy, "prod-restricted");
        assert!(!profile.spec.window.trim().is_empty());

        let cluster = ferrum_cluster();
        assert_eq!(cluster.kind, "FerrumCluster");
        assert!(!cluster.spec.kubeconfig_secret_ref.trim().is_empty());
        assert!(cluster.status.is_none());

        let snap = compliance_snapshot();
        assert_eq!(snap.kind, "ComplianceSnapshot");
        assert!(!snap.spec.frameworks.is_empty());
        assert!(snap.spec.frameworks.iter().all(|f| !f.trim().is_empty()));
    }

    #[test]
    fn spec_from_yaml_reads_spec_document() {
        let yaml = serde_yaml::to_string(&prod_restricted().spec).expect("spec yaml");
        let spec = spec_from_yaml(&yaml);
        assert!(spec.supply.deny_unsigned);
        assert_eq!(
            spec.supply.trust_roots[0].public_keys[0],
            FIXTURE_ED25519_PK
        );
    }

    #[test]
    fn rfc_d_unsigned_deny() {
        let spec = unsigned_deny();
        assert!(spec.supply.require_signed);
        assert!(spec.supply.deny_unsigned);
        assert!(!spec.supply.trust_roots.is_empty());
        assert_eq!(spec.supply.trust_roots[0].public_keys[0].len(), 64);
        assert_eq!(
            prod_restricted().spec.supply.deny_unsigned,
            spec.supply.deny_unsigned
        );
    }

    #[test]
    fn rfc_d_privileged_deny() {
        let spec = privileged_deny();
        assert!(spec.admit.deny.privileged);
        assert_eq!(spec.admit.pss, PssProfile::Restricted);
        assert!(prod_restricted().spec.admit.deny.privileged);
    }

    #[test]
    fn rfc_d_cluster_admin_bind_deny() {
        let spec = cluster_admin_bind_deny();
        assert!(spec.admit.deny.cluster_admin_bind);
        assert!(prod_restricted().spec.admit.deny.cluster_admin_bind);
    }

    #[test]
    fn rfc_d_exec_sh_kill() {
        let spec = exec_sh_kill();
        let rule = &spec.runtime.rules[0];
        assert!(rule.syscalls.iter().any(|s| s == "execve"));
        assert!(rule.match_on.comm_in.iter().any(|c| c == "sh"));
        assert_eq!(rule.action, RuntimeAction::Kill);
        let prod = &prod_restricted().spec.runtime.rules[0];
        assert_eq!(prod.id, "no-shell");
        assert_eq!(prod.action, RuntimeAction::Kill);
    }

    #[test]
    fn rfc_d_docker_sock_kill() {
        let spec = docker_sock_kill();
        let rule = &spec.runtime.rules[0];
        assert!(rule.match_on.path_suffix.iter().any(|p| p == "docker.sock"));
        assert_eq!(rule.action, RuntimeAction::Kill);
        assert!(rule.match_on.container_only);
        let prod = &prod_restricted().spec.runtime.rules[1];
        assert_eq!(prod.id, "no-runtime-sock");
        assert_eq!(prod.action, RuntimeAction::Kill);
        assert!(prod.match_on.container_only);
    }

    /// §D `bpf()` not from the agent. The deny is carried by admission, which
    /// refuses the pod before it runs; the runtime rule is the audit record
    /// that names the caller. A runtime `deny` would be a verdict this plane
    /// decides and never executes.
    #[test]
    fn rfc_d_bpf_not_from_agent() {
        let spec = bpf_not_from_agent_audit();
        let rule = &spec.runtime.rules[0];
        assert!(rule.syscalls.iter().any(|s| s == "bpf"));
        assert!(rule.match_on.not_agent_self);
        assert_eq!(rule.action, RuntimeAction::Audit);
        let prod = &prod_restricted().spec.runtime.rules[2];
        assert!(prod.syscalls.iter().any(|s| s == "bpf"));
        assert_eq!(prod.action, RuntimeAction::Audit);
        // The deny half of the case: admission refuses the module-loading pod.
        let admit = &prod_restricted().spec.admit.deny;
        assert!(admit.added_capabilities.iter().any(|c| c == "SYS_MODULE"));
        assert!(admit.privileged);
    }

    #[test]
    fn unexecutable_action_fixture_decodes_and_names_deny() {
        let obj = runtime_unexecutable_action();
        assert_eq!(obj.kind, "ClusterSecurityPolicy");
        let rule = &obj.spec.runtime.rules[0];
        assert_eq!(rule.id, "no-module");
        assert_eq!(rule.action, RuntimeAction::Deny);
    }

    #[test]
    fn unobservable_syscall_fixture_decodes_and_names_ptrace() {
        let obj = runtime_unobservable_syscall();
        assert_eq!(obj.kind, "ClusterSecurityPolicy");
        let rule = &obj.spec.runtime.rules[0];
        assert_eq!(rule.syscalls, vec!["ptrace"]);
        assert_eq!(rule.action, RuntimeAction::Kill);
    }

    #[test]
    fn arch_split_fixture_decodes_and_names_only_openat() {
        let obj = runtime_arch_split_syscall();
        assert_eq!(obj.kind, "ClusterSecurityPolicy");
        let rule = &obj.spec.runtime.rules[0];
        assert_eq!(
            rule.syscalls,
            vec!["openat"],
            "half of the open/openat pair"
        );
        assert_eq!(rule.action, RuntimeAction::Kill);
    }

    #[test]
    fn rfc_d_exception_without_ttl_rejects_decode() {
        let err = try_exception_from_yaml(EXCEPTION_WITHOUT_TTL_YAML)
            .expect_err("missing expiresAt must not decode");
        let msg = err.to_string();
        assert!(
            msg.contains("expiresAt")
                || msg.contains("expires_at")
                || msg.contains("missing field"),
            "unexpected decode error: {msg}"
        );
    }

    #[test]
    fn rfc_d_cp_down_keeps_last_known_good() {
        let obj = cp_down_last_known_good();
        assert_eq!(obj.kind, "FerrumCluster");
        let status = obj
            .status
            .expect("LKG is recorded on status, not a live client");
        assert!(!status.connected);
        assert!(status.degraded);
        assert!(!status.last_bundle_digest.trim().is_empty());
        assert_eq!(status.last_bundle_digest.len(), 64);
    }

    #[test]
    fn rfc_d_builders_roundtrip_yaml() {
        let specs = [
            unsigned_deny(),
            privileged_deny(),
            cluster_admin_bind_deny(),
            exec_sh_kill(),
            docker_sock_kill(),
            bpf_not_from_agent_audit(),
        ];
        for spec in specs {
            let yaml = serde_yaml::to_string(&spec).expect("spec yaml");
            let back: ClusterSecurityPolicySpec = serde_yaml::from_str(&yaml).expect("roundtrip");
            assert_eq!(spec, back);
        }
    }

    /// The case list is the gate both suites measure themselves against, so a
    /// silent shrink here would weaken them without failing anything.
    #[test]
    fn the_rfc_d_case_list_is_the_eight_mvp_cases() {
        assert_eq!(AcceptanceCase::ALL.len(), 8);
        assert_eq!(AcceptanceCase::runtime().len(), 4);
        let mut labels: Vec<&str> = AcceptanceCase::ALL.iter().map(|c| c.label()).collect();
        labels.sort_unstable();
        let before = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), before, "two cases share a label");
    }
}
