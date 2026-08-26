use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    Observe,
    #[default]
    Audit,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum FailurePolicy {
    #[default]
    Fail,
    Ignore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PssProfile {
    Privileged,
    Baseline,
    #[default]
    Restricted,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeAction {
    Allow,
    #[default]
    Audit,
    Deny,
    Kill,
    Isolate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    #[serde(default)]
    pub match_labels: BTreeMap<String, String>,
    #[serde(default)]
    pub match_expressions: Vec<LabelSelectorRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelectorRequirement {
    pub key: String,
    pub operator: String,
    #[serde(default)]
    pub values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PolicySelector {
    #[serde(default)]
    pub cluster_selector: LabelSelector,
    #[serde(default)]
    pub namespace_selector: LabelSelector,
    #[serde(default)]
    pub workload_selector: LabelSelector,
    #[serde(default)]
    pub service_account_selector: LabelSelector,
    #[serde(default)]
    pub image: ImageSelector,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ImageSelector {
    #[serde(default)]
    pub registries_allow: Vec<String>,
    #[serde(default)]
    pub require_digest: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SupplySpec {
    #[serde(default)]
    pub require_signed: bool,
    #[serde(default)]
    pub deny_unsigned: bool,
    #[serde(default)]
    pub deny_latest_tag: bool,
    #[serde(default)]
    pub trust_roots: Vec<TrustRoot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustRoot {
    pub name: String,
    #[serde(default)]
    pub keyless_issuer_allow: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AdmitSpec {
    #[serde(default)]
    pub failure_policy: FailurePolicy,
    #[serde(default)]
    pub pss: PssProfile,
    #[serde(default)]
    pub deny: AdmitDeny,
    #[serde(default)]
    pub mutate: AdmitMutate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AdmitDeny {
    #[serde(default)]
    pub privileged: bool,
    #[serde(default, rename = "hostPID")]
    pub host_pid: bool,
    #[serde(default, rename = "hostIPC")]
    pub host_ipc: bool,
    #[serde(default)]
    pub host_network: bool,
    #[serde(default)]
    pub host_path: bool,
    #[serde(default)]
    pub allow_privilege_escalation: bool,
    #[serde(default)]
    pub run_as_root: bool,
    #[serde(default)]
    pub wildcards_rbac: bool,
    #[serde(default)]
    pub cluster_admin_bind: bool,
    #[serde(default)]
    pub added_capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AdmitMutate {
    #[serde(default)]
    pub inject_seccomp_runtime_default: bool,
    #[serde(default)]
    pub drop_all_capabilities: bool,
    #[serde(default)]
    pub read_only_root_filesystem: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSpec {
    #[serde(default)]
    pub default_action: RuntimeAction,
    #[serde(default)]
    pub rules: Vec<RuntimeRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeRule {
    pub id: String,
    #[serde(default)]
    pub syscalls: Vec<String>,
    #[serde(default, rename = "match")]
    pub match_on: RuntimeMatch,
    #[serde(default)]
    pub action: RuntimeAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeMatch {
    #[serde(default)]
    pub comm_in: Vec<String>,
    #[serde(default)]
    pub container_only: bool,
    #[serde(default)]
    pub path_prefix: Vec<String>,
    #[serde(default)]
    pub path_suffix: Vec<String>,
    #[serde(default)]
    pub not_agent_self: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PolicyStatus {
    #[serde(default)]
    pub observed_generation: i64,
    #[serde(default)]
    pub compile: CompileStatus,
    #[serde(default)]
    pub rollout: RolloutStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CompileStatus {
    #[serde(default)]
    pub ready: bool,
    #[serde(default)]
    pub bundle_digest: String,
    #[serde(default)]
    pub compiler_version: String,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RolloutStatus {
    #[serde(default)]
    pub clusters_ready: i32,
    #[serde(default)]
    pub clusters_degraded: i32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ClusterSecurityPolicySpec {
    #[serde(default)]
    pub mode: PolicyMode,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub selector: PolicySelector,
    #[serde(default)]
    pub supply: SupplySpec,
    #[serde(default)]
    pub admit: AdmitSpec,
    #[serde(default)]
    pub runtime: RuntimeSpec,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SecurityPolicySpec {
    #[serde(default)]
    pub mode: PolicyMode,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub selector: PolicySelector,
    #[serde(default)]
    pub supply: SupplySpec,
    #[serde(default)]
    pub admit: AdmitSpec,
    #[serde(default)]
    pub runtime: RuntimeSpec,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyExceptionSpec {
    pub ticket: String,
    pub requested_by: String,
    #[serde(default)]
    pub approved_by: String,
    pub reason: String,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub mode: PolicyMode,
    #[serde(default)]
    pub four_eyes: bool,
    #[serde(default)]
    pub target: ExceptionTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ExceptionTarget {
    #[serde(default)]
    pub policies: Vec<String>,
    #[serde(default)]
    pub rules: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PolicyExceptionStatus {
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyLibrarySpec {
    pub source: String,
    #[serde(default)]
    pub digest: String,
    #[serde(default)]
    pub min_agent_abi: u32,
    #[serde(default)]
    pub min_admission_abi: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PolicyLibraryStatus {
    #[serde(default)]
    pub ready: bool,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeProfileSpec {
    pub source_policy: String,
    #[serde(default = "default_window")]
    pub window: String,
}

fn default_window() -> String {
    "7d".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeProfileStatus {
    #[serde(default)]
    pub ready_for_promote: bool,
    #[serde(default)]
    pub drift_count: i32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FerrumClusterSpec {
    pub kubeconfig_secret_ref: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FerrumClusterStatus {
    #[serde(default)]
    pub connected: bool,
    #[serde(default)]
    pub degraded: bool,
    #[serde(default)]
    pub agent_abi: u32,
    #[serde(default)]
    pub last_bundle_digest: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceSnapshotSpec {
    #[serde(default)]
    pub frameworks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceSnapshotStatus {
    #[serde(default)]
    pub pass: i32,
    #[serde(default)]
    pub fail: i32,
    #[serde(default)]
    pub waived: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ObjectMeta {
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

fn default_api_version() -> String {
    "ferrum.io/v1".into()
}

macro_rules! resource {
    ($name:ident, $kind:literal, $spec:ty, $status:ty) => {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            pub api_version: String,
            pub kind: String,
            #[serde(default)]
            pub metadata: ObjectMeta,
            pub spec: $spec,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub status: Option<$status>,
        }

        impl $name {
            pub fn new(name: &str, spec: $spec) -> Self {
                Self {
                    api_version: default_api_version(),
                    kind: $kind.to_string(),
                    metadata: ObjectMeta {
                        name: name.into(),
                        ..ObjectMeta::default()
                    },
                    spec,
                    status: None,
                }
            }
        }
    };
}

resource!(ClusterSecurityPolicy, "ClusterSecurityPolicy", ClusterSecurityPolicySpec, PolicyStatus);
resource!(SecurityPolicy, "SecurityPolicy", SecurityPolicySpec, PolicyStatus);
resource!(PolicyException, "PolicyException", PolicyExceptionSpec, PolicyExceptionStatus);
resource!(PolicyLibrary, "PolicyLibrary", PolicyLibrarySpec, PolicyLibraryStatus);
resource!(RuntimeProfile, "RuntimeProfile", RuntimeProfileSpec, RuntimeProfileStatus);
resource!(FerrumCluster, "FerrumCluster", FerrumClusterSpec, FerrumClusterStatus);
resource!(ComplianceSnapshot, "ComplianceSnapshot", ComplianceSnapshotSpec, ComplianceSnapshotStatus);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_policy_yaml_roundtrip() {
        let yaml = r#"
mode: enforce
priority: 100
admit:
  failurePolicy: Fail
  pss: restricted
  deny:
    privileged: true
    hostPID: true
runtime:
  defaultAction: audit
  rules:
    - id: no-shell
      syscalls: [execve]
      match:
        commIn: [sh, bash]
        containerOnly: true
      action: kill
"#;
        let spec: ClusterSecurityPolicySpec =
            serde_yaml::from_str(yaml).expect("spec must parse");
        assert_eq!(spec.mode, PolicyMode::Enforce);
        assert!(spec.admit.deny.privileged);
        assert!(spec.admit.deny.host_pid);
        assert_eq!(spec.runtime.rules[0].action, RuntimeAction::Kill);
        assert_eq!(spec.runtime.rules[0].match_on.comm_in, vec!["sh", "bash"]);
    }
}
