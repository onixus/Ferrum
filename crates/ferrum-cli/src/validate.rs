use anyhow::{bail, Context, Result};
use ferrum_api::{
    ClusterSecurityPolicy, ComplianceSnapshot, ComplianceSnapshotSpec, FerrumCluster,
    FerrumClusterSpec, PolicyException, PolicyLibrary, PolicyLibrarySpec, RuntimeProfile,
    RuntimeProfileSpec, SecurityPolicy,
};
use ferrum_policy::{validate_cluster_policy, validate_exception, validate_namespaced_policy};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub(crate) struct TypedMeta {
    #[serde(rename = "apiVersion")]
    pub(crate) api_version: String,
    pub(crate) kind: String,
}

pub(crate) fn typed_meta(raw: &str) -> Result<TypedMeta> {
    let meta: TypedMeta = serde_yaml::from_str(raw).context("parse apiVersion/kind")?;
    if meta.api_version != "ferrum.io/v1" {
        bail!("unsupported apiVersion {}", meta.api_version);
    }
    Ok(meta)
}

pub fn validate_file(path: &Path) -> Result<()> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    validate_yaml(&raw)?;
    println!("ok: {}", path.display());
    Ok(())
}

pub fn validate_yaml(raw: &str) -> Result<()> {
    let meta = typed_meta(raw)?;

    match meta.kind.as_str() {
        "ClusterSecurityPolicy" => {
            let obj: ClusterSecurityPolicy = parse_resource(raw, ClusterSecurityPolicy::new)?;
            validate_cluster_policy(&obj.spec).map_err(anyhow::Error::from)?;
        }
        "SecurityPolicy" => {
            let obj: SecurityPolicy = parse_resource(raw, SecurityPolicy::new)?;
            validate_namespaced_policy(&obj.spec).map_err(anyhow::Error::from)?;
        }
        "PolicyException" => {
            let obj: PolicyException = parse_resource(raw, PolicyException::new)?;
            validate_exception(&obj.spec).map_err(anyhow::Error::from)?;
        }
        "PolicyLibrary" => {
            let obj: PolicyLibrary = parse_resource(raw, PolicyLibrary::new)?;
            validate_policy_library(&obj.spec)?;
        }
        "RuntimeProfile" => {
            let obj: RuntimeProfile = parse_resource(raw, RuntimeProfile::new)?;
            validate_runtime_profile(&obj.spec)?;
        }
        "FerrumCluster" => {
            let obj: FerrumCluster = parse_resource(raw, FerrumCluster::new)?;
            validate_ferrum_cluster(&obj.spec)?;
        }
        "ComplianceSnapshot" => {
            let obj: ComplianceSnapshot = parse_resource(raw, ComplianceSnapshot::new)?;
            validate_compliance_snapshot(&obj.spec)?;
        }
        other => bail!("kind {other} validate ещё не подключён"),
    }
    Ok(())
}

fn validate_policy_library(spec: &PolicyLibrarySpec) -> Result<()> {
    require_non_empty("PolicyLibrary.source", &spec.source)?;
    require_non_empty("PolicyLibrary.digest", &spec.digest)?;
    if !is_sha256_hex(&spec.digest) {
        bail!("PolicyLibrary.digest должен быть 64 hex-символа (SHA-256)");
    }
    Ok(())
}

fn validate_runtime_profile(spec: &RuntimeProfileSpec) -> Result<()> {
    require_non_empty("RuntimeProfile.sourcePolicy", &spec.source_policy)?;
    require_non_empty("RuntimeProfile.window", &spec.window)?;
    Ok(())
}

fn validate_ferrum_cluster(spec: &FerrumClusterSpec) -> Result<()> {
    // Name of a Secret, not a live kube client.
    require_non_empty(
        "FerrumCluster.kubeconfigSecretRef",
        &spec.kubeconfig_secret_ref,
    )?;
    Ok(())
}

fn validate_compliance_snapshot(spec: &ComplianceSnapshotSpec) -> Result<()> {
    if spec.frameworks.iter().any(|name| name.trim().is_empty()) {
        bail!("ComplianceSnapshot.frameworks содержит пустую строку");
    }
    Ok(())
}

fn require_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{field} пуст");
    }
    Ok(())
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub(crate) fn parse_resource<T, S>(raw: &str, build: fn(&str, S) -> T) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
    S: for<'de> Deserialize<'de>,
{
    if let Ok(obj) = serde_yaml::from_str(raw) {
        return Ok(obj);
    }
    Ok(build("", extract_spec(raw)?))
}

fn extract_spec<T: for<'de> Deserialize<'de>>(raw: &str) -> Result<T> {
    #[derive(Deserialize)]
    struct Wrap<T> {
        spec: T,
    }
    let wrap: Wrap<T> = serde_yaml::from_str(raw).context("parse spec")?;
    Ok(wrap.spec)
}

#[cfg(test)]
mod tests {
    use super::validate_yaml;
    use ferrum_testkit::{
        COMPLIANCE_SNAPSHOT_YAML, CP_DOWN_LKG_YAML, EXCEPTION_BAD_NO_TICKET_YAML,
        EXCEPTION_OK_YAML, EXCEPTION_WITHOUT_TTL_YAML, FERRUM_CLUSTER_YAML, POLICY_LIBRARY_YAML,
        PROD_RESTRICTED_YAML, RUNTIME_PROFILE_YAML,
    };

    fn err_msg(yaml: &str) -> String {
        match validate_yaml(yaml) {
            Ok(()) => panic!("expected validation error"),
            Err(err) => format!("{err:#}"),
        }
    }

    #[test]
    fn prod_restricted_ok() {
        validate_yaml(PROD_RESTRICTED_YAML).expect("prod-restricted");
    }

    #[test]
    fn exception_ok_ok() {
        validate_yaml(EXCEPTION_OK_YAML).expect("exception-ok");
    }

    #[test]
    fn exception_bad_no_ticket_fails() {
        let msg = err_msg(EXCEPTION_BAD_NO_TICKET_YAML);
        assert!(msg.contains("ticket"), "{msg}");
    }

    #[test]
    fn remaining_kind_examples_ok() {
        validate_yaml(POLICY_LIBRARY_YAML).expect("policy-library");
        validate_yaml(RUNTIME_PROFILE_YAML).expect("runtime-profile");
        validate_yaml(FERRUM_CLUSTER_YAML).expect("ferrum-cluster");
        validate_yaml(COMPLIANCE_SNAPSHOT_YAML).expect("compliance-snapshot");
        validate_yaml(CP_DOWN_LKG_YAML).expect("cp-down-lkg");
    }

    #[test]
    fn exception_without_ttl_fails() {
        let msg = err_msg(EXCEPTION_WITHOUT_TTL_YAML);
        assert!(
            msg.contains("expiresAt") || msg.contains("expires_at") || msg.contains("parse spec"),
            "{msg}"
        );
    }

    #[test]
    fn policy_library_empty_source_fails() {
        let yaml = r#"
apiVersion: ferrum.io/v1
kind: PolicyLibrary
metadata:
  name: bad
spec:
  source: "  "
  digest: "8253ce6ea4260821d86f49a49487bd5f032c763a9d63499d8dea0a3f7e3fabd2"
"#;
        let msg = err_msg(yaml);
        assert!(msg.contains("source"), "{msg}");
    }

    #[test]
    fn policy_library_empty_digest_fails() {
        let yaml = r#"
apiVersion: ferrum.io/v1
kind: PolicyLibrary
metadata:
  name: bad
spec:
  source: oci://registry.internal.example/ferrum/policy-lib:v1
  digest: ""
"#;
        let msg = err_msg(yaml);
        assert!(msg.contains("digest"), "{msg}");
    }

    #[test]
    fn policy_library_malformed_digest_fails() {
        let yaml = r#"
apiVersion: ferrum.io/v1
kind: PolicyLibrary
metadata:
  name: bad
spec:
  source: oci://registry.internal.example/ferrum/policy-lib:v1
  digest: "not-a-digest"
"#;
        let msg = err_msg(yaml);
        assert!(msg.contains("digest"), "{msg}");
    }

    #[test]
    fn runtime_profile_empty_source_policy_fails() {
        let yaml = r#"
apiVersion: ferrum.io/v1
kind: RuntimeProfile
metadata:
  name: bad
spec:
  sourcePolicy: ""
  window: 7d
"#;
        let msg = err_msg(yaml);
        assert!(msg.contains("sourcePolicy"), "{msg}");
    }

    #[test]
    fn runtime_profile_empty_window_fails() {
        let yaml = r#"
apiVersion: ferrum.io/v1
kind: RuntimeProfile
metadata:
  name: bad
spec:
  sourcePolicy: prod-restricted
  window: "  "
"#;
        let msg = err_msg(yaml);
        assert!(msg.contains("window"), "{msg}");
    }

    #[test]
    fn ferrum_cluster_empty_secret_ref_fails() {
        let yaml = r#"
apiVersion: ferrum.io/v1
kind: FerrumCluster
metadata:
  name: bad
spec:
  kubeconfigSecretRef: "  "
"#;
        let msg = err_msg(yaml);
        assert!(msg.contains("kubeconfigSecretRef"), "{msg}");
        assert!(!msg.to_lowercase().contains("connect"), "{msg}");
    }

    #[test]
    fn compliance_snapshot_empty_framework_fails() {
        let yaml = r#"
apiVersion: ferrum.io/v1
kind: ComplianceSnapshot
metadata:
  name: bad
spec:
  frameworks: [""]
"#;
        let msg = err_msg(yaml);
        assert!(msg.contains("frameworks"), "{msg}");
    }

    #[test]
    fn namespaced_policy_ok() {
        let yaml = r#"
apiVersion: ferrum.io/v1
kind: SecurityPolicy
metadata:
  name: ns-restricted
  namespace: payments
spec:
  mode: audit
  admit:
    failurePolicy: Fail
    deny:
      privileged: true
"#;
        validate_yaml(yaml).expect("namespaced policy");
    }

    #[test]
    fn namespaced_ignore_fails() {
        let yaml = r#"
apiVersion: ferrum.io/v1
kind: SecurityPolicy
metadata:
  name: ns-ignore
  namespace: payments
spec:
  admit:
    failurePolicy: Ignore
"#;
        assert!(validate_yaml(yaml).is_err());
    }

    #[test]
    fn enforcement_event_is_not_a_crd() {
        let yaml = r#"
apiVersion: ferrum.io/v1
kind: EnforcementEvent
spec: {}
"#;
        let msg = err_msg(yaml);
        assert!(msg.contains("EnforcementEvent"), "{msg}");
    }

    #[test]
    fn unsupported_api_version_fails() {
        let yaml = r#"
apiVersion: ferrum.io/v2
kind: ClusterSecurityPolicy
spec: {}
"#;
        let msg = err_msg(yaml);
        assert!(msg.contains("apiVersion"), "{msg}");
    }
}
