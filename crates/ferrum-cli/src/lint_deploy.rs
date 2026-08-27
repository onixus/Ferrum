//! Offline lint of the install manifests. Structural invariants only: the exact
//! flag and mount list belongs to whoever owns the binary, drift there is not a
//! finding. YAML is read untyped — `ferrumctl` carries no Kubernetes types.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_yaml::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub const MAX_WEBHOOK_TIMEOUT_SECONDS: i64 = 5;
/// Namespaces the webhook must not gate: the webhook Pod itself and the control
/// plane that has to come up before it.
pub const WEBHOOK_EXEMPT_NAMESPACES: [&str; 2] = ["ferrum", "kube-system"];

const CLUSTER_ADMIN_BIND: &str = "FD001";
const WILDCARD_RBAC: &str = "FD002";
const OBSERVE_SA_OVERREACH: &str = "FD003";
const RESPOND_BINDING_IN_BASE: &str = "FD004";
const MISSING_RESOURCE_LIMITS: &str = "FD005";
const FORBIDDEN_HOST_PATH: &str = "FD006";
const WEBHOOK_SIDE_EFFECTS: &str = "FD007";
const WEBHOOK_TIMEOUT: &str = "FD008";
const WEBHOOK_FAILURE_POLICY: &str = "FD009";
const WEBHOOK_NAMESPACE_SELECTOR: &str = "FD010";
const PRIVILEGED_CONTAINER: &str = "FD011";
const PRIVILEGE_ESCALATION: &str = "FD012";
const CAPABILITIES_NOT_DROPPED: &str = "FD013";
const MISSING_SERVICE_ACCOUNT: &str = "FD014";
const MISSING_CRD: &str = "FD015";

/// A hostPath that hands the node's container runtime or kubelet to the pod.
/// This is the escape route FERRUM itself kills at runtime.
const FORBIDDEN_HOST_PATH_PREFIXES: [&str; 5] = [
    "/var/run",
    "/run",
    "/var/lib/kubelet",
    "/etc/kubernetes",
    "/var/lib/docker",
];

const OBSERVE_FORBIDDEN_VERBS: [&str; 3] = ["delete", "deletecollection", "*"];
const OBSERVE_FORBIDDEN_RESOURCES: [&str; 5] =
    ["secrets", "pods/exec", "pods/attach", "pods/eviction", "*"];

struct Finding {
    code: &'static str,
    file: String,
    msg: String,
}

struct Doc {
    file: String,
    /// Files named `optional-*.yaml` are not part of the base install.
    base: bool,
    value: Value,
}

pub fn lint_deploy_dir(dir: &Path) -> Result<()> {
    let docs = load_docs(dir)?;
    if docs.is_empty() {
        bail!("{}: no YAML manifests found", dir.display());
    }

    let mut findings = Vec::new();
    let roles = collect_roles(&docs);
    check_bindings(&docs, &roles, &mut findings);
    check_wildcard_rules(&docs, &mut findings);
    check_pod_templates(&docs, &mut findings);
    check_webhooks(&docs, &mut findings);
    check_crd_catalog(dir, &mut findings);

    if findings.is_empty() {
        println!("ok: {} ({} manifests)", dir.display(), docs.len());
        return Ok(());
    }
    for f in &findings {
        eprintln!("{} {}: {}", f.code, f.file, f.msg);
    }
    bail!("{} deploy invariant(s) violated", findings.len());
}

fn load_docs(dir: &Path) -> Result<Vec<Doc>> {
    let mut files = Vec::new();
    collect_files(dir, &mut files)?;
    files.sort();

    let mut docs = Vec::new();
    for path in files {
        let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let name = path.display().to_string();
        let base = !path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with("optional-"))
            .unwrap_or(false);
        for (i, doc) in serde_yaml::Deserializer::from_str(&raw).enumerate() {
            let value = Value::deserialize(doc)
                .with_context(|| format!("parse {} (document {})", path.display(), i + 1))?;
            if value.is_null() {
                continue;
            }
            docs.push(Doc {
                file: name.clone(),
                base,
                value,
            });
        }
    }
    Ok(docs)
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = fs::read_dir(dir).with_context(|| format!("read directory {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out)?;
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yaml") | Some("yml")
        ) {
            out.push(path);
        }
    }
    Ok(())
}

fn kind(doc: &Doc) -> &str {
    doc.value.get("kind").and_then(Value::as_str).unwrap_or("")
}

fn name(doc: &Doc) -> &str {
    doc.value
        .get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("<unnamed>")
}

fn seq<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_sequence)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn str_list(value: &Value, key: &str) -> Vec<String> {
    seq(value, key)
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_lowercase)
        .collect()
}

fn collect_roles(docs: &[Doc]) -> BTreeMap<String, &Value> {
    let mut roles = BTreeMap::new();
    for doc in docs {
        let k = kind(doc);
        if k == "Role" || k == "ClusterRole" {
            roles.insert(format!("{k}/{}", name(doc)), &doc.value);
        }
    }
    roles
}

fn check_bindings(docs: &[Doc], roles: &BTreeMap<String, &Value>, findings: &mut Vec<Finding>) {
    for doc in docs {
        let k = kind(doc);
        if k != "RoleBinding" && k != "ClusterRoleBinding" {
            continue;
        }
        let Some(role_ref) = doc.value.get("roleRef") else {
            continue;
        };
        let ref_kind = role_ref.get("kind").and_then(Value::as_str).unwrap_or("");
        let ref_name = role_ref.get("name").and_then(Value::as_str).unwrap_or("");
        if ref_name == "cluster-admin" {
            findings.push(Finding {
                code: CLUSTER_ADMIN_BIND,
                file: doc.file.clone(),
                msg: format!(
                    "{k}/{} binds cluster-admin — the exact grant this product denies at admission",
                    name(doc)
                ),
            });
        }

        let subjects: Vec<String> = seq(&doc.value, "subjects")
            .iter()
            .filter(|s| s.get("kind").and_then(Value::as_str) == Some("ServiceAccount"))
            .filter_map(|s| s.get("name").and_then(Value::as_str))
            .map(str::to_string)
            .collect();

        for subject in &subjects {
            if subject.contains("respond") && doc.base {
                findings.push(Finding {
                    code: RESPOND_BINDING_IN_BASE,
                    file: doc.file.clone(),
                    msg: format!(
                        "{k}/{} binds respond ServiceAccount '{subject}' in the base install; \
                         respond is off by default and belongs in optional-*.yaml",
                        name(doc)
                    ),
                });
            }
            if !subject.contains("observe") {
                continue;
            }
            let Some(role) = roles.get(&format!("{ref_kind}/{ref_name}")) else {
                continue;
            };
            for rule in seq(role, "rules") {
                let verbs = str_list(rule, "verbs");
                let resources = str_list(rule, "resources");
                for verb in &verbs {
                    if OBSERVE_FORBIDDEN_VERBS.contains(&verb.as_str()) {
                        findings.push(Finding {
                            code: OBSERVE_SA_OVERREACH,
                            file: doc.file.clone(),
                            msg: format!(
                                "observe ServiceAccount '{subject}' reaches verb '{verb}' via {ref_kind}/{ref_name}"
                            ),
                        });
                    }
                }
                for resource in &resources {
                    if OBSERVE_FORBIDDEN_RESOURCES.contains(&resource.as_str()) {
                        findings.push(Finding {
                            code: OBSERVE_SA_OVERREACH,
                            file: doc.file.clone(),
                            msg: format!(
                                "observe ServiceAccount '{subject}' reaches resource '{resource}' via {ref_kind}/{ref_name}"
                            ),
                        });
                    }
                }
            }
        }
    }
}

fn check_wildcard_rules(docs: &[Doc], findings: &mut Vec<Finding>) {
    for doc in docs {
        let k = kind(doc);
        if k != "Role" && k != "ClusterRole" {
            continue;
        }
        for rule in seq(&doc.value, "rules") {
            let verbs = str_list(rule, "verbs");
            let resources = str_list(rule, "resources");
            if verbs.iter().any(|v| v == "*") || resources.iter().any(|r| r == "*") {
                findings.push(Finding {
                    code: WILDCARD_RBAC,
                    file: doc.file.clone(),
                    msg: format!(
                        "{k}/{} uses a wildcard verb or resource; the admission policy denies \
                         wildcard RBAC in workloads and must not grant it to itself",
                        name(doc)
                    ),
                });
            }
        }
    }
}

fn pod_spec(doc: &Doc) -> Option<&Value> {
    match kind(doc) {
        "Pod" => doc.value.get("spec"),
        "Deployment" | "DaemonSet" | "StatefulSet" | "ReplicaSet" | "Job" => doc
            .value
            .get("spec")
            .and_then(|s| s.get("template"))
            .and_then(|t| t.get("spec")),
        "CronJob" => doc
            .value
            .get("spec")
            .and_then(|s| s.get("jobTemplate"))
            .and_then(|j| j.get("spec"))
            .and_then(|s| s.get("template"))
            .and_then(|t| t.get("spec")),
        _ => None,
    }
}

fn check_pod_templates(docs: &[Doc], findings: &mut Vec<Finding>) {
    for doc in docs {
        let Some(spec) = pod_spec(doc) else {
            continue;
        };
        let owner = format!("{}/{}", kind(doc), name(doc));

        let sa = spec
            .get("serviceAccountName")
            .and_then(Value::as_str)
            .unwrap_or("");
        if sa.trim().is_empty() {
            findings.push(Finding {
                code: MISSING_SERVICE_ACCOUNT,
                file: doc.file.clone(),
                msg: format!(
                    "{owner} has no serviceAccountName and would run as the namespace default"
                ),
            });
        }

        for volume in seq(spec, "volumes") {
            let Some(path) = volume
                .get("hostPath")
                .and_then(|h| h.get("path"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            let lower = path.to_lowercase();
            let forbidden = lower.ends_with(".sock")
                || lower == "/"
                || FORBIDDEN_HOST_PATH_PREFIXES
                    .iter()
                    .any(|p| lower == *p || lower.starts_with(&format!("{p}/")));
            if forbidden {
                findings.push(Finding {
                    code: FORBIDDEN_HOST_PATH,
                    file: doc.file.clone(),
                    msg: format!("{owner} mounts hostPath '{path}' — that is the escape route the runtime rules kill"),
                });
            }
        }

        for key in ["initContainers", "containers"] {
            for container in seq(spec, key) {
                check_container(doc, &owner, container, findings);
            }
        }
    }
}

fn check_container(doc: &Doc, owner: &str, container: &Value, findings: &mut Vec<Finding>) {
    let cname = container
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("<unnamed>");
    let limits = container.get("resources").and_then(|r| r.get("limits"));
    let has_limit = |field: &str| {
        limits
            .and_then(|l| l.get(field))
            .map(|v| !v.is_null())
            .unwrap_or(false)
    };
    if !has_limit("cpu") || !has_limit("memory") {
        findings.push(Finding {
            code: MISSING_RESOURCE_LIMITS,
            file: doc.file.clone(),
            msg: format!(
                "{owner} container '{cname}' has no resources.limits.cpu/memory — an agent that can \
                 starve its node is a DoS on the node it protects"
            ),
        });
    }

    let sc = container.get("securityContext");
    if sc
        .and_then(|s| s.get("privileged"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        findings.push(Finding {
            code: PRIVILEGED_CONTAINER,
            file: doc.file.clone(),
            msg: format!("{owner} container '{cname}' is privileged; grant capabilities instead"),
        });
    }
    if sc
        .and_then(|s| s.get("allowPrivilegeEscalation"))
        .and_then(Value::as_bool)
        != Some(false)
    {
        findings.push(Finding {
            code: PRIVILEGE_ESCALATION,
            file: doc.file.clone(),
            msg: format!(
                "{owner} container '{cname}' does not set allowPrivilegeEscalation: false"
            ),
        });
    }
    let drops: BTreeSet<String> = sc
        .and_then(|s| s.get("capabilities"))
        .map(|c| str_list(c, "drop"))
        .unwrap_or_default()
        .into_iter()
        .collect();
    if !drops.contains("all") {
        findings.push(Finding {
            code: CAPABILITIES_NOT_DROPPED,
            file: doc.file.clone(),
            msg: format!(
                "{owner} container '{cname}' does not drop ALL capabilities before adding any"
            ),
        });
    }
}

fn check_webhooks(docs: &[Doc], findings: &mut Vec<Finding>) {
    for doc in docs {
        if kind(doc) != "ValidatingWebhookConfiguration" {
            continue;
        }
        for webhook in seq(&doc.value, "webhooks") {
            let wname = webhook
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("<unnamed>");
            if webhook.get("sideEffects").and_then(Value::as_str) != Some("None") {
                findings.push(Finding {
                    code: WEBHOOK_SIDE_EFFECTS,
                    file: doc.file.clone(),
                    msg: format!("webhook '{wname}' must declare sideEffects: None; a dry-run request must not change state"),
                });
            }
            match webhook.get("timeoutSeconds").and_then(Value::as_i64) {
                Some(t) if (1..=MAX_WEBHOOK_TIMEOUT_SECONDS).contains(&t) => {}
                other => findings.push(Finding {
                    code: WEBHOOK_TIMEOUT,
                    file: doc.file.clone(),
                    msg: format!(
                        "webhook '{wname}' timeoutSeconds {} is outside 1..={MAX_WEBHOOK_TIMEOUT_SECONDS}; \
                         a slow webhook with failurePolicy: Fail stalls the API server",
                        other.map(|v| v.to_string()).unwrap_or_else(|| "unset".into())
                    ),
                }),
            }
            if webhook.get("failurePolicy").and_then(Value::as_str) != Some("Fail") {
                findings.push(Finding {
                    code: WEBHOOK_FAILURE_POLICY,
                    file: doc.file.clone(),
                    msg: format!(
                        "webhook '{wname}' must set failurePolicy: Fail; cluster policy does not \
                         degrade to allow when the webhook is unreachable"
                    ),
                });
            }
            let excluded = namespace_exclusions(webhook);
            for ns in WEBHOOK_EXEMPT_NAMESPACES {
                if !excluded.contains(ns) {
                    findings.push(Finding {
                        code: WEBHOOK_NAMESPACE_SELECTOR,
                        file: doc.file.clone(),
                        msg: format!(
                            "webhook '{wname}' does not exclude namespace '{ns}'; with \
                             failurePolicy: Fail a cold cluster deadlocks on itself"
                        ),
                    });
                }
            }
        }
    }
}

fn namespace_exclusions(webhook: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some(selector) = webhook.get("namespaceSelector") else {
        return out;
    };
    for expr in seq(selector, "matchExpressions") {
        let key = expr.get("key").and_then(Value::as_str).unwrap_or("");
        let op = expr.get("operator").and_then(Value::as_str).unwrap_or("");
        if key != "kubernetes.io/metadata.name" || op != "NotIn" {
            continue;
        }
        for value in seq(expr, "values") {
            if let Some(v) = value.as_str() {
                out.insert(v.to_string());
            }
        }
    }
    out
}

/// Every Kind listed in the CRD catalog needs a manifest, otherwise the API
/// server never serves it and the policy it carries cannot exist in a cluster.
fn check_crd_catalog(dir: &Path, findings: &mut Vec<Finding>) {
    let Some(crd_dir) = find_crd_dir(dir) else {
        eprintln!(
            "note: docs/crd not found above {}; CRD catalog check skipped",
            dir.display()
        );
        return;
    };
    let readme = crd_dir.join("README.md");
    let Ok(raw) = fs::read_to_string(&readme) else {
        findings.push(Finding {
            code: MISSING_CRD,
            file: readme.display().to_string(),
            msg: "CRD catalog is unreadable".into(),
        });
        return;
    };
    let mut declared = BTreeSet::new();
    let Ok(entries) = fs::read_dir(&crd_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(value) = serde_yaml::from_str::<Value>(&text) else {
            continue;
        };
        if let Some(k) = value
            .get("spec")
            .and_then(|s| s.get("names"))
            .and_then(|n| n.get("kind"))
            .and_then(Value::as_str)
        {
            declared.insert(k.to_string());
        }
    }
    for kind in catalog_kinds(&raw) {
        if !declared.contains(&kind) {
            findings.push(Finding {
                code: MISSING_CRD,
                file: readme.display().to_string(),
                msg: format!("Kind {kind} is in the catalog but no CRD manifest defines it"),
            });
        }
    }
}

fn catalog_kinds(readme: &str) -> Vec<String> {
    readme
        .lines()
        .filter_map(|line| line.trim().strip_prefix("- "))
        .filter_map(|item| {
            let head = item.split(['—', '-']).next()?.trim();
            let first = head.chars().next()?;
            (first.is_ascii_uppercase() && head.chars().all(|c| c.is_ascii_alphanumeric()))
                .then(|| head.to_string())
        })
        .collect()
}

fn find_crd_dir(start: &Path) -> Option<PathBuf> {
    let mut cur = fs::canonicalize(start).ok()?;
    loop {
        let candidate = cur.join("docs").join("crd");
        if candidate.is_dir() {
            return Some(candidate);
        }
        cur = cur.parent()?.to_path_buf();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_path(rel: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel)
    }

    #[test]
    fn deploy_tree_is_clean() {
        lint_deploy_dir(&repo_path("deploy")).expect("deploy/ must satisfy every invariant");
    }

    #[test]
    fn bad_fixture_tree_is_rejected() {
        let err = lint_deploy_dir(&repo_path("crates/ferrum-testkit/fixtures/deploy-bad"))
            .expect_err("deploy-bad/ must fail");
        assert!(err.to_string().contains("violated"), "{err}");
    }

    #[test]
    fn catalog_kinds_are_parsed() {
        let kinds = catalog_kinds(
            "# CRD\n\n- ClusterSecurityPolicy — политика\n- SecurityPolicy — namespaced\n\nprose\n",
        );
        assert_eq!(kinds, vec!["ClusterSecurityPolicy", "SecurityPolicy"]);
    }

    #[test]
    fn respond_binding_in_base_is_a_finding() {
        let docs = vec![Doc {
            file: "rbac.yaml".into(),
            base: true,
            value: serde_yaml::from_str(
                r#"
kind: ClusterRoleBinding
metadata:
  name: ferrum-agent-respond
roleRef:
  kind: ClusterRole
  name: ferrum-agent-respond
subjects:
  - kind: ServiceAccount
    name: ferrum-agent-respond
    namespace: ferrum
"#,
            )
            .unwrap(),
        }];
        let roles = collect_roles(&docs);
        let mut findings = Vec::new();
        check_bindings(&docs, &roles, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, RESPOND_BINDING_IN_BASE);
    }

    #[test]
    fn respond_binding_outside_base_is_allowed() {
        let docs = vec![Doc {
            file: "optional-respond.yaml".into(),
            base: false,
            value: serde_yaml::from_str(
                r#"
kind: ClusterRoleBinding
metadata:
  name: ferrum-agent-respond
roleRef:
  kind: ClusterRole
  name: ferrum-agent-respond
subjects:
  - kind: ServiceAccount
    name: ferrum-agent-respond
    namespace: ferrum
"#,
            )
            .unwrap(),
        }];
        let roles = collect_roles(&docs);
        let mut findings = Vec::new();
        check_bindings(&docs, &roles, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn observe_sa_reaching_secrets_is_a_finding() {
        let docs: Vec<Doc> = ["role", "binding"]
            .iter()
            .zip([
                r#"
kind: ClusterRole
metadata:
  name: ferrum-agent-observe
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
"#,
                r#"
kind: ClusterRoleBinding
metadata:
  name: ferrum-agent-observe
roleRef:
  kind: ClusterRole
  name: ferrum-agent-observe
subjects:
  - kind: ServiceAccount
    name: ferrum-agent-observe
"#,
            ])
            .map(|(_, yaml)| Doc {
                file: "rbac.yaml".into(),
                base: true,
                value: serde_yaml::from_str(yaml).unwrap(),
            })
            .collect();
        let roles = collect_roles(&docs);
        let mut findings = Vec::new();
        check_bindings(&docs, &roles, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, OBSERVE_SA_OVERREACH);
    }

    #[test]
    fn webhook_defaults_are_findings() {
        let docs = vec![Doc {
            file: "webhook.yaml".into(),
            base: true,
            value: serde_yaml::from_str(
                r#"
kind: ValidatingWebhookConfiguration
metadata:
  name: ferrum-admission
webhooks:
  - name: policy.ferrum.io
    sideEffects: Unknown
    timeoutSeconds: 30
    failurePolicy: Ignore
"#,
            )
            .unwrap(),
        }];
        let mut findings = Vec::new();
        check_webhooks(&docs, &mut findings);
        let codes: BTreeSet<&str> = findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(WEBHOOK_SIDE_EFFECTS));
        assert!(codes.contains(WEBHOOK_TIMEOUT));
        assert!(codes.contains(WEBHOOK_FAILURE_POLICY));
        assert!(codes.contains(WEBHOOK_NAMESPACE_SELECTOR));
    }
}
