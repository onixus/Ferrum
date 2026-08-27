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
const UNRESOLVED_ROLE_REF: &str = "FD016";
const AGGREGATED_ROLE: &str = "FD017";
const RESPOND_WITHOUT_HOST_PID: &str = "FD018";
const UNNEEDED_HOST_PID: &str = "FD019";
const WEBHOOK_CA_BUNDLE: &str = "FD020";
const WEBHOOK_TLS_SECRET: &str = "FD021";

/// The token a webhook template carries instead of a certificate. Committing a
/// real CA is not an option, so the applied file is produced by
/// `ferrumctl gen-webhook-pki` and only the template lives in git.
pub const CA_BUNDLE_PLACEHOLDER: &str = "REPLACE_WITH_PEM_CA_BUNDLE_BASE64";
/// Files whose name carries this infix are templates, not manifests.
pub const TEMPLATE_INFIX: &str = ".tmpl.";
/// Secret name the issuance instruction produces: `<service>` + this.
pub const WEBHOOK_TLS_SECRET_SUFFIX: &str = "-tls";

/// roleRef targets that are not in this tree and that we still accept: the API
/// server creates them itself, and both are narrow enough that binding one is
/// not a grant this lint can improve on. `system:auth-delegator` only allows
/// TokenReview/SubjectAccessReview; the reader Role only reads one ConfigMap in
/// kube-system. Anything else unresolved is a finding — `admin`, `edit` and
/// `system:*` are built-ins too, and binding them is exactly the overreach the
/// rules below look for.
const ALLOWED_EXTERNAL_ROLE_REFS: [&str; 2] = [
    "ClusterRole/system:auth-delegator",
    "Role/extension-apiserver-authentication-reader",
];

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
    /// `*.tmpl.yaml`: not applied as-is, checked for the placeholder instead.
    template: bool,
    value: Value,
}

pub fn lint_deploy_dir(dir: &Path) -> Result<()> {
    let (findings, manifests) = collect_findings(dir)?;

    if findings.is_empty() {
        println!("ok: {} ({manifests} manifests)", dir.display());
        return Ok(());
    }
    for f in &findings {
        eprintln!("{} {}: {}", f.code, f.file, f.msg);
    }
    bail!("{} deploy invariant(s) violated", findings.len());
}

fn collect_findings(dir: &Path) -> Result<(Vec<Finding>, usize)> {
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
    check_webhook_tls(&docs, &mut findings);
    check_crd_catalog(dir, &mut findings);
    Ok((findings, docs.len()))
}

fn load_docs(dir: &Path) -> Result<Vec<Doc>> {
    let mut files = Vec::new();
    collect_files(dir, &mut files)?;
    files.sort();

    let mut docs = Vec::new();
    for path in files {
        let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let name = path.display().to_string();
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let base = !file_name.starts_with("optional-");
        let template = file_name.contains(TEMPLATE_INFIX);
        for (i, doc) in serde_yaml::Deserializer::from_str(&raw).enumerate() {
            let value = Value::deserialize(doc)
                .with_context(|| format!("parse {} (document {})", path.display(), i + 1))?;
            if value.is_null() {
                continue;
            }
            docs.push(Doc {
                file: name.clone(),
                base,
                template,
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
            let key = format!("{ref_kind}/{ref_name}");
            let Some(role) = roles.get(&key) else {
                if !ALLOWED_EXTERNAL_ROLE_REFS.contains(&key.as_str()) {
                    findings.push(Finding {
                        code: UNRESOLVED_ROLE_REF,
                        file: doc.file.clone(),
                        msg: format!(
                            "observe ServiceAccount '{subject}' is bound to {key}, which this tree \
                             does not define; the grant cannot be checked, so it is not allowed"
                        ),
                    });
                }
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
        if doc.value.get("aggregationRule").is_some() {
            findings.push(Finding {
                code: AGGREGATED_ROLE,
                file: doc.file.clone(),
                msg: format!(
                    "{k}/{} has an aggregationRule; the controller fills its rules from labelled \
                     roles at runtime, so what this file grants is not what the cluster grants",
                    name(doc)
                ),
            });
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

        check_host_pid(doc, &owner, spec, findings);

        for key in ["initContainers", "containers"] {
            for container in seq(spec, key) {
                check_container(doc, &owner, container, findings);
            }
        }
    }
}

/// `bpf_get_current_pid_tgid()` reports the tgid of the initial pid namespace.
/// A responder that is not in that namespace would resolve the number against
/// its own namespace and signal an unrelated process, so respond needs
/// `hostPID: true` — and nothing else does, because host pid namespace also
/// hands every other process on the node to whoever gets into this container.
fn check_host_pid(doc: &Doc, owner: &str, spec: &Value, findings: &mut Vec<Finding>) {
    let host_pid = spec.get("hostPID").and_then(Value::as_bool) == Some(true);
    let respond = runs_respond(spec);
    if respond && !host_pid {
        findings.push(Finding {
            code: RESPOND_WITHOUT_HOST_PID,
            file: doc.file.clone(),
            msg: format!(
                "{owner} runs the agent with --role respond but not hostPID: true; kill would \
                 address a pid in the container's own namespace, not the one the kernel reported"
            ),
        });
    }
    if !respond && host_pid {
        findings.push(Finding {
            code: UNNEEDED_HOST_PID,
            file: doc.file.clone(),
            msg: format!(
                "{owner} sets hostPID: true without --role respond; that exposes every process on \
                 the node for a capability this pod does not use"
            ),
        });
    }
}

fn runs_respond(spec: &Value) -> bool {
    seq(spec, "containers")
        .iter()
        .chain(seq(spec, "initContainers"))
        .any(|c| {
            let argv: Vec<String> = ["command", "args"]
                .iter()
                .flat_map(|key| str_list(c, key))
                .collect();
            argv.iter().any(|a| a == "--role=respond")
                || argv
                    .windows(2)
                    .any(|w| w[0] == "--role" && w[1] == "respond")
        })
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
            check_ca_bundle(doc, wname, webhook, findings);
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

/// A webhook whose `caBundle` is a placeholder cannot be applied; a webhook
/// whose `caBundle` is not base64 of PEM CERTIFICATE blocks is applied and then
/// fails every handshake. Templates carry the token and nothing else.
fn check_ca_bundle(doc: &Doc, wname: &str, webhook: &Value, findings: &mut Vec<Finding>) {
    let value = webhook
        .get("clientConfig")
        .and_then(|c| c.get("caBundle"))
        .and_then(Value::as_str);
    let mut fail = |msg: String| {
        findings.push(Finding {
            code: WEBHOOK_CA_BUNDLE,
            file: doc.file.clone(),
            msg,
        })
    };
    let Some(value) = value else {
        fail(format!(
            "webhook '{wname}' has no clientConfig.caBundle; the API server would trust the              cluster's default roots for a certificate no public CA issued"
        ));
        return;
    };
    let value = value.trim();
    if doc.template {
        if value != CA_BUNDLE_PLACEHOLDER {
            fail(format!(
                "webhook '{wname}' is in a template but its caBundle is not the                  {CA_BUNDLE_PLACEHOLDER} token; a template must not carry a real CA"
            ));
        }
        return;
    }
    if value.is_empty() {
        fail(format!("webhook '{wname}' has an empty caBundle"));
        return;
    }
    if value == CA_BUNDLE_PLACEHOLDER {
        fail(format!(
            "webhook '{wname}' still carries the {CA_BUNDLE_PLACEHOLDER} placeholder; run \
             `ferrumctl gen-webhook-pki` and apply what it renders"
        ));
        return;
    }
    let decoded = match ferrum_crypto::x509::base64_decode(value) {
        Ok(bytes) => bytes,
        Err(e) => {
            fail(format!(
                "webhook '{wname}' caBundle is not valid base64: {e}"
            ));
            return;
        }
    };
    let Ok(text) = String::from_utf8(decoded) else {
        fail(format!(
            "webhook '{wname}' caBundle does not decode to PEM text"
        ));
        return;
    };
    if let Err(e) = ferrum_crypto::x509::pem_certificates(&text) {
        fail(format!(
            "webhook '{wname}' caBundle does not decode to PEM CERTIFICATE blocks: {e}"
        ));
    }
}

/// The webhook's Service must be backed by a workload that actually mounts the
/// Secret the issuance step writes, and whose `--tls-cert`/`--tls-key` point
/// inside that mount. A cert on disk somewhere else is a cert the server never
/// serves.
fn check_webhook_tls(docs: &[Doc], findings: &mut Vec<Finding>) {
    for doc in docs {
        if kind(doc) != "ValidatingWebhookConfiguration" {
            continue;
        }
        for webhook in seq(&doc.value, "webhooks") {
            let wname = webhook
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("<unnamed>");
            let Some(service) = webhook
                .get("clientConfig")
                .and_then(|c| c.get("service"))
                .and_then(|s| s.get("name"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            let secret = format!("{service}{WEBHOOK_TLS_SECRET_SUFFIX}");
            let mut fail = |msg: String| {
                findings.push(Finding {
                    code: WEBHOOK_TLS_SECRET,
                    file: doc.file.clone(),
                    msg,
                })
            };
            let Some(spec) = docs
                .iter()
                .filter(|d| name(d) == service)
                .find_map(pod_spec)
            else {
                fail(format!(
                    "webhook '{wname}' is served by Service '{service}', but no workload named                      '{service}' in this tree mounts its serving certificate"
                ));
                continue;
            };
            let Some(mount_dir) = tls_mount_dir(spec, &secret) else {
                fail(format!(
                    "webhook '{wname}' expects Secret '{secret}' (what `ferrumctl                      gen-webhook-pki` writes), but '{service}' mounts no such volume"
                ));
                continue;
            };
            for flag in ["--tls-cert", "--tls-key"] {
                match flag_value(spec, flag) {
                    Some(path) if path.starts_with(&format!("{mount_dir}/")) => {}
                    Some(path) => fail(format!(
                        "webhook '{wname}': '{service}' passes {flag} {path}, which is outside                          the '{secret}' mount at {mount_dir}"
                    )),
                    None => fail(format!(
                        "webhook '{wname}': '{service}' passes no {flag}, so the mounted                          Secret '{secret}' is never served"
                    )),
                }
            }
        }
    }
}

/// mountPath of the container volume backed by `secret`, without a trailing slash.
fn tls_mount_dir(spec: &Value, secret: &str) -> Option<String> {
    let volume = seq(spec, "volumes").iter().find(|v| {
        v.get("secret")
            .and_then(|s| s.get("secretName"))
            .and_then(Value::as_str)
            == Some(secret)
    })?;
    let vname = volume.get("name").and_then(Value::as_str)?;
    seq(spec, "containers")
        .iter()
        .flat_map(|c| seq(c, "volumeMounts"))
        .find(|m| m.get("name").and_then(Value::as_str) == Some(vname))
        .and_then(|m| m.get("mountPath").and_then(Value::as_str))
        .map(|p| p.trim_end_matches('/').to_string())
}

/// `--flag value` and `--flag=value` both count; container args are written
/// either way across this tree.
fn flag_value(spec: &Value, flag: &str) -> Option<String> {
    for container in seq(spec, "containers") {
        // Not `str_list`: it lowercases, and a mount path is case-sensitive.
        let argv: Vec<String> = ["command", "args"]
            .iter()
            .flat_map(|key| seq(container, key))
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        for (i, arg) in argv.iter().enumerate() {
            if let Some(v) = arg.strip_prefix(&format!("{flag}=")) {
                return Some(v.to_string());
            }
            if arg == flag {
                return argv.get(i + 1).cloned();
            }
        }
    }
    None
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

    /// Each negative tree exists for one rule. Asserting the exact code keeps a
    /// fixture from passing the gate on an unrelated finding.
    fn codes_for(fixture: &str) -> BTreeSet<String> {
        let (findings, _) = collect_findings(&repo_path(fixture)).expect("lint fixture");
        assert!(!findings.is_empty(), "{fixture} produced no finding");
        findings.iter().map(|f| f.code.to_string()).collect()
    }

    #[test]
    fn unresolvable_role_ref_is_a_finding() {
        let codes = codes_for("crates/ferrum-testkit/fixtures/deploy-bad-roleref");
        assert_eq!(
            codes,
            ["FD016"]
                .iter()
                .map(|c| c.to_string())
                .collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn aggregated_role_is_a_finding() {
        let codes = codes_for("crates/ferrum-testkit/fixtures/deploy-bad-aggregation");
        assert_eq!(
            codes,
            ["FD017"]
                .iter()
                .map(|c| c.to_string())
                .collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn host_pid_must_match_the_role() {
        let codes = codes_for("crates/ferrum-testkit/fixtures/deploy-bad-hostpid");
        assert_eq!(
            codes,
            ["FD018", "FD019"]
                .iter()
                .map(|c| c.to_string())
                .collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn a_placeholder_ca_bundle_outside_a_template_is_a_finding() {
        let codes = codes_for("crates/ferrum-testkit/fixtures/deploy-bad-cabundle");
        assert_eq!(
            codes,
            [WEBHOOK_CA_BUNDLE]
                .iter()
                .map(|c| c.to_string())
                .collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn a_webhook_that_serves_an_unissued_secret_is_a_finding() {
        let codes = codes_for("crates/ferrum-testkit/fixtures/deploy-bad-webhook-tls");
        assert_eq!(
            codes,
            [WEBHOOK_TLS_SECRET]
                .iter()
                .map(|c| c.to_string())
                .collect::<BTreeSet<_>>()
        );
    }

    /// The committed tree holds the template, never a rendered configuration.
    #[test]
    fn the_template_keeps_the_placeholder_and_nothing_else() {
        let raw = fs::read_to_string(repo_path(
            "deploy/admission/validatingwebhookconfiguration.tmpl.yaml",
        ))
        .expect("webhook template");
        assert!(raw.contains(CA_BUNDLE_PLACEHOLDER));
        assert!(
            !repo_path("deploy/admission/validatingwebhookconfiguration.yaml").exists(),
            "a rendered webhook configuration must not be committed"
        );
    }

    #[test]
    fn a_real_ca_bundle_passes() {
        let ca = ferrum_crypto::x509::issue_ca(
            "ferrum-admission-ca",
            std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        )
        .unwrap();
        let bundle = ferrum_crypto::x509::base64_encode(ca.cert_pem.as_bytes());
        let docs = vec![Doc {
            file: "webhook.yaml".into(),
            base: true,
            template: false,
            value: serde_yaml::from_str(&format!(
                "kind: ValidatingWebhookConfiguration\nwebhooks:\n  - name: policy.ferrum.io\n    clientConfig:\n      caBundle: {bundle}\n"
            ))
            .unwrap(),
        }];
        let mut findings = Vec::new();
        for webhook in seq(&docs[0].value, "webhooks") {
            check_ca_bundle(&docs[0], "policy.ferrum.io", webhook, &mut findings);
        }
        assert!(
            findings.is_empty(),
            "{}",
            findings.first().map(|f| f.msg.clone()).unwrap_or_default()
        );
    }

    #[test]
    fn allowlisted_external_role_ref_is_not_a_finding() {
        let docs = vec![Doc {
            file: "rbac.yaml".into(),
            base: true,
            template: false,
            value: serde_yaml::from_str(
                r#"
kind: ClusterRoleBinding
metadata:
  name: ferrum-agent-observe-auth
roleRef:
  kind: ClusterRole
  name: system:auth-delegator
subjects:
  - kind: ServiceAccount
    name: ferrum-agent-observe
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
    fn respond_role_is_read_from_either_flag_spelling() {
        for args in [r#"["--role", "respond"]"#, r#"["--role=respond"]"#] {
            let spec: Value =
                serde_yaml::from_str(&format!("containers:\n  - name: agent\n    args: {args}\n"))
                    .unwrap();
            assert!(runs_respond(&spec), "{args}");
        }
        let observe: Value = serde_yaml::from_str(
            "containers:\n  - name: agent\n    args: [\"--role\", \"observe\"]\n",
        )
        .unwrap();
        assert!(!runs_respond(&observe));
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
            template: false,
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
            template: false,
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
                template: false,
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
            template: false,
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
        check_webhook_tls(&docs, &mut findings);
        let codes: BTreeSet<&str> = findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(WEBHOOK_SIDE_EFFECTS));
        assert!(codes.contains(WEBHOOK_TIMEOUT));
        assert!(codes.contains(WEBHOOK_FAILURE_POLICY));
        assert!(codes.contains(WEBHOOK_NAMESPACE_SELECTOR));
    }
}
