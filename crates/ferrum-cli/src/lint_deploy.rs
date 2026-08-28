//! Offline lint of the install manifests. Structural invariants only: the exact
//! flag and mount list belongs to whoever owns the binary, drift there is not a
//! finding. YAML is read untyped — `ferrumctl` carries no Kubernetes types.

use anyhow::{bail, Context, Result};
use ferrum_crypto::x509::SERVING_CERT_WARN_DAYS;
use serde::Deserialize;
use serde_yaml::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
const WEBHOOK_PKI_MISMATCH: &str = "FD022";
const PRIVATE_KEY_IN_TREE: &str = "FD023";
const POLICY_NAME_UNJOINED: &str = "FD024";
const DUPLICATE_JOINED_FLAG: &str = "FD025";
const BPF_ELF_WITHOUT_TRACEFS: &str = "FD026";
const LABEL_SOURCE_UNJOINED: &str = "FD027";

/// Bundle Secrets the controller writes: `ferrum-bundle-cluster-<policy>` for a
/// cluster-scoped policy, `ferrum-bundle-ns-<namespace>-<policy>` for a
/// namespaced one.
const BUNDLE_SECRET_PREFIX: &str = "ferrum-bundle-";
const BUNDLE_SECRET_CLUSTER: &str = "cluster-";
const BUNDLE_SECRET_NAMESPACED: &str = "ns-";

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

/// Where a kernel exposes its tracepoint catalogue. Mirrors `TRACEFS_ROOTS` in
/// `crates/ferrum-ebpf/src/lib.rs`; change both together.
const TRACEFS_ROOTS: [&str; 2] = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];

/// The only `hostPath.type` that makes the tracefs mount an assertion.
///
/// Every other value, `DirectoryOrCreate` and the empty default included, lets
/// kubelet mount whatever is there — and `DirectoryOrCreate` has it *make* an
/// empty directory on a node where tracefs is elsewhere or absent, which is
/// byte for byte the state the `emptyDir` fixture exists to catch.
const HOST_PATH_DIRECTORY: &str = "Directory";

/// The two flag spellings that mean "this container reads labels from the
/// apiserver", and the only two watches in this product.
///
/// `--apiserver` opens the cluster-wide namespace/ServiceAccount label watch
/// (`ApiserverConfig::cluster_wide`). `--node` scopes the pod watch
/// (`ApiserverConfig::from_service_account`), whose pod records carry the
/// namespace labels the runtime plane resolves a selector against — and which
/// refuses an empty node name outright, so a `--node` with no value names no
/// watch. Both authenticate with the projected ServiceAccount token and
/// nothing else.
const APISERVER_FLAG: &str = "--apiserver";
const NODE_FLAG: &str = "--node";

/// Policy kinds whose `spec.selector` is what a label watch has to answer.
const POLICY_KINDS: [&str; 2] = ["ClusterSecurityPolicy", "SecurityPolicy"];

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
    check_label_source(&docs, dir, &mut findings);
    check_webhooks(&docs, &mut findings);
    check_webhook_tls(&docs, &mut findings);
    check_webhook_pki(&docs, &mut findings);
    check_crd_catalog(dir, &mut findings);
    check_private_key_material(dir, &mut findings);
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

/// `gen-webhook-pki` writes `ca.key` into this tree, and one `.gitignore` entry
/// is all that stands between it and a commit. Whoever holds that key can issue
/// a leaf the applied ValidatingWebhookConfiguration trusts — a forged
/// admission webhook — so a PEM private key anywhere under the deploy tree is a
/// finding regardless of the file's name or extension.
fn check_private_key_material(dir: &Path, findings: &mut Vec<Finding>) {
    let mut files = Vec::new();
    if collect_any_files(dir, &mut files).is_err() {
        return;
    }
    files.sort();
    for path in files {
        // Lossy, not read_to_string: a binary blob next to the manifests must
        // not let a PEM block hide behind one invalid byte.
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let Some(label) = pem_private_key_label(&String::from_utf8_lossy(&bytes)) else {
            continue;
        };
        findings.push(Finding {
            code: PRIVATE_KEY_IN_TREE,
            file: path.display().to_string(),
            msg: format!(
                "carries a PEM '{label}' block. Private key material does not belong in a \
                 directory that gets committed; move it out of the tree and keep it offline"
            ),
        });
    }
}

/// The label of the first `-----BEGIN ... PRIVATE KEY-----` line, if any.
fn pem_private_key_label(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let label = line
            .trim()
            .strip_prefix("-----BEGIN ")?
            .strip_suffix("-----")?
            .trim();
        label.ends_with("PRIVATE KEY").then(|| label.to_string())
    })
}

/// Every file under `dir`, whatever its extension: `collect_files` sees only
/// YAML, and a private key is not a manifest.
fn collect_any_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = fs::read_dir(dir).with_context(|| format!("read directory {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_any_files(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
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

fn doc_namespace(doc: &Doc) -> Option<&str> {
    doc.value
        .get("metadata")
        .and_then(|m| m.get("namespace"))
        .and_then(Value::as_str)
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
                check_flag_ambiguity(doc, &owner, container, findings);
                check_policy_join(doc, &owner, spec, container, findings);
                check_tracefs(doc, &owner, spec, container, findings);
            }
        }
    }
}

/// An attach build with no tracefs to read.
///
/// `--bpf-elf` is what turns an agent into the datapath: an attach build
/// refuses to start without it. Attaching a tracepoint means reading
/// `events/<category>/<name>/id` out of tracefs, and so does the probe that
/// decides which hooks this kernel actually has — which answers "cannot tell"
/// rather than "absent" when no tracefs is mounted, on purpose, so that a
/// missing filesystem never widens into a swallowed attach error.
///
/// tracefs is a filesystem of its own and no container runtime propagates it.
/// So a container that passes `--bpf-elf` and mounts none has an agent that
/// tries every hook, fails every one, and parks Degraded on every node it lands
/// on — the four RFC section D runtime cases dead in the shipped install, with
/// the binary, the ELF and the RBAC all correct. Nothing at runtime can repair
/// it, and nothing before this point looks wrong.
///
/// A finding, never a warning: this is the same unverifiable join FD005 and
/// FD022 were each added to stop passing. The mount must also be a `hostPath`
/// at a tracefs root — an `emptyDir` there is a directory with no `events` in
/// it, which is exactly the state this rule exists to catch — and its
/// `hostPath.type` must be `Directory`. `DirectoryOrCreate`, or no type at
/// all, is the same blindness with a different author: on a node whose tracefs
/// is somewhere else or absent, kubelet creates an empty directory and mounts
/// that, and the pod starts, hooks nothing and reports the same Degraded as
/// the `emptyDir` fixture. `Directory` is what makes the pod unschedulable and
/// visible instead, and it is what `deploy/agent/README` says the mount does.
fn check_tracefs(
    doc: &Doc,
    owner: &str,
    spec: &Value,
    container: &Value,
    findings: &mut Vec<Finding>,
) {
    let argv = argv_of(container);
    if container_flag(&argv, "--bpf-elf").is_none() {
        return;
    }
    let cname = container
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("<unnamed>");
    let mounted = seq(container, "volumeMounts").iter().any(|m| {
        let Some(path) = m.get("mountPath").and_then(Value::as_str) else {
            return false;
        };
        TRACEFS_ROOTS.contains(&path)
            && mounted_host_path(spec, container, path).is_some_and(|(host, kind)| {
                host == path && kind.as_deref() == Some(HOST_PATH_DIRECTORY)
            })
    });
    if mounted {
        return;
    }
    findings.push(Finding {
        code: BPF_ELF_WITHOUT_TRACEFS,
        file: doc.file.clone(),
        msg: format!(
            "{owner} container '{cname}' passes --bpf-elf but mounts no tracefs hostPath of type \
             {HOST_PATH_DIRECTORY} at one of {TRACEFS_ROOTS:?}; the tracepoint ids the attach \
             reads are not in this container, so every hook fails and the datapath is Degraded on \
             every node. Any other hostPath type — DirectoryOrCreate, or none — has kubelet mount \
             an empty directory it made itself on a node where tracefs is elsewhere, which is that \
             same blindness with the manifest looking complete"
        ),
    });
}

/// The `hostPath` `path` and `type` of the volume mounted at `mount_path` in
/// this container. `type` is `None` when the manifest leaves it out, which
/// Kubernetes reads as "no check at all" and this rule reads the same way.
fn mounted_host_path(
    spec: &Value,
    container: &Value,
    mount_path: &str,
) -> Option<(String, Option<String>)> {
    let volume_name = seq(container, "volumeMounts").iter().find_map(|m| {
        (m.get("mountPath").and_then(Value::as_str)? == mount_path)
            .then(|| m.get("name").and_then(Value::as_str))
            .flatten()
    })?;
    seq(spec, "volumes").iter().find_map(|v| {
        (v.get("name").and_then(Value::as_str)? == volume_name)
            .then(|| v.get("hostPath"))
            .flatten()
            .and_then(|h| {
                let path = h.get("path").and_then(Value::as_str)?.to_string();
                let kind = h
                    .get("type")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .filter(|k| !k.is_empty());
                Some((path, kind))
            })
    })
}

/// The label source the process will actually have, against the selectors the
/// policy it names will actually carry.
///
/// A namespace or ServiceAccount selector is answered from labels no manifest
/// holds: they are read from the apiserver, over a watch that authenticates
/// with the projected ServiceAccount token and nothing else. Two lines of one
/// manifest decide whether that watch can ever list, and they are written far
/// apart — the flag is in the container's argv, the token is a pod-spec field
/// and a ServiceAccount field — so a tree can contradict itself here and look
/// complete from either end.
///
/// Both halves are that same join, and neither is repairable at runtime:
///
/// - A container that names a watch (`--apiserver`, or `--node` with a node
///   name) while automount is off. `ApiserverConfig::in_cluster` used to read
///   only `KUBERNETES_SERVICE_HOST`, which is always set, so construction
///   succeeded and the watcher spawned; `token()` then failed on every
///   connect, forever, behind a backoff. It now refuses at construction,
///   naming the token file — but that is a startup error on a node, and this
///   rule is what keeps the manifest from being applied at all. For admission
///   the old behaviour left `WatchedLabels::is_warm()`
///   false permanently and `review` denies every Pod a selector-bearing policy
///   selects — deny-everything, not fail-open, which is why it survives an
///   audit that looks for the other direction. For the agent the same missing
///   token leaves `spawn_cgroup_refresh` with no pod metadata, the cgroup
///   index empty and no event ever flagged as a container. The RBAC granted to
///   the account is never exercised either way.
///
/// - The mirror: a container naming a `--policy-name` whose policy in this
///   tree carries a `namespaceSelector` or a `serviceAccountSelector`, with no
///   watch named at all. The token may well be projected; nothing reads it,
///   the labels are never fetched, and the selector can never be answered.
///   An unresolved predicate is not a non-match, so that policy denies
///   (admission) or misses (runtime) for as long as the install stands.
///
/// A finding, never a warning, for the reason FD005 and FD022 were each added:
/// a lint that passes on a join it cannot verify is what put this defect in
/// the shipped tree. Deliberately not scoped to one workload — the coupling is
/// identical in the DaemonSet and the Deployment, and a rule that knows which
/// is which is a rule that is right once.
///
/// Read through `container_flag`, not by looking for the flag string in the
/// args array: both binaries key argv into a map, so a repeated flag keeps the
/// last occurrence. A lint reading any other one proves its join against a
/// string the process never sees, which is the FD024/FD018 defect exactly.
fn check_label_source(docs: &[Doc], dir: &Path, findings: &mut Vec<Finding>) {
    let policies = selector_bearing_policies(dir);
    if policies.is_none() {
        eprintln!(
            "note: policies/ not found above {}; the selector half of {LABEL_SOURCE_UNJOINED} \
             is skipped",
            dir.display()
        );
    }
    for doc in docs {
        let Some(spec) = pod_spec(doc) else {
            continue;
        };
        let owner = format!("{}/{}", kind(doc), name(doc));
        for key in ["initContainers", "containers"] {
            for container in seq(spec, key) {
                let cname = container
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("<unnamed>");
                let argv = argv_of(container);
                let mut finding = |msg: String| {
                    findings.push(Finding {
                        code: LABEL_SOURCE_UNJOINED,
                        file: doc.file.clone(),
                        msg,
                    })
                };
                match label_source(&argv) {
                    Some(flag) => {
                        if let Err(why) = token_projected(doc, spec, docs) {
                            finding(format!(
                                "{owner} container '{cname}' passes {flag}, which opens an \
                                 apiserver watch, but {why}. The projected token is the only \
                                 credential that watch has, so every connect fails behind a \
                                 backoff and the cache never lists: a selector is never \
                                 answered, and nothing at runtime repairs it"
                            ));
                        }
                    }
                    None => {
                        let Some(policies) = policies.as_ref() else {
                            continue;
                        };
                        let Some(policy) = container_flag(&argv, "--policy-name")
                            .map(|p| p.trim().to_string())
                            .filter(|p| !p.is_empty())
                        else {
                            continue;
                        };
                        if policies.get(&policy) == Some(&true) {
                            finding(format!(
                                "{owner} container '{cname}' names --policy-name '{policy}', \
                                 whose policy in this tree carries a namespaceSelector or a \
                                 serviceAccountSelector, and names no apiserver label source \
                                 ({APISERVER_FLAG}, or {NODE_FLAG} with a node name). Those \
                                 labels are read from the apiserver and from nowhere else, so \
                                 the selector can never be answered — and an unresolved \
                                 predicate is not a non-match"
                            ));
                        }
                    }
                }
            }
        }
    }
}

/// The apiserver watch this container's argv names, if any. Empty `--node`
/// names none: `from_service_account` refuses an empty node name, and the
/// fallback behind it indexes a node that does not exist.
fn label_source(argv: &[String]) -> Option<&'static str> {
    if container_flag(argv, APISERVER_FLAG).is_some() {
        return Some(APISERVER_FLAG);
    }
    container_flag(argv, NODE_FLAG)
        .filter(|v| !v.trim().is_empty())
        .map(|_| NODE_FLAG)
}

/// Whether a ServiceAccount token is projected into this pod, or why it is
/// not.
///
/// Three-state, and the precedence is Kubernetes': the pod field wins when it
/// is set, the ServiceAccount's value applies when it is not, and unset on
/// both is a mounted token. A ServiceAccount this tree does not define answers
/// neither way, and an unresolved predicate is not a non-match — the same
/// stance FD016 takes on a roleRef it cannot resolve.
fn token_projected(doc: &Doc, spec: &Value, docs: &[Doc]) -> Result<(), String> {
    match spec
        .get("automountServiceAccountToken")
        .and_then(Value::as_bool)
    {
        Some(false) => {
            return Err(
                "the pod spec sets automountServiceAccountToken: false, so no token \
                        file exists in the container"
                    .to_string(),
            )
        }
        // A pod-level `true` overrides whatever the account says.
        Some(true) => return Ok(()),
        None => {}
    }
    let sa = spec
        .get("serviceAccountName")
        .and_then(Value::as_str)
        .unwrap_or("");
    if sa.is_empty() {
        // Running as the namespace default is FD014's finding, and the default
        // account does project a token.
        return Ok(());
    }
    let namespace = doc_namespace(doc);
    let account = docs.iter().find(|d| {
        kind(d) == "ServiceAccount"
            && name(d) == sa
            && match (namespace, doc_namespace(d)) {
                (Some(want), Some(have)) => want == have,
                _ => true,
            }
    });
    match account {
        None => Err(format!(
            "ServiceAccount '{sa}' is not defined in this tree and the pod spec does not set \
             automountServiceAccountToken, so nothing here shows a token is projected"
        )),
        Some(account) => match account
            .value
            .get("automountServiceAccountToken")
            .and_then(Value::as_bool)
        {
            Some(false) => Err(format!(
                "ServiceAccount '{sa}' sets automountServiceAccountToken: false and the pod \
                 spec does not override it"
            )),
            _ => Ok(()),
        },
    }
}

/// Every policy in this tree, by name, and whether its selector needs labels
/// only an apiserver watch can supply.
///
/// `None` when there is no `policies/` directory above the linted one: the
/// claim this makes is about the policies the tree carries, and a tree that
/// carries none is not a tree that contradicts itself. The caller says so on
/// stderr rather than passing quietly, the same way the CRD catalog check
/// does.
fn selector_bearing_policies(dir: &Path) -> Option<BTreeMap<String, bool>> {
    let policy_dir = find_policies_dir(dir)?;
    let mut files = Vec::new();
    collect_files(&policy_dir, &mut files).ok()?;
    files.sort();
    let mut out = BTreeMap::new();
    for path in files {
        let Ok(raw) = fs::read_to_string(&path) else {
            continue;
        };
        for doc in serde_yaml::Deserializer::from_str(&raw) {
            let Ok(value) = Value::deserialize(doc) else {
                continue;
            };
            let kind = value.get("kind").and_then(Value::as_str).unwrap_or("");
            if !POLICY_KINDS.contains(&kind) {
                continue;
            }
            let Some(policy) = value
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            let selector = value.get("spec").and_then(|s| s.get("selector"));
            let watched = ["namespaceSelector", "serviceAccountSelector"]
                .iter()
                .any(|key| {
                    selector
                        .and_then(|s| s.get(key))
                        .is_some_and(selector_is_nonempty)
                });
            out.insert(policy.to_string(), watched);
        }
    }
    Some(out)
}

/// A selector with neither a matchLabels entry nor a matchExpression selects
/// everything and needs no labels to do it.
fn selector_is_nonempty(selector: &Value) -> bool {
    !seq(selector, "matchExpressions").is_empty()
        || selector
            .get("matchLabels")
            .and_then(Value::as_mapping)
            .is_some_and(|m| !m.is_empty())
}

fn find_policies_dir(start: &Path) -> Option<PathBuf> {
    let mut cur = fs::canonicalize(start).ok()?;
    loop {
        let candidate = cur.join("policies");
        if candidate.is_dir() {
            return Some(candidate);
        }
        cur = cur.parent()?.to_path_buf();
    }
}

/// `--policy-name` is an unjoined string.
///
/// The agent matches a `PolicyException` by comparing the exception's
/// `target.policies` against this flag, and the FRMB carries no policy name of
/// its own — nothing at runtime can check that the flag names the policy in
/// the bundle actually mounted. An empty flag matches nothing at all, and a
/// wrong one matches nothing while every signed, verified, in-scope waiver on
/// the node is loaded, counted and logged as reloaded: kills a live waiver
/// should have demoted keep firing, and no counter moves.
///
/// The join cannot be proven at runtime without a bundle format change (an ABI
/// bump, and a bundle every deployed agent would refuse), so it is proven here
/// instead, against objects already deployed: the flag must name the policy the
/// mounted bundle Secret is named for. A finding, never a warning — a lint that
/// passes on an unverifiable join is what FD005 and FD022 were each added to
/// stop being.
fn check_policy_join(
    doc: &Doc,
    owner: &str,
    spec: &Value,
    container: &Value,
    findings: &mut Vec<Finding>,
) {
    let argv = argv_of(container);
    let policy = container_flag(&argv, "--policy-name");
    let bundle = container_flag(&argv, "--bundle");
    // Nothing to join: a workload that names no policy and mounts no bundle is
    // not in this rule's scope.
    if policy.is_none() && bundle.is_none() {
        return;
    }
    let mut finding = |msg: String| {
        findings.push(Finding {
            code: POLICY_NAME_UNJOINED,
            file: doc.file.clone(),
            msg,
        })
    };
    let cname = container
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("<unnamed>");
    let policy = match policy.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        Some(policy) => policy.to_string(),
        None => {
            return finding(format!(
                "{owner} container '{cname}' mounts a policy bundle with no --policy-name; the \
                 exception target is matched on that string, so every waiver in the bundle \
                 applies to nothing"
            ));
        }
    };
    let Some(bundle) = bundle else {
        return finding(format!(
            "{owner} container '{cname}' passes --policy-name '{policy}' with no --bundle; \
             nothing joins the name to a bundle"
        ));
    };
    let Some(secret) = mounted_secret(spec, container, &bundle) else {
        return finding(format!(
            "{owner} container '{cname}' passes --policy-name '{policy}' but '{bundle}' is not a \
             mounted Secret volume; the policy the bundle carries cannot be checked against it"
        ));
    };
    if !secret_names_policy(&secret, &policy) {
        finding(format!(
            "{owner} container '{cname}' passes --policy-name '{policy}' while mounting bundle \
             Secret '{secret}'; the FRMB carries no policy name, so a mismatch here loads every \
             waiver and applies none"
        ));
    }
}

/// Does `secret` name `policy`? The namespace half of a namespaced bundle
/// Secret may itself contain '-', so this verifies the shape rather than
/// parsing the policy back out of it.
fn secret_names_policy(secret: &str, policy: &str) -> bool {
    let Some(rest) = secret.strip_prefix(BUNDLE_SECRET_PREFIX) else {
        return false;
    };
    if let Some(cluster) = rest.strip_prefix(BUNDLE_SECRET_CLUSTER) {
        return cluster == policy;
    }
    match rest.strip_prefix(BUNDLE_SECRET_NAMESPACED) {
        // `ns-<namespace>-<policy>`: a non-empty namespace, then the policy.
        Some(ns) => match ns.strip_suffix(policy).and_then(|n| n.strip_suffix('-')) {
            Some(namespace) => !namespace.is_empty(),
            None => false,
        },
        None => false,
    }
}

/// The `secretName` of the volume mounted at `mount_path` in this container.
fn mounted_secret(spec: &Value, container: &Value, mount_path: &str) -> Option<String> {
    let volume_name = seq(container, "volumeMounts").iter().find_map(|m| {
        (m.get("mountPath").and_then(Value::as_str)? == mount_path)
            .then(|| m.get("name").and_then(Value::as_str))
            .flatten()
    })?;
    seq(spec, "volumes").iter().find_map(|v| {
        (v.get("name").and_then(Value::as_str)? == volume_name)
            .then(|| {
                v.get("secret")
                    .and_then(|s| s.get("secretName"))
                    .and_then(Value::as_str)
            })
            .flatten()
            .map(str::to_string)
    })
}

/// One container's argv, verbatim: not `str_list`, which lowercases, and a
/// mount path is case-sensitive.
fn argv_of(container: &Value) -> Vec<String> {
    ["command", "args"]
        .iter()
        .flat_map(|key| seq(container, key))
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

/// Mirrors `parse_flags` in `crates/ferrum-agent/src/main.rs`, and the
/// identical function in `crates/ferrum-admission/src/main.rs`: both binaries
/// read their argv by inserting into a map, so a repeated flag keeps the
/// **last** occurrence and silently drops the earlier ones.
///
/// A lint that read the first occurrence would prove its joins against a
/// string the process never sees: `--policy-name a … --policy-name b` would be
/// checked as `a` while the agent runs `b`. Change this function whenever
/// either `parse_flags` changes; the occurrence count it also returns is what
/// FD025 is built on.
///
/// Keyed without the leading `--`, as the agent keys it. `--flag=value`,
/// `--flag value` where the value does not itself start with `--`, and a bare
/// `--flag` as an empty value — which is a different finding from an absent
/// flag.
fn parse_argv(argv: &[String]) -> BTreeMap<String, (usize, String)> {
    let mut map: BTreeMap<String, (usize, String)> = BTreeMap::new();
    let mut i = 0;
    while i < argv.len() {
        if let Some(rest) = argv[i].strip_prefix("--") {
            let (key, value) = match rest.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => match argv.get(i + 1) {
                    Some(val) if !val.starts_with("--") => {
                        i += 1;
                        (rest.to_string(), val.clone())
                    }
                    _ => (rest.to_string(), String::new()),
                },
            };
            let seen = map.get(&key).map_or(0, |(n, _)| *n);
            map.insert(key, (seen + 1, value));
        }
        i += 1;
    }
    map
}

/// The value the process would actually run with, or None if the flag is
/// absent.
fn container_flag(argv: &[String], flag: &str) -> Option<String> {
    parse_argv(argv)
        .get(flag.trim_start_matches("--"))
        .map(|(_, v)| v.clone())
}

/// Flags a duplicate of which silently changes what the process enforces,
/// verifies against, or writes down — every one of them read last-wins by the
/// `parse_flags` this file mirrors.
///
/// Two groups. The first is flags this lint proves a claim about: the FD024
/// join (`--policy-name`, `--bundle`), the FD018/FD019 role, the FD021 serving
/// paths, the FD026 datapath (`--bpf-elf`). The second is flags it proves
/// nothing about and still cannot let a manifest state twice, because the value
/// the binary drops is one somebody wrote down and nobody reads:
///
/// - `--trust-root` is the root every bundle signature is verified against. A
///   manifest carrying the operator's key and then another one is a
///   signature-root substitution in plain sight. This lint says nothing about
///   which key is right — it cannot — only that one of the two is inert.
/// - `--lkg-dir` is the policy the node falls back to when the control plane is
///   gone, which is the one moment nothing else can correct it.
/// - `--exceptions` is which waivers admission applies.
/// - `--export-dir` is where the record of a kill is written; a redirected one
///   is the repudiation case with the node still reporting healthy.
/// - `--node` scopes the pod watch, so a second one indexes another node's pods
///   and every identity lookup here misses.
/// - `--reload-ms`, `--export-max-bytes`, `--export-keep` and `--export-queue`
///   are the rest of what `parse_flags` reads last-wins. They were left out for
///   a cycle as "tuning", which is the wrong axis: this rule is not about how
///   important a value is, it is about an argv where nobody chose the value
///   that won. A doubled `--export-keep` or `--export-max-bytes` silently
///   resizes the only record a kill leaves, and a doubled `--reload-ms` decides
///   how stale `status.json` is allowed to be — the freshness contract the
///   README tells an operator to read before believing any other field.
///
/// Deliberately absent, and this is the whole list:
///
/// - admission's `--listen`, where a wrong port is a webhook that fails closed
///   and says so on the first request;
/// - the controller's flags. `--cluster` accumulates on purpose rather than
///   overwriting, so a second one is not ambiguity there. `--min-agent-abi`
///   and `--min-admission-abi` *are* last-wins and would belong on the list on
///   their merits — they are left off because this lint's argv reader mirrors
///   the *agent's* `parse_flags`, which
///   `the_argv_reader_mirrors_the_agents_parse_flags` holds it to, and the
///   controller parses its own way. Adding them would make a claim about a
///   parser nothing here compares against. Whoever mirrors that parser should
///   add them in the same change.
///
/// Inverting this into "every flag except a repeatable allowlist" was
/// considered and not taken: it would draw findings on flags nobody here has an
/// argument about, and this list is meant to be exactly the arguments.
const JOINED_FLAGS: [&str; 15] = [
    "--policy-name",
    "--bundle",
    "--role",
    "--tls-cert",
    "--tls-key",
    "--trust-root",
    "--bpf-elf",
    "--lkg-dir",
    "--exceptions",
    "--export-dir",
    "--node",
    "--reload-ms",
    "--export-max-bytes",
    "--export-keep",
    "--export-queue",
];

/// Mirroring the binary's last-wins parse is only half an answer: a flag
/// written twice in one container's argv is a defect of its own — an overlay
/// or a merge that meant to replace a value and appended it instead — and the
/// value the lint then proves a join for is whichever the parser happened to
/// keep, not one anybody chose. So the ambiguity is its own finding rather
/// than something the lint silently resolves in the binary's favour.
///
/// This is also what keeps `runs_respond` no less catching than the `.any()`
/// over every occurrence that it replaced: an argv naming `respond` somewhere
/// but `observe` last no longer reaches FD018, and lands here instead.
fn check_flag_ambiguity(doc: &Doc, owner: &str, container: &Value, findings: &mut Vec<Finding>) {
    let cname = container
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("<unnamed>");
    let parsed = parse_argv(&argv_of(container));
    for flag in JOINED_FLAGS {
        let Some((count, value)) = parsed.get(flag.trim_start_matches("--")) else {
            continue;
        };
        if *count > 1 {
            findings.push(Finding {
                code: DUPLICATE_JOINED_FLAG,
                file: doc.file.clone(),
                msg: format!(
                    "{owner} container '{cname}' passes {flag} {count} times; the binary keeps \
                     only the last ('{value}') and drops the rest, so every other value here is \
                     one this manifest states and the process never reads"
                ),
            });
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

/// The role each container would actually run with — the last `--role`, not
/// the first. A pod whose argv names `respond` somewhere but runs `observe`
/// is not a respond pod and does not need hostPID; that it says both is
/// FD025's finding, so nothing an `.any()` here would have caught is lost.
fn runs_respond(spec: &Value) -> bool {
    seq(spec, "containers")
        .iter()
        .chain(seq(spec, "initContainers"))
        .any(|c| container_flag(&argv_of(c), "--role").as_deref() == Some("respond"))
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

/// When the issued material is in the tree next to the manifest — the Secret
/// `ferrumctl gen-webhook-pki` writes — the webhook's `caBundle` must be the CA
/// that signed the leaf in it, and neither may be expired or inside the
/// rotation window. Nothing else ties those two files together: today a
/// caBundle that does not match the Secret is discovered as a handshake the API
/// server rejects, which with `failurePolicy: Fail` is a cluster-wide stop.
fn check_webhook_pki(docs: &[Doc], findings: &mut Vec<Finding>) {
    let window = Duration::from_secs(SERVING_CERT_WARN_DAYS * 86_400);
    for doc in docs {
        if doc.template || kind(doc) != "ValidatingWebhookConfiguration" {
            continue;
        }
        for webhook in seq(&doc.value, "webhooks") {
            let wname = webhook
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("<unnamed>");
            let client_service = webhook.get("clientConfig").and_then(|c| c.get("service"));
            let Some(service) = client_service
                .and_then(|s| s.get("name"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            let service_ns = client_service
                .and_then(|s| s.get("namespace"))
                .and_then(Value::as_str);
            let secret = format!("{service}{WEBHOOK_TLS_SECRET_SUFFIX}");
            // No issued material in this tree: the install has not reached the
            // issuance step yet, and FD020/FD021 already cover the manifests.
            let Some((secret_file, leaf)) = tls_secret_certificate(docs, &secret, service_ns)
            else {
                continue;
            };
            let mut fail = |msg: String| {
                findings.push(Finding {
                    code: WEBHOOK_PKI_MISMATCH,
                    file: doc.file.clone(),
                    msg,
                })
            };
            let Some(ca) = ca_bundle_pem(webhook) else {
                continue;
            };
            let leaf = match leaf {
                Ok(pem) => pem,
                Err(e) => {
                    fail(format!(
                        "webhook '{wname}': tls.crt in Secret '{secret}' ({secret_file}) is not \
                         readable PEM: {e}"
                    ));
                    continue;
                }
            };
            if let Err(e) = ferrum_crypto::x509::verify_issued_pair(&ca, &leaf) {
                fail(format!(
                    "webhook '{wname}' trusts a caBundle that does not match the serving \
                     certificate in Secret '{secret}' ({secret_file}): {e}"
                ));
                continue;
            }
            for (what, pem) in [("caBundle CA", &ca), ("serving certificate", &leaf)] {
                match ferrum_crypto::x509::expires_within(pem, window) {
                    Ok(true) => fail(format!(
                        "webhook '{wname}': the {what} has expired or expires within \
                         {SERVING_CERT_WARN_DAYS} days; with failurePolicy: Fail that stops Pod \
                         creation cluster-wide"
                    )),
                    Ok(false) => {}
                    Err(e) => fail(format!("webhook '{wname}': unreadable {what}: {e}")),
                }
            }
        }
    }
}

/// PEM text of a webhook's `caBundle`, when it holds one. Malformed values are
/// FD020's finding, not this rule's.
fn ca_bundle_pem(webhook: &Value) -> Option<String> {
    let value = webhook
        .get("clientConfig")
        .and_then(|c| c.get("caBundle"))
        .and_then(Value::as_str)?
        .trim();
    if value.is_empty() || value == CA_BUNDLE_PLACEHOLDER {
        return None;
    }
    String::from_utf8(ferrum_crypto::x509::base64_decode(value).ok()?).ok()
}

/// `tls.crt` of the `kubernetes.io/tls` Secret named `secret` in `namespace`,
/// with the file it came from.
///
/// A tree holding two installations has two Secrets of that name, and the
/// webhook is served by the one in its own Service's namespace. A Secret that
/// declares no namespace still matches: it is applied into whichever namespace
/// `kubectl` is pointed at, and skipping it would turn a real mismatch into a
/// silent pass.
fn tls_secret_certificate<'a>(
    docs: &'a [Doc],
    secret: &str,
    namespace: Option<&str>,
) -> Option<(&'a str, Result<String, String>)> {
    let doc = docs.iter().find(|d| {
        kind(d) == "Secret"
            && name(d) == secret
            && d.value.get("type").and_then(Value::as_str) == Some("kubernetes.io/tls")
            && match (namespace, doc_namespace(d)) {
                (Some(want), Some(have)) => want == have,
                _ => true,
            }
    })?;
    let raw = doc
        .value
        .get("data")
        .and_then(|d| d.get("tls.crt"))
        .and_then(Value::as_str);
    let pem = match raw {
        None => Err("Secret carries no data.tls.crt".to_string()),
        Some(value) => ferrum_crypto::x509::base64_decode(value)
            .map_err(|e| e.to_string())
            .and_then(|bytes| String::from_utf8(bytes).map_err(|e| e.to_string())),
    };
    Some((doc.file.as_str(), pem))
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
    // The first container that passes the flag, and inside it the occurrence
    // that container's own `parse_flags` keeps — see `container_flag`. Two
    // containers passing the same flag are two processes, not an ambiguity;
    // one container passing it twice is FD025.
    seq(spec, "containers")
        .iter()
        .find_map(|c| container_flag(&argv_of(c), flag))
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

    #[test]
    fn a_private_key_in_the_tree_is_a_finding() {
        let codes = codes_for("crates/ferrum-testkit/fixtures/deploy-bad-private-key");
        assert_eq!(
            codes,
            [PRIVATE_KEY_IN_TREE]
                .iter()
                .map(|c| c.to_string())
                .collect::<BTreeSet<_>>()
        );
    }

    /// A negative tree for FD024, built from the shipped DaemonSet: only the
    /// one line under test differs, so the finding cannot come from anywhere
    /// else. Written to a temp dir rather than a committed fixture because
    /// the fixture tree belongs to another crate.
    fn agent_tree_with(tag: &str, edit: impl Fn(String) -> String) -> PathBuf {
        let dir = tmp_tree(tag);
        let raw = fs::read_to_string(repo_path("deploy/agent/daemonset.yaml"))
            .expect("deploy/agent/daemonset.yaml");
        fs::write(dir.join("daemonset.yaml"), edit(raw)).expect("write manifest");
        dir
    }

    fn codes_in(dir: &Path) -> BTreeSet<String> {
        let (findings, _) = collect_findings(dir).expect("lint fixture");
        findings.iter().map(|f| f.code.to_string()).collect()
    }

    /// FD024. The FRMB carries no policy name, so nothing at runtime joins
    /// `--policy-name` to the bundle in the mounted Secret: a renamed policy
    /// loads every waiver on the node and applies none, with no counter moving
    /// and `is_degraded()` false. This is the end of that join that can be
    /// checked — against objects already deployed.
    #[test]
    fn a_policy_name_that_does_not_name_the_mounted_bundle_is_a_finding() {
        let dir = agent_tree_with("policy-name", |raw| {
            raw.replace(
                "            - prod-restricted\n",
                "            - prod-strict\n",
            )
        });
        assert_eq!(
            codes_in(&dir),
            [POLICY_NAME_UNJOINED]
                .iter()
                .map(|c| c.to_string())
                .collect::<BTreeSet<_>>()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// An empty or absent `--policy-name` is the same defect without a
    /// rename: `waiver_applies` returns None on the first line.
    #[test]
    fn an_agent_that_mounts_a_bundle_without_a_policy_name_is_a_finding() {
        let dir = agent_tree_with("no-policy-name", |raw| {
            raw.replace(
                "            - --policy-name\n            - prod-restricted\n",
                "",
            )
        });
        assert_eq!(
            codes_in(&dir),
            [POLICY_NAME_UNJOINED]
                .iter()
                .map(|c| c.to_string())
                .collect::<BTreeSet<_>>()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The bypass: `parse_flags` keeps the last `--policy-name`, so the agent
    /// joins waivers against `prod-strict` while the Secret it mounts is named
    /// for `prod-restricted`. A lint reading the first occurrence proves the
    /// join for a string the process never sees and reports ok — FD024's whole
    /// claim, that the join is checked against objects already deployed, is
    /// false for exactly this manifest.
    #[test]
    fn the_last_policy_name_is_the_one_joined() {
        let dir = agent_tree_with("dup-policy-name", |raw| {
            raw.replace(
                "            - --policy-name\n            - prod-restricted\n",
                "            - --policy-name\n            - prod-restricted\n            - \
                 --policy-name\n            - prod-strict\n",
            )
        });
        assert_eq!(
            codes_in(&dir),
            [POLICY_NAME_UNJOINED, DUPLICATE_JOINED_FLAG]
                .iter()
                .map(|c| c.to_string())
                .collect::<BTreeSet<_>>()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The same bypass on `--role`: the agent runs respond, the DaemonSet has
    /// no hostPID, and a lint reading the first occurrence sees `observe` and
    /// never fires FD018.
    #[test]
    fn the_last_role_is_the_one_run() {
        let dir = agent_tree_with("dup-role-respond", |raw| {
            raw.replace(
                "            - --role\n            - observe\n",
                "            - --role\n            - observe\n            - --role\n            \
                 - respond\n",
            )
        });
        assert_eq!(
            codes_in(&dir),
            [RESPOND_WITHOUT_HOST_PID, DUPLICATE_JOINED_FLAG]
                .iter()
                .map(|c| c.to_string())
                .collect::<BTreeSet<_>>()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// And the other order, which the `.any()` over every occurrence used to
    /// catch: the agent runs observe, so FD018 is right not to fire — but the
    /// manifest still names two roles, and that is not something this lint
    /// resolves silently.
    #[test]
    fn a_role_named_twice_is_a_finding_whichever_one_runs() {
        let dir = agent_tree_with("dup-role-observe", |raw| {
            raw.replace(
                "            - --role\n            - observe\n",
                "            - --role\n            - respond\n            - --role\n            \
                 - observe\n",
            )
        });
        assert_eq!(
            codes_in(&dir),
            [DUPLICATE_JOINED_FLAG]
                .iter()
                .map(|c| c.to_string())
                .collect::<BTreeSet<_>>()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The same bypass on the flag that decides what the node will trust. The
    /// agent verifies every bundle signature against the last `--trust-root`,
    /// so a manifest carrying the operator's key and then another one is a
    /// signature-root substitution sitting in plain sight — and until
    /// `--trust-root` joined `JOINED_FLAGS` the lint printed ok on it.
    #[test]
    fn a_trust_root_named_twice_is_a_finding() {
        let one = "            - --trust-root\n            - $(FERRUM_TRUST_ROOT)\n";
        let two = "            - --trust-root\n            - $(FERRUM_TRUST_ROOT)\n            - --trust-root\n            - $(ATTACKER_TRUST_ROOT)\n";
        let dir = agent_tree_with("dup-trust-root", |raw| raw.replace(one, two));
        assert_eq!(
            codes_in(&dir),
            [DUPLICATE_JOINED_FLAG]
                .iter()
                .map(|c| c.to_string())
                .collect::<BTreeSet<_>>()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Every flag `parse_flags` reads last-wins is on the list, so a doubled
    /// one is ambiguity wherever it appears.
    ///
    /// `--export-keep` is the case that shows why "tuning" was the wrong reason
    /// to leave four flags off: it decides how many rotations of the only
    /// record a kill leaves survive, and an overlay that appends instead of
    /// replacing picks the winner with nobody choosing it.
    #[test]
    fn a_retention_flag_named_twice_is_a_finding() {
        let one = "            - --export-dir\n";
        let two = "            - --export-keep\n            - \"5\"\n            - --export-keep\n            - \"1\"\n            - --export-dir\n";
        let dir = agent_tree_with("dup-export-keep", |raw| raw.replace(one, two));
        assert_eq!(
            codes_in(&dir),
            [DUPLICATE_JOINED_FLAG]
                .iter()
                .map(|c| c.to_string())
                .collect::<BTreeSet<_>>()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// FD026, against the shipped DaemonSet with one mount removed. tracefs is
    /// a filesystem of its own: nothing propagates it into a container, so an
    /// agent without this mount reads no tracepoint id, fails every attach and
    /// parks Degraded — with the ELF, the capabilities and the RBAC all
    /// correct. This is the state the tree shipped in until it was fixed.
    #[test]
    fn an_attach_build_without_tracefs_is_a_finding() {
        let mount = "            - name: tracefs\n              mountPath: /sys/kernel/tracing\n              readOnly: true\n";
        let dir = agent_tree_with("no-tracefs", |raw| raw.replace(mount, ""));
        assert_eq!(
            codes_in(&dir),
            [BPF_ELF_WITHOUT_TRACEFS]
                .iter()
                .map(|c| c.to_string())
                .collect::<BTreeSet<_>>()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A mount at the right path backed by the wrong thing. An `emptyDir` at
    /// /sys/kernel/tracing is a directory with no `events` in it: the same
    /// blindness, wearing a mount that makes the manifest look complete.
    #[test]
    fn an_emptydir_where_tracefs_belongs_is_still_a_finding() {
        let host = "        - name: tracefs\n          hostPath:\n            path: /sys/kernel/tracing\n            type: Directory\n";
        let empty = "        - name: tracefs\n          emptyDir: {}\n";
        let dir = agent_tree_with("fake-tracefs", |raw| raw.replace(host, empty));
        assert_eq!(
            codes_in(&dir),
            [BPF_ELF_WITHOUT_TRACEFS]
                .iter()
                .map(|c| c.to_string())
                .collect::<BTreeSet<_>>()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The same blindness written by kubelet instead of by the author.
    ///
    /// `type: Directory` is what the rule's own doc comment and
    /// `deploy/agent/README` say makes this mount an assertion: a node whose
    /// tracefs is elsewhere or absent leaves the pod unschedulable and visible.
    /// Under `DirectoryOrCreate` kubelet makes an empty directory and mounts
    /// that, and the pod starts with no `events` under the mount — the state
    /// `an_emptydir_where_tracefs_belongs_is_still_a_finding` exists to catch,
    /// reached without an `emptyDir` anywhere in the manifest. Leaving the type
    /// out entirely is the same answer for the same reason.
    #[test]
    fn a_tracefs_hostpath_kubelet_would_create_is_still_a_finding() {
        for kind in ["            type: DirectoryOrCreate\n", ""] {
            let dir = agent_tree_with("created-tracefs", |raw| {
                raw.replace("            type: Directory\n", kind)
            });
            assert_eq!(
                codes_in(&dir),
                [BPF_ELF_WITHOUT_TRACEFS]
                    .iter()
                    .map(|c| c.to_string())
                    .collect::<BTreeSet<_>>(),
                "hostPath type {kind:?} left FD026 silent"
            );
            let _ = fs::remove_dir_all(&dir);
        }
    }

    /// The committed negative tree the Jenkins 'Validate policies' stage runs,
    /// checked here for the exact code: an assertion of absence with no
    /// positive control proves nothing, and a fixture that fails on an
    /// unrelated finding is that absence again.
    #[test]
    fn the_tracefs_fixture_fails_on_that_rule_and_no_other() {
        let codes = codes_for("crates/ferrum-testkit/fixtures/deploy-bad-tracefs");
        assert_eq!(
            codes,
            [BPF_ELF_WITHOUT_TRACEFS]
                .iter()
                .map(|c| c.to_string())
                .collect::<BTreeSet<_>>()
        );
    }

    /// The shipped admission install, both files that decide whether the watch
    /// it names has a token, with one line under test edited. Written to a temp
    /// dir for the same reason `agent_tree_with` is.
    fn admission_tree_with(tag: &str, edit: impl Fn(String) -> String) -> PathBuf {
        let dir = tmp_tree(tag);
        for file in ["deployment.yaml", "serviceaccount.yaml"] {
            let raw = fs::read_to_string(repo_path(&format!("deploy/admission/{file}")))
                .unwrap_or_else(|e| panic!("deploy/admission/{file}: {e}"));
            fs::write(dir.join(file), edit(raw)).expect("write manifest");
        }
        dir
    }

    fn tmp_tree(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ferrum-lint-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("tmpdir");
        dir
    }

    /// A manifest tree with a `policies/` directory beside it, which is what
    /// the selector half of FD027 resolves `--policy-name` against. Returns
    /// the directory to lint.
    fn tree_beside_policies(
        tag: &str,
        policy: &str,
        manifest_name: &str,
        manifest: &str,
    ) -> PathBuf {
        let root = tmp_tree(tag);
        let policies = root.join("policies");
        let deploy = root.join("deploy");
        fs::create_dir_all(&policies).expect("policies dir");
        fs::create_dir_all(&deploy).expect("deploy dir");
        fs::write(policies.join("policy.yaml"), policy).expect("write policy");
        fs::write(deploy.join(manifest_name), manifest).expect("write manifest");
        deploy
    }

    fn code_set(codes: &[&str]) -> BTreeSet<String> {
        codes.iter().map(|c| c.to_string()).collect()
    }

    fn shipped(rel: &str) -> String {
        fs::read_to_string(repo_path(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    /// The committed negative tree for FD027, checked for the exact code: a
    /// positive control, because an assertion of absence proves nothing on its
    /// own and a fixture that fails on an unrelated finding is that absence
    /// again.
    ///
    /// The ServiceAccount half. The pod spec says nothing about automount, so
    /// the account's `false` applies, and the container passes `--apiserver`
    /// anyway.
    #[test]
    fn the_token_fixture_fails_on_that_rule_and_no_other() {
        let codes = codes_for("crates/ferrum-testkit/fixtures/deploy-bad-token");
        assert_eq!(codes, code_set([LABEL_SOURCE_UNJOINED].as_slice()));
    }

    /// The pod-spec half, against the shipped admission Deployment with that
    /// one line flipped — which is byte for byte the tree this repository
    /// shipped until the manifest beside this rule was fixed. `cluster_wide()`
    /// succeeds regardless (it reads `KUBERNETES_SERVICE_HOST` and nothing
    /// else), the watcher spawns, and `token()` fails on every connect behind
    /// a backoff: `is_warm()` never becomes true and every Pod a
    /// selector-bearing policy selects is denied, forever.
    #[test]
    fn an_apiserver_watch_without_a_projected_token_is_a_finding() {
        let dir = admission_tree_with("no-token", |raw| {
            raw.replace(
                "automountServiceAccountToken: true",
                "automountServiceAccountToken: false",
            )
        });
        assert_eq!(codes_in(&dir), code_set([LABEL_SOURCE_UNJOINED].as_slice()));
        let _ = fs::remove_dir_all(&dir);
    }

    /// Kubernetes' precedence, not this lint's: a pod-level `true` overrides
    /// the account, so the same `false` that is a finding in the fixture is
    /// not one here. Reading the two fields as an `||` would report a defect
    /// the cluster does not have.
    #[test]
    fn a_pod_level_automount_overrides_the_account() {
        let dir = admission_tree_with("pod-overrides-account", |raw| {
            if raw.contains("kind: ServiceAccount") {
                raw.replace(
                    "automountServiceAccountToken: true",
                    "automountServiceAccountToken: false",
                )
            } else {
                raw
            }
        });
        assert!(codes_in(&dir).is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    /// The mirror. The token is projected and nothing reads it: the container
    /// names a policy carrying a `namespaceSelector` and no watch at all, so
    /// the labels that selector is resolved against are never fetched. Either
    /// half alone is a manifest whose two lines contradict.
    #[test]
    fn a_selector_bearing_policy_with_no_label_source_is_a_finding() {
        let dir = tree_beside_policies(
            "no-label-source",
            &shipped("policies/examples/prod-restricted.yaml"),
            "deployment.yaml",
            &shipped("deploy/admission/deployment.yaml").replace("            - --apiserver\n", ""),
        );
        assert_eq!(codes_in(&dir), code_set([LABEL_SOURCE_UNJOINED].as_slice()));
        let _ = fs::remove_dir_all(dir.parent().expect("root"));
    }

    /// A policy whose selector needs no labels puts nobody in scope: the same
    /// manifest, against a policy with the `namespaceSelector` taken out, is
    /// clean. Without this the mirror would be a rule that fires on every
    /// `--policy-name`.
    #[test]
    fn a_policy_without_a_selector_needs_no_label_source() {
        let policy = shipped("policies/examples/prod-restricted.yaml").replace(
            "    namespaceSelector:\n      matchExpressions:\n        - key: ferrum.io/zone\n          operator: In\n          values: [pci, secrets]\n",
            "",
        );
        assert!(!policy.contains("namespaceSelector"), "policy edit missed");
        let dir = tree_beside_policies(
            "selectorless-policy",
            &policy,
            "deployment.yaml",
            &shipped("deploy/admission/deployment.yaml").replace("            - --apiserver\n", ""),
        );
        assert!(codes_in(&dir).is_empty());
        let _ = fs::remove_dir_all(dir.parent().expect("root"));
    }

    /// The bypass this rule must not have. `--node` is what scopes the agent's
    /// pod watch, and `parse_flags` keeps the last one: an argv naming a node
    /// and then naming none runs with none, so the watch this manifest appears
    /// to open does not exist. A lint that looked for the string `--node` in
    /// the args array — rather than reading the value through `container_flag`
    /// — would see it present and print ok, which is the FD024/FD018 defect
    /// exactly.
    #[test]
    fn the_last_node_is_the_one_watched() {
        let dir = tree_beside_policies(
            "dup-node",
            &shipped("policies/examples/prod-restricted.yaml"),
            "daemonset.yaml",
            &shipped("deploy/agent/daemonset.yaml").replace(
                "            - --node\n            - $(NODE_NAME)\n",
                "            - --node\n            - $(NODE_NAME)\n            - --node\n",
            ),
        );
        assert_eq!(
            codes_in(&dir),
            code_set([LABEL_SOURCE_UNJOINED, DUPLICATE_JOINED_FLAG].as_slice())
        );
        let _ = fs::remove_dir_all(dir.parent().expect("root"));
    }

    /// The agent reaches the apiserver by `--node`, not `--apiserver`, and it
    /// needs the token for the same reason: without it `spawn_cgroup_refresh`
    /// gets no pod metadata, the cgroup index stays empty and no event is ever
    /// flagged as a container. A rule that knew only about the webhook would
    /// be right once.
    #[test]
    fn the_agents_pod_watch_needs_the_same_token() {
        let dir = agent_tree_with("agent-no-token", |raw| {
            raw.replace(
                "automountServiceAccountToken: true",
                "automountServiceAccountToken: false",
            )
        });
        assert_eq!(codes_in(&dir), code_set([LABEL_SOURCE_UNJOINED].as_slice()));
        let _ = fs::remove_dir_all(&dir);
    }

    /// `--node` with no value names no node: `from_service_account` refuses an
    /// empty one, and the HOSTNAME fallback behind it scopes the watch to a
    /// node that does not exist. So it is not a label source, and it does not
    /// pull the container into the token half either.
    #[test]
    fn an_empty_node_flag_is_not_a_label_source() {
        let argv = |args: &[&str]| args.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(label_source(&argv(&["--node", "node-1"])), Some(NODE_FLAG));
        assert_eq!(label_source(&argv(&["--node"])), None);
        assert_eq!(label_source(&argv(&["--node", "--bundle", "/b"])), None);
        // An `--apiserver` with no value is the documented in-cluster default,
        // not an absent flag: `label_source` in ferrum-admission only
        // overrides host/port when the value is non-empty.
        assert_eq!(label_source(&argv(&["--apiserver"])), Some(APISERVER_FLAG));
        assert_eq!(label_source(&argv(&["--bundle", "/b"])), None);
    }

    /// Only a selector that actually needs labels counts.
    #[test]
    fn an_empty_selector_needs_no_labels() {
        let selector = |yaml: &str| serde_yaml::from_str::<Value>(yaml).unwrap();
        assert!(selector_is_nonempty(&selector(
            "matchExpressions:\n  - key: ferrum.io/zone\n    operator: Exists\n"
        )));
        assert!(selector_is_nonempty(&selector(
            "matchLabels:\n  tier: prod\n"
        )));
        assert!(!selector_is_nonempty(&selector("matchLabels: {}\n")));
        assert!(!selector_is_nonempty(&selector("matchExpressions: []\n")));
    }

    /// The lint's argv reader must agree with `parse_flags` in
    /// `crates/ferrum-agent/src/main.rs` on every shape that function handles,
    /// not only on the duplicate: a value is never taken from an argument that
    /// itself starts with `--`, and a consumed value is not re-read as a flag.
    #[test]
    fn the_argv_reader_mirrors_the_agents_parse_flags() {
        let argv = |args: &[&str]| args.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let cases: [(&[&str], &str, Option<&str>); 7] = [
            (&["--role", "respond"], "--role", Some("respond")),
            (&["--role=respond"], "--role", Some("respond")),
            (&["--role", "--bundle", "/b"], "--role", Some("")),
            (&["--role"], "--role", Some("")),
            (&["--role="], "--role", Some("")),
            (&["--bundle", "--role"], "--role", Some("")),
            (&["--bundle", "/etc/role"], "--role", None),
        ];
        for (args, flag, want) in cases {
            assert_eq!(
                container_flag(&argv(args), flag).as_deref(),
                want,
                "{args:?} {flag}"
            );
        }
        // A value is consumed, so it cannot open a second occurrence of the
        // flag it belongs to.
        let parsed = parse_argv(&argv(&["--bundle", "--role", "--role", "respond"]));
        assert_eq!(parsed.get("role"), Some(&(2usize, "respond".to_string())));
        assert_eq!(parsed.get("bundle"), Some(&(1usize, String::new())));
    }

    /// A policy name checked against nothing is not a join. FD024 is a
    /// finding on an unverifiable one, never a warning: that is what FD005
    /// and FD022 were each added to stop being.
    #[test]
    fn a_policy_name_with_no_resolvable_bundle_secret_is_a_finding() {
        let dir = agent_tree_with("no-bundle-secret", |raw| {
            raw.replace(
                "          secret:\n            secretName: ferrum-bundle-cluster-prod-restricted\n            optional: true",
                "          emptyDir: {}",
            )
        });
        assert_eq!(
            codes_in(&dir),
            [POLICY_NAME_UNJOINED]
                .iter()
                .map(|c| c.to_string())
                .collect::<BTreeSet<_>>()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bundle_secret_names_its_policy_in_both_scopes() {
        assert!(secret_names_policy(
            "ferrum-bundle-cluster-prod-restricted",
            "prod-restricted"
        ));
        assert!(secret_names_policy(
            "ferrum-bundle-ns-payments-prod-restricted",
            "prod-restricted"
        ));
        // A policy whose name merely ends the same way is not the same policy.
        assert!(!secret_names_policy(
            "ferrum-bundle-cluster-staging-restricted",
            "restricted"
        ));
        assert!(!secret_names_policy(
            "ferrum-bundle-ns-payments-prod-restricted",
            "payments-prod-restricted"
        ));
        assert!(!secret_names_policy(
            "ferrum-bundle-prod-restricted",
            "prod-restricted"
        ));
        assert!(!secret_names_policy("some-other-secret", "prod-restricted"));
    }

    /// The key `gen-webhook-pki` writes is what the ignore rules have to cover;
    /// the lint only catches it once it is already on disk.
    #[test]
    fn the_deploy_ignore_rules_cover_the_ca_key() {
        let raw = fs::read_to_string(repo_path("deploy/admission/.gitignore"))
            .expect("deploy/admission/.gitignore");
        let rules: BTreeSet<&str> = raw
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        for rule in [crate::gen_pki::CA_KEY_FILE, "*.key"] {
            assert!(rules.contains(rule), "{rule} is not ignored: {rules:?}");
        }
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

    fn issued(days: u64) -> (String, String) {
        use std::time::SystemTime;
        let not_after = SystemTime::now() + Duration::from_secs(days * 86_400);
        let ca = ferrum_crypto::x509::issue_ca("ferrum-admission-ca", not_after).unwrap();
        let serving =
            ferrum_crypto::x509::issue_serving_cert(&ca, "ferrum-admission", "ferrum", not_after)
                .unwrap();
        (ca.cert_pem, serving.cert_pem)
    }

    /// The pair a finished install has on disk: the rendered webhook plus the
    /// Secret `gen-webhook-pki` wrote next to it.
    fn pki_docs(ca_pem: &str, leaf_pem: &str) -> Vec<Doc> {
        let bundle = ferrum_crypto::x509::base64_encode(ca_pem.as_bytes());
        let crt = ferrum_crypto::x509::base64_encode(leaf_pem.as_bytes());
        [
            format!(
                "kind: ValidatingWebhookConfiguration\nwebhooks:\n  - name: policy.ferrum.io\n    \
                 clientConfig:\n      service:\n        name: ferrum-admission\n      \
                 caBundle: {bundle}\n"
            ),
            format!(
                "kind: Secret\nmetadata:\n  name: ferrum-admission-tls\n\
                 type: kubernetes.io/tls\ndata:\n  tls.crt: {crt}\n"
            ),
        ]
        .iter()
        .map(|yaml| Doc {
            file: "issued.yaml".into(),
            base: true,
            template: false,
            value: serde_yaml::from_str(yaml).unwrap(),
        })
        .collect()
    }

    fn doc_from(yaml: &str) -> Doc {
        Doc {
            file: "issued.yaml".into(),
            base: true,
            template: false,
            value: serde_yaml::from_str(yaml).unwrap(),
        }
    }

    fn webhook_doc(namespace: &str, ca_pem: &str) -> Doc {
        let bundle = ferrum_crypto::x509::base64_encode(ca_pem.as_bytes());
        doc_from(&format!(
            "kind: ValidatingWebhookConfiguration\nwebhooks:\n  - name: policy.ferrum.io\n    \
             clientConfig:\n      service:\n        name: ferrum-admission\n        \
             namespace: {namespace}\n      caBundle: {bundle}\n"
        ))
    }

    fn secret_doc(namespace: &str, leaf_pem: &str) -> Doc {
        let crt = ferrum_crypto::x509::base64_encode(leaf_pem.as_bytes());
        doc_from(&format!(
            "kind: Secret\nmetadata:\n  name: ferrum-admission-tls\n  namespace: {namespace}\n\
             type: kubernetes.io/tls\ndata:\n  tls.crt: {crt}\n"
        ))
    }

    /// Two installations in one tree. The webhook is served by the Secret in
    /// its own Service's namespace; comparing its caBundle against the other
    /// one's leaf reports a mismatch that does not exist.
    #[test]
    fn the_secret_is_matched_in_the_webhook_service_namespace() {
        let (ca, leaf) = issued(365);
        let (other_ca, other_leaf) = issued(365);
        let docs = vec![
            secret_doc("staging", &other_leaf),
            secret_doc("ferrum", &leaf),
            webhook_doc("ferrum", &ca),
        ];
        let findings = pki_findings(&docs);
        assert!(
            findings.is_empty(),
            "{}",
            findings.first().map(|f| f.msg.clone()).unwrap_or_default()
        );
        // The other installation is still checked, against its own Secret.
        let swapped = vec![
            secret_doc("staging", &leaf),
            secret_doc("ferrum", &leaf),
            webhook_doc("staging", &other_ca),
        ];
        assert_eq!(pki_findings(&swapped).len(), 1);
    }

    fn pki_findings(docs: &[Doc]) -> Vec<Finding> {
        let mut findings = Vec::new();
        check_webhook_pki(docs, &mut findings);
        assert!(findings.iter().all(|f| f.code == WEBHOOK_PKI_MISMATCH));
        findings
    }

    #[test]
    fn issued_material_matching_the_ca_bundle_passes() {
        let (ca, leaf) = issued(365);
        let findings = pki_findings(&pki_docs(&ca, &leaf));
        assert!(
            findings.is_empty(),
            "{}",
            findings.first().map(|f| f.msg.clone()).unwrap_or_default()
        );
    }

    /// The failure that is only visible in production today: the webhook is
    /// applied with one CA and the Secret holds a leaf from another.
    #[test]
    fn a_ca_bundle_that_does_not_match_the_secret_is_a_finding() {
        let (_ca, leaf) = issued(365);
        let (other_ca, _other_leaf) = issued(365);
        let findings = pki_findings(&pki_docs(&other_ca, &leaf));
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].msg.contains("does not match"),
            "{}",
            findings[0].msg
        );
    }

    #[test]
    fn material_inside_the_rotation_window_is_a_finding() {
        let (ca, leaf) = issued(SERVING_CERT_WARN_DAYS / 2);
        let findings = pki_findings(&pki_docs(&ca, &leaf));
        assert_eq!(findings.len(), 2, "the CA and the leaf are both expiring");
        assert!(findings.iter().all(|f| f.msg.contains("expires within")));
    }

    /// No issued material next to the manifests: the rule has nothing to check
    /// and must not invent a finding for the committed tree.
    #[test]
    fn a_tree_without_issued_material_is_not_a_finding() {
        let docs = vec![pki_docs(&issued(365).0, &issued(365).1).remove(0)];
        assert!(pki_findings(&docs).is_empty());
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
        check_webhook_pki(&docs, &mut findings);
        let codes: BTreeSet<&str> = findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(WEBHOOK_SIDE_EFFECTS));
        assert!(codes.contains(WEBHOOK_TIMEOUT));
        assert!(codes.contains(WEBHOOK_FAILURE_POLICY));
        assert!(codes.contains(WEBHOOK_NAMESPACE_SELECTOR));
    }
}
