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
const OPTIONAL_REQUIRED_MOUNT: &str = "FD028";
const UNREADABLE_VOLUME_MODE: &str = "FD029";

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

/// The one directory every client in this workspace reads a ServiceAccount
/// token from. Mirrors `SERVICE_ACCOUNT_DIR` in
/// `crates/ferrum-k8smeta/src/watch.rs`, where `ApiserverConfig` joins `token`
/// onto it and opens nothing else; change both together.
///
/// The path is load-bearing and not decoration: a pod may project a token into
/// any directory it likes, and one projected at `/var/run/secrets/tokens` is a
/// file no binary in this product ever opens. So it is the mount path, not the
/// existence of a projection, that says whether the watch has a credential.
const SERVICE_ACCOUNT_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

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
    check_label_source(&docs, &roles, dir, &mut findings);
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
                check_optional_required_mount(doc, &owner, spec, container, findings);
                check_volume_readability(doc, &owner, spec, container, findings);
            }
        }
    }
}

/// A tolerance the manifest declares and the binary does not have.
///
/// `optional: true` on a Secret or ConfigMap volume is a statement to kubelet:
/// start the Pod with the mount empty if the object is absent. It is the right
/// answer for a file the process treats as absent-is-fine, and it is a lie
/// about a file the process cannot start without — and the two are written far
/// apart, the tolerance in `volumes:` and the requirement in the binary that
/// the argv above names.
///
/// Both agent manifests and the webhook's Deployment carried it on the bundle
/// mount while all three binaries `exit(2)` on a bundle they cannot load. The
/// result is not a missing file: kubelet starts the Pod, the process exits,
/// and the whole install CrashLoopBackOffs until a human creates the Secret —
/// with `failurePolicy: Fail` on the webhook denying every Pod outside
/// `ferrum` and `kube-system` throughout, and readiness being a TCP connect,
/// so nothing reports the cause. Without the tolerance kubelet leaves the Pod
/// in `ContainerCreating` and `kubectl describe` names the Secret it is
/// waiting for: the same failure, said once, in the place an operator looks.
///
/// A finding rather than a warning, on the project's own rule: nothing else
/// in the tree can catch it. Both cycle-11 slices removed the three instances
/// by hand, which is a repair with no gate under it.
///
/// The rule is the requirement, not the file name. It reads the container's
/// own argv for a flag whose value the process must be able to open, follows
/// that path to the volume that serves it, and refuses a tolerance declared
/// there. A volume serving a path the binary genuinely tolerates — the
/// webhook's `--exceptions`, whose absent arm starts with an empty waiver
/// list on purpose, the agent's `--lkg-dir` and `--export-dir` — is not a
/// finding and must not become one: `optional: true` is the honest declaration
/// for those, and a rule that refused them would push the tree toward the less
/// accurate manifest.
fn check_optional_required_mount(
    doc: &Doc,
    owner: &str,
    spec: &Value,
    container: &Value,
    findings: &mut Vec<Finding>,
) {
    let argv = argv_of(container);
    let cname = container
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("<unnamed>");
    for (flag, consequence) in REQUIRED_PATH_FLAGS {
        let Some(path) = container_flag(&argv, flag).filter(|p| !p.is_empty()) else {
            continue;
        };
        let Some((mount_path, volume)) = volume_serving(spec, container, &path) else {
            continue;
        };
        let Some(source) = declared_optional(volume) else {
            continue;
        };
        findings.push(Finding {
            code: OPTIONAL_REQUIRED_MOUNT,
            file: doc.file.clone(),
            msg: format!(
                "{owner} container '{cname}' passes {flag} {path}, served by the volume mounted \
                 at {mount_path}, and that volume declares the {source} `optional: true`. {consequence} \
                 So the manifest promises a tolerance the process does not have: kubelet starts \
                 the Pod with an empty mount, the process exits, and the Pod CrashLoopBackOffs \
                 until a human creates the object. Without `optional: true` it stays in \
                 ContainerCreating with the missing object named on it"
            ),
        });
    }
}

/// A path with its trailing slashes removed, so `/etc/ferrum/bundle/` and
/// `/etc/ferrum/bundle` are one directory. Root stays `/`.
///
/// Both sides need it. `mountPath: /etc/ferrum/bundle/` is legal Kubernetes and
/// names the same mount, while `--bundle /etc/ferrum/bundle` is the argv this
/// tree ships. Unnormalised, `path == at` is false and so is
/// `starts_with("{at}/")`, so the mount resolves to nothing and FD028 misses a
/// manifest that declares the bundle Secret optional — the finding that rule
/// exists for, silenced by one character.
fn normalised_path(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/"
    } else {
        trimmed
    }
}

/// The volume that serves `path` in this container, and the mount path it
/// arrives on.
///
/// Longest matching mount wins, which is Kubernetes' own resolution: a
/// container may mount `/etc/ferrum` and `/etc/ferrum/tls`, and a file under
/// the second is served by the second. Length is compared on the normalised
/// form, so a trailing slash cannot make one mount win over a longer one.
/// A file the process cannot open, promised by the manifest that mounts it.
///
/// kubelet writes a Secret or ConfigMap volume as root:root and applies
/// `defaultMode` verbatim; the group is changed to `fsGroup` only when the Pod
/// declares one. So a mode with no world bits, under a `runAsUser` that is not
/// 0 and with no `fsGroup`, is a file the container cannot read — and the
/// tighter the mode looks, the more certainly it is broken. The controller
/// shipped exactly that: `defaultMode: 0400` on the bundle signing key under
/// `runAsUser: 65532`, so `/etc/ferrum/signing/seed` was root-only and the
/// process that has to read it is not root. Nothing in the tree could catch
/// it: the flags are right, the mount is right, the file is there, and the
/// open fails at runtime on a cluster.
///
/// The rule is the whole class rather than that one file, and it is checked
/// against *both* readings of the literal, because the two readers of this
/// tree disagree about it. `defaultMode: 0400` is 256 to a YAML 1.1 parser
/// (kubectl, client-go — leading zero means octal) and 400 to a YAML 1.2 one
/// (`serde_yaml`, this lint — leading zeros are decimal). A manifest whose
/// meaning depends on which parser applies it is already a finding, so a mode
/// that is unreadable under either reading is reported under the same code:
/// writing it in plain decimal (`288` for `0440`) is the one form both agree
/// on.
fn check_volume_readability(
    doc: &Doc,
    owner: &str,
    spec: &Value,
    container: &Value,
    findings: &mut Vec<Finding>,
) {
    let Some(uid) = effective_run_as_user(spec, container).filter(|uid| *uid != 0) else {
        // Running as root, or as whatever uid the image declares: this rule
        // has nothing it can prove.
        return;
    };
    let fs_group = pod_security_context(spec)
        .and_then(|c| c.get("fsGroup"))
        .and_then(Value::as_i64);
    let cname = container
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("<unnamed>");
    for mount in seq(container, "volumeMounts") {
        let Some(vname) = mount.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(volume) = seq(spec, "volumes")
            .iter()
            .find(|v| v.get("name").and_then(Value::as_str) == Some(vname))
        else {
            continue;
        };
        let at = mount
            .get("mountPath")
            .and_then(Value::as_str)
            .unwrap_or("<no mountPath>");
        for (source, written, readings) in declared_modes(volume) {
            let unreadable: Vec<String> = readings
                .iter()
                .filter(|mode| !readable_by(**mode, fs_group.is_some()))
                .map(|mode| format!("0o{mode:o}"))
                .collect();
            if unreadable.is_empty() {
                continue;
            }
            findings.push(Finding {
                code: UNREADABLE_VOLUME_MODE,
                file: doc.file.clone(),
                msg: format!(
                    "{owner} container '{cname}' mounts volume '{vname}' at {at} whose {source} \
                     is {written} — {} to this parser and to the one that applies the file — and \
                     the Pod runs as uid {uid}{}. kubelet writes those files root:root and moves \
                     the group only for an fsGroup, so this uid is left with the `other` bits, \
                     which are empty: the process cannot open the file it is mounted for. Give \
                     the Pod `fsGroup: {uid}` and a group-readable mode, and write that mode in \
                     plain decimal — 0440 is 288 — because a leading zero is octal to the YAML \
                     1.1 parser that applies this manifest and not an integer at all to a 1.2 \
                     one",
                    unreadable.join(" or "),
                    match fs_group {
                        Some(g) => format!(" with fsGroup {g}"),
                        None => " with no fsGroup".to_string(),
                    }
                ),
            });
        }
    }
}

fn pod_security_context(spec: &Value) -> Option<&Value> {
    spec.get("securityContext")
}

/// The uid the container actually runs as: its own `runAsUser` if it sets one,
/// otherwise the Pod's.
fn effective_run_as_user(spec: &Value, container: &Value) -> Option<i64> {
    container
        .get("securityContext")
        .and_then(|c| c.get("runAsUser"))
        .and_then(Value::as_i64)
        .or_else(|| {
            pod_security_context(spec)
                .and_then(|c| c.get("runAsUser"))
                .and_then(Value::as_i64)
        })
}

/// Every file mode this volume declares: the source, the literal as written,
/// and every mode that literal can mean.
fn declared_modes(volume: &Value) -> Vec<(String, String, Vec<u32>)> {
    let mut out = Vec::new();
    let mut from = |label: &str, source: &Value| {
        if let Some(mode) = source.get("defaultMode").and_then(mode_readings) {
            out.push((format!("{label} defaultMode"), mode.0, mode.1));
        }
        for item in seq(source, "items") {
            if let Some(mode) = item.get("mode").and_then(mode_readings) {
                let key = item.get("key").and_then(Value::as_str).unwrap_or("<item>");
                out.push((format!("{label} item '{key}' mode"), mode.0, mode.1));
            }
        }
    };
    for (key, label) in [("secret", "Secret"), ("configMap", "ConfigMap")] {
        if let Some(source) = volume.get(key) {
            from(label, source);
        }
    }
    if let Some(projected) = volume.get("projected") {
        from("projected", projected);
        for source in seq(projected, "sources") {
            for (key, label) in [
                ("secret", "projected Secret"),
                ("configMap", "projected ConfigMap"),
            ] {
                if let Some(source) = source.get(key) {
                    from(label, source);
                }
            }
        }
    }
    out
}

/// The literal as written, and every mode it can mean.
///
/// `0400` is not one value in this file, it is two and a half. To the YAML 1.1
/// parser that applies the manifest (kubectl, client-go) it is octal 256. To
/// the YAML 1.2 parser reading it here it is not an integer at all — leading
/// zeros are not decimal ints in the core schema — so it arrives as the string
/// `"0400"`, which is a type the API server rejects outright from any client
/// that sends it on. Both readings are returned and both have to be readable:
/// a mode whose value depends on who parses the file is a finding under either
/// answer. A mode written in plain decimal (288 for 0440) has exactly one
/// reading, which is why the message asks for that form.
fn mode_readings(value: &Value) -> Option<(String, Vec<u32>)> {
    let (written, mut readings) = match value {
        Value::Number(n) => {
            let as_written = u32::try_from(n.as_i64()?).ok()?;
            (as_written.to_string(), vec![as_written])
        }
        Value::String(s) => (s.clone(), s.trim().parse::<u32>().into_iter().collect()),
        _ => return None,
    };
    // The same digits read as octal: what a YAML 1.1 parser does with the
    // leading zero this one could not read as a number.
    if let Ok(as_octal) = u32::from_str_radix(written.trim().trim_start_matches('0'), 8) {
        if !readings.contains(&as_octal) {
            readings.push(as_octal);
        }
    }
    (!readings.is_empty()).then_some((written, readings))
}

/// kubelet gives the container's uid the `other` bits, and the `group` bits
/// only when the Pod declares an `fsGroup`.
fn readable_by(mode: u32, has_fs_group: bool) -> bool {
    mode & 0o004 != 0 || (has_fs_group && mode & 0o040 != 0)
}

fn volume_serving<'a>(
    spec: &'a Value,
    container: &'a Value,
    path: &str,
) -> Option<(String, &'a Value)> {
    let path = normalised_path(path);
    let mount = seq(container, "volumeMounts")
        .iter()
        .filter_map(|m| {
            let at = normalised_path(m.get("mountPath").and_then(Value::as_str)?);
            let serves = at == "/" || path == at || path.starts_with(&format!("{at}/"));
            serves.then_some((at, m.get("name").and_then(Value::as_str)?))
        })
        .max_by_key(|(at, _)| at.len())?;
    let volume = seq(spec, "volumes")
        .iter()
        .find(|v| v.get("name").and_then(Value::as_str) == Some(mount.1))?;
    Some((mount.0.to_string(), volume))
}

/// The volume source that declares itself optional, if any.
///
/// `projected` is read too: a projected Secret marked optional is the same
/// statement written one level in, and the token projections this tree already
/// carries are projected volumes.
fn declared_optional(volume: &Value) -> Option<&'static str> {
    for (key, label) in [("secret", "Secret"), ("configMap", "ConfigMap")] {
        if volume
            .get(key)
            .and_then(|s| s.get("optional"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            return Some(label);
        }
    }
    for source in seq(volume.get("projected")?, "sources") {
        for (key, label) in [
            ("secret", "projected Secret"),
            ("configMap", "projected ConfigMap"),
        ] {
            if source
                .get(key)
                .and_then(|s| s.get("optional"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                return Some(label);
            }
        }
    }
    None
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
        // Both sides normalised, for the reason on `normalised_path`: a
        // trailing slash on either the mountPath or the hostPath names the
        // same tracefs directory, and comparing raw strings made this rule
        // report a missing mount about a manifest that has one.
        let path = normalised_path(path);
        TRACEFS_ROOTS.contains(&path)
            && mounted_host_path(spec, container, path).is_some_and(|(host, kind)| {
                normalised_path(&host) == path && kind.as_deref() == Some(HOST_PATH_DIRECTORY)
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
        (normalised_path(m.get("mountPath").and_then(Value::as_str)?)
            == normalised_path(mount_path))
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
/// - The third case, which the two flags cannot reach: a pod whose
///   ServiceAccount this tree *grants RBAC to* and into which no token is
///   projected at all. `--apiserver` and `--node` are the two workloads this
///   rule knew about, and "a rule that knows about one workload is a rule that
///   will be right once" applies to the flag names as much as to the workload
///   names — `deploy/controller/deployment.yaml` passes neither, and its whole
///   job is reconcile-compile-rollout against the API server while it mounts
///   the bundle signing key. A workload with no token authenticates as
///   `system:anonymous`: every request the grant covers is refused, and the
///   grant itself becomes a claim about an identity nothing uses. The trigger
///   is therefore read out of the tree's own RBAC rather than out of a list of
///   flags this file would have to keep up to date.
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
fn check_label_source(
    docs: &[Doc],
    roles: &BTreeMap<String, &Value>,
    dir: &Path,
    findings: &mut Vec<Finding>,
) {
    let granted = granted_service_accounts(docs, roles);
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
        // Whether the flag half already reported this pod. The RBAC half below
        // is a strictly weaker claim about the same missing file, so reporting
        // both would print one defect twice.
        let mut flagged = false;
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
                        if let Err(why) = token_projected(doc, spec, Some(container), docs) {
                            flagged = true;
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

        if flagged {
            continue;
        }
        let sa = spec
            .get("serviceAccountName")
            .and_then(Value::as_str)
            .unwrap_or("");
        // An empty one is FD014's finding, and the namespace default projects
        // a token anyway; naming an account this tree grants nothing is not a
        // claim about the apiserver at all.
        let Some(binding) = granted.get(sa) else {
            continue;
        };
        if let Err(why) = token_projected(doc, spec, None, docs) {
            findings.push(Finding {
                code: LABEL_SOURCE_UNJOINED,
                file: doc.file.clone(),
                msg: format!(
                    "{owner} runs as ServiceAccount '{sa}', which {binding} grants RBAC in this \
                     tree, but {why}. Without a token the pod authenticates as system:anonymous \
                     and every request that grant covers is refused: the grant describes an \
                     identity no container in this pod can present"
                ),
            });
        }
    }
}

/// Every ServiceAccount this tree grants RBAC to, and the binding that does it.
///
/// A grant counts when the roleRef resolves here to a Role or ClusterRole that
/// carries at least one rule, or names one of the built-ins `ALLOWED_EXTERNAL_
/// ROLE_REFS` accepts — those are real grants the API server defines. A roleRef
/// that resolves to nothing is left alone: FD016 is the finding for that, and
/// stacking a second code on it would say the same thing twice. A Role with no
/// rules grants nothing, so a pod with no token contradicts nothing.
fn granted_service_accounts(
    docs: &[Doc],
    roles: &BTreeMap<String, &Value>,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for doc in docs {
        let k = kind(doc);
        if k != "RoleBinding" && k != "ClusterRoleBinding" {
            continue;
        }
        let Some(role_ref) = doc.value.get("roleRef") else {
            continue;
        };
        let key = format!(
            "{}/{}",
            role_ref.get("kind").and_then(Value::as_str).unwrap_or(""),
            role_ref.get("name").and_then(Value::as_str).unwrap_or("")
        );
        let grants = match roles.get(&key) {
            Some(role) => !seq(role, "rules").is_empty(),
            None => ALLOWED_EXTERNAL_ROLE_REFS.contains(&key.as_str()),
        };
        if !grants {
            continue;
        }
        for subject in seq(&doc.value, "subjects") {
            if subject.get("kind").and_then(Value::as_str) != Some("ServiceAccount") {
                continue;
            }
            let Some(sname) = subject.get("name").and_then(Value::as_str) else {
                continue;
            };
            out.entry(sname.to_string())
                .or_insert_with(|| format!("{k}/{} -> {key}", name(doc)));
        }
    }
    out
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

/// The volumes of this pod that project a ServiceAccount token, by name.
///
/// `automountServiceAccountToken: false` beside an explicit
/// `volumes: - projected: { sources: [ { serviceAccountToken: … } ] }` is the
/// hardened *spelling* of a mounted token, not the absence of one: it is how a
/// pod keeps the ambient token out of every container and hands one scoped,
/// short-lived token to the container that needs it. Reading only the automount
/// field would make that tree a finding on an install that works, and — since
/// this code is never a warning — the only way to satisfy the rule would be to
/// turn automount back on, which widens the token's exposure to every container
/// in the pod. A rule that pushes a tree towards the less hardened shape is
/// worse than no rule.
fn projected_token_volumes(spec: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for volume in seq(spec, "volumes") {
        let Some(vname) = volume.get("name").and_then(Value::as_str) else {
            continue;
        };
        let projects_token = volume
            .get("projected")
            .map(|projected| {
                seq(projected, "sources")
                    .iter()
                    .any(|source| source.get("serviceAccountToken").is_some())
            })
            .unwrap_or(false);
        if projects_token {
            out.insert(vname.to_string());
        }
    }
    out
}

/// Whether this container mounts one of those volumes where the code looks.
///
/// Both halves are required. A projection no container mounts is a token in the
/// kubelet's head and nowhere in the filesystem; a projection mounted somewhere
/// other than `SERVICE_ACCOUNT_DIR` is a file this product does not open.
fn mounts_token_at_service_account_dir(container: &Value, volumes: &BTreeSet<String>) -> bool {
    seq(container, "volumeMounts").iter().any(|mount| {
        let named = mount
            .get("name")
            .and_then(Value::as_str)
            .map(|n| volumes.contains(n))
            .unwrap_or(false);
        let at_dir = mount
            .get("mountPath")
            .and_then(Value::as_str)
            .map(|p| p.trim_end_matches('/') == SERVICE_ACCOUNT_DIR)
            .unwrap_or(false);
        named && at_dir
    })
}

/// Whether a ServiceAccount token is projected into this pod, or why it is
/// not.
///
/// An explicit projection mounted at `SERVICE_ACCOUNT_DIR` wins over every
/// automount answer below it, because it is a token file the container can
/// actually open whatever the automount field says. `container` is the one
/// asking: a projection is mounted per container, so the flag half of FD027
/// passes the container whose argv names the watch, and the pod-level half
/// passes `None` and accepts a mount by any container.
///
/// Failing that the precedence is Kubernetes': the pod field wins when it is
/// set, the ServiceAccount's value applies when it is not, and unset on both is
/// a mounted token. A ServiceAccount this tree does not define answers neither
/// way, and an unresolved predicate is not a non-match — the same stance FD016
/// takes on a roleRef it cannot resolve.
fn token_projected(
    doc: &Doc,
    spec: &Value,
    container: Option<&Value>,
    docs: &[Doc],
) -> Result<(), String> {
    let projected = projected_token_volumes(spec);
    if !projected.is_empty() {
        let mounted = match container {
            Some(container) => mounts_token_at_service_account_dir(container, &projected),
            None => ["initContainers", "containers"].iter().any(|key| {
                seq(spec, key)
                    .iter()
                    .any(|c| mounts_token_at_service_account_dir(c, &projected))
            }),
        };
        if mounted {
            return Ok(());
        }
    }
    // Said once and appended to every answer below: without it a pod that
    // projects a token and mounts it in the wrong place is told only that
    // automount is off, which is the one thing about it that is deliberate.
    let unmounted = if projected.is_empty() {
        String::new()
    } else {
        format!(
            " (the pod projects a ServiceAccount token in volume(s) {}, and no volumeMount here \
             puts one at {SERVICE_ACCOUNT_DIR}, which is the only directory this product opens a \
             token from)",
            projected.iter().cloned().collect::<Vec<_>>().join(", ")
        )
    };
    token_from_automount(doc, spec, docs).map_err(|why| format!("{why}{unmounted}"))
}

/// The automount half of the answer above, unchanged: pod field, then account.
fn token_from_automount(doc: &Doc, spec: &Value, docs: &[Doc]) -> Result<(), String> {
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
        (normalised_path(m.get("mountPath").and_then(Value::as_str)?)
            == normalised_path(mount_path))
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

/// Flags whose value is a path the process must be able to open before it can
/// do its job, paired with what the binary does when it cannot — quoted into
/// the finding, because the whole rule is that the manifest and the binary
/// disagree about that sentence.
///
/// Deliberately absent, and this is the argument rather than an oversight:
/// `--exceptions`, `--lkg-dir` and `--export-dir` name paths whose absence
/// every binary here handles on purpose. The webhook starts with an empty
/// waiver list and says so; the agent restores no last-known-good and runs;
/// an export directory that will not open is a degradation reason, not an
/// exit. `optional: true` on a volume serving one of those is the *accurate*
/// declaration, and a rule that refused it would push this tree toward the
/// less honest manifest — the FD027 mistake, which read `automount` and
/// punished the more hardened shape.
const REQUIRED_PATH_FLAGS: [(&str, &str); 5] = [
    (
        "--bundle",
        "A binary handed a bundle it cannot load exits 2 — the agent unless a last-known-good \
         is already on the node, the webhook unconditionally — before the poll loop that would \
         pick a later one up.",
    ),
    (
        "--bpf-elf",
        "An attach build reads this ELF once at startup and dies if it cannot: there is no \
         datapath without it.",
    ),
    (
        "--tls-cert",
        "The webhook loads its serving certificate before it binds and exits 2 if it cannot, \
         and under failurePolicy: Fail a webhook that never serves denies every Pod it gates.",
    ),
    (
        "--tls-key",
        "The webhook loads its serving key before it binds and exits 2 if it cannot, and under \
         failurePolicy: Fail a webhook that never serves denies every Pod it gates.",
    ),
    (
        "--seed-file",
        "The controller loads the bundle signing seed before it reconciles anything and exits \
         if the file is not there, so nothing signs policy at all.",
    ),
];

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

    /// A mounted file the container's uid cannot open is a broken install,
    /// and nothing else in this tree can see it: the flags are right, the
    /// mount is right, the file is there, and `open()` fails on a cluster.
    #[test]
    fn a_volume_mode_the_run_as_user_cannot_read_is_a_finding() {
        let codes = codes_for("crates/ferrum-testkit/fixtures/deploy-bad-volume-mode");
        assert_eq!(
            codes,
            [UNREADABLE_VOLUME_MODE]
                .iter()
                .map(|c| c.to_string())
                .collect::<BTreeSet<_>>()
        );
    }

    /// The arithmetic behind that rule, including the two answers one literal
    /// can have. `0400` is octal 256 to the YAML 1.1 parser that applies a
    /// manifest and a string to the 1.2 parser reading it here; `288` is the
    /// same mode to both, which is why the finding asks for decimal.
    #[test]
    fn a_mode_is_readable_only_through_bits_the_uid_actually_gets() {
        // No fsGroup: the container's uid gets `other` and nothing else.
        assert!(!readable_by(0o400, false));
        assert!(!readable_by(0o440, false));
        assert!(readable_by(0o444, false));
        // With one, the group bits are the container's too.
        assert!(readable_by(0o440, true));
        assert!(!readable_by(0o400, true));

        let ambiguous = mode_readings(&Value::String("0400".into())).expect("readings");
        assert_eq!(ambiguous.0, "0400");
        assert_eq!(ambiguous.1, vec![0o620, 0o400], "decimal 400, then octal");
        let plain = mode_readings(&Value::Number(288.into())).expect("readings");
        assert_eq!(plain.1, vec![0o440], "288 decimal is one mode and only one");
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

    /// The mount written the other legal way, on the rule cycle 11 left
    /// un-normalised.
    ///
    /// `mountPath: /sys/kernel/tracing/` names the directory the agent opens,
    /// and so does `hostPath.path` with the same slash. FD026 compared both
    /// against `TRACEFS_ROOTS` and against each other as raw strings, so a
    /// manifest that mounts tracefs correctly reported an agent that mounts
    /// none, and `lint-deploy` exited 1 on a tree with nothing wrong with it.
    /// The direction that matters: this is a finding fired at a correct
    /// manifest, not one missed on a broken one.
    #[test]
    fn a_trailing_slash_on_the_tracefs_mount_is_not_a_missing_mount() {
        let mount = "              mountPath: /sys/kernel/tracing\n";
        let host = "            path: /sys/kernel/tracing\n";
        let dir = agent_tree_with("tracefs-slash", |raw| {
            assert!(
                raw.contains(mount) && raw.contains(host),
                "the tracefs mount moved"
            );
            raw.replace(mount, "              mountPath: /sys/kernel/tracing/\n")
                .replace(host, "            path: /sys/kernel/tracing/\n")
        });
        assert_eq!(
            codes_in(&dir),
            code_set(&[]),
            "a trailing slash names the same tracefs directory; FD026 must not report a \
             missing mount about a manifest that has one"
        );
        let _ = fs::remove_dir_all(&dir);
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

    /// FD028, against the shipped DaemonSet with the one line put back that
    /// both cycle-11 slices removed by hand. This is byte for byte the tree
    /// this repository shipped: the agent `exit(2)`s on a bundle it cannot
    /// load with no last-known-good beside it, and the manifest told kubelet to
    /// start it anyway.
    const OPTIONAL_BUNDLE_SECRET: (&str, &str) = (
        "        - name: bundle\n          secret:\n            secretName: \
         ferrum-bundle-cluster-prod-restricted\n",
        "        - name: bundle\n          secret:\n            secretName: \
         ferrum-bundle-cluster-prod-restricted\n            optional: true\n",
    );

    #[test]
    fn a_required_mount_declared_optional_is_a_finding() {
        let (plain, tolerant) = OPTIONAL_BUNDLE_SECRET;
        let dir = agent_tree_with("optional-bundle", |raw| {
            assert!(raw.contains(plain), "the bundle volume moved");
            raw.replace(plain, tolerant)
        });
        assert_eq!(
            codes_in(&dir),
            code_set([OPTIONAL_REQUIRED_MOUNT].as_slice())
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The same line on the other plane, and the worse half of it: the webhook
    /// has no last-known-good at all, readiness is a TCP connect so two
    /// CrashLoopBackOff replicas still report Ready, and `failurePolicy: Fail`
    /// denies every Pod outside `ferrum` and `kube-system` while they do.
    /// The same finding, with the mount path written the other legal way.
    ///
    /// Not a second test of the rule: a test of the join between the argv and
    /// the volume, which is where a whole finding used to disappear without a
    /// diff to the rule itself. The exact code set is what makes it two
    /// findings at once — `mounted_secret` compared the same two strings the
    /// same unnormalised way, so the slash also made FD024 report that the
    /// bundle «is not a mounted Secret volume» about a manifest that mounts
    /// one.
    #[test]
    fn a_trailing_slash_on_the_mount_path_does_not_hide_the_finding() {
        let (plain, tolerant) = OPTIONAL_BUNDLE_SECRET;
        let dir = agent_tree_with("optional-bundle-slash", |raw| {
            assert!(raw.contains(plain), "the bundle volume moved");
            let raw = raw.replace(plain, tolerant);
            assert!(
                raw.contains("              mountPath: /etc/ferrum/bundle\n"),
                "the bundle mountPath moved"
            );
            raw.replace(
                "              mountPath: /etc/ferrum/bundle\n",
                "              mountPath: /etc/ferrum/bundle/\n",
            )
        });
        assert_eq!(
            codes_in(&dir),
            code_set([OPTIONAL_REQUIRED_MOUNT].as_slice()),
            "a trailing slash on mountPath names the same directory the agent opens, and \
             the rule must not stop seeing the volume because of it"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_webhooks_bundle_mount_is_the_same_finding() {
        let (plain, tolerant) = OPTIONAL_BUNDLE_SECRET;
        let dir = admission_tree_with("optional-webhook-bundle", |raw| {
            raw.replace(plain, tolerant)
        });
        assert_eq!(
            codes_in(&dir),
            code_set([OPTIONAL_REQUIRED_MOUNT].as_slice())
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Not a rule about the word `bundle`. The serving certificate is a
    /// different volume, named by two different flags, and it is required for
    /// a different reason: `TlsSource::load` runs before the listener binds,
    /// and a webhook that never serves denies every Pod it gates.
    #[test]
    fn an_optional_serving_certificate_is_a_finding_too() {
        let plain = "        - name: tls\n          secret:\n            secretName: ferrum-admission-tls\n";
        let tolerant = "        - name: tls\n          secret:\n            secretName: ferrum-admission-tls\n            optional: true\n";
        let dir = admission_tree_with("optional-tls", |raw| raw.replace(plain, tolerant));
        assert!(
            fs::read_to_string(dir.join("deployment.yaml"))
                .expect("deployment.yaml")
                .contains(tolerant),
            "the tls volume moved and this test edited nothing"
        );
        assert_eq!(
            codes_in(&dir),
            code_set([OPTIONAL_REQUIRED_MOUNT].as_slice())
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The other half, without which this rule would be "no volume may be
    /// optional" — a rule that makes every manifest less accurate.
    ///
    /// `--exceptions` names a mount the webhook genuinely tolerates: the absent
    /// arm starts with an empty waiver list and logs, on purpose, and
    /// `optional: true` on the volume that serves it is the true statement.
    /// Here it is given a volume of its own so that the two flags stop sharing
    /// one mount, and the tree must stay clean.
    #[test]
    fn a_mount_the_binary_tolerates_may_be_optional() {
        let dir = admission_tree_with("optional-waivers", |raw| {
            let moved = raw.replace(
                "            - /etc/ferrum/bundle/exceptions.fsig\n",
                "            - /etc/ferrum/waivers/exceptions.fsig\n",
            );
            let mounted = moved.replace(
                "            - name: bundle\n              mountPath: /etc/ferrum/bundle\n              readOnly: true\n",
                "            - name: bundle\n              mountPath: /etc/ferrum/bundle\n              readOnly: true\n            - name: waivers\n              mountPath: /etc/ferrum/waivers\n              readOnly: true\n",
            );
            let (plain, _) = OPTIONAL_BUNDLE_SECRET;
            mounted.replace(
                plain,
                &format!(
                    "{plain}        - name: waivers\n          secret:\n            secretName: \
                     ferrum-exceptions\n            optional: true\n"
                ),
            )
        });
        let written = fs::read_to_string(dir.join("deployment.yaml")).expect("deployment.yaml");
        assert!(
            written.contains("/etc/ferrum/waivers/exceptions.fsig")
                && written.contains("            optional: true\n"),
            "this test edited nothing, so an empty finding set proves nothing"
        );
        assert!(
            codes_in(&dir).is_empty(),
            "a volume serving a path the binary tolerates must not be a finding: \
             `optional: true` is the accurate declaration there, and a rule that \
             refused it would push this tree toward the less honest manifest"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The resolver under the rule. A container may mount a directory and a
    /// subdirectory of it; the file is served by the longer mount, which is
    /// Kubernetes' own answer and not this lint's convenience. Without this,
    /// `an_optional_serving_certificate_is_a_finding_too` would be equally
    /// satisfied by a resolver that returned the first mount it saw.
    #[test]
    fn a_file_is_served_by_the_longest_mount_that_covers_it() {
        let spec: Value = serde_yaml::from_str(
            "containers:\n  - name: c\n    volumeMounts:\n      - name: outer\n        mountPath: /etc/ferrum\n      - name: inner\n        mountPath: /etc/ferrum/tls\nvolumes:\n  - name: outer\n    secret:\n      secretName: a\n  - name: inner\n    secret:\n      secretName: b\n      optional: true\n",
        )
        .expect("fixture spec");
        let container = &seq(&spec, "containers")[0];
        let (at, volume) =
            volume_serving(&spec, container, "/etc/ferrum/tls/tls.crt").expect("a mount serves it");
        assert_eq!(at, "/etc/ferrum/tls");
        assert_eq!(declared_optional(volume), Some("Secret"));
        // The outer mount still serves what the inner one does not cover, and
        // a prefix that is not a path boundary is not a mount: `/etc/ferrumx`
        // is a different directory.
        let (at, volume) =
            volume_serving(&spec, container, "/etc/ferrum/bundle").expect("the outer mount");
        assert_eq!(at, "/etc/ferrum");
        assert_eq!(declared_optional(volume), None);
        assert!(volume_serving(&spec, container, "/etc/ferrumx/tls.crt").is_none());
    }

    /// The trailing slash, on both sides of the same comparison.
    ///
    /// `mountPath: /etc/ferrum/bundle/` is legal Kubernetes and names the
    /// directory the agent opens as `--bundle /etc/ferrum/bundle`. The resolver
    /// matched `path == at` or `path.starts_with("{at}/")` on unnormalised
    /// strings, and a slash on either side made both false: the mount resolved
    /// to nothing, `check_optional_required_mount` returned before it reached
    /// `declared_optional`, and FD028 missed a bundle Secret declared optional.
    /// One character, and the finding this rule exists for is gone — the same
    /// shape as the manifest line that started this cycle.
    #[test]
    fn a_trailing_slash_names_the_same_directory_on_either_side() {
        let spec: Value = serde_yaml::from_str(
            "containers:\n  - name: c\n    volumeMounts:\n      - name: bundle\n        mountPath: /etc/ferrum/bundle/\n      - name: outer\n        mountPath: /etc/ferrum\nvolumes:\n  - name: bundle\n    secret:\n      secretName: b\n      optional: true\n  - name: outer\n    secret:\n      secretName: a\n",
        )
        .expect("fixture spec");
        let container = &seq(&spec, "containers")[0];
        for path in [
            "/etc/ferrum/bundle",
            "/etc/ferrum/bundle/",
            "/etc/ferrum/bundle/exceptions.fsig",
        ] {
            let (at, volume) = volume_serving(&spec, container, path)
                .unwrap_or_else(|| panic!("{path} is served by the bundle mount"));
            assert_eq!(at, "/etc/ferrum/bundle", "{path}");
            assert_eq!(
                declared_optional(volume),
                Some("Secret"),
                "{path} resolved to the wrong volume, so FD028 would read the tolerance of a \
                 mount the process never opens"
            );
        }
        // Normalising must not make a longer mount lose to a shorter one that
        // only looked longer for its slash.
        let (at, _) = volume_serving(&spec, container, "/etc/ferrum/other").expect("outer mount");
        assert_eq!(at, "/etc/ferrum");
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

    /// The shipped controller Deployment, its ServiceAccount and its RBAC,
    /// with one edit applied to all three.
    fn controller_tree_with(tag: &str, edit: impl Fn(String) -> String) -> PathBuf {
        let dir = tmp_tree(tag);
        for file in ["deployment.yaml", "serviceaccount.yaml", "rbac.yaml"] {
            let raw = fs::read_to_string(repo_path(&format!("deploy/controller/{file}")))
                .unwrap_or_else(|e| panic!("deploy/controller/{file}: {e}"));
            fs::write(dir.join(file), edit(raw)).expect("write manifest");
        }
        dir
    }

    /// The workload the two flags cannot see. `ferrum-controller` passes
    /// neither `--apiserver` nor `--node`; its whole job is reconcile-compile-
    /// rollout against the API server, and it mounts the bundle signing key.
    /// Flip its automount to `false` and every earlier spelling of this rule
    /// printed ok on a Deployment that authenticates as nobody — the rule knew
    /// two flag names, and a rule that knows about one workload is right once.
    #[test]
    fn a_granted_service_account_with_no_projected_token_is_a_finding() {
        let dir = controller_tree_with("controller-no-token", |raw| {
            raw.replace(
                "automountServiceAccountToken: true",
                "automountServiceAccountToken: false",
            )
        });
        assert_eq!(codes_in(&dir), code_set([LABEL_SOURCE_UNJOINED].as_slice()));
        let _ = fs::remove_dir_all(&dir);
    }

    /// The control, and the reason the trigger is the tree's RBAC rather than a
    /// list of workload names: the same Deployment with the same flip, with no
    /// binding beside it, grants nothing to that account and so contradicts
    /// nothing. A rule that fired here would fire on every pod in every tree.
    #[test]
    fn a_service_account_this_tree_grants_nothing_needs_no_token() {
        let dir = tmp_tree("controller-ungranted");
        for file in ["deployment.yaml", "serviceaccount.yaml"] {
            let raw = shipped(&format!("deploy/controller/{file}")).replace(
                "automountServiceAccountToken: true",
                "automountServiceAccountToken: false",
            );
            fs::write(dir.join(file), raw).expect("write manifest");
        }
        assert!(codes_in(&dir).is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A Role that grants no verb is not a grant. Without this the rule above
    /// would be satisfied by the existence of a binding rather than by anything
    /// the identity can do.
    #[test]
    fn a_binding_to_a_ruleless_role_is_not_a_grant() {
        let dir = tmp_tree("controller-ruleless");
        for file in ["deployment.yaml", "serviceaccount.yaml"] {
            let raw = shipped(&format!("deploy/controller/{file}")).replace(
                "automountServiceAccountToken: true",
                "automountServiceAccountToken: false",
            );
            fs::write(dir.join(file), raw).expect("write manifest");
        }
        fs::write(
            dir.join("rbac.yaml"),
            "apiVersion: rbac.authorization.k8s.io/v1\n\
             kind: ClusterRole\n\
             metadata:\n  name: ferrum-controller\n\
             rules: []\n\
             ---\n\
             apiVersion: rbac.authorization.k8s.io/v1\n\
             kind: ClusterRoleBinding\n\
             metadata:\n  name: ferrum-controller\n\
             roleRef:\n\
             \x20 apiGroup: rbac.authorization.k8s.io\n\
             \x20 kind: ClusterRole\n\
             \x20 name: ferrum-controller\n\
             subjects:\n\
             \x20 - kind: ServiceAccount\n\
             \x20   name: ferrum-controller\n\
             \x20   namespace: ferrum\n",
        )
        .expect("write rbac");
        assert!(codes_in(&dir).is_empty(), "{:?}", codes_in(&dir));
        let _ = fs::remove_dir_all(&dir);
    }

    /// The shipped admission Deployment in the shape F5 is about: automount
    /// off, one explicit `projected` ServiceAccount token, mounted by the
    /// container that opens the watch. `mount_path` is the only thing the three
    /// cases below differ by; `None` mounts the projection nowhere.
    fn hardened_admission_tree(tag: &str, mount_path: Option<&str>) -> PathBuf {
        admission_tree_with(tag, |raw| {
            if !raw.contains("kind: Deployment") {
                return raw;
            }
            let mut out = raw.replace(
                "      automountServiceAccountToken: true",
                "      automountServiceAccountToken: false",
            );
            assert!(
                out.contains("automountServiceAccountToken: false"),
                "the automount edit missed"
            );
            if let Some(path) = mount_path {
                out = out.replace(
                    "          volumeMounts:\n",
                    &format!(
                        "          volumeMounts:\n\
                         \x20           - name: sa-token\n\
                         \x20             mountPath: {path}\n\
                         \x20             readOnly: true\n"
                    ),
                );
                assert!(out.contains("name: sa-token"), "the mount edit missed");
            }
            let volumes = "      volumes:\n\
                 \x20       - name: sa-token\n\
                 \x20         projected:\n\
                 \x20           sources:\n\
                 \x20             - serviceAccountToken:\n\
                 \x20                 path: token\n\
                 \x20                 expirationSeconds: 3600\n";
            let out = out.replace("      volumes:\n", volumes);
            assert!(out.contains("projected:"), "the volume edit missed");
            out
        })
    }

    /// The hardened shape is not a finding. Keeping the ambient token out of
    /// every container and handing one scoped, expiring token to the container
    /// that authenticates is the *more* defensive manifest; a rule reading only
    /// `automountServiceAccountToken` called it a hard finding, and since
    /// FD027 is never a warning the only repair on offer was to widen the
    /// token's exposure to the whole pod.
    #[test]
    fn a_projected_token_where_the_code_reads_it_is_not_a_finding() {
        let dir = hardened_admission_tree("projected-ok", Some(SERVICE_ACCOUNT_DIR));
        assert!(codes_in(&dir).is_empty(), "{:?}", codes_in(&dir));
        let _ = fs::remove_dir_all(&dir);
    }

    /// And the path is the check, not the projection. `ApiserverConfig` joins
    /// `token` onto `SERVICE_ACCOUNT_DIR` and opens nothing else, so a token
    /// projected at `/var/run/secrets/tokens` is a file this product never
    /// reads — the same cold cache, arriving by a different route.
    #[test]
    fn a_projected_token_mounted_somewhere_else_is_still_a_finding() {
        let dir = hardened_admission_tree("projected-elsewhere", Some("/var/run/secrets/tokens"));
        assert_eq!(codes_in(&dir), code_set([LABEL_SOURCE_UNJOINED].as_slice()));
        let _ = fs::remove_dir_all(&dir);
    }

    /// A projection no container mounts is a token in the kubelet's head and
    /// nowhere in the filesystem.
    #[test]
    fn a_projected_token_no_container_mounts_is_still_a_finding() {
        let dir = hardened_admission_tree("projected-unmounted", None);
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
                "          secret:\n            secretName: ferrum-bundle-cluster-prod-restricted",
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
        let docs = [Doc {
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
