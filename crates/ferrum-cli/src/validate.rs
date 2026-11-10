use anyhow::{bail, Context, Result};
use chrono::Utc;
use ferrum_api::{
    ClusterSecurityPolicy, ClusterSecurityPolicySpec, ComplianceSnapshot, ComplianceSnapshotSpec,
    FerrumCluster, FerrumClusterSpec, PolicyException, PolicyExceptionSpec, PolicyLibrary,
    PolicyLibrarySpec, PolicyMode, RuntimeAction, RuntimeProfile, RuntimeProfileSpec,
    SecurityPolicy,
};
use ferrum_policy::{
    exception_applies, validate_cluster_policy, validate_exception, validate_namespaced_policy,
};
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
    if is_mitre_mapping_manifest(&raw)? {
        return validate_mitre_mapping_file(path, &raw);
    }
    validate_yaml(&raw)?;
    println!("ok: {}", path.display());
    Ok(())
}

fn is_mitre_mapping_manifest(raw: &str) -> Result<bool> {
    let value: serde_yaml::Value = match serde_yaml::from_str(raw) {
        Ok(value) => value,
        Err(err) => {
            if raw.contains("schemaVersion:") && raw.contains("sourcePolicy:") {
                return Err(err).context("parse MITRE mapping manifest");
            }
            return Ok(false);
        }
    };
    let Some(map) = value.as_mapping() else {
        return Ok(false);
    };
    let has_schema = yaml_key(map, "schemaVersion").is_some();
    let has_source = yaml_key(map, "sourcePolicy").is_some();
    if !has_schema || !has_source {
        return Ok(false);
    }
    match yaml_key(map, "mappings").and_then(serde_yaml::Value::as_sequence) {
        Some(_) => Ok(true),
        None => bail!("MITRE mapping: mappings должен быть списком"),
    }
}

fn yaml_key<'a>(map: &'a serde_yaml::Mapping, key: &str) -> Option<&'a serde_yaml::Value> {
    map.get(serde_yaml::Value::String(key.to_string()))
}

fn validate_mitre_mapping_file(path: &Path, manifest_raw: &str) -> Result<()> {
    // sourcePolicy в манифесте — путь относительно корня репозитория;
    // разрешаем его так же, как шаг Jenkins, а не из cwd вызывающего.
    let manifest_dir = path.parent().unwrap_or(Path::new("."));
    let repo_root = manifest_dir
        .ancestors()
        .find(|d| d.join("policies").is_dir() && d.join("crates").is_dir())
        .unwrap_or(manifest_dir);
    let key: serde_yaml::Value =
        serde_yaml::from_str(manifest_raw).context("parse MITRE mapping manifest")?;
    let source_rel = key
        .get("sourcePolicy")
        .and_then(|v| v.as_str())
        .context("MITRE mapping: нет поля sourcePolicy")?;
    let policy_path = repo_root.join(source_rel);
    let policy_raw = fs::read_to_string(&policy_path)
        .with_context(|| format!("read {}", policy_path.display()))?;
    validate_mitre_mapping(manifest_raw, &policy_raw)?;
    println!("ok: {} (MITRE mapping)", path.display());
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

// Official names for techniques this mapping may cite. T1059.005 is Visual
// Basic and T1525 (Implant Internal Image) has no control here, so both are
// absent. A listed id still may not cite an arbitrary rule.
const ATTACK_CATALOG: &[(&str, &str)] = &[
    ("T1059", "Command and Scripting Interpreter"),
    ("T1609", "Container Administration Command"),
    ("T1610", "Deploy Container"),
    ("T1611", "Escape to Host"),
];

// Schema 1 has no bundle binding. Accepting it would let an unbound file pass.
const MAPPING_SCHEMA_VERSION: u32 = 2;
const PLATFORM_CONTAINERS: &str = "containers";

const CAPABILITY_RUNTIME_OBSERVE: &str = "runtime-observe";
const CAPABILITY_DETECT_THEN_KILL: &str = "detect-then-kill";
const CAPABILITY_ADMIT_DENY: &str = "admit-deny";
const CAPABILITY_SYNCHRONOUS_DENY: &str = "synchronous-deny";

const PROCEDURE_EXEC_COMM_SHELL: &str = "exec-comm-shell";
const PROCEDURE_EXEC_PATH_SUFFIX_RUNTIME_SOCK: &str = "exec-path-suffix-runtime-sock";
const PROCEDURE_TRACEPOINT_BPF_OR_INIT_MODULE: &str = "tracepoint-bpf-or-init-module";
const PROCEDURE_ADMIT_POD_REJECT: &str = "admit-pod-reject";

#[derive(Debug, Deserialize)]
struct MitreMappingManifest {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    #[serde(rename = "bundleDigest")]
    bundle_digest: String,
    mappings: Vec<MitreMappingEntry>,
}

#[derive(Debug, Deserialize)]
struct MitreMappingEntry {
    technique: String,
    name: String,
    platform: String,
    refs: Vec<MitreMappingRef>,
    limits: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MitreMappingRef {
    kind: String,
    path: String,
    capability: String,
    procedure: String,
}

struct MappingClaim<'a> {
    policy_name: &'a str,
    exceptions: &'a [PolicyExceptionSpec],
    admission_suspended: bool,
}

pub(crate) fn validate_mitre_mapping(manifest_raw: &str, policy_raw: &str) -> Result<()> {
    // File validation carries no exceptions and does not verify a grant.
    // `admission_suspended` stays false unless a caller arms it.
    validate_mitre_binding(manifest_raw, policy_raw, &[], false)
}

pub(crate) fn validate_mitre_binding(
    manifest_raw: &str,
    policy_raw: &str,
    exceptions: &[PolicyExceptionSpec],
    admission_suspended: bool,
) -> Result<()> {
    let manifest: MitreMappingManifest =
        serde_yaml::from_str(manifest_raw).context("parse MITRE mapping manifest")?;
    if manifest.schema_version != MAPPING_SCHEMA_VERSION {
        bail!(
            "MITRE mapping: schemaVersion {} не поддерживается (живой: {MAPPING_SCHEMA_VERSION})",
            manifest.schema_version
        );
    }
    require_digest_format(&manifest.bundle_digest)?;
    if manifest.mappings.is_empty() {
        bail!("MITRE mapping: пустой список mappings");
    }
    let obj: ClusterSecurityPolicy = parse_resource(policy_raw, ClusterSecurityPolicy::new)?;
    validate_cluster_policy(&obj.spec).map_err(anyhow::Error::from)?;
    // Digest is CompiledBundle.digest. A mismatch refuses the mapping and
    // does not rewrite the policy or the bundle.
    let compiled = ferrum_compiler::compile_cluster_policy(&obj.spec)
        .map_err(anyhow::Error::from)
        .context("MITRE mapping: compile sourcePolicy не удался")?;
    if compiled.digest.as_str() != manifest.bundle_digest {
        bail!(
            "MITRE mapping: bundleDigest {} не равен digest скомпилированного bundle {}",
            manifest.bundle_digest,
            compiled.digest.as_str()
        );
    }
    let spec_json = serde_json::json!({
        "spec": serde_json::to_value(&obj.spec).context("serialize ClusterSecurityPolicy spec")?,
    });
    let claim = MappingClaim {
        policy_name: &obj.metadata.name,
        exceptions,
        admission_suspended,
    };

    for entry in &manifest.mappings {
        check_mapping_entry(&obj.spec, &spec_json, &claim, entry)?;
    }
    Ok(())
}

fn require_digest_format(claimed: &str) -> Result<()> {
    if claimed.is_empty() {
        bail!("MITRE mapping: bundleDigest обязателен");
    }
    if !is_lowercase_sha256_hex(claimed) {
        bail!("MITRE mapping: bundleDigest должен быть 64 lowercase hex, получено {claimed:?}");
    }
    Ok(())
}

fn is_lowercase_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn check_mapping_entry(
    spec: &ClusterSecurityPolicySpec,
    spec_json: &serde_json::Value,
    claim: &MappingClaim<'_>,
    entry: &MitreMappingEntry,
) -> Result<()> {
    match ATTACK_CATALOG.iter().find(|(id, _)| *id == entry.technique) {
        None => bail!(
            "MITRE mapping: техника {:?} нет в каталоге этого маппинга",
            entry.technique
        ),
        Some((_, official)) if *official != entry.name => bail!(
            "MITRE mapping: {}: имя {:?} не совпадает с официальным {}",
            entry.technique,
            entry.name,
            official
        ),
        Some(_) => {}
    }
    if entry.platform != PLATFORM_CONTAINERS {
        bail!(
            "MITRE mapping: {}: platform {:?} не containers",
            entry.technique,
            entry.platform
        );
    }
    if entry.limits.trim().is_empty() {
        bail!(
            "MITRE mapping: {}: у записи обязан быть написанный limit, \
             маппинг без границы — завышенное соответствие",
            entry.technique
        );
    }
    if entry.refs.is_empty() {
        bail!(
            "MITRE mapping: {}: ни одной ссылки на механизм",
            entry.technique
        );
    }
    for reference in &entry.refs {
        // Kind exception is not evidence, expired or not. synchronous-deny
        // is a real token and nothing in the current policy may claim it.
        if reference.kind == "exception" {
            bail!(
                "MITRE mapping: {}: kind exception не подтверждает capability, просрочено исключение или нет",
                entry.technique
            );
        }
        reject_unowned_capability(entry, reference)?;
    }
    if entry.technique == "T1611" && !t1611_cites_both(&entry.refs) {
        bail!(
            "MITRE mapping: T1611: одного path match недостаточно (в том числе одного \
             docker.sock suffix): нужны оба ref no-runtime-sock \
             ({PROCEDURE_EXEC_PATH_SUFFIX_RUNTIME_SOCK}) и no-module \
             ({PROCEDURE_TRACEPOINT_BPF_OR_INIT_MODULE}). no-module — не «bpf() denied»"
        );
    }
    for reference in &entry.refs {
        check_mapping_ref(spec, spec_json, claim, entry, reference)?;
    }
    Ok(())
}

fn t1611_cites_both(refs: &[MitreMappingRef]) -> bool {
    let sock = refs
        .iter()
        .any(|r| r.kind == "rule" && r.path == "no-runtime-sock");
    let module = refs
        .iter()
        .any(|r| r.kind == "rule" && r.path == "no-module");
    sock && module
}

fn reject_unowned_capability(entry: &MitreMappingEntry, reference: &MitreMappingRef) -> Result<()> {
    match reference.capability.as_str() {
        CAPABILITY_SYNCHRONOUS_DENY => bail!(
            "MITRE mapping: {}: capability synchronous-deny не подтверждена — ни правило {:?}, ни поле её не даёт",
            entry.technique,
            reference.path
        ),
        "runtime-kill" | "SIGKILL" => bail!(
            "MITRE mapping: {}: capability {:?} не синоним detect-then-kill",
            entry.technique,
            reference.capability
        ),
        CAPABILITY_RUNTIME_OBSERVE | CAPABILITY_DETECT_THEN_KILL | CAPABILITY_ADMIT_DENY => Ok(()),
        _ => bail!(
            "MITRE mapping: {}: capability {:?} нет среди runtime-observe, detect-then-kill, admit-deny, synchronous-deny",
            entry.technique,
            reference.capability
        ),
    }
}

fn check_mapping_ref(
    spec: &ClusterSecurityPolicySpec,
    spec_json: &serde_json::Value,
    claim: &MappingClaim<'_>,
    entry: &MitreMappingEntry,
    reference: &MitreMappingRef,
) -> Result<()> {
    if !technique_allows(&entry.technique, &reference.kind, &reference.path) {
        bail!(
            "MITRE mapping: {}: {:?} {:?} не относится к этой технике",
            entry.technique,
            reference.kind,
            reference.path
        );
    }
    if mutate_predicate(&reference.path) {
        bail!(
            "MITRE mapping: {}: field {:?} — mutate, capability нет",
            entry.technique,
            reference.path
        );
    }
    let Some(expected) = pinned_procedure(
        &entry.technique,
        &reference.kind,
        &reference.path,
        &reference.capability,
    ) else {
        bail!(
            "MITRE mapping: {}: capability {:?} не закреплена за {:?} {:?}",
            entry.technique,
            reference.capability,
            reference.kind,
            reference.path
        );
    };
    if reference.procedure != expected {
        bail!(
            "MITRE mapping: {}: procedure {:?} не соответствует {:?} {:?}, нужна {expected}",
            entry.technique,
            reference.procedure,
            reference.kind,
            reference.path
        );
    }
    match reference.capability.as_str() {
        CAPABILITY_RUNTIME_OBSERVE => check_runtime_observe(spec, entry, reference),
        CAPABILITY_DETECT_THEN_KILL => check_detect_then_kill(spec, claim, entry, reference),
        CAPABILITY_ADMIT_DENY => check_admit_deny(spec, spec_json, claim, entry, reference),
        _ => bail!(
            "MITRE mapping: {}: capability {:?} не подтверждена",
            entry.technique,
            reference.capability
        ),
    }
}

fn check_runtime_observe(
    spec: &ClusterSecurityPolicySpec,
    entry: &MitreMappingEntry,
    reference: &MitreMappingRef,
) -> Result<()> {
    let action = rule_action(spec, &entry.technique, &reference.path)?;
    let effective = effective_runtime_action(spec, action);
    if effective != RuntimeAction::Audit {
        bail!(
            "MITRE mapping: {}: rule {:?} capability runtime-observe, эффективное действие {effective:?}",
            entry.technique,
            reference.path
        );
    }
    Ok(())
}

fn check_detect_then_kill(
    spec: &ClusterSecurityPolicySpec,
    claim: &MappingClaim<'_>,
    entry: &MitreMappingEntry,
    reference: &MitreMappingRef,
) -> Result<()> {
    let action = rule_action(spec, &entry.technique, &reference.path)?;
    let effective = effective_runtime_action(spec, action);
    if effective != RuntimeAction::Kill {
        bail!(
            "MITRE mapping: {}: rule {:?} capability detect-then-kill, эффективное действие {effective:?} (mode {:?}, disabled={})",
            entry.technique,
            reference.path,
            spec.mode,
            spec.disabled
        );
    }
    // Same probe as the agent's waiver_can_apply: the waiver's own target
    // namespace, not "". Empty matches only an empty hit namespace; a
    // namespaced waiver still demotes the kill for pods in that namespace.
    let now = Utc::now();
    if let Some(exception) = claim.exceptions.iter().find(|exception| {
        exception_applies(
            exception,
            &exception.target.namespace,
            claim.policy_name,
            &reference.path,
            now,
        )
    }) {
        bail!(
            "MITRE mapping: {}: rule {:?} capability detect-then-kill снята живым exception (namespace {:?}) и не является предотвращением",
            entry.technique,
            reference.path,
            exception.target.namespace
        );
    }
    Ok(())
}

fn rule_action(
    spec: &ClusterSecurityPolicySpec,
    technique: &str,
    id: &str,
) -> Result<RuntimeAction> {
    spec.runtime
        .rules
        .iter()
        .find(|rule| rule.id == id)
        .map(|rule| rule.action)
        .with_context(|| {
            format!("MITRE mapping: {technique}: rule {id:?} нет среди id правил политики")
        })
}

fn technique_allows(technique: &str, kind: &str, path: &str) -> bool {
    match (technique, kind, path) {
        ("T1059" | "T1609", "rule", "no-shell") => true,
        ("T1611", "rule", "no-runtime-sock" | "no-module") => true,
        ("T1610", "field", path) if deny_predicate(path).is_some() => true,
        ("T1610", "field", path) if mutate_predicate(path) => true,
        _ => false,
    }
}

/// One procedure per path. A docker.sock suffix is not T1611, and a deny
/// field may cite `admit-pod-reject` only as admit-deny. Mutate has none.
fn pinned_procedure(
    technique: &str,
    kind: &str,
    path: &str,
    capability: &str,
) -> Option<&'static str> {
    match (technique, kind, path, capability) {
        (
            "T1059" | "T1609",
            "rule",
            "no-shell",
            CAPABILITY_RUNTIME_OBSERVE | CAPABILITY_DETECT_THEN_KILL,
        ) => Some(PROCEDURE_EXEC_COMM_SHELL),
        (
            "T1611",
            "rule",
            "no-runtime-sock",
            CAPABILITY_RUNTIME_OBSERVE | CAPABILITY_DETECT_THEN_KILL,
        ) => Some(PROCEDURE_EXEC_PATH_SUFFIX_RUNTIME_SOCK),
        (
            "T1611",
            "rule",
            "no-module",
            CAPABILITY_RUNTIME_OBSERVE | CAPABILITY_DETECT_THEN_KILL,
        ) => Some(PROCEDURE_TRACEPOINT_BPF_OR_INIT_MODULE),
        ("T1610", "field", path, CAPABILITY_ADMIT_DENY) if deny_predicate(path).is_some() => {
            Some(PROCEDURE_ADMIT_POD_REJECT)
        }
        _ => None,
    }
}

fn check_admit_deny(
    spec: &ClusterSecurityPolicySpec,
    spec_json: &serde_json::Value,
    claim: &MappingClaim<'_>,
    entry: &MitreMappingEntry,
    reference: &MitreMappingRef,
) -> Result<()> {
    let Some(predicate) = deny_predicate(&reference.path) else {
        bail!(
            "MITRE mapping: {}: field {:?} не является предикатом admit-deny",
            entry.technique,
            reference.path
        );
    };
    // Paths are serde names (`hostPID`), not Rust field names.
    let Some(value) = value_at_path(spec_json, &reference.path) else {
        bail!(
            "MITRE mapping: {}: field {:?} нет в сериализации ClusterSecurityPolicy (поле переименовано или удалено)",
            entry.technique,
            reference.path
        );
    };
    if !predicate_is_on(predicate, value) {
        bail!(
            "MITRE mapping: {}: field {:?} выключено",
            entry.technique,
            reference.path
        );
    }
    if !admission_enforces(spec) {
        bail!(
            "MITRE mapping: {}: capability admit-deny требует mode=enforce, у политики {:?} (disabled={})",
            entry.technique,
            spec.mode,
            spec.disabled
        );
    }
    if claim.admission_suspended {
        bail!(
            "MITRE mapping: {}: capability admit-deny не является активным предотвращением: break-glass is not active prevention",
            entry.technique
        );
    }
    Ok(())
}

enum Predicate {
    Bool,
    NonEmptyList,
}

/// Admission denies on these fields only. `trustRoots` is verifying material,
/// not a deny switch: an image is refused when `requireSigned` or
/// `denyUnsigned` is set.
fn deny_predicate(path: &str) -> Option<Predicate> {
    match path {
        "spec.supply.requireSigned"
        | "spec.supply.denyUnsigned"
        | "spec.supply.denyLatestTag"
        | "spec.selector.image.requireDigest"
        | "spec.admit.deny.privileged"
        | "spec.admit.deny.hostPID"
        | "spec.admit.deny.hostIPC"
        | "spec.admit.deny.hostNetwork"
        | "spec.admit.deny.hostPath"
        | "spec.admit.deny.allowPrivilegeEscalation"
        | "spec.admit.deny.runAsRoot"
        | "spec.admit.deny.wildcardsRbac"
        | "spec.admit.deny.clusterAdminBind" => Some(Predicate::Bool),
        "spec.selector.image.registriesAllow" | "spec.admit.deny.addedCapabilities" => {
            Some(Predicate::NonEmptyList)
        }
        _ => None,
    }
}

fn mutate_predicate(path: &str) -> bool {
    matches!(
        path,
        "spec.admit.mutate.injectSeccompRuntimeDefault"
            | "spec.admit.mutate.dropAllCapabilities"
            | "spec.admit.mutate.readOnlyRootFilesystem"
    )
}

fn predicate_is_on(predicate: Predicate, value: &serde_json::Value) -> bool {
    match predicate {
        Predicate::Bool => matches!(value, serde_json::Value::Bool(true)),
        Predicate::NonEmptyList => {
            matches!(value, serde_json::Value::Array(items) if !items.is_empty())
        }
    }
}

fn value_at_path<'a>(root: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = root;
    for segment in path.split('.') {
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

fn admission_enforces(spec: &ClusterSecurityPolicySpec) -> bool {
    spec.mode == PolicyMode::Enforce && !spec.disabled
}

// Observe, audit, and disabled do not install Kill/Deny/Isolate.
// Same downgrade as ferrum-ebpf `cap_for_mode`.
fn effective_runtime_action(
    spec: &ClusterSecurityPolicySpec,
    action: RuntimeAction,
) -> RuntimeAction {
    if spec.disabled || !matches!(spec.mode, PolicyMode::Enforce) {
        match action {
            RuntimeAction::Allow | RuntimeAction::Audit => action,
            _ => RuntimeAction::Audit,
        }
    } else {
        action
    }
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
    use super::{validate_file, validate_mitre_binding, validate_mitre_mapping, validate_yaml};
    use chrono::{Days, Utc};
    use ferrum_api::{
        ClusterSecurityPolicy, ExceptionTarget, PolicyExceptionSpec, PolicyMode, RuntimeAction,
    };

    const MITRE_MAPPING_YAML: &str =
        include_str!("../../../policies/mapping/mitre-attack-mapping.yaml");
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

    /// Проверяет правила, а не календарь: дата подставляется свежая.
    ///
    /// Раньше здесь стоял файл как есть, и тест падал не когда ломались
    /// правила, а когда истекала записанная в примере дата — что и случилось
    /// 2026-09-09 в 18:35, через тридцать пять минут после её истечения.
    #[test]
    fn exception_ok_ok() {
        validate_yaml(&ferrum_testkit::exception_ok_yaml_valid_now()).expect("exception-ok");
    }

    /// А это — про сам поставляемый файл: он обязан разбираться и нести всё,
    /// что делает его примером. Дату здесь не проверяют: она иллюстрация, и
    /// её истечение — не поломка кода.
    #[test]
    fn exception_ok_example_parses() {
        let obj: ferrum_api::PolicyException =
            serde_yaml::from_str(EXCEPTION_OK_YAML).expect("example yaml");
        assert_eq!(obj.spec.ticket, "JIRA-18421");
        assert!(!obj.spec.target.rules.is_empty());
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

    // ---- MITRE ATT&CK mapping (issue #43) ----

    fn mitre_err(manifest: &str) -> String {
        format!(
            "{:#}",
            validate_mitre_mapping(manifest, PROD_RESTRICTED_YAML).unwrap_err()
        )
    }

    fn compiled_digest(policy_yaml: &str) -> String {
        let obj: ClusterSecurityPolicy = serde_yaml::from_str(policy_yaml).expect("policy yaml");
        ferrum_compiler::compile_cluster_policy(&obj.spec)
            .expect("compile")
            .digest
            .as_str()
            .to_string()
    }

    fn mapping_document(policy_yaml: &str, mappings: &str) -> String {
        format!(
            "schemaVersion: 2\nbundleDigest: {}\nsourcePolicy: policies/examples/prod-restricted.yaml\nmappings:\n{mappings}",
            compiled_digest(policy_yaml)
        )
    }

    fn single_ref(
        policy_yaml: &str,
        technique: &str,
        name: &str,
        kind: &str,
        path: &str,
        capability: &str,
        procedure: &str,
    ) -> String {
        mapping_document(
            policy_yaml,
            &format!(
                "  - technique: {technique}\n    name: {name}\n    platform: containers\n    refs:\n      - kind: {kind}\n        path: {path}\n        capability: {capability}\n        procedure: {procedure}\n    limits: stated\n"
            ),
        )
    }

    fn enforce_policy() -> String {
        let yaml =
            PROD_RESTRICTED_YAML.replacen("spec:\n  mode: audit", "spec:\n  mode: enforce", 1);
        assert!(yaml.contains("\n  mode: enforce\n"), "{yaml}");
        yaml
    }

    fn disabled_audit_policy() -> String {
        let yaml = PROD_RESTRICTED_YAML.replacen(
            "spec:\n  mode: audit",
            "spec:\n  disabled: true\n  mode: audit",
            1,
        );
        assert!(yaml.contains("disabled: true"), "{yaml}");
        yaml
    }

    fn flip_hex(digest: &str) -> String {
        let mut bytes = digest.as_bytes().to_vec();
        bytes[0] = if bytes[0] == b'a' { b'b' } else { b'a' };
        String::from_utf8(bytes).expect("hex")
    }

    fn exception_for(
        namespace: &str,
        rule: &str,
        expires_at: chrono::DateTime<Utc>,
    ) -> PolicyExceptionSpec {
        PolicyExceptionSpec {
            ticket: "JIRA-18421".into(),
            requested_by: "platform-sre".into(),
            approved_by: "ib-architect".into(),
            reason: "temporary debug sidecar after incident".into(),
            expires_at,
            mode: PolicyMode::Audit,
            four_eyes: true,
            target: ExceptionTarget {
                namespace: namespace.into(),
                policies: vec!["prod-restricted".into()],
                rules: vec![rule.into()],
            },
        }
    }

    /// Поставляемый манифест сходится с prod-restricted и не обещает
    /// prevention, которого у audit-политики нет.
    #[test]
    fn mitre_mapping_manifest_matches_shipped_policy() {
        let obj: ClusterSecurityPolicy =
            serde_yaml::from_str(PROD_RESTRICTED_YAML).expect("prod-restricted");
        let compiled =
            ferrum_compiler::compile_cluster_policy(&obj.spec).expect("compile prod-restricted");
        let yaml_hash = ferrum_crypto::bundle_digest(PROD_RESTRICTED_YAML.as_bytes());
        assert_ne!(yaml_hash.as_str(), compiled.digest.as_str());
        let manifest: serde_yaml::Value =
            serde_yaml::from_str(MITRE_MAPPING_YAML).expect("mapping yaml");
        assert_eq!(manifest["schemaVersion"].as_u64(), Some(2));
        assert_eq!(
            manifest["bundleDigest"].as_str(),
            Some(compiled.digest.as_str())
        );
        validate_mitre_mapping(MITRE_MAPPING_YAML, PROD_RESTRICTED_YAML)
            .expect("mitre mapping manifest must cross-validate against prod-restricted");
        let again =
            ferrum_compiler::compile_cluster_policy(&obj.spec).expect("compile after validate");
        assert_eq!(again, compiled);
        assert_eq!(obj.spec.mode, PolicyMode::Audit);
        assert!(obj
            .spec
            .runtime
            .rules
            .iter()
            .any(|rule| rule.id == "no-shell" && rule.action == RuntimeAction::Kill));
        assert!(MITRE_MAPPING_YAML.contains("capability: runtime-observe"));
        assert!(!MITRE_MAPPING_YAML.contains("detect-then-kill"));
        assert!(!MITRE_MAPPING_YAML.contains("admit-deny"));
        assert!(!MITRE_MAPPING_YAML.contains("synchronous-deny"));
        assert!(!MITRE_MAPPING_YAML.contains("effect:"));
        assert!(
            !MITRE_MAPPING_YAML.contains("SIGKILL"),
            "{MITRE_MAPPING_YAML}"
        );
        assert!(!MITRE_MAPPING_YAML.contains("T1059.005"));
        assert!(!MITRE_MAPPING_YAML.contains("T1525"));
        assert!(!MITRE_MAPPING_YAML.contains("T1610"));
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../policies/mapping/mitre-attack-mapping.yaml");
        validate_file(&path).expect("validate_file resolves sourcePolicy from the repo root");
    }

    #[test]
    fn mitre_mapping_unknown_rule_id_fails() {
        let bad = MITRE_MAPPING_YAML.replace("path: no-shell", "path: no-shell-renamed");
        let msg = mitre_err(&bad);
        assert!(msg.contains("no-shell-renamed"), "{msg}");
    }

    #[test]
    fn mitre_mapping_unknown_field_path_fails() {
        let bad = single_ref(
            PROD_RESTRICTED_YAML,
            "T1610",
            "Deploy Container",
            "field",
            "spec.admit.deny.noSuchFlag",
            "admit-deny",
            "admit-pod-reject",
        );
        let msg = mitre_err(&bad);
        assert!(msg.contains("noSuchFlag"), "{msg}");
    }

    #[test]
    fn mitre_mapping_without_limit_fails() {
        let bad = MITRE_MAPPING_YAML.replace(
            "limits: >-\n      То же правило no-shell. python -c не ловится: предикат по comm — целое имя.",
            "limits: \"\"",
        );
        assert_ne!(bad, MITRE_MAPPING_YAML, "replacement must apply");
        let msg = mitre_err(&bad);
        assert!(msg.contains("limit"), "{msg}");
    }

    #[test]
    fn mitre_mapping_schema_1_and_3_fail() {
        for version in [1, 3] {
            let bad = MITRE_MAPPING_YAML
                .replace("schemaVersion: 2", &format!("schemaVersion: {version}"));
            assert_ne!(bad, MITRE_MAPPING_YAML);
            let msg = mitre_err(&bad);
            assert!(msg.contains("schemaVersion"), "{msg}");
            assert!(msg.contains(&version.to_string()), "{msg}");
        }
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("mitre-schema1.yaml");
        let _guard = RemoveFile {
            path: path.clone(),
            dir: std::path::PathBuf::new(),
        };
        std::fs::write(
            &path,
            MITRE_MAPPING_YAML.replace("schemaVersion: 2", "schemaVersion: 1"),
        )
        .expect("write");
        let msg = format!("{}", validate_file(&path).unwrap_err());
        assert!(msg.contains("schemaVersion"), "{msg}");
    }

    #[test]
    fn mitre_mapping_wrong_technique_id_fails() {
        let msg =
            mitre_err(&MITRE_MAPPING_YAML.replace("technique: T1059", "technique: T1059.005"));
        assert!(msg.contains("T1059.005"), "{msg}");
        assert!(msg.contains("каталоге"), "{msg}");
    }

    #[test]
    fn mitre_mapping_wrong_official_name_fails() {
        let msg = mitre_err(
            &MITRE_MAPPING_YAML.replace("name: Escape to Host", "name: Load Kernel Module"),
        );
        assert!(msg.contains("Escape to Host"), "{msg}");
    }

    #[test]
    fn mitre_mapping_runtime_kill_on_audit_policy_fails() {
        let bad =
            MITRE_MAPPING_YAML.replace("capability: runtime-observe", "capability: runtime-kill");
        let msg = mitre_err(&bad);
        assert!(msg.contains("runtime-kill"), "{msg}");
        assert!(msg.contains("не синоним"), "{msg}");
        let sig = MITRE_MAPPING_YAML.replace("capability: runtime-observe", "capability: SIGKILL");
        let msg = mitre_err(&sig);
        assert!(msg.contains("SIGKILL"), "{msg}");
        assert!(msg.contains("не синоним"), "{msg}");
        let effect =
            MITRE_MAPPING_YAML.replace("capability: runtime-observe", "effect: runtime-kill");
        let msg = mitre_err(&effect);
        assert!(
            msg.contains("effect") || msg.contains("capability"),
            "{msg}"
        );
    }

    #[test]
    fn mitre_mapping_admit_deny_on_audit_policy_fails() {
        let bad = single_ref(
            PROD_RESTRICTED_YAML,
            "T1610",
            "Deploy Container",
            "field",
            "spec.admit.deny.privileged",
            "admit-deny",
            "admit-pod-reject",
        );
        let msg = mitre_err(&bad);
        assert!(msg.contains("mode=enforce"), "{msg}");
    }

    #[test]
    fn mitre_mapping_implant_image_is_not_in_the_catalog() {
        let bad = single_ref(
            PROD_RESTRICTED_YAML,
            "T1525",
            "Implant Internal Image",
            "rule",
            "no-shell",
            "runtime-observe",
            "exec-comm-shell",
        );
        let msg = mitre_err(&bad);
        assert!(msg.contains("T1525"), "{msg}");
        assert!(msg.contains("каталоге"), "{msg}");
    }

    #[test]
    fn mitre_mapping_technique_cannot_cite_another_control() {
        let bad = MITRE_MAPPING_YAML.replace("path: no-shell", "path: no-module");
        let msg = mitre_err(&bad);
        assert!(msg.contains("no-module"), "{msg}");
        assert!(msg.contains("не относится"), "{msg}");
    }

    #[test]
    fn mitre_mapping_trust_roots_are_not_a_deny_switch() {
        let policy = enforce_policy();
        let bad = single_ref(
            &policy,
            "T1610",
            "Deploy Container",
            "field",
            "spec.supply.trustRoots",
            "admit-deny",
            "admit-pod-reject",
        );
        let msg = format!("{}", validate_mitre_mapping(&bad, &policy).unwrap_err());
        assert!(msg.contains("trustRoots"), "{msg}");
        assert!(!msg.contains("mode=enforce"), "{msg}");
        let mutate = single_ref(
            &policy,
            "T1610",
            "Deploy Container",
            "field",
            "spec.admit.mutate.dropAllCapabilities",
            "admit-deny",
            "admit-pod-reject",
        );
        let msg = format!("{}", validate_mitre_mapping(&mutate, &policy).unwrap_err());
        assert!(msg.contains("dropAllCapabilities"), "{msg}");
        assert!(msg.contains("mutate"), "{msg}");
        assert!(!msg.contains("mode=enforce"), "{msg}");
    }

    #[test]
    fn mitre_mapping_flipped_digest_fails_and_second_compile_is_unchanged() {
        let policy_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../policies/examples/prod-restricted.yaml");
        let mapping_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../policies/mapping/mitre-attack-mapping.yaml");
        let policy_before = std::fs::read(&policy_path).expect("policy bytes");
        let mapping_before = std::fs::read(&mapping_path).expect("mapping bytes");
        let obj: ClusterSecurityPolicy =
            serde_yaml::from_str(PROD_RESTRICTED_YAML).expect("prod-restricted");
        let first =
            ferrum_compiler::compile_cluster_policy(&obj.spec).expect("compile before reject");
        let flipped = flip_hex(first.digest.as_str());
        let bad = MITRE_MAPPING_YAML.replace(first.digest.as_str(), &flipped);
        assert_ne!(bad, MITRE_MAPPING_YAML);
        let msg = mitre_err(&bad);
        assert!(msg.contains("bundleDigest"), "{msg}");
        assert!(msg.contains(&flipped), "{msg}");
        let second =
            ferrum_compiler::compile_cluster_policy(&obj.spec).expect("compile after reject");
        assert_eq!(second, first);
        assert_eq!(obj.spec.mode, PolicyMode::Audit);
        assert_eq!(
            std::fs::read(&policy_path).expect("policy bytes"),
            policy_before
        );
        assert_eq!(
            std::fs::read(&mapping_path).expect("mapping bytes"),
            mapping_before
        );
    }

    #[test]
    fn mitre_mapping_missing_or_uppercase_digest_fails() {
        let missing = MITRE_MAPPING_YAML
            .lines()
            .filter(|line| !line.trim_start().starts_with("bundleDigest:"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_ne!(missing, MITRE_MAPPING_YAML);
        let msg = mitre_err(&missing);
        assert!(msg.contains("bundleDigest"), "{msg}");

        let digest = compiled_digest(PROD_RESTRICTED_YAML);
        let upper = MITRE_MAPPING_YAML.replace(&digest, &digest.to_uppercase());
        assert_ne!(upper, MITRE_MAPPING_YAML);
        let msg = mitre_err(&upper);
        assert!(msg.contains("lowercase"), "{msg}");
        assert_eq!(compiled_digest(PROD_RESTRICTED_YAML), digest);
    }

    #[test]
    fn mitre_mapping_one_ref_t1611_fails() {
        for (path, procedure) in [
            ("no-runtime-sock", "exec-path-suffix-runtime-sock"),
            ("no-module", "tracepoint-bpf-or-init-module"),
        ] {
            let manifest = single_ref(
                PROD_RESTRICTED_YAML,
                "T1611",
                "Escape to Host",
                "rule",
                path,
                "runtime-observe",
                procedure,
            );
            let msg = mitre_err(&manifest);
            assert!(msg.contains("T1611"), "{msg}");
            assert!(msg.contains("no-runtime-sock"), "{msg}");
            assert!(msg.contains("no-module"), "{msg}");
            assert!(msg.contains("docker.sock"), "{msg}");
        }
    }

    #[test]
    fn mitre_mapping_procedure_is_pinned_to_one_path() {
        let swapped = MITRE_MAPPING_YAML.replace(
            "procedure: exec-path-suffix-runtime-sock",
            "procedure: exec-comm-shell",
        );
        let msg = mitre_err(&swapped);
        assert!(msg.contains("procedure"), "{msg}");
        assert!(msg.contains("exec-path-suffix-runtime-sock"), "{msg}");

        let shell = MITRE_MAPPING_YAML.replace(
            "procedure: exec-comm-shell",
            "procedure: tracepoint-bpf-or-init-module",
        );
        let msg = mitre_err(&shell);
        assert!(msg.contains("exec-comm-shell"), "{msg}");

        let wrong_platform =
            MITRE_MAPPING_YAML.replacen("platform: containers", "platform: linux", 1);
        let msg = mitre_err(&wrong_platform);
        assert!(msg.contains("platform"), "{msg}");
        assert!(msg.contains("containers"), "{msg}");
    }

    #[test]
    fn mitre_mapping_synchronous_deny_is_unverified() {
        for (technique, name, kind, path, procedure) in [
            (
                "T1059",
                "Command and Scripting Interpreter",
                "rule",
                "no-shell",
                "exec-comm-shell",
            ),
            (
                "T1611",
                "Escape to Host",
                "rule",
                "no-module",
                "tracepoint-bpf-or-init-module",
            ),
            (
                "T1610",
                "Deploy Container",
                "field",
                "spec.admit.deny.privileged",
                "admit-pod-reject",
            ),
        ] {
            let manifest = single_ref(
                PROD_RESTRICTED_YAML,
                technique,
                name,
                kind,
                path,
                "synchronous-deny",
                procedure,
            );
            let msg = mitre_err(&manifest);
            assert!(msg.contains("synchronous-deny"), "{msg}");
            assert!(msg.contains("не подтверждена"), "{msg}");
            assert!(msg.contains(path), "{msg}");
            assert!(!msg.contains("mode=enforce"), "{msg}");
        }
    }

    #[test]
    fn mitre_mapping_enforce_kill_is_detect_then_kill_not_synchronous_deny() {
        let policy = enforce_policy();
        let kill = single_ref(
            &policy,
            "T1059",
            "Command and Scripting Interpreter",
            "rule",
            "no-shell",
            "detect-then-kill",
            "exec-comm-shell",
        );
        validate_mitre_mapping(&kill, &policy).expect("detect-then-kill while enforcing");
        let denied = kill.replace(
            "capability: detect-then-kill",
            "capability: synchronous-deny",
        );
        let msg = format!("{}", validate_mitre_mapping(&denied, &policy).unwrap_err());
        assert!(msg.contains("synchronous-deny"), "{msg}");
        assert!(msg.contains("не подтверждена"), "{msg}");
        let alias = kill.replace("capability: detect-then-kill", "capability: runtime-kill");
        let msg = format!("{}", validate_mitre_mapping(&alias, &policy).unwrap_err());
        assert!(msg.contains("не синоним"), "{msg}");
        let again = compiled_digest(&policy);
        assert_eq!(again, compiled_digest(&policy));
        assert!(policy.contains("mode: enforce"));
    }

    #[test]
    fn mitre_mapping_audit_disabled_exception_and_break_glass_are_not_prevention() {
        let audit_kill = single_ref(
            PROD_RESTRICTED_YAML,
            "T1059",
            "Command and Scripting Interpreter",
            "rule",
            "no-shell",
            "detect-then-kill",
            "exec-comm-shell",
        );
        let msg = mitre_err(&audit_kill);
        assert!(msg.contains("detect-then-kill"), "{msg}");
        assert!(msg.contains("Audit"), "{msg}");

        let disabled = disabled_audit_policy();
        let disabled_kill = single_ref(
            &disabled,
            "T1609",
            "Container Administration Command",
            "rule",
            "no-shell",
            "detect-then-kill",
            "exec-comm-shell",
        );
        let msg = format!(
            "{}",
            validate_mitre_mapping(&disabled_kill, &disabled).unwrap_err()
        );
        assert!(msg.contains("Audit"), "{msg}");
        assert!(msg.contains("disabled=true"), "{msg}");
        let disabled_deny = single_ref(
            &disabled,
            "T1610",
            "Deploy Container",
            "field",
            "spec.admit.deny.privileged",
            "admit-deny",
            "admit-pod-reject",
        );
        let msg = format!(
            "{}",
            validate_mitre_mapping(&disabled_deny, &disabled).unwrap_err()
        );
        assert!(msg.contains("mode=enforce"), "{msg}");
        assert!(msg.contains("disabled=true"), "{msg}");

        let policy = enforce_policy();
        let kill = single_ref(
            &policy,
            "T1059",
            "Command and Scripting Interpreter",
            "rule",
            "no-shell",
            "detect-then-kill",
            "exec-comm-shell",
        );
        // Empty target namespace is its own hit. It is not how a cluster
        // policy stands in for every pod namespace.
        let live = exception_for("", "no-shell", Utc::now() + Days::new(1));
        let msg = format!(
            "{}",
            validate_mitre_binding(&kill, &policy, &[live], false).unwrap_err()
        );
        assert!(msg.contains("exception"), "{msg}");
        assert!(msg.contains("no-shell"), "{msg}");

        let other = exception_for("", "no-module", Utc::now() + Days::new(1));
        validate_mitre_binding(&kill, &policy, &[other], false)
            .expect("an exception on another rule does not waive no-shell");
        let expired = exception_for("", "no-shell", Utc::now() - Days::new(1));
        validate_mitre_binding(&kill, &policy, std::slice::from_ref(&expired), false)
            .expect("an expired exception does not waive detect-then-kill");

        let deny = single_ref(
            &policy,
            "T1610",
            "Deploy Container",
            "field",
            "spec.admit.deny.privileged",
            "admit-deny",
            "admit-pod-reject",
        );
        validate_mitre_binding(&deny, &policy, &[], false).expect("admit-deny while enforcing");
        let msg = format!(
            "{}",
            validate_mitre_binding(&deny, &policy, &[], true).unwrap_err()
        );
        assert!(
            msg.contains("break-glass is not active prevention"),
            "{msg}"
        );

        let as_exception = single_ref(
            &policy,
            "T1059",
            "Command and Scripting Interpreter",
            "exception",
            "no-shell",
            "detect-then-kill",
            "exec-comm-shell",
        );
        let msg = format!(
            "{}",
            validate_mitre_binding(&as_exception, &policy, &[expired], false).unwrap_err()
        );
        assert!(msg.contains("kind exception"), "{msg}");
        assert!(msg.contains("просроч"), "{msg}");

        let observe = single_ref(
            PROD_RESTRICTED_YAML,
            "T1059",
            "Command and Scripting Interpreter",
            "rule",
            "no-shell",
            "runtime-observe",
            "exec-comm-shell",
        );
        let live = exception_for("", "no-shell", Utc::now() + Days::new(1));
        validate_mitre_binding(&observe, PROD_RESTRICTED_YAML, &[live], true)
            .expect("runtime-observe is not prevention and is not suspended with admission");
    }

    #[test]
    fn mitre_mapping_payments_namespace_exception_blocks_detect_then_kill() {
        let policy = enforce_policy();
        let obj: ClusterSecurityPolicy = serde_yaml::from_str(&policy).expect("enforce policy");
        let before =
            ferrum_compiler::compile_cluster_policy(&obj.spec).expect("compile before reject");
        let kill = single_ref(
            &policy,
            "T1059",
            "Command and Scripting Interpreter",
            "rule",
            "no-shell",
            "detect-then-kill",
            "exec-comm-shell",
        );
        let payments = exception_for("payments", "no-shell", Utc::now() + Days::new(1));
        let msg = format!(
            "{}",
            validate_mitre_binding(&kill, &policy, std::slice::from_ref(&payments), false)
                .unwrap_err()
        );
        assert!(msg.contains("exception"), "{msg}");
        assert!(msg.contains("no-shell"), "{msg}");
        assert!(msg.contains("payments"), "{msg}");
        let other = exception_for("payments", "no-module", Utc::now() + Days::new(1));
        validate_mitre_binding(&kill, &policy, std::slice::from_ref(&other), false)
            .expect("a payments waiver of another rule does not waive no-shell");
        let after =
            ferrum_compiler::compile_cluster_policy(&obj.spec).expect("compile after reject");
        assert_eq!(after.digest, before.digest);
        assert_eq!(obj.spec.mode, PolicyMode::Enforce);
        assert!(policy.contains("mode: enforce"));
    }

    #[test]
    fn mappings_key_alone_is_not_a_mapping_manifest() {
        let msg = err_msg("mappings: null\n");
        assert!(msg.contains("apiVersion") || msg.contains("parse"), "{msg}");
        assert!(!msg.contains("MITRE"), "{msg}");
    }

    #[test]
    fn broken_mapping_yaml_reports_a_mapping_parse_error() {
        let dir = std::env::temp_dir().join(format!("ferrum-mitre-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("mitre-attack-mapping.yaml");
        let _guard = RemoveFile {
            path: path.clone(),
            dir: dir.clone(),
        };
        std::fs::write(
            &path,
            "schemaVersion: 1\nsourcePolicy: policies/examples/prod-restricted.yaml\nmappings: [\n",
        )
        .expect("write");
        let msg = format!("{}", validate_file(&path).unwrap_err());
        assert!(msg.contains("parse MITRE mapping manifest"), "{msg}");
    }

    #[test]
    fn validate_file_wrong_source_policy_fails_inside_repo() {
        let path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("mitre-mapping-test.yaml");
        let _guard = RemoveFile {
            path: path.clone(),
            dir: std::path::PathBuf::new(),
        };
        std::fs::write(
            &path,
            "schemaVersion: 1\nsourcePolicy: policies/examples/missing.yaml\nmappings:\n  - technique: T1609\n    name: Container Administration Command\n    refs:\n      - kind: rule\n        path: no-shell\n        effect: runtime-audit\n    limits: x\n",
        )
        .expect("write");
        let msg = format!("{}", validate_file(&path).unwrap_err());
        assert!(msg.contains("missing.yaml"), "{msg}");
    }

    #[test]
    fn validate_file_outside_repo_does_not_invent_a_root() {
        let dir = std::env::temp_dir().join(format!("ferrum-mitre-root-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("mitre-attack-mapping.yaml");
        let _guard = RemoveFile {
            path: path.clone(),
            dir: dir.clone(),
        };
        std::fs::write(
            &path,
            "schemaVersion: 1\nsourcePolicy: policies/examples/prod-restricted.yaml\nmappings:\n  - technique: T1609\n    name: Container Administration Command\n    refs:\n      - kind: rule\n        path: no-shell\n        effect: runtime-audit\n    limits: x\n",
        )
        .expect("write");
        let msg = format!("{}", validate_file(&path).unwrap_err());
        assert!(msg.contains("prod-restricted.yaml"), "{msg}");
        assert!(!msg.contains("no-shell"), "{msg}");
    }

    struct RemoveFile {
        path: std::path::PathBuf,
        dir: std::path::PathBuf,
    }

    impl Drop for RemoveFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
            if self.dir.as_os_str().is_empty() {
                return;
            }
            let _ = std::fs::remove_dir(&self.dir);
        }
    }
}
