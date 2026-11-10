use anyhow::{bail, Context, Result};
use ferrum_api::{
    ClusterSecurityPolicy, ClusterSecurityPolicySpec, ComplianceSnapshot, ComplianceSnapshotSpec,
    FerrumCluster, FerrumClusterSpec, PolicyException, PolicyLibrary, PolicyLibrarySpec,
    PolicyMode, RuntimeAction, RuntimeProfile, RuntimeProfileSpec, SecurityPolicy,
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

// Official container-matrix names. A real id with the wrong technique
// (T1059.005 is Visual Basic) is absent on purpose.
const ATTACK_CATALOG: &[(&str, &str)] = &[
    ("T1059", "Command and Scripting Interpreter"),
    ("T1525", "Implant Internal Image"),
    ("T1609", "Container Administration Command"),
    ("T1610", "Deploy Container"),
    ("T1611", "Escape to Host"),
];

#[derive(Debug, Deserialize)]
struct MitreMappingManifest {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    mappings: Vec<MitreMappingEntry>,
}

#[derive(Debug, Deserialize)]
struct MitreMappingEntry {
    technique: String,
    name: String,
    refs: Vec<MitreMappingRef>,
    limits: String,
}

#[derive(Debug, Deserialize)]
struct MitreMappingRef {
    kind: String,
    path: String,
    effect: String,
}

pub(crate) fn validate_mitre_mapping(manifest_raw: &str, policy_raw: &str) -> Result<()> {
    let manifest: MitreMappingManifest =
        serde_yaml::from_str(manifest_raw).context("parse MITRE mapping manifest")?;
    if manifest.schema_version != 1 {
        bail!(
            "MITRE mapping: schemaVersion {} не поддерживается (живой: 1)",
            manifest.schema_version
        );
    }
    if manifest.mappings.is_empty() {
        bail!("MITRE mapping: пустой список mappings");
    }
    let obj: ClusterSecurityPolicy = parse_resource(policy_raw, ClusterSecurityPolicy::new)?;
    validate_cluster_policy(&obj.spec).map_err(anyhow::Error::from)?;
    let spec_json = serde_json::json!({
        "spec": serde_json::to_value(&obj.spec).context("serialize ClusterSecurityPolicy spec")?,
    });

    for entry in &manifest.mappings {
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
            check_mapping_ref(&obj.spec, &spec_json, entry, reference)?;
        }
    }
    Ok(())
}

fn check_mapping_ref(
    spec: &ClusterSecurityPolicySpec,
    spec_json: &serde_json::Value,
    entry: &MitreMappingEntry,
    reference: &MitreMappingRef,
) -> Result<()> {
    match (reference.kind.as_str(), reference.effect.as_str()) {
        ("rule", "runtime-kill") => {
            let action = rule_action(spec, &entry.technique, &reference.path)?;
            let effective = effective_runtime_action(spec, action);
            if effective != RuntimeAction::Kill {
                bail!(
                    "MITRE mapping: {}: rule {:?} effect runtime-kill, эффективное действие {effective:?} (mode {:?}, disabled={})",
                    entry.technique,
                    reference.path,
                    spec.mode,
                    spec.disabled
                );
            }
        }
        ("rule", "runtime-audit") => {
            let action = rule_action(spec, &entry.technique, &reference.path)?;
            let effective = effective_runtime_action(spec, action);
            if effective != RuntimeAction::Audit {
                bail!(
                    "MITRE mapping: {}: rule {:?} effect runtime-audit, эффективное действие {effective:?}",
                    entry.technique,
                    reference.path
                );
            }
        }
        ("field", "admit-deny") => check_admit_field(
            spec,
            spec_json,
            entry,
            reference,
            &["spec.admit.deny.", "spec.supply.", "spec.selector.image."],
        )?,
        ("field", "admit-mutate") => {
            check_admit_field(spec, spec_json, entry, reference, &["spec.admit.mutate."])?
        }
        _ => bail!(
            "MITRE mapping: {}: kind {:?} и effect {:?} не сочетаются",
            entry.technique,
            reference.kind,
            reference.effect
        ),
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

fn check_admit_field(
    spec: &ClusterSecurityPolicySpec,
    spec_json: &serde_json::Value,
    entry: &MitreMappingEntry,
    reference: &MitreMappingRef,
    prefixes: &[&str],
) -> Result<()> {
    if !prefixes
        .iter()
        .any(|prefix| reference.path.starts_with(prefix))
    {
        bail!(
            "MITRE mapping: {}: field {:?} не относится к effect {}",
            entry.technique,
            reference.path,
            reference.effect
        );
    }
    // Paths are serde names (`hostPID`), not Rust field names.
    let Some(value) = value_at_path(spec_json, &reference.path) else {
        bail!(
            "MITRE mapping: {}: field {:?} нет в сериализации ClusterSecurityPolicy (поле переименовано или удалено)",
            entry.technique,
            reference.path
        );
    };
    if !admission_enforces(spec) {
        bail!(
            "MITRE mapping: {}: effect {} требует mode=enforce, у политики {:?} (disabled={})",
            entry.technique,
            reference.effect,
            spec.mode,
            spec.disabled
        );
    }
    if !flag_is_on(value) {
        bail!(
            "MITRE mapping: {}: field {:?} выключено",
            entry.technique,
            reference.path
        );
    }
    Ok(())
}

fn value_at_path<'a>(root: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = root;
    for segment in path.split('.') {
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

fn flag_is_on(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Bool(on) => *on,
        serde_json::Value::Array(items) => !items.is_empty(),
        serde_json::Value::String(text) => !text.trim().is_empty(),
        _ => false,
    }
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
    use super::{validate_file, validate_mitre_mapping, validate_yaml};

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
            "{}",
            validate_mitre_mapping(manifest, PROD_RESTRICTED_YAML).unwrap_err()
        )
    }

    /// Поставляемый манифест сходится с prod-restricted и не обещает
    /// prevention, которого у audit-политики нет.
    #[test]
    fn mitre_mapping_manifest_matches_shipped_policy() {
        validate_mitre_mapping(MITRE_MAPPING_YAML, PROD_RESTRICTED_YAML)
            .expect("mitre mapping manifest must cross-validate against prod-restricted");
        assert!(
            !MITRE_MAPPING_YAML.contains("SIGKILL"),
            "{MITRE_MAPPING_YAML}"
        );
        assert!(!MITRE_MAPPING_YAML.contains("T1059.005"));
        assert!(!MITRE_MAPPING_YAML.contains("T1525"));
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
        let bad = r#"
schemaVersion: 1
sourcePolicy: policies/examples/prod-restricted.yaml
mappings:
  - technique: T1610
    name: Deploy Container
    refs:
      - kind: field
        path: spec.admit.deny.noSuchFlag
        effect: admit-deny
    limits: the field is not on ClusterSecurityPolicy
"#;
        let msg = mitre_err(bad);
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
    fn mitre_mapping_future_schema_version_fails() {
        let msg = mitre_err(&MITRE_MAPPING_YAML.replace("schemaVersion: 1", "schemaVersion: 2"));
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
        let bad = MITRE_MAPPING_YAML.replace("effect: runtime-audit", "effect: runtime-kill");
        let msg = mitre_err(&bad);
        assert!(msg.contains("runtime-kill"), "{msg}");
        assert!(msg.contains("Audit"), "{msg}");
    }

    #[test]
    fn mitre_mapping_admit_deny_on_audit_policy_fails() {
        let bad = r#"
schemaVersion: 1
sourcePolicy: policies/examples/prod-restricted.yaml
mappings:
  - technique: T1610
    name: Deploy Container
    refs:
      - kind: field
        path: spec.admit.deny.privileged
        effect: admit-deny
    limits: admission does not deny while mode is audit
"#;
        let msg = mitre_err(bad);
        assert!(msg.contains("mode=enforce"), "{msg}");
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
