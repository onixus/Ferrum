use serde_json::Value;
use std::{fs, path::PathBuf};

fn manifest() -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let raw = fs::read_to_string(root.join("apex-contract").join("manifest.json"))
        .expect("apex-contract/manifest.json must exist at repository root");
    serde_json::from_str(&raw).expect("apex-contract/manifest.json must be valid JSON")
}

#[test]
fn apex_contract_keeps_ferrum_as_the_enforcement_authority() {
    let m = manifest();
    assert_eq!(m["apex_contract_version"], "1.0");
    assert_eq!(m["canonical"]["repo"], "onixus/unified-platform");
    assert_eq!(m["system"], "ferrum");
    assert_eq!(m["namespace"], "ferrum");
    assert_eq!(m["role"], "k8s-enforcement");

    assert_eq!(m["ownership"]["gateway_is_source_of_truth"], false);
    assert_eq!(m["ownership"]["clickhouse_is_transactional_source"], false);
    assert_eq!(
        m["identity"]["production_trusts_unsigned_role_header"],
        false
    );
    assert_eq!(m["identity"]["owning_service_authorizes_mutations"], true);
}

#[test]
fn apex_contract_publishes_stable_ferrum_boundary_names() {
    let m = manifest();
    let resources = m["resources"]["mappings"]
        .as_array()
        .expect("resources.mappings array");

    let prefix_for = |kind: &str| {
        resources
            .iter()
            .find(|item| item["kind"] == kind)
            .and_then(|item| item["urn_prefix"].as_str())
            .unwrap_or_else(|| panic!("missing resource kind {kind}"))
    };

    assert_eq!(prefix_for("policy"), "urn:apex:policy:ferrum:");
    assert_eq!(prefix_for("event"), "urn:apex:event:ferrum:");
    assert_eq!(prefix_for("evidence"), "urn:apex:evidence:ferrum:");

    let event_types = m["integration"]["event_types"]
        .as_array()
        .expect("event_types array");
    assert!(event_types
        .iter()
        .any(|item| item == "apex.ferrum.enforcement.v1"));
}
