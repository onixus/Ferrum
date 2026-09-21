use std::path::{Path, PathBuf};

use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("workspace root")
}

#[test]
fn apex_contract_wraps_but_does_not_replace_ferrum_event_contract() {
    let root = root();
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("apex-contract/manifest.json")).unwrap(),
    )
    .unwrap();

    assert_eq!(manifest["apex_contract_version"], "1.0");
    assert_eq!(manifest["canonical"]["commit"], "878d138c560cd4106ab0d6cccde804ddc3e5ae1d");
    assert_eq!(manifest["system"], "ferrum");
    assert_eq!(manifest["namespace"], "ferrum");
    assert_eq!(
        manifest["identity"]["trust_unsigned_role_header"],
        Value::Bool(false)
    );

    let boundary = &manifest["boundaries"][0];
    assert_eq!(boundary["event_type"], "apex.ferrum.enforcement.v1");
    assert_eq!(
        boundary["payload_contract"],
        "crates/ferrum-proto/schema/v1.1.json"
    );

    let native: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("crates/ferrum-proto/schema/v1.1.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(native["schema"], ferrum_proto::EVENT_SCHEMA);
    assert_eq!(
        native["version"].as_str().unwrap(),
        ferrum_proto::EVENT_SCHEMA_VERSION.to_string()
    );
}
