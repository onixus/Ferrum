use ferrum_api::ClusterSecurityPolicySpec;

pub fn spec_from_yaml(yaml: &str) -> ClusterSecurityPolicySpec {
    serde_yaml::from_str(yaml).expect("fixture yaml")
}
