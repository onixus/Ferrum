use ferrum_api::ClusterSecurityPolicySpec;
use ferrum_common::{FerrumError, Result};
use ferrum_ids::Digest;
use ferrum_policy::validate_cluster_policy;

#[derive(Debug, Clone)]
pub struct CompiledBundle {
    pub digest: Digest,
    pub admission_program: Vec<u8>,
    pub ebpf_spec: Vec<u8>,
    pub wasm: Vec<u8>,
}

pub fn compile_cluster_policy(spec: &ClusterSecurityPolicySpec) -> Result<CompiledBundle> {
    validate_cluster_policy(spec)?;
    Err(FerrumError::Compile(
        "compiler backend not wired; admission must not wait for it per Pod".into(),
    ))
}
