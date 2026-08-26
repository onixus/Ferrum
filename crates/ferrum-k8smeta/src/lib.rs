use ferrum_common::{FerrumError, Result};

#[derive(Debug, Clone)]
pub struct WorkloadIdentity {
    pub namespace: String,
    pub pod: String,
    pub container: String,
    pub service_account: String,
}

pub fn lookup_cgroup(_inode: u64) -> Result<WorkloadIdentity> {
    Err(FerrumError::Degraded("k8smeta cache empty".into()))
}
