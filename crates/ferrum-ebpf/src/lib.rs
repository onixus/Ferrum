use ferrum_common::{FerrumError, Result};
use ferrum_ids::Digest;

pub fn load_bundle(_digest: &Digest, _spec: &[u8]) -> Result<()> {
    Err(FerrumError::Degraded("eBPF loader not linked".into()))
}
