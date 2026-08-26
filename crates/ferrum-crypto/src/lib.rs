use ferrum_common::{FerrumError, Result};
use ferrum_ids::Digest;

pub fn verify_bundle_signature(_raw: &[u8], _sig: &[u8]) -> Result<Digest> {
    Err(FerrumError::Integrity(
        "verify_bundle_signature: not implemented, and that is better than a fake Ok".into(),
    ))
}
