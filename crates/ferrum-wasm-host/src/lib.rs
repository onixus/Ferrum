use ferrum_common::{FerrumError, Result};

pub fn eval_policy(_module: &[u8], _input: &[u8]) -> Result<bool> {
    Err(FerrumError::Degraded("wasm host not embedded".into()))
}
