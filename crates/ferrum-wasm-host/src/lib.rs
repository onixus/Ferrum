//! Wasm policy host. Empty, unknown ABI, or placeholder modules fail closed.
//! This slice does not embed wasmtime; it never allow-by-default.

#![deny(unsafe_code)]

use ferrum_common::{FerrumError, Result};
use ferrum_wasm_abi::ModuleHeader;

pub fn eval_policy(module: &[u8], _input: &[u8]) -> Result<bool> {
    if module.is_empty() {
        return Err(FerrumError::Degraded("wasm module is empty".into()));
    }
    let header = ferrum_wasm_abi::parse_header(module)
        .ok_or_else(|| FerrumError::Compile("wasm module missing or unknown ABI header".into()))?;
    check_header(header)?;
    match header.kind {
        ferrum_wasm_abi::KIND_PLACEHOLDER => Err(FerrumError::Degraded(
            "wasm module is a versioned placeholder; host does not execute it".into(),
        )),
        other => Err(FerrumError::Compile(format!(
            "unsupported wasm module kind {other}"
        ))),
    }
}

fn check_header(header: ModuleHeader) -> Result<()> {
    if header.abi != ferrum_wasm_abi::ABI_VERSION {
        return Err(FerrumError::Degraded(format!(
            "wasm ABI {} incompatible with host ABI {}",
            header.abi,
            ferrum_wasm_abi::ABI_VERSION
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_wasm_abi::placeholder_module;

    fn fail_closed(result: Result<bool>) {
        match result {
            Err(FerrumError::Degraded(_) | FerrumError::Compile(_)) => {}
            Ok(true) => panic!("eval_policy must not allow-by-default"),
            other => panic!("eval_policy must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn empty_fails_closed() {
        fail_closed(eval_policy(&[], b""));
        match eval_policy(&[], b"") {
            Err(FerrumError::Degraded(_)) => {}
            other => panic!("empty module should be Degraded, got {other:?}"),
        }
    }

    #[test]
    fn garbage_fails_closed() {
        fail_closed(eval_policy(b"\0asm garbage", b""));
        fail_closed(eval_policy(b"not-a-module", b""));
        match eval_policy(b"not-a-module", b"") {
            Err(FerrumError::Compile(_)) => {}
            other => panic!("garbage should be Compile, got {other:?}"),
        }
    }

    #[test]
    fn unknown_abi_fails_closed() {
        let mut blob = placeholder_module();
        blob[4..8].copy_from_slice(&0xFFFFu32.to_le_bytes());
        fail_closed(eval_policy(&blob, b""));
        match eval_policy(&blob, b"") {
            Err(FerrumError::Degraded(msg)) => {
                assert!(msg.contains("incompatible"), "{msg}");
            }
            other => panic!("unknown ABI should be Degraded, got {other:?}"),
        }
    }

    #[test]
    fn placeholder_fails_closed() {
        fail_closed(eval_policy(&placeholder_module(), b""));
        match eval_policy(&placeholder_module(), b"input") {
            Err(FerrumError::Degraded(_)) => {}
            other => panic!("placeholder should be Degraded, got {other:?}"),
        }
    }

    #[test]
    fn unknown_kind_fails_closed() {
        let mut blob = placeholder_module();
        blob[8] = 0x7F;
        fail_closed(eval_policy(&blob, b""));
        match eval_policy(&blob, b"") {
            Err(FerrumError::Compile(_)) => {}
            other => panic!("unknown kind should be Compile, got {other:?}"),
        }
    }
}
