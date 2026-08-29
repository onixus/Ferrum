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

/// What a plane loading a signed bundle must do with the bundle's wasm slot,
/// and it is not «read the length and skip the bytes».
///
/// The slot is length-prefixed inside FRMB and covered by the bundle digest, so
/// whatever is in it is signed. Both planes used to drop it anyway:
/// `parse_frmb` in `ferrum-ebpf` and `extract_admission_program` in
/// `ferrum-admission` each took the slice and bound it to `_`. A bundle whose
/// slot carried a real module therefore loaded, and every rule that module was
/// meant to carry went unenforced — signed policy, silently not applied, with
/// no counter, no `Degraded` and nothing in the object to read it off. Signing
/// does not launder that: the signature says the controller wrote those bytes,
/// not that this binary can execute them.
///
/// There is no wasm executor in this tree — `eval_policy` refuses every input
/// it can parse, the placeholder included — so the only slot a plane may load
/// is one that asks for nothing to be executed: the versioned placeholder at
/// this host's ABI. Anything else is a bundle this binary cannot enforce in
/// full, and refusing it is the only answer that is not fail-open.
///
/// `Degraded` where a different build could answer differently — an ABI this
/// host does not speak, a module kind it has no executor for — so the plane
/// keeps last-known-good rather than treating the bundle as malformed.
/// `Compile` where the bytes are wrong for every build.
pub fn accept_bundle_slot(module: &[u8]) -> Result<()> {
    let header = ferrum_wasm_abi::parse_header(module).ok_or_else(|| {
        FerrumError::Compile(format!(
            "bundle wasm slot is not a Ferrum wasm module: {} bytes, no readable header",
            module.len()
        ))
    })?;
    check_header(header)?;
    match header.kind {
        ferrum_wasm_abi::KIND_PLACEHOLDER => Ok(()),
        other => Err(FerrumError::Degraded(format!(
            "bundle wasm slot carries module kind {other} and this host executes none: \
             loading it would enforce every part of the bundle except that module"
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
    use ferrum_wasm_abi::{placeholder_module, HEADER_LEN};

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

    /// The slot check is the inverse of `eval_policy` on exactly one input and
    /// agrees with it on every other: the placeholder is the only module a
    /// plane may load, and the only one no plane may run.
    #[test]
    fn only_the_versioned_placeholder_is_a_loadable_slot() {
        accept_bundle_slot(&placeholder_module()).expect("the placeholder asks for nothing");

        match accept_bundle_slot(&[]) {
            Err(FerrumError::Compile(msg)) => assert!(msg.contains("0 bytes"), "{msg}"),
            other => panic!("an empty slot is not a module, got {other:?}"),
        }
        match accept_bundle_slot(b"not-a-module") {
            Err(FerrumError::Compile(_)) => {}
            other => panic!("garbage must be refused, got {other:?}"),
        }
        match accept_bundle_slot(&placeholder_module()[..HEADER_LEN - 1]) {
            Err(FerrumError::Compile(_)) => {}
            other => panic!("a truncated header must be refused, got {other:?}"),
        }

        // Both of these could be a bundle a newer controller signed for a newer
        // plane, so they keep last-known-good rather than reading as corruption.
        let mut future_abi = placeholder_module();
        future_abi[4..8].copy_from_slice(&0xFFFFu32.to_le_bytes());
        match accept_bundle_slot(&future_abi) {
            Err(FerrumError::Degraded(msg)) => assert!(msg.contains("incompatible"), "{msg}"),
            other => panic!("an ABI this host does not speak is Degraded, got {other:?}"),
        }
        let mut real_module = placeholder_module();
        real_module[8] = 0x01;
        match accept_bundle_slot(&real_module) {
            Err(FerrumError::Degraded(msg)) => assert!(msg.contains("kind 1"), "{msg}"),
            other => panic!("a module this host cannot run must not load silently, got {other:?}"),
        }

        // And the reader on the input whose answer is known from the other
        // side: the one slot that loads is the one nothing executes.
        assert!(
            eval_policy(&placeholder_module(), b"").is_err(),
            "if the host ever executes the placeholder, `accept_bundle_slot` is deciding the \
             wrong question and both planes are back to loading modules they ignore"
        );
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
