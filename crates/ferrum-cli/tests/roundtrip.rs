//! compile → sign → verify через реальный бинарь ferrumctl, без кластера.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

// RFC 8032 §7.1 test-1 seed/public key: fixture only, not a prod key.
const SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PK_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn ferrumctl(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ferrumctl"))
        .args(args)
        .output()
        .expect("run ferrumctl")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn example(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../policies/examples")
        .join(name)
        .display()
        .to_string()
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ferrumctl-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn digest_from(line: &str) -> String {
    let digest = line
        .split("digest=")
        .nth(1)
        .expect("digest in output")
        .trim()
        .to_string();
    assert_eq!(digest.len(), 64, "sha256 hex: {digest}");
    digest
}

#[test]
fn compile_sign_verify_roundtrip() {
    let dir = temp_dir("roundtrip");
    let frmb = dir.join("prod-restricted.frmb");
    let fsig = dir.join("prod-restricted.fsig");
    let key = dir.join("signer.hex");
    fs::write(&key, SEED_HEX).expect("key file");

    let out = ferrumctl(&[
        "compile",
        &example("prod-restricted.yaml"),
        "-o",
        frmb.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{out:?}");
    let compiled_digest = digest_from(&stdout(&out));
    assert!(fs::read(&frmb).expect("frmb").starts_with(b"FRMB"));

    let out = ferrumctl(&[
        "sign",
        frmb.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "-o",
        fsig.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(digest_from(&stdout(&out)), compiled_digest);
    assert!(fs::read(&fsig).expect("fsig").starts_with(b"FSIG"));

    let out = ferrumctl(&["verify", fsig.to_str().unwrap(), "--trust-root", PK_HEX]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(digest_from(&stdout(&out)), compiled_digest);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn verify_rejects_wrong_pin_and_tampered_payload() {
    let dir = temp_dir("reject");
    let frmb = dir.join("bundle.frmb");
    let fsig = dir.join("bundle.fsig");
    let key = dir.join("signer.hex");
    fs::write(&key, SEED_HEX).expect("key file");

    let out = ferrumctl(&[
        "compile",
        &example("prod-restricted.yaml"),
        "-o",
        frmb.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{out:?}");
    let out = ferrumctl(&[
        "sign",
        frmb.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "-o",
        fsig.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{out:?}");

    let wrong_pin = format!("{}{}", &PK_HEX[..62], "00");
    let out = ferrumctl(&["verify", fsig.to_str().unwrap(), "--trust-root", &wrong_pin]);
    assert!(!out.status.success(), "wrong pin must fail verify");

    let mut tampered = fs::read(&fsig).expect("fsig");
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let bad = dir.join("tampered.fsig");
    fs::write(&bad, &tampered).expect("tampered");
    let out = ferrumctl(&["verify", bad.to_str().unwrap(), "--trust-root", PK_HEX]);
    assert!(!out.status.success(), "tampered payload must fail verify");

    // Unsigned FRMB is not verifiable and not re-signable as FSIG input.
    let out = ferrumctl(&["verify", frmb.to_str().unwrap(), "--trust-root", PK_HEX]);
    assert!(!out.status.success(), "unsigned FRMB must fail verify");
    let out = ferrumctl(&[
        "sign",
        fsig.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "-o",
        dir.join("double.fsig").to_str().unwrap(),
    ]);
    assert!(!out.status.success(), "double-sign must fail");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn validate_examples_keep_their_verdicts() {
    let out = ferrumctl(&["validate", &example("prod-restricted.yaml")]);
    assert!(out.status.success(), "{out:?}");
    let out = ferrumctl(&["validate", &example("exception-ok.yaml")]);
    assert!(out.status.success(), "{out:?}");
    let out = ferrumctl(&["validate", &example("exception-bad-no-ticket.yaml")]);
    assert!(!out.status.success(), "bad example must keep failing");
}

#[test]
fn compile_rejects_invalid_policy() {
    let dir = temp_dir("invalid");
    let yaml = dir.join("bad.yaml");
    // disabled=true + mode=enforce is a validation error, not a compile warning.
    fs::write(
        &yaml,
        "apiVersion: ferrum.io/v1\nkind: ClusterSecurityPolicy\nmetadata:\n  name: bad\nspec:\n  mode: enforce\n  disabled: true\n",
    )
    .expect("bad yaml");
    let out = ferrumctl(&[
        "compile",
        yaml.to_str().unwrap(),
        "-o",
        dir.join("bad.frmb").to_str().unwrap(),
    ]);
    assert!(!out.status.success(), "invalid policy must not compile");
    let _ = fs::remove_dir_all(&dir);
}
