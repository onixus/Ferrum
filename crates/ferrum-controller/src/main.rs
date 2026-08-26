//! Offline compile+sign. Does not watch a cluster.

use ferrum_api::{ClusterSecurityPolicy, ClusterSecurityPolicySpec};
use ferrum_controller::{compile_and_sign, compile_status_ok};
use ferrum_crypto::ED25519_SECRET_KEY_LEN;
use std::env;
use std::fs;
use std::path::Path;
use std::process;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let policy_arg = args.next().ok_or_else(usage)?;
    if policy_arg == "-h" || policy_arg == "--help" {
        println!("{}", usage());
        return Ok(());
    }
    let key_hex = args.next().ok_or_else(usage)?;
    let out_path = args.next();
    if args.next().is_some() {
        return Err(usage());
    }

    let spec = load_spec(Path::new(&policy_arg))?;
    let secret = parse_seed(&key_hex)?;
    let bundle = compile_and_sign(&spec, &secret).map_err(|e| e.to_string())?;
    let status = compile_status_ok(&bundle);

    println!("compile.ready: {}", status.ready);
    println!("compile.bundleDigest: {}", status.bundle_digest);
    println!("compile.compilerVersion: {}", status.compiler_version);
    println!("compile.message: {}", status.message);
    println!("publicKey: {}", hex_encode(&bundle.public_key));
    println!("signature: {}", hex_encode(&bundle.signature));
    println!("minAgentAbi: {}", bundle.min_agent_abi);
    println!("minAdmissionAbi: {}", bundle.min_admission_abi);

    if let Some(path) = out_path {
        let encoded = bundle.encode().map_err(|e| e.to_string())?;
        fs::write(&path, encoded).map_err(|e| format!("write {path}: {e}"))?;
        println!("wrote: {path}");
    }
    Ok(())
}

fn load_spec(path: &Path) -> Result<ClusterSecurityPolicySpec, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let kind = yaml_kind(&raw)?;
    match kind.as_str() {
        "" => {
            serde_yaml::from_str(&raw).map_err(|e| format!("parse ClusterSecurityPolicySpec: {e}"))
        }
        "ClusterSecurityPolicy" => {
            let obj: ClusterSecurityPolicy = serde_yaml::from_str(&raw)
                .map_err(|e| format!("parse ClusterSecurityPolicy: {e}"))?;
            Ok(obj.spec)
        }
        other => Err(format!(
            "kind {other} is not ClusterSecurityPolicy; this binary does not watch a cluster"
        )),
    }
}

fn yaml_kind(raw: &str) -> Result<String, String> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(raw).map_err(|e| format!("parse yaml: {e}"))?;
    let serde_yaml::Value::Mapping(map) = value else {
        return Ok(String::new());
    };
    let key = serde_yaml::Value::String("kind".into());
    match map.get(&key) {
        Some(serde_yaml::Value::String(kind)) => Ok(kind.clone()),
        _ => Ok(String::new()),
    }
}

fn parse_seed(hex: &str) -> Result<Vec<u8>, String> {
    let bytes = hex_decode(hex)?;
    if bytes.len() != ED25519_SECRET_KEY_LEN {
        return Err(format!(
            "Ed25519 seed must be {} bytes ({} hex chars), got {}",
            ED25519_SECRET_KEY_LEN,
            ED25519_SECRET_KEY_LEN * 2,
            bytes.len()
        ));
    }
    Ok(bytes)
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("hex seed has odd length".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("hex seed contains a non-hex character".into()),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn usage() -> String {
    "usage: ferrum-controller <policy.yaml> <ed25519-seed-hex> [signed-bundle.fsig]".into()
}
