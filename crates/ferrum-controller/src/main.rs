//! Offline compile+sign is the default. `run` watches a cluster.

use ferrum_api::{ClusterSecurityPolicy, ClusterSecurityPolicySpec, PolicyLibrarySpec};
use ferrum_controller::{
    compile_and_sign, compile_status_ok, hex_encode, load_seed, parse_public_key_hex,
    parse_seed_hex, run_watch, ClusterAbi, WatchConfig, DEFAULT_NAMESPACE,
};
use ferrum_crypto::ED25519_SECRET_KEY_LEN;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
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
    if policy_arg == "run" {
        let cfg = parse_run(args)?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("tokio runtime: {e}"))?;
        return rt.block_on(run_watch(cfg)).map_err(|e| e.to_string());
    }

    let key_hex = args.next().ok_or_else(usage)?;
    let out_path = args.next();
    if args.next().is_some() {
        return Err(usage());
    }

    let spec = load_spec(Path::new(&policy_arg))?;
    let secret = parse_seed_hex(&key_hex).map_err(|e| e.to_string())?;
    if secret.len() != ED25519_SECRET_KEY_LEN {
        return Err(format!(
            "Ed25519 seed must be {} bytes, got {}",
            ED25519_SECRET_KEY_LEN,
            secret.len()
        ));
    }
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

struct RunOpts {
    seed_file: Option<PathBuf>,
    status_dir: Option<PathBuf>,
    namespace: String,
    clusters: Vec<ClusterAbi>,
    min_agent_abi: u32,
    min_admission_abi: u32,
    trust_root: Option<String>,
}

fn parse_run(args: impl Iterator<Item = String>) -> Result<WatchConfig, String> {
    let mut opts = RunOpts {
        seed_file: None,
        status_dir: None,
        namespace: DEFAULT_NAMESPACE.to_string(),
        clusters: Vec::new(),
        min_agent_abi: 0,
        min_admission_abi: 0,
        trust_root: None,
    };
    let mut it = args;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => return Err(usage()),
            "--seed-file" => {
                opts.seed_file = Some(PathBuf::from(require_val("--seed-file", it.next())?));
            }
            "--namespace" => {
                opts.namespace = require_val("--namespace", it.next())?;
            }
            "--status-dir" => {
                opts.status_dir = Some(PathBuf::from(require_val("--status-dir", it.next())?));
            }
            "--cluster" => {
                opts.clusters
                    .push(parse_cluster(&require_val("--cluster", it.next())?)?);
            }
            "--min-agent-abi" => {
                opts.min_agent_abi = parse_u32(
                    "--min-agent-abi",
                    &require_val("--min-agent-abi", it.next())?,
                )?;
            }
            "--min-admission-abi" => {
                opts.min_admission_abi = parse_u32(
                    "--min-admission-abi",
                    &require_val("--min-admission-abi", it.next())?,
                )?;
            }
            "--trust-root" => {
                opts.trust_root = Some(require_val("--trust-root", it.next())?);
            }
            other => return Err(format!("unknown flag {other}\n{}", usage())),
        }
    }
    if opts.namespace.trim().is_empty() {
        return Err("--namespace must not be empty".into());
    }
    let secret_key = load_seed(opts.seed_file.as_deref()).map_err(|e| e.to_string())?;
    let trust_root = match opts.trust_root {
        Some(hex) => parse_public_key_hex(&hex).map_err(|e| e.to_string())?,
        None => ferrum_crypto::public_key_from_secret(&secret_key).map_err(|e| e.to_string())?,
    };
    let library = if opts.min_agent_abi == 0 && opts.min_admission_abi == 0 {
        None
    } else {
        Some(PolicyLibrarySpec {
            source: "cli".into(),
            digest: String::new(),
            min_agent_abi: opts.min_agent_abi,
            min_admission_abi: opts.min_admission_abi,
        })
    };
    Ok(WatchConfig {
        namespace: opts.namespace,
        secret_key,
        trust_root,
        library,
        clusters: opts.clusters,
        status_dir: opts.status_dir,
    })
}

fn parse_cluster(spec: &str) -> Result<ClusterAbi, String> {
    let mut parts = spec.split(':');
    let name = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "--cluster expected name:agentAbi:admissionAbi".to_string())?;
    let agent = parts
        .next()
        .ok_or_else(|| format!("--cluster {spec}: missing agentAbi"))?;
    let admission = parts
        .next()
        .ok_or_else(|| format!("--cluster {spec}: missing admissionAbi"))?;
    if parts.next().is_some() {
        return Err(format!(
            "--cluster {spec}: expected name:agentAbi:admissionAbi"
        ));
    }
    Ok(ClusterAbi {
        name: name.to_string(),
        agent_abi: parse_u32("--cluster agentAbi", agent)?,
        admission_abi: parse_u32("--cluster admissionAbi", admission)?,
    })
}

fn parse_u32(flag: &str, raw: &str) -> Result<u32, String> {
    raw.parse::<u32>()
        .map_err(|_| format!("{flag}: expected u32, got {raw}"))
}

/// The next token, once it has been shown not to be a flag.
///
/// No value in this grammar starts with `--`: a seed path, a namespace, a
/// `name:agentAbi:admissionAbi` triple, a u32, a hex key. Without this check
/// `run --namespace --cluster` swallows the flag as the namespace, passes the
/// emptiness test, and the controller reconciles a namespace that does not
/// exist. Most mis-orderings die on the following token instead, so this bites
/// only where the swallowed flag is last — which is the shape a truncated argv
/// or a Helm template with a trailing comma produces.
fn require_val(flag: &str, val: Option<String>) -> Result<String, String> {
    match val {
        Some(v) if v.starts_with("--") => Err(format!(
            "{flag} requires a value, got the flag {v}: no value in this grammar starts with --"
        )),
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(format!("{flag} requires a value")),
    }
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

fn usage() -> String {
    "usage: ferrum-controller <policy.yaml> <ed25519-seed-hex> [signed-bundle.fsig]\n       ferrum-controller run --seed-file <path> [--namespace ferrum] [--status-dir /run/ferrum] [--cluster name:agentAbi:admissionAbi]...".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A seed file good enough for `parse_run` to reach the end of the parse.
    /// Without one the argv below fails on the missing seed and says nothing
    /// about which namespace it was going to reconcile.
    fn seed_file() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ferrum-controller-seed-{}-{}",
            process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::write(&path, "11".repeat(ED25519_SECRET_KEY_LEN)).expect("seed file");
        path
    }

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    /// A flag is never a value.
    ///
    /// `run --namespace --cluster` is what a truncated argv or a Helm template
    /// with a trailing comma produces. Before the guard the parser took
    /// `--cluster` as the namespace: non-empty, so the `trim().is_empty()`
    /// check passed, and the controller went on to reconcile a namespace no
    /// cluster has. Every other parser in the tree already refuses this.
    #[test]
    fn a_flag_is_never_taken_as_the_value_of_the_flag_before_it() {
        let seed = seed_file();
        let seed = seed.to_string_lossy().into_owned();

        // The exact shape: the swallowed flag is the last token, so nothing
        // downstream trips over it.
        let err = parse_run(argv(&["--seed-file", &seed, "--namespace", "--cluster"]).into_iter())
            .expect_err("--cluster is not a namespace");
        assert!(err.contains("--namespace requires a value"), "{err}");
        assert!(err.contains("--cluster"), "{err}");

        // Every flag that takes a value, not just the one the report named.
        for flag in [
            "--seed-file",
            "--namespace",
            "--status-dir",
            "--cluster",
            "--min-agent-abi",
            "--min-admission-abi",
            "--trust-root",
        ] {
            let err = parse_run(argv(&[flag, "--trust-root"]).into_iter())
                .err()
                .unwrap_or_else(|| panic!("{flag} took a flag as its value"));
            assert!(
                err.contains(&format!("{flag} requires a value")),
                "{flag}: {err}"
            );
        }

        // And the well-formed argv still parses, with `--cluster`
        // accumulating rather than replacing.
        let cfg = parse_run(
            argv(&[
                "--seed-file",
                &seed,
                "--namespace",
                "ferrum",
                "--cluster",
                "east:3:2",
                "--cluster",
                "west:4:2",
            ])
            .into_iter(),
        )
        .expect("well-formed run argv");
        assert_eq!(cfg.namespace, "ferrum");
        assert_eq!(
            cfg.clusters
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>(),
            vec!["east", "west"]
        );
        let _ = fs::remove_file(&seed);
    }
}
