//! ferrumctl — единственный честный способ проверить политику без кластера.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ferrum_api::{
    ClusterSecurityPolicy, ClusterSecurityPolicySpec, PolicyException, PolicyExceptionSpec,
    SecurityPolicy, SecurityPolicySpec,
};
use ferrum_policy::{validate_cluster_policy, validate_exception, validate_namespaced_policy};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ferrumctl", about = "FERRUM policy toolchain. Не заменяет kube-bench.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Проверить YAML политики/исключения на инварианты.
    Validate { path: PathBuf },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TypedMeta {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Validate { path } => validate_file(&path),
    }
}

fn validate_file(path: &PathBuf) -> Result<()> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let meta: TypedMeta = serde_yaml::from_str(&raw).context("parse apiVersion/kind")?;
    if meta.api_version != "ferrum.io/v1" {
        bail!("unsupported apiVersion {}", meta.api_version);
    }

    match meta.kind.as_str() {
        "ClusterSecurityPolicy" => {
            let obj: ClusterSecurityPolicy =
                serde_yaml::from_str(&raw).or_else(|_| parse_spec_wrapped::<ClusterSecurityPolicySpec, _>(&raw, |s| {
                    ClusterSecurityPolicy::new("", s)
                }))?;
            validate_cluster_policy(&obj.spec).map_err(|e| anyhow::anyhow!(e))?;
        }
        "SecurityPolicy" => {
            let spec: SecurityPolicySpec = extract_spec(&raw)?;
            validate_namespaced_policy(&spec).map_err(|e| anyhow::anyhow!(e))?;
            let _ = SecurityPolicy::new("", spec);
        }
        "PolicyException" => {
            let spec: PolicyExceptionSpec = extract_spec(&raw)?;
            validate_exception(&spec).map_err(|e| anyhow::anyhow!(e))?;
            let _ = PolicyException::new("", spec);
        }
        other => bail!("kind {other} validate ещё не подключён"),
    }

    println!("ok: {}", path.display());
    Ok(())
}

fn extract_spec<T: for<'de> Deserialize<'de>>(raw: &str) -> Result<T> {
    #[derive(Deserialize)]
    struct Wrap<T> {
        spec: T,
    }
    let wrap: Wrap<T> = serde_yaml::from_str(raw).context("parse spec")?;
    Ok(wrap.spec)
}

fn parse_spec_wrapped<S, T>(
    raw: &str,
    build: impl FnOnce(S) -> T,
) -> Result<T>
where
    S: for<'de> Deserialize<'de>,
{
    Ok(build(extract_spec(raw)?))
}
