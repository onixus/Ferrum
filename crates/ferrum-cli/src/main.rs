//! ferrumctl — единственный честный способ проверить политику без кластера.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod compile;
mod fsig;
mod sign;
mod validate;
mod verify;

#[derive(Parser)]
#[command(
    name = "ferrumctl",
    about = "FERRUM policy toolchain. Не заменяет kube-bench."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Проверить YAML политики/исключения на инварианты.
    Validate { path: PathBuf },
    /// Скомпилировать YAML в неподписанный FRMB PolicyBundle.
    Compile {
        path: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Подписать FRMB ключом (файл с 32-байтным hex Ed25519 seed) в FSIG.
    Sign {
        path: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Проверить подпись FSIG пином trust root (64 hex-символа Ed25519).
    Verify {
        path: PathBuf,
        #[arg(long)]
        trust_root: String,
    },
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
        Commands::Validate { path } => validate::validate_file(&path),
        Commands::Compile { path, output } => compile::compile_file(&path, &output),
        Commands::Sign { path, key, output } => sign::sign_file(&path, &key, &output),
        Commands::Verify { path, trust_root } => verify::verify_file(&path, &trust_root),
    }
}
