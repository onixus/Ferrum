//! ferrumctl — единственный честный способ проверить политику без кластера.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod validate;

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
    }
}
