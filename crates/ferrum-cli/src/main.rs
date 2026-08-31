//! ferrumctl — единственный честный способ проверить политику без кластера.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use ferrum_cli::{break_glass, compile, gen_pki, lint_deploy, sign, validate, verify};

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
    /// Проверить манифесты установки на инварианты threat model. Офлайн, без kube.
    LintDeploy { dir: PathBuf },
    /// Выпустить офлайн CA и serving-сертификат вебхука; напечатать Secret и caBundle.
    GenWebhookPki {
        #[arg(long, default_value = "ferrum-admission")]
        service: String,
        #[arg(long, default_value = "ferrum")]
        namespace: String,
        #[arg(long, default_value_t = 365)]
        days: u64,
        /// Записать Secret, ca.crt и отрендеренную конфигурацию вебхука в каталог.
        #[arg(long)]
        out_dir: Option<PathBuf>,
        /// Шаблон вебхука; по умолчанию берётся из --out-dir.
        #[arg(long)]
        template: Option<PathBuf>,
        /// Ротация: переиспользовать этот CA вместо выпуска нового; caBundle не меняется.
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        /// Ключ CA для ротации; задаётся вместе с --ca-cert.
        #[arg(long)]
        ca_key: Option<PathBuf>,
        /// Применённая в кластере ValidatingWebhookConfiguration: её caBundle —
        /// единственное свидетельство того, какому CA кластер доверяет.
        /// Обязательна при ротации, если рядом с --ca-cert или --out-dir
        /// отрендеренной конфигурации нет.
        #[arg(long)]
        webhook_config: Option<PathBuf>,
    },
    /// Проверить подпись FSIG пином trust root (64 hex-символа Ed25519).
    Verify {
        path: PathBuf,
        #[arg(long)]
        trust_root: String,
    },
    /// Подписать break-glass grant его собственным доменом. Инварианты
    /// проверяются до подписи: окно, тикет, scope, непустые поля. Печатает
    /// публичный ключ seed'а — тот самый trust root, которым армируют кластер.
    SignBreakGlass {
        path: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Проверить цепочку break-glass журнала: нумерацию, ссылки и хеши.
    /// Печатает записи и голову цепочки.
    VerifyJournal { path: PathBuf },
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
        Commands::SignBreakGlass { path, key, output } => {
            break_glass::sign_grant(&path, &key, &output)
        }
        Commands::VerifyJournal { path } => break_glass::verify_journal(&path),
        Commands::LintDeploy { dir } => lint_deploy::lint_deploy_dir(&dir),
        Commands::GenWebhookPki {
            service,
            namespace,
            days,
            out_dir,
            template,
            ca_cert,
            ca_key,
            webhook_config,
        } => gen_pki::gen_webhook_pki(&gen_pki::GenPkiArgs {
            service,
            namespace,
            days,
            out_dir,
            template,
            ca_cert,
            ca_key,
            webhook_config,
        }),
    }
}
