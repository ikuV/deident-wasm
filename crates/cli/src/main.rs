//! `deident` — CLI for the privacy transformation engine.
//!
//! Two modes:
//! - `pseudonymize`: reversible, deterministic tokenization of direct
//!   identifiers (output remains personal data),
//! - `anonymize`: irreversible, risk-assessed transformation of direct and
//!   quasi-identifiers with a JSON risk report.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};
use deident_host::{Engine, NativeEngine, WasmEngine, WasmLimits};
use deident_types::{JobOutcome, JobRequest, Mode, RiskReport};

#[derive(Parser)]
#[command(
    name = "deident",
    version,
    disable_version_flag = true,
    about = "Privacy transformation engine: pseudonymization and risk-assessed anonymization for structured datasets"
)]
struct Cli {
    /// Print version.
    #[arg(short = 'v', short_alias = 'V', long, action = clap::ArgAction::Version)]
    version: Option<bool>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Reversibly tokenize direct identifiers (deterministic per dataset/policy).
    Pseudonymize(JobArgs),
    /// Irreversibly remove/generalize identifiers and produce a risk report.
    Anonymize(JobArgs),
}

#[derive(Args)]
struct JobArgs {
    /// Input CSV file.
    input: PathBuf,
    /// Policy YAML describing field classes and strategies.
    #[arg(long)]
    policy: PathBuf,
    /// Output CSV file.
    #[arg(long)]
    out: PathBuf,
    /// Optional JSON risk report file.
    #[arg(long)]
    report: Option<PathBuf>,

    /// Execution engine: `wasm` runs the job in a per-job WebAssembly
    /// sandbox (fresh store, job directory as the only filesystem
    /// capability, no network); `native` runs in-process.
    #[arg(long, value_enum, default_value_t = EngineKind::Native)]
    engine: EngineKind,

    /// Path to the compiled worker module (wasm engine only). Defaults to
    /// `$DEIDENT_WORKER_WASM`, then `deident-worker.wasm` next to this
    /// binary, then the local cargo build under target/wasm32-wasip1/.
    #[arg(long)]
    worker: Option<PathBuf>,

    /// Guest memory limit in MiB (wasm engine only).
    #[arg(long, default_value_t = 256)]
    max_memory_mib: usize,

    /// Job timeout in seconds (wasm engine only).
    #[arg(long, default_value_t = 30)]
    timeout_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum EngineKind {
    Native,
    Wasm,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let (mode, args) = match &cli.command {
        Command::Pseudonymize(args) => (Mode::Pseudonymize, args),
        Command::Anonymize(args) => (Mode::Anonymize, args),
    };

    match run_job(mode, args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run_job(mode: Mode, args: &JobArgs) -> anyhow::Result<ExitCode> {
    let policy_yaml = std::fs::read_to_string(&args.policy)
        .with_context(|| format!("cannot read policy '{}'", args.policy.display()))?;

    let request = JobRequest {
        job_id: uuid::Uuid::new_v4().to_string(),
        mode,
        policy_yaml,
        input_path: path_to_string(&args.input)?,
        output_path: path_to_string(&args.out)?,
        report_path: args.report.as_deref().map(path_to_string).transpose()?,
    };

    let engine = build_engine(args)?;
    let response = engine.run(&request)?;

    match response.outcome {
        JobOutcome::Succeeded { report } => {
            print_summary(mode, args, &report);
            Ok(ExitCode::SUCCESS)
        }
        JobOutcome::Failed { error } => {
            eprintln!("error: job {} failed: {error}", response.job_id);
            Ok(ExitCode::FAILURE)
        }
    }
}

fn build_engine(args: &JobArgs) -> anyhow::Result<Box<dyn Engine>> {
    match args.engine {
        EngineKind::Native => Ok(Box::new(NativeEngine)),
        EngineKind::Wasm => {
            let worker = resolve_worker_module(args.worker.as_deref())?;
            let limits = WasmLimits {
                max_memory_bytes: args.max_memory_mib * 1024 * 1024,
                timeout: std::time::Duration::from_secs(args.timeout_secs),
                ..WasmLimits::default()
            };
            Ok(Box::new(WasmEngine::from_file(&worker, limits)?))
        }
    }
}

/// Locate the compiled worker module: explicit flag, then env var, then next
/// to the executable, then the local cargo build (dev convenience).
fn resolve_worker_module(flag: Option<&Path>) -> anyhow::Result<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(path) = flag {
        candidates.push(path.to_path_buf());
    }
    if let Ok(path) = std::env::var("DEIDENT_WORKER_WASM") {
        candidates.push(PathBuf::from(path));
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        candidates.push(dir.join("deident-worker.wasm"));
    }
    for profile in ["release", "debug"] {
        candidates.push(
            PathBuf::from("target/wasm32-wasip1")
                .join(profile)
                .join("deident-worker.wasm"),
        );
    }
    for candidate in &candidates {
        if candidate.is_file() {
            return Ok(candidate.clone());
        }
    }
    anyhow::bail!(
        "cannot find the worker module (looked at: {}); build it with \
         `cargo build -p deident-worker --target wasm32-wasip1 --release` \
         or point --worker / $DEIDENT_WORKER_WASM at it",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn print_summary(mode: Mode, args: &JobArgs, report: &RiskReport) {
    let mode_label = match mode {
        Mode::Pseudonymize => "Pseudonymize",
        Mode::Anonymize => "Anonymize",
    };
    println!(
        "{mode_label} complete: {} row(s) in, {} row(s) out (dataset '{}')",
        report.rows_read, report.rows_written, report.dataset
    );
    if !report.direct_identifiers.is_empty() {
        let actions: Vec<String> = report
            .direct_identifiers
            .iter()
            .map(|f| format!("{} ({})", f.field, f.action))
            .collect();
        println!("  direct identifiers: {}", actions.join(", "));
    }
    if let Some(qi) = &report.quasi_identifiers {
        println!(
            "  quasi-identifiers [{}]: {} equivalence class(es), min size {}, {} unique row(s) ({:.1}%)",
            qi.fields.join(", "),
            qi.equivalence_classes,
            qi.min_class_size,
            qi.unique_rows,
            qi.unique_row_ratio * 100.0
        );
    }
    for warning in &report.warnings {
        println!("  warning: {warning}");
    }
    println!("  output: {}", args.out.display());
    if let Some(report_path) = &args.report {
        println!("  report: {}", report_path.display());
    }
    if mode == Mode::Pseudonymize {
        println!(
            "  note: pseudonymized data remains personal data; protect the key material separately"
        );
    }
}

fn path_to_string(path: &Path) -> anyhow::Result<String> {
    path.to_str()
        .map(str::to_string)
        .with_context(|| format!("path '{}' is not valid UTF-8", path.display()))
}
