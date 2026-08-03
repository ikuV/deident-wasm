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
use clap::{Args, Parser, Subcommand};
use deident_host::{Engine, NativeEngine};
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

    // MVP: in-process execution. Phase 3 adds `--engine wasm` running the
    // same request in a per-job Wasmtime sandbox.
    let response = NativeEngine.run(&request)?;

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
