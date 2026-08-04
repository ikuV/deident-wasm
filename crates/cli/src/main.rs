//! `deident` — CLI for the privacy transformation engine.
//!
//! Commands:
//! - `pseudonymize`: reversible, deterministic tokenization of direct
//!   identifiers (output remains personal data),
//! - `anonymize`: irreversible, risk-assessed transformation of direct and
//!   quasi-identifiers with a JSON risk report,
//! - `chain`: several datasets of one export, with shared token scoping,
//! - `lint`: report risky-but-valid policy patterns,
//! - `vault`: inspect/export an encrypted mapping vault,
//! - `reverse`: re-identify tokenized columns using a vault,
//! - `dicom`: de-identify DICOM instance metadata (a separate data model, see
//!   the `deident-dicom` crate).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};
use deident_core::lint::LintLevel;
use deident_core::vault::{MappingEntry, derive_vault_key, read_vault};
use deident_host::wasm::FuelPolicy;
use deident_host::{AuditLog, AuditedEngine, Engine, NativeEngine, WasmEngine, WasmLimits};
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
    /// Run several datasets of one logical export as a chain, with shared
    /// token scoping and a combined report.
    Chain(ChainArgs),
    /// Check a policy for risky-but-valid configurations.
    Lint(LintArgs),
    /// Inspect or export an encrypted mapping vault.
    Vault(VaultArgs),
    /// Re-identify tokenized columns of a dataset using a vault.
    Reverse(ReverseArgs),
    /// De-identify DICOM instance metadata (single file or directory tree).
    Dicom(DicomArgs),
}

#[derive(Args)]
struct DicomArgs {
    /// Input `.dcm` file, or a directory to process recursively.
    input: PathBuf,
    /// DICOM policy YAML (`kind: dicom`).
    #[arg(long)]
    policy: PathBuf,
    /// Output file, or output directory when the input is a directory.
    #[arg(long)]
    out: PathBuf,
    /// Optional JSON report (per-instance, or aggregated for a directory).
    #[arg(long)]
    report: Option<PathBuf>,
    /// Write an encrypted mapping vault recording every reversible mapping.
    #[arg(long)]
    vault: Option<PathBuf>,
}

#[derive(Args)]
struct JobArgs {
    /// Input file (.csv, .jsonl, .parquet).
    input: PathBuf,
    /// Policy YAML describing field classes and strategies.
    #[arg(long)]
    policy: PathBuf,
    /// Output file; its extension selects the output format.
    #[arg(long)]
    out: PathBuf,
    /// Optional JSON risk report file.
    #[arg(long)]
    report: Option<PathBuf>,
    /// Write an encrypted mapping vault (re-identification material) here.
    #[arg(long)]
    vault: Option<PathBuf>,

    #[command(flatten)]
    lint: LintPolicyArgs,
    #[command(flatten)]
    engine: EngineArgs,
}

#[derive(Args)]
struct ChainArgs {
    /// Chain manifest YAML listing the jobs (inputs, policies, outputs).
    manifest: PathBuf,

    /// Transformation mode applied to every job in the chain.
    #[arg(long, value_enum)]
    mode: CliMode,

    /// Optional combined JSON chain report file.
    #[arg(long)]
    report: Option<PathBuf>,

    #[command(flatten)]
    engine: EngineArgs,
}

#[derive(Args)]
struct LintArgs {
    /// Policy YAML to check.
    policy: PathBuf,
    /// Restrict to lints relevant for one mode.
    #[arg(long, value_enum)]
    mode: Option<CliMode>,
    /// Emit findings as JSON.
    #[arg(long)]
    json: bool,
    /// Exit non-zero if any warning-level lint fires.
    #[arg(long)]
    deny: bool,
}

#[derive(Args)]
struct VaultArgs {
    #[command(subcommand)]
    command: VaultCommand,
}

#[derive(Subcommand)]
enum VaultCommand {
    /// Decrypt a vault and write its mappings as CSV (token,original).
    Export(VaultExportArgs),
}

#[derive(Args)]
struct VaultExportArgs {
    /// Encrypted vault file.
    vault: PathBuf,
    /// Policy the vault was produced with (supplies dataset + key source).
    #[arg(long)]
    policy: PathBuf,
    /// Output CSV; defaults to stdout.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
struct ReverseArgs {
    /// Pseudonymized input file.
    input: PathBuf,
    /// Encrypted vault holding the mappings.
    #[arg(long)]
    vault: PathBuf,
    /// Policy the data was produced with (supplies dataset + key source).
    #[arg(long)]
    policy: PathBuf,
    /// Output file with tokens replaced by their original values.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct LintPolicyArgs {
    /// Skip the pre-flight policy lint.
    #[arg(long)]
    no_lint: bool,
    /// Refuse to run when a warning-level lint fires.
    #[arg(long)]
    deny_lints: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliMode {
    Pseudonymize,
    Anonymize,
}

impl From<CliMode> for Mode {
    fn from(mode: CliMode) -> Self {
        match mode {
            CliMode::Pseudonymize => Mode::Pseudonymize,
            CliMode::Anonymize => Mode::Anonymize,
        }
    }
}

#[derive(Args)]
struct EngineArgs {
    /// Execution engine. `auto` (default) uses the wasm sandbox when a worker
    /// module is available and falls back to in-process execution with a
    /// warning; `wasm` requires the sandbox; `native` runs in-process.
    #[arg(long, value_enum, default_value_t = EngineKind::Auto)]
    engine: EngineKind,

    /// Path to the compiled worker module. Defaults to
    /// `$DEIDENT_WORKER_WASM`, then `deident-worker.wasm` next to this
    /// binary, then the local cargo build under target/wasm32-wasip1/.
    #[arg(long)]
    worker: Option<PathBuf>,

    /// Guest memory limit in MiB (sandbox only).
    #[arg(long, default_value_t = 256)]
    max_memory_mib: usize,

    /// Job timeout in seconds (sandbox only).
    #[arg(long, default_value_t = 30)]
    timeout_secs: u64,

    /// Fixed CPU budget in Wasmtime fuel units (sandbox only). Default scales
    /// the budget with the input size.
    #[arg(long)]
    fuel: Option<u64>,

    /// Disable fuel metering; the wall-clock timeout still applies.
    #[arg(long, conflicts_with = "fuel")]
    no_fuel: bool,

    /// Append a structured JSONL audit record per job to this file.
    #[arg(long)]
    audit_log: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum EngineKind {
    Auto,
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
    let result = match &cli.command {
        Command::Pseudonymize(args) => run_job(Mode::Pseudonymize, args),
        Command::Anonymize(args) => run_job(Mode::Anonymize, args),
        Command::Chain(args) => run_chain(args),
        Command::Lint(args) => run_lint(args),
        Command::Vault(args) => run_vault(args),
        Command::Reverse(args) => run_reverse(args),
        Command::Dicom(args) => run_dicom(args),
    };

    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

// --- transformation jobs -------------------------------------------------

fn run_job(mode: Mode, args: &JobArgs) -> anyhow::Result<ExitCode> {
    let policy_yaml = std::fs::read_to_string(&args.policy)
        .with_context(|| format!("cannot read policy '{}'", args.policy.display()))?;

    if !args.lint.no_lint
        && let Some(code) = preflight_lint(&policy_yaml, Some(mode), args.lint.deny_lints)?
    {
        return Ok(code);
    }

    let request = JobRequest {
        job_id: uuid::Uuid::new_v4().to_string(),
        mode,
        policy_yaml,
        input_path: path_to_string(&args.input)?,
        output_path: path_to_string(&args.out)?,
        report_path: args.report.as_deref().map(path_to_string).transpose()?,
        vault_path: args.vault.as_deref().map(path_to_string).transpose()?,
    };

    // The sandbox build has no Parquet support (it would bloat the guest
    // module), so an `auto` run involving Parquet must stay in-process.
    let needs_native = [&request.input_path, &request.output_path]
        .iter()
        .any(|path| is_parquet(path));
    let engine = build_engine_for(&args.engine, needs_native)?;
    let audit = args.engine.audit_log.as_ref().map(AuditLog::new);
    let response = match &audit {
        Some(log) => AuditedEngine::new(engine.as_ref(), log.clone()).run(&request)?,
        None => engine.run(&request)?,
    };

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

fn run_chain(args: &ChainArgs) -> anyhow::Result<ExitCode> {
    let engine = build_engine(&args.engine)?;
    let audit = args.engine.audit_log.as_ref().map(AuditLog::new);
    let audited;
    let engine: &dyn Engine = match &audit {
        Some(log) => {
            audited = AuditedEngine::new(engine.as_ref(), log.clone());
            &audited
        }
        None => engine.as_ref(),
    };
    let report = deident_host::run_chain(&args.manifest, args.mode.into(), engine)?;

    println!(
        "Chain '{}' ({:?}): {} of {} job(s) succeeded",
        report.name,
        report.mode,
        report
            .jobs
            .iter()
            .filter(|j| matches!(j.outcome, JobOutcome::Succeeded { .. }))
            .count(),
        report.jobs.len()
    );
    for job in &report.jobs {
        match &job.outcome {
            JobOutcome::Succeeded { report } => println!(
                "  {}: ok — {} row(s) -> {}",
                job.name, report.rows_written, job.output
            ),
            JobOutcome::Failed { error } => println!("  {}: FAILED — {error}", job.name),
        }
    }
    for warning in &report.warnings {
        println!("  warning: {warning}");
    }
    if let Some(report_path) = &args.report {
        std::fs::write(report_path, serde_json::to_vec_pretty(&report)?)
            .with_context(|| format!("cannot write chain report '{}'", report_path.display()))?;
        println!("  report: {}", report_path.display());
    }

    Ok(if report.completed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

// --- lint ----------------------------------------------------------------

fn run_lint(args: &LintArgs) -> anyhow::Result<ExitCode> {
    let policy_yaml = std::fs::read_to_string(&args.policy)
        .with_context(|| format!("cannot read policy '{}'", args.policy.display()))?;
    let policy = deident_core::Policy::from_yaml(&policy_yaml)
        .with_context(|| format!("invalid policy '{}'", args.policy.display()))?;
    let lints = deident_core::lint(&policy, args.mode.map(Into::into));

    if args.json {
        println!("{}", serde_json::to_string_pretty(&lints)?);
    } else if lints.is_empty() {
        println!("No lints for '{}'.", args.policy.display());
    } else {
        for lint in &lints {
            let subject = lint
                .subject
                .as_ref()
                .map(|s| format!(" [{s}]"))
                .unwrap_or_default();
            println!("{}{}: {} ({})", lint.level.label(), subject, lint.message, lint.rule);
        }
    }

    let warnings = lints.iter().filter(|l| l.level == LintLevel::Warning).count();
    Ok(if args.deny && warnings > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

/// Lint before a job. Returns `Some(exit code)` when the job must not run.
fn preflight_lint(
    policy_yaml: &str,
    mode: Option<Mode>,
    deny: bool,
) -> anyhow::Result<Option<ExitCode>> {
    let Ok(policy) = deident_core::Policy::from_yaml(policy_yaml) else {
        // Let the job itself produce the parse error, with its own context.
        return Ok(None);
    };
    let lints = deident_core::lint(&policy, mode);
    let warnings: Vec<_> = lints
        .iter()
        .filter(|l| l.level == LintLevel::Warning)
        .collect();
    for lint in &warnings {
        let subject = lint
            .subject
            .as_ref()
            .map(|s| format!(" [{s}]"))
            .unwrap_or_default();
        eprintln!("policy lint{}: {} ({})", subject, lint.message, lint.rule);
    }
    if deny && !warnings.is_empty() {
        eprintln!(
            "error: {} policy lint warning(s) and --deny-lints is set; not running the job",
            warnings.len()
        );
        return Ok(Some(ExitCode::FAILURE));
    }
    Ok(None)
}

// --- vault & reversal ----------------------------------------------------

/// Load a policy and derive its vault key.
fn vault_key_for(policy_path: &Path) -> anyhow::Result<([u8; 32], String)> {
    let policy_yaml = std::fs::read_to_string(policy_path)
        .with_context(|| format!("cannot read policy '{}'", policy_path.display()))?;
    let policy = deident_core::Policy::from_yaml(&policy_yaml)
        .with_context(|| format!("invalid policy '{}'", policy_path.display()))?;
    let mut warnings = Vec::new();
    let secret = deident_core::key::resolve_secret(&policy, &mut warnings)
        .context("cannot resolve the key material the vault was encrypted with")?;
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
    Ok((derive_vault_key(&secret, &policy.dataset), policy.dataset))
}

fn load_vault(vault_path: &Path, policy_path: &Path) -> anyhow::Result<Vec<MappingEntry>> {
    let (key, _dataset) = vault_key_for(policy_path)?;
    let file = std::fs::File::open(vault_path)
        .with_context(|| format!("cannot open vault '{}'", vault_path.display()))?;
    read_vault(std::io::BufReader::new(file), &key)
        .with_context(|| format!("cannot read vault '{}'", vault_path.display()))
}

fn run_vault(args: &VaultArgs) -> anyhow::Result<ExitCode> {
    match &args.command {
        VaultCommand::Export(args) => {
            let entries = load_vault(&args.vault, &args.policy)?;
            let mut writer: Box<dyn std::io::Write> = match &args.out {
                Some(path) => Box::new(std::io::BufWriter::new(
                    std::fs::File::create(path)
                        .with_context(|| format!("cannot create '{}'", path.display()))?,
                )),
                None => Box::new(std::io::stdout().lock()),
            };
            let mut csv = csv::Writer::from_writer(&mut writer);
            csv.write_record(["domain", "token", "original"])?;
            for entry in &entries {
                csv.write_record([&entry.field, &entry.token, &entry.original])?;
            }
            csv.flush()?;
            drop(csv);
            if let Some(path) = &args.out {
                eprintln!(
                    "Exported {} mapping(s) to {} — this file is re-identification material.",
                    entries.len(),
                    path.display()
                );
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn run_reverse(args: &ReverseArgs) -> anyhow::Result<ExitCode> {
    let entries = load_vault(&args.vault, &args.policy)?;
    // Column tokens replaced a whole cell, but pattern tokens and mocks were
    // substituted *inside* a value (an IBAN within a free-text note), so they
    // have to be reversed as substrings.
    let mut whole_cell: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    let mut embedded: Vec<(&str, &str)> = Vec::new();
    for entry in &entries {
        if entry.field.starts_with("pattern:") {
            embedded.push((entry.token.as_str(), entry.original.as_str()));
        } else {
            whole_cell.insert(entry.token.as_str(), entry.original.as_str());
        }
    }
    // Longest first, so a short replacement cannot clobber part of a longer
    // token that contains it.
    embedded.sort_by_key(|(token, _)| std::cmp::Reverse(token.len()));

    let input_format = deident_core::Format::for_path(&path_to_string(&args.input)?)?;
    let output_format = deident_core::Format::for_path(&path_to_string(&args.out)?)?;
    let input = std::io::BufReader::new(
        std::fs::File::open(&args.input)
            .with_context(|| format!("cannot open input '{}'", args.input.display()))?,
    );
    let output = std::io::BufWriter::new(
        std::fs::File::create(&args.out)
            .with_context(|| format!("cannot create output '{}'", args.out.display()))?,
    );

    let mut reader = deident_core::format::reader(input_format, input)?;
    let mut writer = deident_core::format::writer(output_format, output)?;
    let headers = reader.headers()?;
    writer.write_headers(&headers)?;

    let mut rows = 0u64;
    let mut restored = 0u64;
    while let Some(row) = reader.next_row()? {
        let restored_row: Vec<String> = row
            .into_iter()
            .map(|cell| {
                if let Some(original) = whole_cell.get(cell.as_str()) {
                    restored += 1;
                    return (*original).to_string();
                }
                let mut value = cell;
                for (token, original) in &embedded {
                    let hits = value.matches(token).count();
                    if hits > 0 {
                        value = value.replace(token, original);
                        restored += hits as u64;
                    }
                }
                value
            })
            .collect();
        writer.write_row(&restored_row)?;
        rows += 1;
    }
    writer.finish()?;

    println!(
        "Reversed {restored} value(s) across {rows} row(s) using {} mapping(s) -> {}",
        entries.len(),
        args.out.display()
    );
    println!("  note: the output contains original personal data again");
    Ok(ExitCode::SUCCESS)
}

// --- DICOM ---------------------------------------------------------------

fn run_dicom(args: &DicomArgs) -> anyhow::Result<ExitCode> {
    let policy_yaml = std::fs::read_to_string(&args.policy)
        .with_context(|| format!("cannot read DICOM policy '{}'", args.policy.display()))?;
    let policy = deident_dicom::DicomPolicy::from_yaml(&policy_yaml)
        .with_context(|| format!("invalid DICOM policy '{}'", args.policy.display()))?;
    let options = deident_dicom::engine::RunOptions {
        vault_path: args.vault.clone(),
    };

    // The DICOM stack is not compiled into the wasm guest, so these jobs always
    // run in-process. Say so rather than implying sandbox isolation.
    eprintln!(
        "note: DICOM jobs run in-process; the wasm sandbox does not carry the DICOM parser"
    );

    if args.input.is_dir() {
        let report =
            deident_dicom::deidentify_directory(&args.input, &args.out, &policy, &options)?;
        println!(
            "DICOM de-identification: {} instance(s) written, {} failed, {} skipped (dataset '{}')",
            report.instances_written,
            report.instances_failed,
            report.non_dicom_skipped,
            report.dataset
        );
        println!(
            "  {} distinct UID(s) remapped consistently across the run",
            report.distinct_uids_remapped
        );
        println!("  highest pixel risk: {}", report.highest_pixel_risk);
        for warning in &report.warnings {
            println!("  warning: {warning}");
        }
        print_pixel_caveat();
        if let Some(path) = &args.report {
            write_json(path, &report)?;
            println!("  report: {}", path.display());
        }
        return Ok(if report.instances_failed == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        });
    }

    let report = deident_dicom::deidentify_file(&args.input, &args.out, &policy, &options)?;
    println!(
        "DICOM de-identification complete: {} attribute(s) examined, {} modified (dataset '{}')",
        report.attributes_examined, report.attributes_modified, report.dataset
    );
    let mut by_action: std::collections::BTreeMap<&str, u64> = std::collections::BTreeMap::new();
    for finding in &report.tags {
        *by_action.entry(finding.action.as_str()).or_default() += finding.occurrences;
    }
    for (action, count) in by_action {
        println!("  {action}: {count} attribute(s)");
    }
    println!(
        "  {} UID(s) remapped, sequence depth {}, {} private attribute(s)",
        report.uids_remapped, report.max_sequence_depth, report.private_attributes
    );
    println!("  pixel risk: {}", report.pixel_risk.level);
    for warning in &report.warnings {
        println!("  warning: {warning}");
    }
    print_pixel_caveat();
    println!("  output: {}", args.out.display());
    if let Some(path) = &args.report {
        write_json(path, &report)?;
        println!("  report: {}", path.display());
    }
    if let Some(path) = &args.vault {
        println!("  vault: {}", path.display());
    }
    Ok(ExitCode::SUCCESS)
}

/// The one caveat that must never be omitted from a DICOM run.
fn print_pixel_caveat() {
    println!(
        "  note: pixel data was NOT modified — identifiers burned into the image survive; \
         coverage is a curated Annex E core, not full conformance"
    );
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    std::fs::write(path, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("cannot write '{}'", path.display()))
}

// --- engines -------------------------------------------------------------

/// Whether a path names a Parquet file (unsupported inside the sandbox).
fn is_parquet(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".parquet") || lower.ends_with(".pq")
}

fn build_engine(args: &EngineArgs) -> anyhow::Result<Box<dyn Engine>> {
    build_engine_for(args, false)
}

/// Build the requested engine. `needs_native` forces in-process execution in
/// `auto` mode for jobs the sandbox build cannot handle.
fn build_engine_for(args: &EngineArgs, needs_native: bool) -> anyhow::Result<Box<dyn Engine>> {
    let limits = WasmLimits {
        max_memory_bytes: args.max_memory_mib * 1024 * 1024,
        timeout: std::time::Duration::from_secs(args.timeout_secs),
        fuel: match (args.no_fuel, args.fuel) {
            (true, _) => FuelPolicy::Unmetered,
            (false, Some(fuel)) => FuelPolicy::Fixed(fuel),
            (false, None) => FuelPolicy::Scaled,
        },
    };
    match args.engine {
        EngineKind::Native => Ok(Box::new(NativeEngine)),
        EngineKind::Wasm => {
            let worker = resolve_worker_module(args.worker.as_deref())
                .context("--engine wasm was requested but no worker module was found")?;
            Ok(Box::new(WasmEngine::from_file(&worker, limits)?))
        }
        EngineKind::Auto if needs_native => {
            eprintln!(
                "note: running in-process without sandbox isolation because Parquet is not \
                 supported inside the sandbox build"
            );
            Ok(Box::new(NativeEngine))
        }
        EngineKind::Auto => match resolve_worker_module(args.worker.as_deref()) {
            Ok(worker) => Ok(Box::new(WasmEngine::from_file(&worker, limits)?)),
            Err(err) => {
                eprintln!(
                    "warning: running in-process without sandbox isolation ({err}); \
                     pass --engine wasm to require the sandbox"
                );
                Ok(Box::new(NativeEngine))
            }
        },
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
        "no worker module found (looked at: {}); build it with \
         `cargo build -p deident-worker --target wasm32-wasip1 --release` \
         or point --worker / $DEIDENT_WORKER_WASM at it",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

// --- output --------------------------------------------------------------

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
    for finding in &report.patterns {
        println!(
            "  pattern '{}' in {}: {} match(es) {}",
            finding.pattern, finding.field, finding.matches, finding.action
        );
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
    if let Some(vault_path) = &args.vault {
        println!("  vault: {}", vault_path.display());
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
