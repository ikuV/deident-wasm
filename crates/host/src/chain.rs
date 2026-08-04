//! Chained multi-dataset runs.
//!
//! A chain manifest lists several input/policy/output triples that belong to
//! one logical export. Running them as a chain (instead of separate CLI
//! invocations) buys:
//!
//! - **consistent key scoping** — an optional manifest-level `dataset` and
//!   `key` override every job's policy, so all files tokenize in the same
//!   scope and cross-file joins keep working (combine with per-field
//!   `pseudonymize.domain` when the linking columns are named differently),
//! - **linkage checks** — diverging dataset scopes in pseudonymize mode are
//!   flagged as warnings before they silently break joins,
//! - **one combined report** covering every job.

use std::path::{Path, PathBuf};

use anyhow::Context;
use deident_core::Policy;
use deident_core::policy::KeySource;
use deident_types::{ChainJobResult, ChainReport, JobOutcome, JobRequest, Mode};
use serde::Deserialize;

use crate::Engine;

/// A chain manifest, loaded from YAML.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainManifest {
    /// Manifest schema version; currently only `1`.
    pub version: u32,
    /// Chain name (used in job ids and the report).
    pub name: String,
    /// When set, overrides `dataset` in every job policy so all jobs share
    /// one token scope.
    #[serde(default)]
    pub dataset: Option<String>,
    /// When set, overrides the key source in every job policy.
    #[serde(default)]
    pub key: Option<KeySource>,
    pub jobs: Vec<ChainJobSpec>,
}

/// One dataset within a chain. Relative paths are resolved against the
/// manifest file's directory.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainJobSpec {
    pub name: String,
    pub input: PathBuf,
    pub policy: PathBuf,
    pub output: PathBuf,
    /// Optional per-job JSON risk report.
    #[serde(default)]
    pub report: Option<PathBuf>,
    /// Optional per-job encrypted mapping vault.
    #[serde(default)]
    pub vault: Option<PathBuf>,
}

impl ChainManifest {
    /// Load and validate a manifest from a YAML file.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read chain manifest '{}'", path.display()))?;
        let manifest: ChainManifest = serde_yaml::from_str(&raw)
            .with_context(|| format!("invalid chain manifest '{}'", path.display()))?;
        anyhow::ensure!(
            manifest.version == 1,
            "unsupported chain manifest version {} (expected 1)",
            manifest.version
        );
        anyhow::ensure!(!manifest.jobs.is_empty(), "chain has no jobs");
        // Names end up in job ids, logs and audit records, so keep them to a
        // boring character set rather than sanitizing at every use site.
        check_name("chain name", &manifest.name)?;
        let mut names = std::collections::HashSet::new();
        for job in &manifest.jobs {
            check_name("chain job name", &job.name)?;
            anyhow::ensure!(
                names.insert(job.name.as_str()),
                "chain job '{}' is listed more than once",
                job.name
            );
        }
        Ok(manifest)
    }
}

/// Reject names that are empty, over-long, or contain anything but
/// `[A-Za-z0-9._-]`. Path separators and `..` are the reason this exists.
fn check_name(what: &str, name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!name.is_empty(), "{what} must not be empty");
    anyhow::ensure!(
        name.len() <= 64,
        "{what} '{name}' is too long (max 64 characters)"
    );
    if let Some(bad) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
    {
        anyhow::bail!(
            "{what} '{name}' contains the disallowed character {bad:?}; \
             use letters, digits, '.', '_' or '-'"
        );
    }
    Ok(())
}

/// Run every job of the manifest at `manifest_path` sequentially through
/// `engine`, stopping at the first failure.
pub fn run_chain(
    manifest_path: &Path,
    mode: Mode,
    engine: &dyn Engine,
) -> anyhow::Result<ChainReport> {
    let manifest = ChainManifest::from_file(manifest_path)?;
    let base = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    tracing::info!(chain = %manifest.name, jobs = manifest.jobs.len(), "running chain");

    let mut warnings: Vec<String> = Vec::new();
    let mut prepared: Vec<(JobRequest, &ChainJobSpec)> = Vec::new();
    let mut datasets: Vec<String> = Vec::new();

    for job in &manifest.jobs {
        let policy_path = base.join(&job.policy);
        let policy_raw = std::fs::read_to_string(&policy_path).with_context(|| {
            format!("job '{}': cannot read policy '{}'", job.name, policy_path.display())
        })?;
        let mut policy = Policy::from_yaml(&policy_raw)
            .with_context(|| format!("job '{}': invalid policy", job.name))?;
        if let Some(dataset) = &manifest.dataset {
            policy.dataset = dataset.clone();
        }
        if let Some(key) = &manifest.key {
            policy.key = Some(key.clone());
        }
        datasets.push(policy.dataset.clone());

        let output = base.join(&job.output);
        if let Some(parent) = output.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("job '{}': cannot create output directory '{}'", job.name, parent.display())
            })?;
        }
        let request = JobRequest {
            job_id: format!("{}:{}", manifest.name, job.name),
            mode,
            policy_yaml: serde_yaml::to_string(&policy)
                .context("cannot re-serialize policy with chain overrides")?,
            input_path: path_string(&base.join(&job.input))?,
            output_path: path_string(&output)?,
            report_path: job
                .report
                .as_ref()
                .map(|p| path_string(&base.join(p)))
                .transpose()?,
            vault_path: job
                .vault
                .as_ref()
                .map(|p| path_string(&base.join(p)))
                .transpose()?,
        };
        prepared.push((request, job));
    }

    // Diverging token scopes silently break cross-file joins — flag them.
    if mode == Mode::Pseudonymize && manifest.dataset.is_none() {
        let first = &datasets[0];
        if datasets.iter().any(|d| d != first) {
            warnings.push(format!(
                "job policies use different 'dataset' scopes ({}); the same value will tokenize \
                 differently across files — set a chain-level 'dataset' to link them",
                datasets.join(", ")
            ));
        }
    }

    let mut jobs: Vec<ChainJobResult> = Vec::new();
    let mut completed = true;
    for (request, spec) in &prepared {
        let response = engine.run(request)?;
        let failed = matches!(response.outcome, JobOutcome::Failed { .. });
        jobs.push(ChainJobResult {
            name: spec.name.clone(),
            input: request.input_path.clone(),
            output: request.output_path.clone(),
            outcome: response.outcome,
        });
        if failed {
            completed = false;
            let remaining = prepared.len() - jobs.len();
            if remaining > 0 {
                warnings.push(format!(
                    "chain stopped at failed job '{}'; {remaining} job(s) were not run",
                    spec.name
                ));
            }
            break;
        }
    }

    Ok(ChainReport {
        tool_version: deident_types::VERSION.to_string(),
        name: manifest.name,
        mode,
        completed,
        jobs,
        warnings,
    })
}

fn path_string(path: &Path) -> anyhow::Result<String> {
    path.to_str()
        .map(str::to_string)
        .with_context(|| format!("path '{}' is not valid UTF-8", path.display()))
}
