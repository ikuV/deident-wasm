//! File-based job execution shared by the native engine and the wasm worker.

use std::fs::File;
use std::io::{BufReader, BufWriter};

use deident_types::{JobOutcome, JobRequest, JobResponse, Mode, RiskReport};

use crate::engine;
use crate::error::CoreError;
use crate::format::Format;
use crate::key;
use crate::policy::Policy;
use crate::vault::{EncryptedVault, MappingVault, NoopVault, derive_vault_key};

/// Execute a job request against the local filesystem (host paths for the
/// native engine, guest paths inside the preopened dir for the wasm worker).
///
/// Never panics on job errors: failures are folded into the response so the
/// caller can report them uniformly.
pub fn execute(request: &JobRequest) -> JobResponse {
    let outcome = match run(request) {
        Ok(report) => JobOutcome::Succeeded {
            report: Box::new(report),
        },
        Err(err) => JobOutcome::Failed {
            error: err.to_string(),
        },
    };
    JobResponse {
        job_id: request.job_id.clone(),
        outcome,
    }
}

fn run(request: &JobRequest) -> Result<RiskReport, CoreError> {
    let policy = Policy::from_yaml(&request.policy_yaml)?;
    let input_format = Format::for_path(&request.input_path)?;
    let output_format = Format::for_path(&request.output_path)?;
    let input = BufReader::new(File::open(&request.input_path).map_err(|e| {
        CoreError::Policy(format!("cannot open input '{}': {e}", request.input_path))
    })?);
    let output = BufWriter::new(File::create(&request.output_path).map_err(|e| {
        CoreError::Policy(format!("cannot create output '{}': {e}", request.output_path))
    })?);

    // A vault only makes sense when the job actually produces reversible
    // values (tokens or mocks); otherwise there is nothing to reverse.
    let produces_tokens = request.mode == Mode::Pseudonymize
        || policy.patterns.iter().any(|p| p.action.needs_key());
    let report = match (&request.vault_path, produces_tokens) {
        (Some(path), true) => {
            let mut key_warnings = Vec::new();
            let secret = key::resolve_secret(&policy, &mut key_warnings)?;
            let vault_key = derive_vault_key(&secret, &policy.dataset);
            let file = BufWriter::new(File::create(path).map_err(|e| {
                CoreError::Vault(format!("cannot create vault '{path}': {e}"))
            })?);
            let mut vault = EncryptedVault::new(file, &vault_key, &policy.dataset);
            let mut report = run_job(request, &policy, input, output, input_format, output_format, &mut vault)?;
            report.warnings.push(format!(
                "an encrypted mapping vault was written to '{path}'; it is re-identification \
                 material — store and access-control it separately from the output"
            ));
            report
        }
        (Some(path), false) => {
            let mut report = run_job(
                request,
                &policy,
                input,
                output,
                input_format,
                output_format,
                &mut NoopVault,
            )?;
            report.warnings.push(format!(
                "no vault was written to '{path}': this job produces no reversible values"
            ));
            report
        }
        (None, _) => run_job(
            request,
            &policy,
            input,
            output,
            input_format,
            output_format,
            &mut NoopVault,
        )?,
    };

    if let Some(report_path) = &request.report_path {
        let json = serde_json::to_vec_pretty(&report)
            .map_err(|e| CoreError::Policy(format!("cannot serialize report: {e}")))?;
        std::fs::write(report_path, json)?;
    }
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn run_job<R: std::io::Read, W: std::io::Write + Send>(
    request: &JobRequest,
    policy: &Policy,
    input: R,
    output: W,
    input_format: Format,
    output_format: Format,
    vault: &mut dyn MappingVault,
) -> Result<RiskReport, CoreError> {
    engine::run_job(
        request.mode,
        policy,
        input,
        output,
        input_format,
        output_format,
        vault,
    )
}
