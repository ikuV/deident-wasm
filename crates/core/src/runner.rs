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
    // Creating the output truncates it, so writing over the input would destroy
    // the source before a byte is read — and the job would then "succeed" on an
    // empty file. Refuse instead, comparing canonical paths so `./a.csv` and
    // `a.csv` are recognised as the same file.
    refuse_in_place(&request.input_path, &request.output_path)?;
    let input = BufReader::new(File::open(&request.input_path).map_err(|e| {
        CoreError::Policy(format!("cannot open input '{}': {e}", request.input_path))
    })?);
    let output = BufWriter::new(File::create(&request.output_path).map_err(|e| {
        CoreError::Policy(format!("cannot create output '{}': {e}", request.output_path))
    })?);

    // A vault only makes sense when the job actually produces reversible
    // values (tokens or mocks); otherwise there is nothing to reverse.
    // Must consider the EXPANDED rule set: a policy whose tokenizing rules come
    // from `presets` still produces reversible values, and deciding otherwise
    // silently discards the vault while the report claims none was needed.
    let produces_tokens = request.mode == Mode::Pseudonymize
        || policy
            .effective_patterns()
            .iter()
            .any(|p| p.action.needs_key());
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

/// Reject an output path that resolves to the input file.
///
/// Canonicalizing the input is safe (it exists); the output usually does not, so
/// its parent directory is canonicalized and the file name appended. If either
/// path cannot be resolved the check passes — a genuinely broken path will fail
/// with a clearer error moments later when it is opened.
pub fn refuse_in_place(input: &str, output: &str) -> Result<(), CoreError> {
    let input_path = std::path::Path::new(input);
    let output_path = std::path::Path::new(output);
    let resolved_input = input_path.canonicalize();
    let resolved_output = match (output_path.parent(), output_path.file_name()) {
        (Some(parent), Some(name)) => {
            let parent = if parent.as_os_str().is_empty() {
                std::path::Path::new(".")
            } else {
                parent
            };
            parent.canonicalize().map(|dir| dir.join(name))
        }
        _ => return Ok(()),
    };
    if let (Ok(input), Ok(output)) = (resolved_input, resolved_output)
        && input == output
    {
        return Err(CoreError::Policy(format!(
            "refusing to write the output over the input ('{}'): that would destroy the source \
             data before it is read. Choose a different --out path"
        , input.display())));
    }
    Ok(())
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
