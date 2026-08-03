//! File-based job execution shared by the native engine and the wasm worker.

use std::fs::File;
use std::io::{BufReader, BufWriter};

use deident_types::{JobOutcome, JobRequest, JobResponse, RiskReport};

use crate::engine;
use crate::error::CoreError;
use crate::policy::Policy;
use crate::vault::NoopVault;

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
    let input = BufReader::new(File::open(&request.input_path).map_err(|e| {
        CoreError::Policy(format!("cannot open input '{}': {e}", request.input_path))
    })?);
    let output = BufWriter::new(File::create(&request.output_path).map_err(|e| {
        CoreError::Policy(format!("cannot create output '{}': {e}", request.output_path))
    })?);

    // TODO(roadmap, Phase 4): wire a persistent (encrypted) mapping vault.
    let mut vault = NoopVault;
    let report = engine::run_csv_job(request.mode, &policy, input, output, &mut vault)?;

    if let Some(report_path) = &request.report_path {
        let json = serde_json::to_vec_pretty(&report)
            .map_err(|e| CoreError::Policy(format!("cannot serialize report: {e}")))?;
        std::fs::write(report_path, json)?;
    }
    Ok(report)
}
