//! Guest worker for the deident privacy transformation engine.
//!
//! Runs exactly one job and exits. The host (Phase 3: Wasmtime, fresh
//! Store/WasiCtx per job) preopens a single job workspace directory that
//! contains `request.json` and the input file; the worker writes the output,
//! optional report and `response.json` back into that same directory. It also
//! compiles natively so the protocol can be tested without a wasm runtime.
//!
//! Usage: `deident-worker [request_path] [response_path]`
//! (defaults: `/job/request.json`, `/job/response.json`)

use std::process::ExitCode;

use deident_types::{JobOutcome, JobRequest, JobResponse};

const DEFAULT_REQUEST_PATH: &str = "/job/request.json";
const DEFAULT_RESPONSE_PATH: &str = "/job/response.json";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let request_path = args.get(1).map_or(DEFAULT_REQUEST_PATH, String::as_str);
    let response_path = args.get(2).map_or(DEFAULT_RESPONSE_PATH, String::as_str);

    let response = match load_request(request_path) {
        Ok(request) => deident_core::runner::execute(&request),
        Err(error) => JobResponse {
            job_id: "unknown".to_string(),
            outcome: JobOutcome::Failed { error },
        },
    };

    let succeeded = matches!(response.outcome, JobOutcome::Succeeded { .. });
    match serde_json::to_string_pretty(&response) {
        Ok(json) => {
            if let Err(e) = std::fs::write(response_path, json) {
                eprintln!("deident-worker: cannot write response '{response_path}': {e}");
                return ExitCode::FAILURE;
            }
        }
        Err(e) => {
            eprintln!("deident-worker: cannot serialize response: {e}");
            return ExitCode::FAILURE;
        }
    }

    if succeeded { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

fn load_request(path: &str) -> Result<JobRequest, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read request '{path}': {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("invalid request '{path}': {e}"))
}
