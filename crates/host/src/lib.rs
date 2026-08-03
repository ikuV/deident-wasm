//! Execution engines for deident jobs.
//!
//! [`Engine`] abstracts *where* a job runs so callers (the CLI, future
//! services) don't care whether transformation happens in-process or inside
//! a per-job WebAssembly sandbox.

use deident_types::{JobRequest, JobResponse};

pub mod chain;
pub mod wasm;

pub use chain::{ChainManifest, run_chain};
pub use wasm::{WasmEngine, WasmLimits};

/// Runs one job to completion. Implementations must be safe to reuse across
/// jobs but must not share per-job state.
pub trait Engine {
    fn run(&self, request: &JobRequest) -> anyhow::Result<JobResponse>;
}

/// In-process execution of the shared core logic. No sandboxing — intended
/// for development, tests and as the reference behavior the wasm engine must
/// match byte-for-byte.
pub struct NativeEngine;

impl Engine for NativeEngine {
    fn run(&self, request: &JobRequest) -> anyhow::Result<JobResponse> {
        tracing::info!(job_id = %request.job_id, engine = "native", "running job");
        Ok(deident_core::runner::execute(request))
    }
}
