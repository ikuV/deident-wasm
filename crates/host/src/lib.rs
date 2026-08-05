//! Execution engines for deident jobs.
//!
//! [`Engine`] abstracts *where* a job runs so callers (the CLI, future
//! services) don't care whether transformation happens in-process or inside
//! a per-job WebAssembly sandbox.

use deident_types::{JobRequest, JobResponse};

pub mod audit;
pub mod chain;
pub mod parallel;
pub mod wasm;

pub use audit::{AuditLimits, AuditLog, AuditRecord};
pub use chain::{ChainManifest, run_chain};
pub use parallel::{ParallelOptions, run_many, run_split};
pub use wasm::{WasmEngine, WasmLimits};

/// Runs one job to completion. Implementations must be safe to reuse across
/// jobs but must not share per-job state.
///
/// `Send + Sync` is required because the parallel paths share one engine across
/// worker threads — that is the point of compiling the guest module once and
/// giving each job only its own `Store`.
pub trait Engine: Send + Sync {
    fn run(&self, request: &JobRequest) -> anyhow::Result<JobResponse>;

    /// Short engine name, recorded in logs and audit records.
    fn name(&self) -> &'static str;

    /// Resource limits this engine enforces, if any.
    fn audit_limits(&self) -> Option<AuditLimits> {
        None
    }

    /// Who authored the report this engine returns.
    ///
    /// `host-attested` means the host computed or verified the figures;
    /// `guest-attested` means they are a claim made by code running inside the
    /// sandbox. A compromised worker could report clean counts over untransformed
    /// data, so a consumer needs to know which it is holding.
    fn report_provenance(&self) -> &'static str {
        "host-attested"
    }
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

    fn name(&self) -> &'static str {
        "native"
    }
}

/// Decorator that appends an [`AuditRecord`] for every job an inner engine
/// runs. Wrapping rather than building the log into each engine keeps audit
/// behavior identical across native and sandboxed execution, including for
/// chained runs.
pub struct AuditedEngine<'a> {
    inner: &'a dyn Engine,
    log: AuditLog,
}

impl<'a> AuditedEngine<'a> {
    pub fn new(inner: &'a dyn Engine, log: AuditLog) -> Self {
        Self { inner, log }
    }
}

impl Engine for AuditedEngine<'_> {
    fn run(&self, request: &JobRequest) -> anyhow::Result<JobResponse> {
        let response = self.inner.run(request);
        // A failed *engine* (not a failed job) is still worth an audit line.
        let record_response = match &response {
            Ok(response) => response.clone(),
            Err(err) => JobResponse {
                job_id: request.job_id.clone(),
                outcome: deident_types::JobOutcome::Failed {
                    error: format!("{err:#}"),
                },
            },
        };
        if let Err(err) = self.log.record(
            request,
            &record_response,
            self.inner.name(),
            self.inner.audit_limits(),
            self.inner.report_provenance(),
        ) {
            tracing::error!(error = %err, path = %self.log.path().display(), "cannot write audit record");
        }
        response
    }

    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn audit_limits(&self) -> Option<AuditLimits> {
        self.inner.audit_limits()
    }

    fn report_provenance(&self) -> &'static str {
        self.inner.report_provenance()
    }
}
