//! Per-job WebAssembly sandbox execution via Wasmtime + WASI.
//!
//! Isolation model (a mitigation, not an absolute boundary):
//! - the worker module is compiled once; every job then gets a **fresh
//!   `Store` and `WasiCtx`**, so no instance state survives across jobs,
//! - each job runs against its own temporary workspace directory, which is
//!   the **only preopened path** — input, request, output, report and
//!   response all live inside it; host paths never reach the guest,
//! - deny-by-default WASI: no network, no inherited stdio except stderr for
//!   diagnostics, and no environment except the single key variable a
//!   pseudonymize policy names,
//! - per-job resource limits: memory via [`StoreLimits`], wall-clock via
//!   epoch interruption, and an optional fuel budget for CPU.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use deident_types::{JobOutcome, JobRequest, JobResponse};
use wasmtime::{Config, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::{DirPerms, FilePerms, I32Exit, WasiCtxBuilder};

use crate::Engine;

/// Guest-side paths inside the preopened job directory.
const GUEST_DIR: &str = "/job";
const GUEST_REQUEST: &str = "/job/request.json";
const GUEST_RESPONSE: &str = "/job/response.json";
const GUEST_INPUT: &str = "/job/input.csv";
const GUEST_OUTPUT: &str = "/job/output.csv";
const GUEST_REPORT: &str = "/job/report.json";

/// Interval of the background epoch ticker; timeouts are rounded up to it.
const EPOCH_TICK: Duration = Duration::from_millis(100);

/// Per-job resource limits.
#[derive(Debug, Clone)]
pub struct WasmLimits {
    /// Maximum linear memory of the guest, in bytes.
    pub max_memory_bytes: usize,
    /// Wall-clock budget per job, enforced via epoch interruption.
    pub timeout: Duration,
    /// Optional CPU budget in Wasmtime fuel units. `None` disables fuel
    /// metering (placeholder until costs are tuned; see AGENT_PLAN Phase 4).
    pub fuel: Option<u64>,
}

impl Default for WasmLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 256 * 1024 * 1024,
            timeout: Duration::from_secs(30),
            fuel: None,
        }
    }
}

/// Per-store state: the WASI context plus the resource limiter.
struct JobState {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

/// Executes each job in its own Wasmtime sandbox.
///
/// The module is compiled once at construction; [`Engine::run`] then stages a
/// job workspace, executes the guest with a fresh store, and collects the
/// results back onto the host paths in the request.
pub struct WasmEngine {
    engine: wasmtime::Engine,
    module: Module,
    linker: Linker<JobState>,
    limits: WasmLimits,
    jobs_root: PathBuf,
}

impl WasmEngine {
    /// Compile the worker module from `worker_wasm` and prepare the engine.
    ///
    /// Spawns a detached background thread that advances the epoch every
    /// [`EPOCH_TICK`] for the lifetime of the process (the timeout mechanism
    /// for all jobs of all `WasmEngine` instances created from it).
    pub fn from_file(worker_wasm: &Path, limits: WasmLimits) -> anyhow::Result<Self> {
        let mut config = Config::new();
        config.epoch_interruption(true);
        config.consume_fuel(limits.fuel.is_some());
        let engine = wasmtime::Engine::new(&config)?;

        let module = Module::from_file(&engine, worker_wasm).map_err(|e| {
            e.context(format!(
                "cannot load worker module '{}'",
                worker_wasm.display()
            ))
        })?;
        let mut linker: Linker<JobState> = Linker::new(&engine);
        p1::add_to_linker_sync(&mut linker, |state| &mut state.wasi)?;

        let ticker = engine.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(EPOCH_TICK);
                ticker.increment_epoch();
            }
        });

        Ok(Self {
            engine,
            module,
            linker,
            limits,
            jobs_root: std::env::temp_dir().join("deident-jobs"),
        })
    }

    /// Override where per-job workspace directories are created
    /// (default: `<system temp>/deident-jobs`).
    pub fn with_jobs_root(mut self, jobs_root: PathBuf) -> Self {
        self.jobs_root = jobs_root;
        self
    }

    /// Run the guest against an already-staged workspace containing
    /// `request.json` (with guest-side paths). The workspace becomes the only
    /// preopened directory; `env` is the complete guest environment.
    ///
    /// Exposed for integration tests that probe the isolation behavior;
    /// normal callers use [`Engine::run`].
    pub fn execute_in_workspace(
        &self,
        workspace: &Path,
        env: &[(String, String)],
    ) -> anyhow::Result<()> {
        let mut builder = WasiCtxBuilder::new();
        builder
            .args(&["deident-worker", GUEST_REQUEST, GUEST_RESPONSE])
            .inherit_stderr();
        for (key, value) in env {
            builder.env(key, value);
        }
        builder
            .preopened_dir(workspace, GUEST_DIR, DirPerms::all(), FilePerms::all())
            .map_err(|e| {
                e.context(format!("cannot preopen workspace '{}'", workspace.display()))
            })?;

        let state = JobState {
            wasi: builder.build_p1(),
            limits: StoreLimitsBuilder::new()
                .memory_size(self.limits.max_memory_bytes)
                .instances(1)
                .memories(1)
                .build(),
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);
        let deadline_ticks =
            (self.limits.timeout.as_millis() / EPOCH_TICK.as_millis()).max(1) as u64;
        store.set_epoch_deadline(deadline_ticks);
        if let Some(fuel) = self.limits.fuel {
            store.set_fuel(fuel)?;
        }

        let instance = self
            .linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| e.context("cannot instantiate worker (memory limit too low?)"))?;
        let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
        match start.call(&mut store, ()) {
            Ok(()) => Ok(()),
            // Any explicit exit means the worker ran to completion and wrote
            // its response; success/failure is judged from response.json.
            Err(err) if err.downcast_ref::<I32Exit>().is_some() => Ok(()),
            Err(err) => Err(err
                .context("worker trapped (timeout, memory limit, or bug)")
                .into()),
        }
    }
}

impl Engine for WasmEngine {
    fn run(&self, request: &JobRequest) -> anyhow::Result<JobResponse> {
        tracing::info!(
            job_id = %request.job_id,
            engine = "wasm",
            memory_limit = self.limits.max_memory_bytes,
            timeout_ms = self.limits.timeout.as_millis() as u64,
            "running job in sandbox"
        );
        let workspace = self.jobs_root.join(format!("job-{}", request.job_id));
        let result = self.run_in_fresh_workspace(request, &workspace);
        if let Err(err) = std::fs::remove_dir_all(&workspace)
            && workspace.exists()
        {
            tracing::warn!(workspace = %workspace.display(), error = %err, "cannot clean up job workspace");
        }
        let outcome = result.unwrap_or_else(|err| JobOutcome::Failed {
            error: format!("{err:#}"),
        });
        Ok(JobResponse {
            job_id: request.job_id.clone(),
            outcome,
        })
    }
}

impl WasmEngine {
    fn run_in_fresh_workspace(
        &self,
        request: &JobRequest,
        workspace: &Path,
    ) -> anyhow::Result<JobOutcome> {
        // Stage: workspace with input copy + request rewritten to guest paths.
        std::fs::create_dir_all(workspace)
            .with_context(|| format!("cannot create job workspace '{}'", workspace.display()))?;
        std::fs::copy(&request.input_path, workspace.join("input.csv"))
            .with_context(|| format!("cannot stage input '{}'", request.input_path))?;
        let guest_request = JobRequest {
            job_id: request.job_id.clone(),
            mode: request.mode,
            policy_yaml: request.policy_yaml.clone(),
            input_path: GUEST_INPUT.to_string(),
            output_path: GUEST_OUTPUT.to_string(),
            report_path: request.report_path.as_ref().map(|_| GUEST_REPORT.to_string()),
        };
        std::fs::write(
            workspace.join("request.json"),
            serde_json::to_vec_pretty(&guest_request)?,
        )?;

        // Deny-by-default environment: pass through only the key variable the
        // policy names, and only when the host actually has it set.
        let mut env: Vec<(String, String)> = Vec::new();
        if let Ok(policy) = deident_core::Policy::from_yaml(&request.policy_yaml)
            && let Some(var) = policy.key.as_ref().and_then(|k| k.env.clone())
            && let Ok(value) = std::env::var(&var)
        {
            env.push((var, value));
        }

        // Execute with a fresh store/WASI context.
        self.execute_in_workspace(workspace, &env)?;

        // Collect: the worker's response decides success; outputs are copied
        // from the workspace to the host paths in the original request.
        let response_raw = std::fs::read_to_string(workspace.join("response.json"))
            .context("worker finished without writing a response")?;
        let response: JobResponse =
            serde_json::from_str(&response_raw).context("worker wrote an invalid response")?;
        if let JobOutcome::Succeeded { .. } = &response.outcome {
            std::fs::copy(workspace.join("output.csv"), &request.output_path)
                .with_context(|| format!("cannot collect output to '{}'", request.output_path))?;
            if let Some(report_path) = &request.report_path {
                std::fs::copy(workspace.join("report.json"), report_path)
                    .with_context(|| format!("cannot collect report to '{report_path}'"))?;
            }
        }
        Ok(response.outcome)
    }
}
