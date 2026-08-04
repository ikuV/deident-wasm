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

/// Guest-side paths inside the preopened job directory. Input and output keep
/// the host file's extension so the guest infers the same format.
const GUEST_DIR: &str = "/job";
const GUEST_REQUEST: &str = "/job/request.json";
const GUEST_RESPONSE: &str = "/job/response.json";
const GUEST_REPORT: &str = "/job/report.json";
const GUEST_VAULT: &str = "/job/vault.jsonl";

/// Interval of the background epoch ticker; timeouts are rounded up to it.
const EPOCH_TICK: Duration = Duration::from_millis(100);

/// Fuel granted regardless of input size: covers module start-up, policy
/// parsing and report generation.
pub const FUEL_BASE: u64 = 2_000_000_000;
/// Additional fuel per byte of input. Measured against the bundled examples
/// with roughly an order of magnitude of headroom, so ordinary jobs never hit
/// the limit while a runaway loop still terminates.
pub const FUEL_PER_INPUT_BYTE: u64 = 20_000;

/// Per-job resource limits.
#[derive(Debug, Clone)]
pub struct WasmLimits {
    /// Maximum linear memory of the guest, in bytes.
    pub max_memory_bytes: usize,
    /// Wall-clock budget per job, enforced via epoch interruption.
    pub timeout: Duration,
    /// CPU budget policy in Wasmtime fuel units.
    pub fuel: FuelPolicy,
}

/// How much CPU a job may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuelPolicy {
    /// No fuel metering (wall-clock timeout still applies).
    Unmetered,
    /// Scale the budget with the input size: `FUEL_BASE + bytes *
    /// FUEL_PER_INPUT_BYTE`. This is the default — a fixed budget would
    /// either starve large jobs or be meaningless for small ones.
    Scaled,
    /// A fixed budget, whatever the input size.
    Fixed(u64),
}

impl FuelPolicy {
    /// Resolve to a concrete budget for an input of `input_bytes`.
    pub fn budget(&self, input_bytes: u64) -> Option<u64> {
        match self {
            FuelPolicy::Unmetered => None,
            FuelPolicy::Scaled => {
                Some(FUEL_BASE.saturating_add(input_bytes.saturating_mul(FUEL_PER_INPUT_BYTE)))
            }
            FuelPolicy::Fixed(fuel) => Some(*fuel),
        }
    }
}

impl Default for WasmLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 256 * 1024 * 1024,
            timeout: Duration::from_secs(30),
            fuel: FuelPolicy::Scaled,
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
        config.consume_fuel(limits.fuel != FuelPolicy::Unmetered);
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
        self.execute_in_workspace_with_fuel(workspace, env, 0)
    }

    /// Same as [`Self::execute_in_workspace`], with the fuel budget scaled to
    /// `input_bytes` when the fuel policy is [`FuelPolicy::Scaled`].
    pub fn execute_in_workspace_with_fuel(
        &self,
        workspace: &Path,
        env: &[(String, String)],
        input_bytes: u64,
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
        if let Some(fuel) = self.limits.fuel.budget(input_bytes) {
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
        let workspace = self.jobs_root.join(workspace_name(&request.job_id));
        // Defence in depth: the workspace is created and later *recursively
        // deleted*, so refuse to act on anything that is not a direct child of
        // the jobs root, whatever the job id contained.
        if workspace.parent() != Some(self.jobs_root.as_path()) {
            return Ok(JobResponse {
                job_id: request.job_id.clone(),
                outcome: JobOutcome::Failed {
                    error: format!(
                        "refusing to use job workspace '{}': not a direct child of '{}'",
                        workspace.display(),
                        self.jobs_root.display()
                    ),
                },
            });
        }
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

    fn name(&self) -> &'static str {
        "wasm"
    }

    fn audit_limits(&self) -> Option<crate::AuditLimits> {
        Some(crate::AuditLimits {
            max_memory_bytes: self.limits.max_memory_bytes,
            timeout_ms: self.limits.timeout.as_millis() as u64,
            // Scaled budgets depend on the input, so record the base policy.
            fuel: self.limits.fuel.budget(0),
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
        // File extensions are preserved so the guest infers the same formats.
        std::fs::create_dir_all(workspace)
            .with_context(|| format!("cannot create job workspace '{}'", workspace.display()))?;
        let input_name = format!("input.{}", extension_of(&request.input_path));
        let output_name = format!("output.{}", extension_of(&request.output_path));
        let input_bytes = std::fs::copy(&request.input_path, workspace.join(&input_name))
            .with_context(|| format!("cannot stage input '{}'", request.input_path))?;
        let guest_request = JobRequest {
            job_id: request.job_id.clone(),
            mode: request.mode,
            policy_yaml: request.policy_yaml.clone(),
            input_path: format!("{GUEST_DIR}/{input_name}"),
            output_path: format!("{GUEST_DIR}/{output_name}"),
            report_path: request.report_path.as_ref().map(|_| GUEST_REPORT.to_string()),
            vault_path: request.vault_path.as_ref().map(|_| GUEST_VAULT.to_string()),
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
        self.execute_in_workspace_with_fuel(workspace, &env, input_bytes)?;

        // Collect: the worker's response decides success; outputs are copied
        // from the workspace to the host paths in the original request.
        let response_raw = std::fs::read_to_string(workspace.join("response.json"))
            .context("worker finished without writing a response")?;
        let response: JobResponse =
            serde_json::from_str(&response_raw).context("worker wrote an invalid response")?;
        if let JobOutcome::Succeeded { .. } = &response.outcome {
            std::fs::copy(workspace.join(&output_name), &request.output_path)
                .with_context(|| format!("cannot collect output to '{}'", request.output_path))?;
            if let Some(report_path) = &request.report_path {
                std::fs::copy(workspace.join("report.json"), report_path)
                    .with_context(|| format!("cannot collect report to '{report_path}'"))?;
            }
            if let Some(vault_path) = &request.vault_path {
                let staged = workspace.join("vault.jsonl");
                // The guest only writes a vault when the job produced
                // reversible values.
                if staged.is_file() {
                    std::fs::copy(staged, vault_path)
                        .with_context(|| format!("cannot collect vault to '{vault_path}'"))?;
                }
            }
        }
        Ok(response.outcome)
    }
}

/// Directory name for a job's workspace.
///
/// Job ids are caller-supplied (a chain manifest builds them from
/// author-controlled names), and this name is interpolated into a path that is
/// later passed to `remove_dir_all`. Hashing rather than interpolating means no
/// input can introduce a path separator, a `..` component, or any other
/// surprise — while staying deterministic, which keeps workspaces greppable
/// against a job id.
fn workspace_name(job_id: &str) -> String {
    format!("job-{}", &blake3::hash(job_id.as_bytes()).to_hex()[..24])
}

/// Lowercase file extension of a path, defaulting to `csv` when absent so a
/// staged file still carries a format the guest can infer.
fn extension_of(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| "csv".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions_drive_guest_format_inference() {
        assert_eq!(extension_of("/data/in.CSV"), "csv");
        assert_eq!(extension_of("in.jsonl"), "jsonl");
        assert_eq!(extension_of("in.parquet"), "parquet");
        assert_eq!(extension_of("noext"), "csv");
    }

    /// A job id can come from a chain manifest, i.e. from author-controlled
    /// YAML. It must never be able to steer the workspace path, which is
    /// later handed to `remove_dir_all`.
    #[test]
    fn workspace_name_neutralizes_path_traversal() {
        for hostile in [
            "../../../../etc",
            "export:../../Documents",
            "a/b/c",
            "..",
            "",
        ] {
            let name = workspace_name(hostile);
            assert!(name.starts_with("job-"), "{name}");
            assert_eq!(
                std::path::Path::new(&name).components().count(),
                1,
                "workspace name must be a single path component: {name}"
            );
            assert!(!name.contains(".."), "{name}");
            assert!(!name.contains('/') && !name.contains('\\'), "{name}");
        }
        // Deterministic, and distinct per job id.
        assert_eq!(workspace_name("a"), workspace_name("a"));
        assert_ne!(workspace_name("a"), workspace_name("b"));
    }

    #[test]
    fn fuel_scales_with_input_size() {
        assert_eq!(FuelPolicy::Unmetered.budget(1000), None);
        assert_eq!(FuelPolicy::Fixed(42).budget(1000), Some(42));
        let small = FuelPolicy::Scaled.budget(0).unwrap();
        let large = FuelPolicy::Scaled.budget(1_000_000).unwrap();
        assert_eq!(small, FUEL_BASE);
        assert!(large > small, "bigger inputs must get more fuel");
    }
}
