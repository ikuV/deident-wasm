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

/// Interval of the background epoch ticker. Timeouts are rounded up to a whole
/// number of ticks, plus one tick of slack for the ticker's phase.
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
    /// Fuel budget actually granted to the most recent job, so the audit record
    /// states an enforced figure rather than a nominal one.
    last_fuel: std::sync::Mutex<Option<u64>>,
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
            last_fuel: std::sync::Mutex::new(None),
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
                // Table storage lives on the HOST heap and is not counted against
                // `memory_size`, so leaving it unlimited let a hostile module
                // allocate past the advertised cap.
                .tables(1)
                .table_elements(100_000)
                .build(),
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);
        let budget = self.limits.fuel.budget(input_bytes);
        *self.last_fuel.lock().expect("fuel budget lock") = budget;
        // Round UP, and add a tick to absorb the ticker's phase: the ticker is not
        // synchronised with job start, so truncating made a 150 ms budget expire
        // anywhere in (0, 100] ms and `--timeout-secs 0` mean ~100 ms.
        let deadline_ticks = self
            .limits
            .timeout
            .as_millis()
            .div_ceil(EPOCH_TICK.as_millis())
            .saturating_add(1)
            .try_into()
            .unwrap_or(u64::MAX);
        store.set_epoch_deadline(deadline_ticks);
        if let Some(fuel) = budget {
            store.set_fuel(fuel)?;
        }

        let instance = self
            .linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| e.context("cannot instantiate worker (memory limit too low?)"))?;
        // Record the pre-call fuel so a trap can be attributed correctly below.
        let fuel_before = store.get_fuel().ok();
        let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
        match start.call(&mut store, ()) {
            Ok(()) => Ok(()),
            // Any explicit exit means the worker ran to completion and wrote
            // its response; success/failure is judged from response.json.
            Err(err) if err.downcast_ref::<I32Exit>().is_some() => Ok(()),
            Err(err) => {
                // Distinguish the causes instead of blaming memory for everything:
                // exhausted fuel and an expired epoch look identical in the error
                // otherwise, and the old wording misdiagnosed both.
                let exhausted_fuel = fuel_before.is_some()
                    && store.get_fuel().is_ok_and(|remaining| remaining == 0);
                let cause = if exhausted_fuel {
                    "worker exhausted its CPU budget (fuel) — raise --fuel or pass --no-fuel"
                } else {
                    "worker trapped: wall-clock timeout, memory limit, or a fault in the worker"
                };
                Err(err.context(cause).into())
            }
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

    fn report_provenance(&self) -> &'static str {
        // The row counts and statistics come from the guest. The host verifies
        // what it cheaply can (see `verify_guest_report`) and states the rest as a
        // claim rather than a fact.
        "guest-attested-host-verified"
    }

    fn audit_limits(&self) -> Option<crate::AuditLimits> {
        Some(crate::AuditLimits {
            max_memory_bytes: self.limits.max_memory_bytes,
            timeout_ms: self.limits.timeout.as_millis() as u64,
            // The scaled budget depends on the input size, so no single number is
            // right for the policy as a whole. Record the actual budget of the
            // last job instead of `budget(0)`, which claimed a limit no job ran
            // under.
            fuel: *self.last_fuel.lock().expect("fuel budget lock"),
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
        create_private_dir(workspace)?;
        let input_name = format!("input.{}", extension_of(&request.input_path));
        let output_name = format!("output.{}", extension_of(&request.output_path));
        let input_bytes = std::fs::copy(&request.input_path, workspace.join(&input_name))
            .with_context(|| format!("cannot stage input '{}'", request.input_path))?;
        let guest_request = JobRequest {
            job_id: request.job_id.clone(),
            mode: request.mode,
            // The guest gets the policy with any inline secret removed: this file
            // sits on disk for the duration of the job, and the secret reaches the
            // guest through the WASI environment instead, which is the scoped
            // channel. Leaving it here put the key that reverses every token into
            // a plain file.
            policy_yaml: redact_inline_key(&request.policy_yaml),
            input_path: format!("{GUEST_DIR}/{input_name}"),
            output_path: format!("{GUEST_DIR}/{output_name}"),
            report_path: request.report_path.as_ref().map(|_| GUEST_REPORT.to_string()),
            vault_path: request.vault_path.as_ref().map(|_| GUEST_VAULT.to_string()),
        };
        write_private(
            &workspace.join("request.json"),
            &serde_json::to_vec_pretty(&guest_request)?,
        )?;

        // Deny-by-default environment: pass through only the key variable the
        // policy names, and only when the host actually has it set.
        let mut env: Vec<(String, String)> = Vec::new();
        let mut fell_back_from: Option<String> = None;
        if let Ok(policy) = deident_core::Policy::from_yaml(&request.policy_yaml) {
            // The variable NAME comes from the policy, so without a prefix rule a
            // policy could name any host variable — `key: { env:
            // AWS_SECRET_ACCESS_KEY }` would forward that secret into the guest.
            // Restrict it to the tool's own namespace.
            match policy.key.as_ref().and_then(|k| k.env.clone()) {
                Some(var) if !var.starts_with(KEY_ENV_PREFIX) => {
                    tracing::warn!(
                        variable = %var,
                        "policy names a key environment variable outside the {KEY_ENV_PREFIX}* \
                         namespace; not forwarding it to the sandbox"
                    );
                }
                Some(var) => {
                    if let Ok(value) = std::env::var(&var) {
                        env.push((var, value));
                    }
                }
                None => {}
            }
            // An inline secret must still reach the guest, since it was stripped
            // from request.json above.
            if let Some(inline) = policy.key.as_ref().and_then(|k| k.inline.clone())
                && env.is_empty()
                // Only when the job actually resolves a key. Anonymize-only jobs
                // with no tokenizing pattern never touch it, and warning about a
                // fallback that did not happen would contradict the native engine.
                && deident_core::runner::needs_key(&policy, request.mode)
            {
                // The guest will find its key in the environment and therefore
                // cannot know a fallback happened; record it so the host can state
                // it in the report and stay consistent with the native engine.
                if let Some(var) = policy.key.as_ref().and_then(|k| k.env.clone()) {
                    fell_back_from = Some(var);
                }
                env.push((INLINE_KEY_ENV.to_string(), inline));
            }
        }

        // Execute with a fresh store/WASI context.
        self.execute_in_workspace_with_fuel(workspace, &env, input_bytes)?;

        // Collect: the worker's response decides success; outputs are copied
        // from the workspace to the host paths in the original request.
        let response_raw = std::fs::read_to_string(workspace.join("response.json"))
            .context("worker finished without writing a response")?;
        let mut response: JobResponse =
            serde_json::from_str(&response_raw).context("worker wrote an invalid response")?;

        // The guest resolved its key from the environment the host set, so it
        // could not know that an inline fallback occurred. Say it here, wording it
        // exactly as the native engine does — the two engines must report the same
        // facts about the same job.
        if let (Some(var), JobOutcome::Succeeded { report }) = (&fell_back_from, &mut response.outcome)
        {
            report.warnings.insert(
                0,
                format!(
                    "environment variable '{var}' is unset or empty, so the policy's INLINE key \
                     was used (allow_inline_fallback is set). Anyone holding the policy file can \
                     reverse every token in this output"
                ),
            );
        }

        if let JobOutcome::Succeeded { report } = &mut response.outcome {
            // The guest authored these figures. Check what the host can check
            // cheaply, and replace what the host owns outright — a compromised
            // worker could otherwise copy the input to the output and report clean
            // counts with an emptied limitations block.
            verify_guest_report(report, &workspace.join(&output_name), output_format(&request.output_path))?;

            collect_artifact(&workspace.join(&output_name), &request.output_path, true)?;
            // Write the report from the response the host holds, rather than
            // copying the guest's file: the host adds facts the guest cannot know
            // (an inline-key fallback) and must not ship a report that disagrees
            // with what it returns to the caller.
            if let (Some(report_path), JobOutcome::Succeeded { report }) =
                (&request.report_path, &response.outcome)
            {
                std::fs::write(report_path, serde_json::to_vec_pretty(report)?)
                    .with_context(|| format!("cannot write report '{report_path}'"))?;
            }
            if let Some(vault_path) = &request.vault_path {
                // The guest only writes a vault when the job produced reversible
                // values, so a missing file is not an error here.
                collect_artifact(&workspace.join("vault.jsonl"), vault_path, false)?;
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

/// Output format of a path, for the row-count check.
fn output_format(path: &str) -> Option<&'static str> {
    match Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("csv") => Some("csv"),
        Some("jsonl") | Some("ndjson") => Some("jsonl"),
        _ => None,
    }
}

/// Check the guest's report against the artifact it claims to describe.
///
/// The host cannot recompute the privacy statistics without doing the whole job
/// again, but it can do two things cheaply:
///
/// 1. **Own the limitations text.** It is fixed language the host is entitled to
///    assert, and a guest that emptied or reworded it would be misrepresenting
///    what the tool guarantees. The host overwrites it unconditionally.
/// 2. **Count the output rows** for line-oriented formats and compare against
///    `rows_written`. A guest claiming 12 transformed rows over a 500-row
///    passthrough is caught here.
fn verify_guest_report(
    report: &mut deident_types::RiskReport,
    output: &Path,
    format: Option<&'static str>,
) -> anyhow::Result<()> {
    // Host-owned facts, not guest claims.
    report.limitations = deident_core::report::LIMITATIONS
        .iter()
        .map(|s| s.to_string())
        .collect();
    report.tool_version = deident_types::VERSION.to_string();

    let Some(format) = format else {
        // Parquet and friends are not line-oriented; nothing cheap to compare.
        return Ok(());
    };
    let Ok(contents) = std::fs::read_to_string(output) else {
        return Ok(());
    };
    let non_empty = contents.lines().filter(|l| !l.trim().is_empty()).count() as u64;
    // CSV carries a header row; JSONL does not.
    let actual = match format {
        "csv" => non_empty.saturating_sub(1),
        _ => non_empty,
    };
    anyhow::ensure!(
        actual == report.rows_written,
        "the sandboxed worker reported {} written row(s) but the output contains {actual}; \
         refusing a report that does not describe its own output",
        report.rows_written
    );
    Ok(())
}

/// Only environment variables in this namespace are forwarded to the guest.
pub const KEY_ENV_PREFIX: &str = "DEIDENT_";
/// Guest-side variable carrying an inline policy secret, so the secret never has
/// to be written into the staged `request.json`.
pub const INLINE_KEY_ENV: &str = "DEIDENT_INLINE_KEY";

/// Create a directory only the current user can enter.
///
/// The workspace holds a plaintext copy of the input dataset and, when one is
/// requested, the mapping vault. On a shared host the default `0755` made all of
/// that world-readable for the duration of every job.
fn create_private_dir(path: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("cannot create job workspace '{}'", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("cannot restrict permissions on '{}'", path.display()))?;
    }
    Ok(())
}

/// Write a file only the current user can read.
fn write_private(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, contents)
        .with_context(|| format!("cannot write '{}'", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("cannot restrict permissions on '{}'", path.display()))?;
    }
    Ok(())
}

/// Copy one artifact out of the workspace, refusing anything that is not a
/// regular file.
///
/// The guest can create symlinks inside its own preopened directory, and while
/// cap-std stops the *guest* from following them, `std::fs::copy` on the host
/// does follow them — so a guest could point `output.csv` at `/etc/passwd` and
/// have the host copy that into the operator's output. `symlink_metadata` does
/// not follow, which closes it.
fn collect_artifact(staged: &Path, destination: &str, required: bool) -> anyhow::Result<()> {
    let metadata = match std::fs::symlink_metadata(staged) {
        Ok(metadata) => metadata,
        Err(_) if !required => return Ok(()),
        Err(err) => {
            return Err(anyhow::anyhow!(
                "cannot collect '{}': {err}",
                staged.display()
            ));
        }
    };
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "refusing to collect '{}': the guest replaced it with a {:?} rather than a regular file",
        staged.display(),
        metadata.file_type()
    );
    std::fs::copy(staged, destination)
        .with_context(|| format!("cannot collect artifact to '{destination}'"))?;
    Ok(())
}

/// Remove an inline secret from a policy document before it is written to disk.
///
/// Operates on the parsed policy so it cannot be fooled by formatting; if the
/// document does not parse it is passed through unchanged, and the job will fail
/// on it moments later anyway.
fn redact_inline_key(policy_yaml: &str) -> String {
    match deident_core::Policy::from_yaml(policy_yaml) {
        Ok(mut policy) => {
            let had_inline = policy
                .key
                .as_ref()
                .is_some_and(|k| k.inline.is_some());
            if !had_inline {
                return policy_yaml.to_string();
            }
            if let Some(key) = policy.key.as_mut() {
                key.inline = None;
                // The guest reads the secret from its environment instead.
                key.env = Some(INLINE_KEY_ENV.to_string());
                key.allow_inline_fallback = false;
            }
            serde_yaml::to_string(&policy).unwrap_or_else(|_| policy_yaml.to_string())
        }
        Err(_) => policy_yaml.to_string(),
    }
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

#[cfg(test)]
mod hardening_tests {
    use super::*;

    /// The staged request sits on disk for the job's lifetime, so it must not
    /// carry the key that reverses every token.
    #[test]
    fn the_staged_policy_carries_no_inline_secret() {
        let policy = "version: 1\ndataset: d\nkey:\n  env: DEIDENT_KEY\n  \
                      inline: \"super-secret-material-0123456789abcdef\"\n  \
                      allow_inline_fallback: true\nfields: []\n";
        let redacted = redact_inline_key(policy);
        assert!(
            !redacted.contains("super-secret-material"),
            "the secret survived redaction: {redacted}"
        );
        // The guest must still be told where to find it.
        assert!(redacted.contains(INLINE_KEY_ENV), "{redacted}");
        // A policy with no inline key is passed through untouched.
        let no_inline = "version: 1\ndataset: d\nkey:\n  env: DEIDENT_KEY\nfields: []\n";
        assert_eq!(redact_inline_key(no_inline), no_inline);
        // An unparsable policy is passed through; the job fails on it later.
        assert_eq!(redact_inline_key("not: [valid"), "not: [valid");
    }

    #[cfg(unix)]
    #[test]
    fn workspaces_and_staged_files_are_private_to_the_user() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let workspace = tmp.path().join("job-x");
        create_private_dir(&workspace).unwrap();
        let mode = std::fs::metadata(&workspace).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "workspace holds plaintext input and the vault");

        let file = workspace.join("request.json");
        write_private(&file, b"{}").unwrap();
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// cap-std stops the guest following a symlink, but `std::fs::copy` on the
    /// host does follow one — so collection must refuse anything that is not a
    /// regular file.
    #[cfg(unix)]
    #[test]
    fn collection_refuses_a_symlinked_artifact() {
        let tmp = tempfile::tempdir().unwrap();
        let secret = tmp.path().join("host-secret.txt");
        std::fs::write(&secret, "sensitive host file").unwrap();
        let staged = tmp.path().join("output.csv");
        std::os::unix::fs::symlink(&secret, &staged).unwrap();
        let destination = tmp.path().join("collected.csv");

        let err = collect_artifact(&staged, destination.to_str().unwrap(), true)
            .expect_err("a symlinked artifact must be refused");
        assert!(
            err.to_string().contains("regular file"),
            "unexpected error: {err}"
        );
        assert!(!destination.exists(), "nothing may be collected");

        // A real file collects normally.
        std::fs::remove_file(&staged).unwrap();
        std::fs::write(&staged, "id\n1\n").unwrap();
        collect_artifact(&staged, destination.to_str().unwrap(), true).unwrap();
        assert_eq!(std::fs::read_to_string(&destination).unwrap(), "id\n1\n");

        // A missing optional artifact is not an error.
        collect_artifact(&tmp.path().join("absent"), destination.to_str().unwrap(), false).unwrap();
    }
}
