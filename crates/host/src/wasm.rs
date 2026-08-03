//! Per-job WebAssembly sandbox execution — Phase 3 (see AGENT_PLAN.md).
//!
//! Planned shape:
//! - one long-lived `wasmtime::Engine` with the compiled worker module cached,
//! - a **fresh `Store` and `WasiCtx` per job** so no state crosses jobs,
//! - a per-job workspace directory that is the **only preopened path**
//!   (input, `request.json`, output and `response.json` all live inside it),
//! - deny-by-default WASI: no network, no extra env, no inherited stdio
//!   handles beyond captured stderr for diagnostics,
//! - resource limits per job: `StoreLimits` for memory, epoch interruption
//!   for wall-clock timeouts, fuel as a CPU budget placeholder.
//!
//! Sandboxing reduces the blast radius of risky parsing/transform logic and
//! future untrusted plugins; it is a mitigation, not an absolute boundary.
//!
//! TODO(roadmap, Phase 3): implement `WasmEngine` and add it to the CLI's
//! `--engine` flag.
