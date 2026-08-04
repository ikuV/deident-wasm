//! Integration tests for the per-job Wasm sandbox.
//!
//! These build the worker for wasm32-wasip1 once (cached by cargo) and then
//! exercise the full host/worker execution path, including isolation and
//! resource-limit behavior.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use deident_host::{Engine, NativeEngine, WasmEngine, WasmLimits};
use deident_types::{JobOutcome, JobRequest, JobResponse, Mode};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Build the worker module once per test process and return its path.
fn worker_wasm() -> &'static Path {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT.get_or_init(|| {
        let root = workspace_root();
        let status = std::process::Command::new("cargo")
            .args(["build", "-p", "deident-worker", "--target", "wasm32-wasip1", "--release"])
            .current_dir(&root)
            .status()
            .expect("cargo must be runnable");
        assert!(status.success(), "worker wasm build failed");
        root.join("target/wasm32-wasip1/release/deident-worker.wasm")
    })
}

fn example(rel: &str) -> String {
    workspace_root()
        .join("examples")
        .join(rel)
        .to_str()
        .unwrap()
        .to_string()
}

fn request(mode: Mode, dir: &Path, with_report: bool) -> JobRequest {
    JobRequest {
        job_id: format!("test-{mode:?}-{with_report}").to_lowercase(),
        mode,
        policy_yaml: std::fs::read_to_string(example("policies/patients.yaml")).unwrap(),
        input_path: example("data/patients.csv"),
        output_path: dir.join("out.csv").to_str().unwrap().to_string(),
        report_path: with_report.then(|| dir.join("report.json").to_str().unwrap().to_string()),
        vault_path: None,
    }
}

fn wasm_engine(limits: WasmLimits, jobs_root: &Path) -> WasmEngine {
    WasmEngine::from_file(worker_wasm(), limits)
        .unwrap()
        .with_jobs_root(jobs_root.to_path_buf())
}

#[test]
fn wasm_output_is_byte_identical_to_native() {
    let tmp = tempfile::tempdir().unwrap();
    let native_dir = tmp.path().join("native");
    let wasm_dir = tmp.path().join("wasm");
    std::fs::create_dir_all(&native_dir).unwrap();
    std::fs::create_dir_all(&wasm_dir).unwrap();

    for mode in [Mode::Pseudonymize, Mode::Anonymize] {
        let native_response = NativeEngine.run(&request(mode, &native_dir, true)).unwrap();
        assert!(matches!(native_response.outcome, JobOutcome::Succeeded { .. }));

        let engine = wasm_engine(WasmLimits::default(), tmp.path());
        let wasm_response = engine.run(&request(mode, &wasm_dir, true)).unwrap();
        assert!(
            matches!(wasm_response.outcome, JobOutcome::Succeeded { .. }),
            "wasm {mode:?} failed: {:?}",
            wasm_response.outcome
        );

        let native_out = std::fs::read(native_dir.join("out.csv")).unwrap();
        let wasm_out = std::fs::read(wasm_dir.join("out.csv")).unwrap();
        assert_eq!(native_out, wasm_out, "{mode:?}: outputs must be byte-identical");

        let native_report = std::fs::read(native_dir.join("report.json")).unwrap();
        let wasm_report = std::fs::read(wasm_dir.join("report.json")).unwrap();
        assert_eq!(native_report, wasm_report, "{mode:?}: reports must be byte-identical");
    }
}

#[test]
fn sandbox_job_failure_is_reported_not_panicked() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = wasm_engine(WasmLimits::default(), tmp.path());

    // Policy that rejects the input (unlisted columns) must come back as a
    // clean Failed outcome from inside the sandbox.
    let mut req = request(Mode::Anonymize, tmp.path(), false);
    req.policy_yaml = "version: 1\ndataset: strict\nfields: []\n".to_string();
    let response = engine.run(&req).unwrap();
    match response.outcome {
        JobOutcome::Failed { error } => assert!(error.contains("not covered by the policy")),
        other => panic!("expected failure, got {other:?}"),
    }
}

/// The guest must not be able to read anything outside its preopened job
/// directory — neither absolute host paths nor `..` escapes.
#[test]
fn guest_cannot_read_outside_preopened_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    // A real, readable host file *outside* the workspace the guest will get.
    let secret = tmp.path().join("secret.csv");
    std::fs::write(&secret, "a,b\n1,2\n").unwrap();

    let policy = "version: 1\ndataset: iso\non_unlisted: keep\nfields: []\n";
    // Each escape attempt with the refusal it must produce. The first two are
    // real sandbox refusals (the path resolves to a readable host file, and
    // the guest still cannot open it). `/etc/hosts` has no extension, so the
    // format layer rejects it even earlier — either way the guest never reads
    // outside its preopened directory.
    let escape_paths = [
        (secret.to_str().unwrap().to_string(), "cannot open input"), // absolute host path
        ("/job/../secret.csv".to_string(), "cannot open input"),     // .. escape
        ("/etc/hosts".to_string(), "format"),                        // well-known host file
    ];

    let engine = wasm_engine(WasmLimits::default(), tmp.path());
    for (i, (escape, expected_refusal)) in escape_paths.iter().enumerate() {
        let workspace = tmp.path().join(format!("job-esc-{i}"));
        std::fs::create_dir_all(&workspace).unwrap();
        let guest_request = JobRequest {
            job_id: format!("esc-{i}"),
            mode: Mode::Anonymize,
            policy_yaml: policy.to_string(),
            input_path: escape.clone(),
            output_path: "/job/output.csv".to_string(),
            report_path: None,
            vault_path: None,
        };
        std::fs::write(
            workspace.join("request.json"),
            serde_json::to_vec(&guest_request).unwrap(),
        )
        .unwrap();

        engine.execute_in_workspace(&workspace, &[]).unwrap();
        let response: JobResponse = serde_json::from_str(
            &std::fs::read_to_string(workspace.join("response.json")).unwrap(),
        )
        .unwrap();
        match response.outcome {
            JobOutcome::Failed { error } => assert!(
                error.contains(expected_refusal),
                "path '{escape}' must be refused with '{expected_refusal}', got: {error}"
            ),
            JobOutcome::Succeeded { .. } => {
                panic!("guest read '{escape}' outside its sandbox")
            }
        }
    }
}

#[test]
fn memory_limit_is_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    let limits = WasmLimits {
        max_memory_bytes: 64 * 1024, // far below what the worker needs
        timeout: Duration::from_secs(30),
        fuel: deident_host::wasm::FuelPolicy::Unmetered,
    };
    let engine = wasm_engine(limits, tmp.path());
    let response = engine.run(&request(Mode::Anonymize, tmp.path(), false)).unwrap();
    match response.outcome {
        JobOutcome::Failed { error } => assert!(
            error.contains("instantiate") || error.contains("memory"),
            "unexpected error: {error}"
        ),
        other => panic!("expected memory-limit failure, got {other:?}"),
    }
}
