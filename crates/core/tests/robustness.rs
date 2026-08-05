//! Failure and near-miss handling.
//!
//! These cover the cases where the tool could plausibly *look* like it worked
//! while leaving identifiers in the clear, or leave behind an artifact that a
//! downstream consumer would mistake for a finished dataset.

use deident_types::{JobOutcome, JobRequest, Mode};

const POLICY: &str = r#"
version: 1
dataset: robust
key: { inline: "robustness-test-secret-0123456789abcdef01" }
fields:
  - name: patient_id
    class: direct_identifier
    pseudonymize: { prefix: "pid_" }
  - name: age
    class: quasi_identifier
"#;

/// `on_unlisted: keep` is the permissive setting: an unmatched column is carried
/// through instead of failing the job. It is exactly the configuration in which a
/// mistyped field name goes unnoticed, so that is where the diagnosis has to be
/// good. (With the default `on_unlisted: error` the job fails outright.)
const LENIENT_POLICY: &str = r#"
version: 1
dataset: robust
on_unlisted: keep
key: { inline: "robustness-test-secret-0123456789abcdef01" }
fields:
  - name: patient_id
    class: direct_identifier
    pseudonymize: { prefix: "pid_" }
  - name: age
    class: quasi_identifier
"#;

fn request(dir: &std::path::Path, input: &str, output: &str) -> JobRequest {
    JobRequest {
        job_id: "robust-job".into(),
        mode: Mode::Pseudonymize,
        policy_yaml: POLICY.to_string(),
        input_path: dir.join(input).to_string_lossy().into_owned(),
        output_path: dir.join(output).to_string_lossy().into_owned(),
        report_path: None,
        vault_path: None,
    }
}

fn run(request: &JobRequest) -> JobOutcome {
    deident_core::runner::execute(request).outcome
}

#[test]
fn a_utf8_bom_does_not_stop_the_first_column_from_matching() {
    let tmp = tempfile::tempdir().unwrap();
    // Excel writes this. Left in place, the first header is "\u{feff}patient_id"
    // and the policy field silently matches nothing.
    std::fs::write(
        tmp.path().join("bom.csv"),
        "\u{feff}patient_id,age\nP001,34\nP002,52\n",
    )
    .unwrap();

    let request = request(tmp.path(), "bom.csv", "out.csv");
    let report = match run(&request) {
        JobOutcome::Succeeded { report } => *report,
        JobOutcome::Failed { error } => panic!("{error}"),
    };

    let output = std::fs::read_to_string(&request.output_path).unwrap();
    assert!(
        !output.contains("P001"),
        "the identifier survived a BOM-prefixed header: {output}"
    );
    assert!(output.contains("pid_"), "no token was written: {output}");
    assert!(
        !report
            .warnings
            .iter()
            .any(|w| w.contains("does not exist in the input")),
        "the field matched, so nothing should be reported as missing: {:?}",
        report.warnings
    );
    assert!(
        output.starts_with("patient_id,"),
        "the BOM must not be re-emitted into the header: {output}"
    );
}

#[test]
fn a_case_mismatched_column_is_called_out_by_name() {
    let tmp = tempfile::tempdir().unwrap();
    // `Patient_ID` != `patient_id`: matching is exact, so this identifier is
    // copied through untouched. The warning has to make that obvious.
    std::fs::write(tmp.path().join("case.csv"), "Patient_ID,age\nP001,34\n").unwrap();

    let mut request = request(tmp.path(), "case.csv", "out.csv");
    request.policy_yaml = LENIENT_POLICY.to_string();
    let report = match run(&request) {
        JobOutcome::Succeeded { report } => *report,
        JobOutcome::Failed { error } => panic!("{error}"),
    };
    let warning = report
        .warnings
        .iter()
        .find(|w| w.contains("patient_id"))
        .unwrap_or_else(|| panic!("no warning about the field: {:?}", report.warnings));
    assert!(warning.contains("NOT applied"), "{warning}");
    assert!(warning.contains("Patient_ID"), "names the actual column: {warning}");
}

#[test]
fn a_missing_direct_identifier_field_says_the_data_passed_through() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("other.csv"), "mrn,age\nP001,34\n").unwrap();

    let mut request = request(tmp.path(), "other.csv", "out.csv");
    request.policy_yaml = LENIENT_POLICY.to_string();
    let report = match run(&request) {
        JobOutcome::Succeeded { report } => *report,
        JobOutcome::Failed { error } => panic!("{error}"),
    };
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("copied through unchanged")),
        "{:?}",
        report.warnings
    );
}

#[test]
fn a_failed_job_leaves_no_output_file_behind() {
    let tmp = tempfile::tempdir().unwrap();
    // Row 2 declares a key the first record did not, which fails mid-stream —
    // after row 1 has already been written.
    std::fs::write(
        tmp.path().join("bad.jsonl"),
        "{\"patient_id\":\"P001\",\"age\":34}\n{\"patient_id\":\"P002\",\"surprise\":1}\n",
    )
    .unwrap();

    let request = request(tmp.path(), "bad.jsonl", "out.jsonl");
    match run(&request) {
        JobOutcome::Failed { error } => assert!(error.contains("surprise"), "{error}"),
        JobOutcome::Succeeded { .. } => panic!("the undeclared key should have failed the job"),
    }

    assert!(
        !std::path::Path::new(&request.output_path).exists(),
        "a partial output must not be published — a consumer would read it as complete"
    );
    // Nor may the staging file be left lying around.
    let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".part"))
        .collect();
    assert!(leftovers.is_empty(), "staging files left behind: {leftovers:?}");
}

#[test]
fn a_failed_job_does_not_publish_a_vault() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("bad.jsonl"),
        "{\"patient_id\":\"P001\",\"age\":34}\n{\"patient_id\":\"P002\",\"surprise\":1}\n",
    )
    .unwrap();

    let mut request = request(tmp.path(), "bad.jsonl", "out.jsonl");
    let vault = tmp.path().join("v.bin");
    request.vault_path = Some(vault.to_string_lossy().into_owned());
    assert!(matches!(run(&request), JobOutcome::Failed { .. }));

    assert!(
        !vault.exists(),
        "re-identification material must not outlive a job that produced no output"
    );
}

#[test]
fn a_successful_job_overwrites_a_previous_output_atomically() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("in.csv"), "patient_id,age\nP001,34\n").unwrap();
    let request = request(tmp.path(), "in.csv", "out.csv");
    std::fs::write(&request.output_path, "stale content\n").unwrap();

    assert!(matches!(run(&request), JobOutcome::Succeeded { .. }));
    let output = std::fs::read_to_string(&request.output_path).unwrap();
    assert!(!output.contains("stale"), "{output}");
    assert!(output.contains("pid_"), "{output}");
}

#[test]
fn an_undeclared_jsonl_key_cannot_flood_the_error_message() {
    let tmp = tempfile::tempdir().unwrap();
    // A key is input-derived, so its length is not ours to trust; the error text
    // travels into logs and audit records.
    let key = format!("surprise{}", "x".repeat(4000));
    std::fs::write(
        tmp.path().join("bad.jsonl"),
        format!("{{\"patient_id\":\"P001\",\"age\":34}}\n{{\"{key}\":1}}\n"),
    )
    .unwrap();

    let error = match run(&request(tmp.path(), "bad.jsonl", "out.jsonl")) {
        JobOutcome::Failed { error } => error,
        JobOutcome::Succeeded { .. } => panic!("expected a failure"),
    };
    assert!(error.contains("characters)"), "over-long key not capped: {error}");
    assert!(error.len() < 200, "error is unbounded: {}", error.len());
}
