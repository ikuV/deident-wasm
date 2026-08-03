//! End-to-end CLI tests against the example dataset and policy.

use std::path::PathBuf;

use assert_cmd::Command;
use deident_types::RiskReport;
use predicates::prelude::*;

fn example(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(rel)
}

fn deident() -> Command {
    Command::cargo_bin("deident").unwrap()
}

#[test]
fn pseudonymize_example_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out.csv");

    deident()
        .arg("pseudonymize")
        .arg(example("data/patients.csv"))
        .arg("--policy")
        .arg(example("policies/patients.yaml"))
        .arg("--out")
        .arg(&out)
        .assert()
        .success()
        .stdout(predicate::str::contains("Pseudonymize complete: 12 row(s) in"))
        .stdout(predicate::str::contains("remains personal data"));

    let csv = std::fs::read_to_string(&out).unwrap();
    let mut lines = csv.lines();
    assert_eq!(
        lines.next().unwrap(),
        "patient_id,full_name,email,age,zip,admission_date,diagnosis,notes"
    );
    let first: Vec<&str> = lines.next().unwrap().split(',').collect();
    assert!(first[0].starts_with("pid_"), "patient_id must be tokenized");
    assert!(!csv.contains("alice.muster@example.com"));
    assert!(csv.contains("81549"), "quasi-identifiers stay intact in pseudonymize mode");
}

#[test]
fn anonymize_example_writes_report() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out.csv");
    let report_path = tmp.path().join("report.json");

    deident()
        .arg("anonymize")
        .arg(example("data/patients.csv"))
        .arg("--policy")
        .arg(example("policies/patients.yaml"))
        .arg("--out")
        .arg(&out)
        .arg("--report")
        .arg(&report_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Anonymize complete: 12 row(s) in"));

    let csv = std::fs::read_to_string(&out).unwrap();
    assert_eq!(
        csv.lines().next().unwrap(),
        "age,zip,admission_date,diagnosis,notes"
    );
    assert!(!csv.contains("Alice"), "direct identifiers must be removed");
    assert!(csv.contains("30-39"), "ages must be bucketed");
    assert!(csv.contains("815**"), "zips must be prefix-truncated");

    let report: RiskReport =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    assert_eq!(report.rows_read, 12);
    assert_eq!(report.direct_identifiers.len(), 3);
    let qi = report.quasi_identifiers.unwrap();
    assert_eq!(qi.equivalence_classes, 5);
    assert_eq!(qi.min_class_size, 1);
    assert_eq!(qi.max_class_size, 5);
    assert_eq!(qi.unique_rows, 1);
    assert!(!report.limitations.is_empty());
}

#[test]
fn missing_input_fails_with_nonzero_exit() {
    let tmp = tempfile::tempdir().unwrap();
    deident()
        .arg("anonymize")
        .arg(tmp.path().join("nope.csv"))
        .arg("--policy")
        .arg(example("policies/patients.yaml"))
        .arg("--out")
        .arg(tmp.path().join("out.csv"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot open input"));
}
