//! Integration tests for chained multi-dataset runs.

use std::path::Path;

use deident_host::{NativeEngine, run_chain};
use deident_types::{JobOutcome, Mode};

const PATIENTS_POLICY: &str = r#"
version: 1
dataset: chain-test
key: { inline: "chain-test-secret-0123456789abcdef012345" }
fields:
  - name: patient_id
    class: direct_identifier
    pseudonymize: { prefix: "pid_" }
  - name: age
    class: quasi_identifier
    anonymize: { strategy: bucket, width: 10 }
"#;

const VISITS_POLICY: &str = r#"
version: 1
dataset: chain-test
key: { inline: "chain-test-secret-0123456789abcdef012345" }
fields:
  - name: visit_id
    class: direct_identifier
  - name: patient_ref
    class: direct_identifier
    pseudonymize: { prefix: "pid_", domain: patient_id }
"#;

fn write_fixture(dir: &Path) {
    std::fs::write(dir.join("patients.csv"), "patient_id,age\nP001,34\nP002,52\n").unwrap();
    std::fs::write(
        dir.join("visits.csv"),
        "visit_id,patient_ref\nV1,P001\nV2,P001\nV3,P002\n",
    )
    .unwrap();
    std::fs::write(dir.join("patients.yaml"), PATIENTS_POLICY).unwrap();
    std::fs::write(dir.join("visits.yaml"), VISITS_POLICY).unwrap();
    std::fs::write(
        dir.join("chain.yaml"),
        r#"
version: 1
name: chain-test
jobs:
  - name: patients
    input: patients.csv
    policy: patients.yaml
    output: out/patients.csv
  - name: visits
    input: visits.csv
    policy: visits.yaml
    output: out/visits.csv
"#,
    )
    .unwrap();
}

#[test]
fn chain_links_tokens_across_files() {
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());

    let report = run_chain(&tmp.path().join("chain.yaml"), Mode::Pseudonymize, &NativeEngine)
        .unwrap();
    assert!(report.completed);
    assert_eq!(report.jobs.len(), 2);
    assert!(report.warnings.is_empty(), "warnings: {:?}", report.warnings);
    assert!(
        report
            .jobs
            .iter()
            .all(|j| matches!(j.outcome, JobOutcome::Succeeded { .. }))
    );

    // P001's token in patients.csv must equal P001's token in visits.csv,
    // because patient_ref declares `domain: patient_id`.
    let patients = std::fs::read_to_string(tmp.path().join("out/patients.csv")).unwrap();
    let visits = std::fs::read_to_string(tmp.path().join("out/visits.csv")).unwrap();
    let p001_token = patients.lines().nth(1).unwrap().split(',').next().unwrap().to_string();
    assert!(p001_token.starts_with("pid_"));
    let v1_ref = visits.lines().nth(1).unwrap().split(',').nth(1).unwrap();
    let v2_ref = visits.lines().nth(2).unwrap().split(',').nth(1).unwrap();
    assert_eq!(p001_token, v1_ref, "foreign key must survive pseudonymization");
    assert_eq!(v1_ref, v2_ref, "same patient, same token within a file");
    let v3_ref = visits.lines().nth(3).unwrap().split(',').nth(1).unwrap();
    assert_ne!(v1_ref, v3_ref, "different patients must not collide");
}

#[test]
fn chain_stops_at_first_failure() {
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    // Break the first job's policy: unlisted column -> job fails.
    std::fs::write(
        tmp.path().join("patients.yaml"),
        "version: 1\ndataset: chain-test\nfields: []\n",
    )
    .unwrap();

    let report = run_chain(&tmp.path().join("chain.yaml"), Mode::Anonymize, &NativeEngine)
        .unwrap();
    assert!(!report.completed);
    assert_eq!(report.jobs.len(), 1, "second job must not run after a failure");
    assert!(matches!(report.jobs[0].outcome, JobOutcome::Failed { .. }));
    assert!(report.warnings.iter().any(|w| w.contains("not run")));
}

#[test]
fn diverging_dataset_scopes_are_flagged() {
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    std::fs::write(
        tmp.path().join("visits.yaml"),
        VISITS_POLICY.replace("dataset: chain-test", "dataset: other-scope"),
    )
    .unwrap();

    let report = run_chain(&tmp.path().join("chain.yaml"), Mode::Pseudonymize, &NativeEngine)
        .unwrap();
    assert!(
        report.warnings.iter().any(|w| w.contains("different 'dataset' scopes")),
        "warnings: {:?}",
        report.warnings
    );
}

#[test]
fn manifest_dataset_override_restores_linkage() {
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    std::fs::write(
        tmp.path().join("visits.yaml"),
        VISITS_POLICY.replace("dataset: chain-test", "dataset: other-scope"),
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("chain.yaml"),
        r#"
version: 1
name: chain-test
dataset: unified-scope
jobs:
  - name: patients
    input: patients.csv
    policy: patients.yaml
    output: out/patients.csv
  - name: visits
    input: visits.csv
    policy: visits.yaml
    output: out/visits.csv
"#,
    )
    .unwrap();

    let report = run_chain(&tmp.path().join("chain.yaml"), Mode::Pseudonymize, &NativeEngine)
        .unwrap();
    assert!(report.completed);
    assert!(report.warnings.is_empty());
    let patients = std::fs::read_to_string(tmp.path().join("out/patients.csv")).unwrap();
    let visits = std::fs::read_to_string(tmp.path().join("out/visits.csv")).unwrap();
    let p001_token = patients.lines().nth(1).unwrap().split(',').next().unwrap();
    let v1_ref = visits.lines().nth(1).unwrap().split(',').nth(1).unwrap();
    assert_eq!(p001_token, v1_ref);
}

/// A chain manifest is a shareable config artifact, so hostile names must be
/// rejected at load time — they used to reach a path that is `remove_dir_all`ed.
#[test]
fn rejects_hostile_manifest_and_job_names() {
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    let manifest = tmp.path().join("chain.yaml");

    let cases = [
        ("../../../../Users/someone/Documents", "job name traversal"),
        ("a/b", "job name separator"),
        ("", "empty job name"),
    ];
    for (name, what) in cases {
        std::fs::write(
            &manifest,
            format!(
                "version: 1\nname: ok\njobs:\n  - name: \"{name}\"\n    \
                 input: patients.csv\n    policy: patients.yaml\n    output: out/p.csv\n"
            ),
        )
        .unwrap();
        let err = run_chain(&manifest, Mode::Anonymize, &NativeEngine)
            .expect_err(&format!("{what} must be rejected"));
        let message = format!("{err:#}");
        assert!(
            message.contains("chain job name"),
            "{what}: unexpected error: {message}"
        );
    }

    // The chain-level name is validated the same way.
    std::fs::write(
        &manifest,
        "version: 1\nname: \"../escape\"\njobs:\n  - name: p\n    \
         input: patients.csv\n    policy: patients.yaml\n    output: out/p.csv\n",
    )
    .unwrap();
    let err = run_chain(&manifest, Mode::Anonymize, &NativeEngine).unwrap_err();
    assert!(format!("{err:#}").contains("chain name"));
}
