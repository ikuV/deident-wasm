//! Mock values collide, and the tool has to say so.
//!
//! A mock preserves the format it imitates, so its value space is bounded by that
//! shape — a 9-digit phone number has 10^9 possible mocks, which by the birthday
//! bound starts colliding around 31,000 distinct values. That is a *small*
//! dataset. When it happens, two identities share one mock in the output and the
//! mapping is no longer invertible.
//!
//! These tests pin the real generator's behaviour, not a hand-built fixture.

use deident_core::mock::{MockShape, generate};
use deident_types::{JobOutcome, JobRequest, Mode};

const SECRET: &[u8] = b"collision-probe-secret-0123456789abcdef";

/// Two originals found by exhaustive search to share one mock under `SECRET`.
/// They collided after ~31k values, matching sqrt(10^9) almost exactly.
const COLLIDING_A: &str = "555-021-678";
const COLLIDING_B: &str = "555-031-074";

#[test]
fn format_preserving_mocks_really_do_collide() {
    let key = deident_core::key::derive_dataset_key(SECRET, "ds");
    let a = generate(MockShape::Phone, &key, "pattern:phone", COLLIDING_A);
    let b = generate(MockShape::Phone, &key, "pattern:phone", COLLIDING_B);
    assert_ne!(COLLIDING_A, COLLIDING_B);
    assert_eq!(
        a, b,
        "these two originals are the documented collision; if this changes, the \
         constants above must be re-derived rather than the assertion relaxed"
    );
}

#[test]
fn mocks_stay_deterministic_for_one_value() {
    let key = deident_core::key::derive_dataset_key(SECRET, "ds");
    let once = generate(MockShape::Phone, &key, "pattern:phone", COLLIDING_A);
    let twice = generate(MockShape::Phone, &key, "pattern:phone", COLLIDING_A);
    assert_eq!(once, twice, "mocks must stay stable within a dataset");
}

const MOCK_POLICY: &str = r#"
version: 1
dataset: ds
on_unlisted: keep
key: { inline: "collision-probe-secret-0123456789abcdef" }
fields:
  - name: id
    class: direct_identifier
    pseudonymize: { prefix: "id_" }
patterns:
  - name: phone
    regex: '555-[0-9]{3}-[0-9]{3}'
    fields: [phone]
    action: mock
    mock: phone
    validate: none
"#;

fn run(dir: &std::path::Path, csv: &str) -> deident_types::RiskReport {
    let input = dir.join("in.csv");
    std::fs::write(&input, csv).unwrap();
    let request = JobRequest {
        job_id: "mock-collision".into(),
        mode: Mode::Pseudonymize,
        policy_yaml: MOCK_POLICY.to_string(),
        input_path: input.to_string_lossy().into_owned(),
        output_path: dir.join("out.csv").to_string_lossy().into_owned(),
        report_path: None,
        vault_path: Some(dir.join("vault.jsonl").to_string_lossy().into_owned()),
    };
    match deident_core::runner::execute(&request).outcome {
        JobOutcome::Succeeded { report } => *report,
        JobOutcome::Failed { error } => panic!("{error}"),
    }
}

#[test]
fn a_colliding_dataset_is_reported_at_transformation_time() {
    let tmp = tempfile::tempdir().unwrap();
    let report = run(
        tmp.path(),
        &format!("id,phone\nA,{COLLIDING_A}\nB,{COLLIDING_B}\n"),
    );

    let warning = report
        .warnings
        .iter()
        .find(|w| w.contains("COLLIDING"))
        .unwrap_or_else(|| panic!("collision not reported: {:?}", report.warnings));
    assert!(warning.contains("refuse those values"), "{warning}");

    // The output really does merge the two identities — that is the damage the
    // warning exists to disclose.
    let output = std::fs::read_to_string(tmp.path().join("out.csv")).unwrap();
    let phones: Vec<&str> = output
        .lines()
        .skip(1)
        .map(|l| l.split(',').nth(1).unwrap())
        .collect();
    assert_eq!(phones[0], phones[1], "the collision is real in the output");
}

#[test]
fn a_clean_dataset_reports_no_collision() {
    let tmp = tempfile::tempdir().unwrap();
    let report = run(
        tmp.path(),
        &format!("id,phone\nA,{COLLIDING_A}\nB,555-999-999\n"),
    );
    assert!(
        !report.warnings.iter().any(|w| w.contains("COLLIDING")),
        "false positive: {:?}",
        report.warnings
    );
}

#[test]
fn repeating_one_value_is_not_a_collision() {
    let tmp = tempfile::tempdir().unwrap();
    // The same original appearing twice maps to one mock by design. Counting
    // that as a collision would make the warning fire on every ordinary dataset.
    let report = run(
        tmp.path(),
        &format!("id,phone\nA,{COLLIDING_A}\nB,{COLLIDING_A}\nC,{COLLIDING_A}\n"),
    );
    assert!(
        !report.warnings.iter().any(|w| w.contains("COLLIDING")),
        "repeated values must not count as colliding: {:?}",
        report.warnings
    );
}
