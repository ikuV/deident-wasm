//! End-to-end engine tests for the pseudonymize and anonymize flows.

use deident_core::vault::{InMemoryVault, NoopVault};
use deident_core::{Policy, run_csv_job};
use deident_types::Mode;

const POLICY: &str = r#"
version: 1
dataset: flow-test
key:
  inline: "integration-test-secret"
on_unlisted: error
fields:
  - name: id
    class: direct_identifier
    pseudonymize: { prefix: "tok_" }
  - name: name
    class: direct_identifier
  - name: age
    class: quasi_identifier
    anonymize: { strategy: bucket, width: 10 }
  - name: zip
    class: quasi_identifier
    anonymize: { strategy: keep_prefix, chars: 3 }
  - name: visit
    class: quasi_identifier
    anonymize: { strategy: date_truncate, granularity: year }
  - name: diagnosis
    class: sensitive
"#;

const INPUT: &str = "\
id,name,age,zip,visit,diagnosis
1,Ada,34,81549,2024-03-14,A
2,Ben,37,81541,2024-07-02,B
3,Cem,52,80331,2023-11-20,C
4,Dua,58,80333,2019-05-08,D
";

fn run(mode: Mode, input: &str) -> (String, deident_types::RiskReport) {
    let policy = Policy::from_yaml(POLICY).unwrap();
    let mut out = Vec::new();
    let mut vault = NoopVault;
    let report = run_csv_job(mode, &policy, input.as_bytes(), &mut out, &mut vault).unwrap();
    (String::from_utf8(out).unwrap(), report)
}

#[test]
fn pseudonymize_is_deterministic_and_reversibly_mapped() {
    let (out1, report) = run(Mode::Pseudonymize, INPUT);
    let (out2, _) = run(Mode::Pseudonymize, INPUT);
    assert_eq!(out1, out2, "same input + policy must give identical output");

    // header unchanged, ids tokenized with prefix, quasi/sensitive untouched
    let mut lines = out1.lines();
    assert_eq!(
        lines.next().unwrap(),
        "id,name,age,zip,visit,diagnosis"
    );
    let first: Vec<&str> = lines.next().unwrap().split(',').collect();
    assert!(first[0].starts_with("tok_"));
    assert_ne!(first[1], "Ada");
    assert_eq!(&first[2..], &["34", "81549", "2024-03-14", "A"]);

    assert_eq!(report.rows_read, 4);
    assert_eq!(report.rows_written, 4);
    assert_eq!(report.direct_identifiers.len(), 2);
    assert!(report.direct_identifiers.iter().all(|f| f.action == "tokenized"));
    // inline key use must be surfaced
    assert!(report.warnings.iter().any(|w| w.contains("inline")));

    // same value in different rows -> same token (stability)
    let repeated = "id,name,age,zip,visit,diagnosis\n9,Ada,1,2,2020-01-01,X\n9,Ada,1,2,2020-01-01,X\n";
    let (out, _) = run(Mode::Pseudonymize, repeated);
    let rows: Vec<&str> = out.lines().skip(1).collect();
    assert_eq!(rows[0], rows[1]);
}

#[test]
fn pseudonymize_records_mappings_in_vault() {
    let policy = Policy::from_yaml(POLICY).unwrap();
    let mut out = Vec::new();
    let mut vault = InMemoryVault::new();
    run_csv_job(Mode::Pseudonymize, &policy, INPUT.as_bytes(), &mut out, &mut vault).unwrap();
    // 4 ids + 4 names
    assert_eq!(vault.len(), 8);
    let ada = vault
        .entries()
        .find(|e| e.field == "name" && e.original == "Ada")
        .unwrap();
    assert_ne!(ada.token, "Ada");
}

#[test]
fn anonymize_removes_direct_identifiers_and_generalizes() {
    let (out, report) = run(Mode::Anonymize, INPUT);
    let mut lines = out.lines();
    assert_eq!(lines.next().unwrap(), "age,zip,visit,diagnosis");
    let rows: Vec<&str> = lines.collect();
    assert_eq!(rows[0], "30-39,815**,2024,A");
    assert_eq!(rows[1], "30-39,815**,2024,B");
    assert_eq!(rows[2], "50-59,803**,2023,C");
    assert_eq!(rows[3], "50-59,803**,2019,D");
    assert!(!out.contains("Ada"), "no direct identifier may survive");

    assert_eq!(report.direct_identifiers.len(), 2);
    assert!(report.direct_identifiers.iter().all(|f| f.action == "removed"));

    // classes: {30-39,815**,2024} x2, {50-59,803**,2023} x1, {50-59,803**,2019} x1
    let qi = report.quasi_identifiers.unwrap();
    assert_eq!(qi.fields, vec!["age", "zip", "visit"]);
    assert_eq!(qi.equivalence_classes, 3);
    assert_eq!(qi.min_class_size, 1);
    assert_eq!(qi.max_class_size, 2);
    assert_eq!(qi.unique_rows, 2);
    assert_eq!(qi.k_thresholds[0].k, 2);
    assert_eq!(qi.k_thresholds[0].rows_at_or_above, 2);
    assert!(
        report.limitations.iter().any(|l| l.contains("does not certify")),
        "limitations language must be embedded"
    );
}

#[test]
fn anonymize_suppresses_unparsable_values() {
    let input = "id,name,age,zip,visit,diagnosis\n1,Ada,unknown,81549,soon,A\n";
    let (out, report) = run(Mode::Anonymize, input);
    assert_eq!(out.lines().nth(1).unwrap(), "*,815**,*,A");
    assert!(report.warnings.iter().any(|w| w.contains("suppressed")));
}

#[test]
fn unlisted_columns_fail_by_default() {
    let policy = Policy::from_yaml(POLICY).unwrap();
    let input = "id,name,age,zip,visit,diagnosis,extra\n";
    let mut out = Vec::new();
    let err = run_csv_job(
        Mode::Anonymize,
        &policy,
        input.as_bytes(),
        &mut out,
        &mut NoopVault,
    )
    .unwrap_err();
    assert!(err.to_string().contains("extra"));
}
