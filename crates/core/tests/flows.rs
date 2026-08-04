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

const PATTERN_POLICY: &str = r#"
version: 1
dataset: pattern-test
key:
  inline: "integration-test-secret"
on_unlisted: error
fields:
  - name: id
    class: direct_identifier
  - name: notes
    class: utility
patterns:
  - name: iban
    builtin: iban
    fields: [notes]
    action: redact
  - name: email
    builtin: email
    action: token
    prefix: "em_"
  - name: phone
    builtin: phone
    fields: [notes]
    action: detect
"#;

#[test]
fn patterns_detect_redact_and_tokenize_in_free_text() {
    let policy = Policy::from_yaml(PATTERN_POLICY).unwrap();
    let input = "id,notes\n\
        1,pay to DE89370400440532013000 or mail ada@example.com\n\
        2,call +49 89 1234567 twice\n\
        3,plain note\n";
    let mut out = Vec::new();
    let report = run_csv_job(
        Mode::Anonymize,
        &policy,
        input.as_bytes(),
        &mut out,
        &mut NoopVault,
    )
    .unwrap();
    let out = String::from_utf8(out).unwrap();

    assert!(!out.contains("DE89370400440532013000"), "IBAN must be redacted");
    assert!(out.contains("[IBAN]"));
    assert!(!out.contains("ada@example.com"), "email must be tokenized");
    assert!(out.contains("em_"), "email token must carry its prefix");
    assert!(out.contains("+49 89 1234567"), "detect must leave values in place");

    let find = |p: &str| report.patterns.iter().find(|f| f.pattern == p).unwrap();
    assert_eq!(find("iban").action, "redacted");
    assert_eq!(find("iban").matches, 1);
    assert_eq!(find("email").action, "tokenized");
    assert_eq!(find("phone").action, "detected");
    assert!(
        report.warnings.iter().any(|w| w.contains("action: detect")),
        "detect-only matches must be surfaced as a warning"
    );
    assert!(
        report.warnings.iter().any(|w| w.contains("pseudonymous")),
        "tokens in anonymize output must be flagged as pseudonymous"
    );

    // Token patterns are deterministic: the same email in a second run gets
    // the same token.
    let mut out2 = Vec::new();
    run_csv_job(Mode::Anonymize, &policy, input.as_bytes(), &mut out2, &mut NoopVault).unwrap();
    assert_eq!(out, String::from_utf8(out2).unwrap());
}

#[test]
fn token_pattern_without_key_fails() {
    let yaml = r#"
version: 1
dataset: no-key
fields:
  - name: notes
    class: utility
patterns:
  - name: email
    builtin: email
    action: token
"#;
    let policy = Policy::from_yaml(yaml).unwrap();
    let err = run_csv_job(
        Mode::Anonymize,
        &policy,
        "notes\nhello\n".as_bytes(),
        Vec::new(),
        &mut NoopVault,
    )
    .unwrap_err();
    assert!(err.to_string().contains("key"));
}

#[test]
fn shared_domain_links_tokens_across_differently_named_columns() {
    let policy_a = r#"
version: 1
dataset: linked
key: { inline: "integration-test-secret" }
fields:
  - name: patient_id
    class: direct_identifier
    pseudonymize: { prefix: "pid_" }
"#;
    let policy_b = r#"
version: 1
dataset: linked
key: { inline: "integration-test-secret" }
fields:
  - name: patient_ref
    class: direct_identifier
    pseudonymize: { prefix: "pid_", domain: patient_id }
"#;
    let token_from = |policy_yaml: &str, header: &str| {
        let policy = Policy::from_yaml(policy_yaml).unwrap();
        let input = format!("{header}\nP001\n");
        let mut out = Vec::new();
        run_csv_job(Mode::Pseudonymize, &policy, input.as_bytes(), &mut out, &mut NoopVault)
            .unwrap();
        String::from_utf8(out).unwrap().lines().nth(1).unwrap().to_string()
    };
    assert_eq!(
        token_from(policy_a, "patient_id"),
        token_from(policy_b, "patient_ref"),
        "same domain + dataset + key must yield the same token"
    );
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

/// Presets enable whole detector groups, and an explicit rule of the same name
/// still wins.
#[test]
fn presets_expand_and_explicit_rules_override_them() {
    let yaml = r#"
version: 1
dataset: preset-test
key: { inline: "s" }
on_unlisted: keep
fields: []
patterns:
  - { name: iban, builtin: iban, action: detect }
presets:
  - { preset: precise, action: redact }
"#;
    let policy = Policy::from_yaml(yaml).unwrap();
    let rules = policy.effective_patterns();
    let iban = rules.iter().find(|r| r.name == "iban").unwrap();
    assert_eq!(
        iban.action,
        deident_core::policy::PatternAction::Detect,
        "the explicit iban rule must win over the preset"
    );
    assert_eq!(
        rules.iter().filter(|r| r.name == "iban").count(),
        1,
        "no duplicate rule for an overridden name"
    );
    // The rest of the `precise` group is present and redacting.
    for expected in ["email", "credit_card", "ip_address", "url", "api_key", "ifsc"] {
        let rule = rules
            .iter()
            .find(|r| r.name == expected)
            .unwrap_or_else(|| panic!("preset must include {expected}"));
        assert_eq!(rule.action, deident_core::policy::PatternAction::Redact);
    }
}

/// A checksum-rejected match must be left alone AND reported, so a card-shaped
/// value that failed Luhn is visible rather than silently ignored.
#[test]
fn checksum_rejections_are_left_intact_and_reported() {
    let yaml = r#"
version: 1
dataset: reject-test
on_unlisted: keep
fields: []
patterns:
  - { name: credit_card, builtin: credit_card, action: redact }
"#;
    let policy = Policy::from_yaml(yaml).unwrap();
    // 4532123456789012 is NOT Luhn-valid; 4111111111111111 is.
    let input = "notes\norder 4532123456789012 and card 4111111111111111\n";
    let mut out = Vec::new();
    let report = run_csv_job(
        Mode::Anonymize,
        &policy,
        input.as_bytes(),
        &mut out,
        &mut NoopVault,
    )
    .unwrap();
    let out = String::from_utf8(out).unwrap();

    assert!(!out.contains("4111111111111111"), "the valid card must be redacted");
    assert!(
        out.contains("4532123456789012"),
        "a Luhn-failing value must be left exactly as it was: {out}"
    );
    assert!(
        report.warnings.iter().any(|w| w.contains("failed the") && w.contains("checksum")),
        "rejections must be surfaced: {:?}",
        report.warnings
    );
}

/// Heuristic detectors must announce themselves in the report.
#[test]
fn heuristic_detectors_warn_about_their_own_reliability() {
    let yaml = r#"
version: 1
dataset: heuristic-test
on_unlisted: keep
fields: []
patterns:
  - { name: person_name, builtin: person_name, action: detect }
"#;
    let policy = Policy::from_yaml(yaml).unwrap();
    let input = "notes\nseen by Dr. Priya Sharma today\n";
    let mut out = Vec::new();
    let report = run_csv_job(
        Mode::Anonymize,
        &policy,
        input.as_bytes(),
        &mut out,
        &mut NoopVault,
    )
    .unwrap();
    assert!(
        report.patterns.iter().any(|p| p.pattern == "person_name"),
        "the name must be detected"
    );
    assert!(
        report.warnings.iter().any(|w| w.contains("heuristic detector")),
        "a heuristic detector must flag its own unreliability: {:?}",
        report.warnings
    );
}
