//! Feature-combination matrix over the sample dataset.
//!
//! Runs every mode × run-style × engine combination against the example data
//! (each twice) and checks invariants that must hold no matter how the sample
//! dataset is edited:
//!
//! - determinism (identical output across repeated runs),
//! - native/wasm engine parity (byte-identical outputs and reports),
//! - no direct-identifier value survives into any output,
//! - pattern handling matches what is actually present in the data (expected
//!   counts are recomputed from the input, not hardcoded),
//! - anonymize outputs have the right shape (buckets, prefixes, truncated
//!   dates, redaction labels),
//! - chained runs keep foreign keys joinable across files.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use assert_cmd::Command;
use deident_core::detect::BuiltinPattern;
use deident_types::{ChainReport, JobOutcome, RiskReport};
use regex::Regex;

const MODES: [&str; 2] = ["pseudonymize", "anonymize"];
const STYLES: [&str; 2] = ["single", "chain"];
const ENGINES: [&str; 2] = ["native", "wasm"];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn example(rel: &str) -> PathBuf {
    root().join("examples").join(rel)
}

/// Build the worker module once per test process.
fn worker_wasm() -> &'static Path {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT.get_or_init(|| {
        let status = std::process::Command::new("cargo")
            .args(["build", "-p", "deident-worker", "--target", "wasm32-wasip1", "--release"])
            .current_dir(root())
            .status()
            .expect("cargo must be runnable");
        assert!(status.success(), "worker wasm build failed");
        root().join("target/wasm32-wasip1/release/deident-worker.wasm")
    })
}

fn deident() -> Command {
    let mut cmd = Command::cargo_bin("deident").unwrap();
    // Hermetic: always use the policies' inline demo keys.
    cmd.env_remove("DEIDENT_KEY");
    cmd
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn parse_csv(text: &str) -> (Vec<String>, Vec<Vec<String>>) {
    let mut reader = csv::Reader::from_reader(text.as_bytes());
    let headers = reader.headers().unwrap().iter().map(str::to_string).collect();
    let rows = reader
        .records()
        .map(|r| r.unwrap().iter().map(str::to_string).collect())
        .collect();
    (headers, rows)
}

fn column(text: &str, name: &str) -> Vec<String> {
    let (headers, rows) = parse_csv(text);
    let idx = headers
        .iter()
        .position(|h| h == name)
        .unwrap_or_else(|| panic!("column '{name}' missing in {headers:?}"));
    rows.into_iter().map(|mut r| r.swap_remove(idx)).collect()
}

/// One executed combination.
struct ComboResult {
    patients_csv: String,
    visits_csv: Option<String>,
    /// RiskReport JSON (single) or ChainReport JSON (chain).
    report_json: String,
}

fn run_combo(mode: &str, style: &str, engine: &str, dir: &Path) -> ComboResult {
    std::fs::create_dir_all(dir).unwrap();
    // Always name the engine explicitly: the default is `auto`, which would
    // resolve to wasm whenever a worker module exists and silently turn the
    // native/wasm parity check into wasm-vs-wasm.
    let mut engine_args: Vec<String> = vec!["--engine".into(), engine.into()];
    if engine == "wasm" {
        engine_args.extend(["--worker".into(), worker_wasm().to_str().unwrap().into()]);
    }

    if style == "single" {
        let out = dir.join("patients.csv");
        let report = dir.join("report.json");
        deident()
            .arg(mode)
            .arg(example("data/patients.csv"))
            .arg("--policy")
            .arg(example("policies/patients-full.yaml"))
            .arg("--out")
            .arg(&out)
            .arg("--report")
            .arg(&report)
            .args(&engine_args)
            .assert()
            .success();
        ComboResult {
            patients_csv: read(&out),
            visits_csv: None,
            report_json: read(&report),
        }
    } else {
        let manifest = dir.join("chain.yaml");
        std::fs::write(
            &manifest,
            format!(
                r#"
version: 1
name: matrix
dataset: matrix-scope
key: {{ inline: "matrix-secret-0123456789abcdef0123456789" }}
jobs:
  - name: patients
    input: {patients}
    policy: {patients_policy}
    output: out/patients.csv
  - name: visits
    input: {visits}
    policy: {visits_policy}
    output: out/visits.csv
"#,
                patients = example("data/patients.csv").display(),
                patients_policy = example("policies/patients-full.yaml").display(),
                visits = example("data/visits.csv").display(),
                visits_policy = example("policies/visits.yaml").display(),
            ),
        )
        .unwrap();
        let report = dir.join("chain-report.json");
        deident()
            .arg("chain")
            .arg(&manifest)
            .arg("--mode")
            .arg(mode)
            .arg("--report")
            .arg(&report)
            .args(&engine_args)
            .assert()
            .success();
        ComboResult {
            patients_csv: read(&dir.join("out/patients.csv")),
            visits_csv: Some(read(&dir.join("out/visits.csv"))),
            report_json: read(&report),
        }
    }
}

/// Expected pattern behavior in the notes column, recomputed from the current
/// input by simulating the rule order of patients-full.yaml
/// (iban:redact → phone:detect → email:token).
struct ExpectedPatterns {
    ibans: u64,
    phones: u64,
    emails: u64,
    /// Exact phone substrings that must still be present in the output
    /// (detect leaves them in place; computed on text with both replacements
    /// applied so they cannot overlap a replaced region).
    surviving_phones: Vec<String>,
}

fn expected_patterns(input_notes: &[String]) -> ExpectedPatterns {
    let iban = Regex::new(BuiltinPattern::Iban.regex_source()).unwrap();
    let phone = Regex::new(BuiltinPattern::Phone.regex_source()).unwrap();
    let email = Regex::new(BuiltinPattern::Email.regex_source()).unwrap();
    let mut expected = ExpectedPatterns {
        ibans: 0,
        phones: 0,
        emails: 0,
        surviving_phones: Vec::new(),
    };
    for note in input_notes.iter().filter(|n| !n.is_empty()) {
        expected.ibans += iban
            .find_iter(note)
            .filter(|m| BuiltinPattern::Iban.validator().accepts(m.as_str()))
            .count() as u64;
        let after_iban = iban.replace_all(note, "[IBAN]");
        expected.phones += phone.find_iter(&after_iban).count() as u64;
        expected.emails += email.find_iter(&after_iban).count() as u64;
        // The placeholder contains no digits, so phone matches found here lie
        // entirely in unreplaced text and appear verbatim in the real output.
        let after_email = email.replace_all(&after_iban, "em_x");
        expected
            .surviving_phones
            .extend(phone.find_iter(&after_email).map(|m| m.as_str().to_string()));
    }
    expected
}

/// Count matches the way the engine does: shape **and** checksum.
///
/// A raw regex scan would report false positives — a 32-character hex token can
/// begin with two letters and two digits and so matches the IBAN shape, and only
/// the mod-97 check distinguishes it from a real IBAN.
fn validated_matches(builtin: BuiltinPattern, text: &str) -> usize {
    let regex = Regex::new(builtin.regex_source()).unwrap();
    let validator = builtin.validator();
    regex
        .find_iter(text)
        .filter(|m| validator.accepts(m.as_str()))
        .count()
}

fn pattern_total(report: &RiskReport, pattern: &str) -> u64 {
    report
        .patterns
        .iter()
        .filter(|f| f.pattern == pattern)
        .map(|f| f.matches)
        .sum()
}

/// Invariants on a transformed patients file, independent of engine/style.
fn assert_patients_invariants(mode: &str, output: &str, ctx: &str) {
    let input = read(&example("data/patients.csv"));
    let (in_headers, in_rows) = parse_csv(&input);
    let (out_headers, out_rows) = parse_csv(output);
    assert_eq!(out_rows.len(), in_rows.len(), "{ctx}: row count must be preserved");

    // No IBAN and no email may survive anywhere (redacted/tokenized).
    assert_eq!(
        validated_matches(BuiltinPattern::Iban, output),
        0,
        "{ctx}: IBAN survived"
    );
    assert_eq!(
        validated_matches(BuiltinPattern::Email, output),
        0,
        "{ctx}: email survived"
    );

    match mode {
        "pseudonymize" => {
            assert_eq!(out_headers, in_headers, "{ctx}: header must be unchanged");
            // No original direct-identifier value may survive.
            for col in ["patient_id", "full_name", "email"] {
                let originals = column(&input, col);
                let transformed = column(output, col);
                for (orig, new) in originals.iter().zip(&transformed) {
                    if !orig.is_empty() {
                        assert_ne!(orig, new, "{ctx}: '{col}' value survived");
                        assert!(!output.contains(orig.as_str()), "{ctx}: '{orig}' leaked");
                    }
                }
            }
            for token in column(output, "patient_id") {
                assert!(token.starts_with("pid_"), "{ctx}: token prefix missing: {token}");
            }
            // Quasi-identifiers stay intact in pseudonymize mode.
            assert_eq!(column(output, "age"), column(&input, "age"), "{ctx}");
        }
        "anonymize" => {
            assert_eq!(
                out_headers,
                ["full_name", "age", "zip", "admission_date", "diagnosis", "notes"],
                "{ctx}: anonymize header shape"
            );
            let shape = |name: &str, re: &str| {
                let re = Regex::new(re).unwrap();
                for v in column(output, name) {
                    assert!(
                        v.is_empty() || v == "*" || re.is_match(&v),
                        "{ctx}: '{name}' value '{v}' has wrong shape"
                    );
                }
            };
            for v in column(output, "full_name") {
                assert_eq!(v, "REDACTED", "{ctx}: full_name must be redacted");
            }
            shape("age", r"^-?\d+--?\d+$"); // e.g. 30-39
            shape("zip", r"^.{1,3}\**$"); // e.g. 815**
            shape("admission_date", r"^\d{4}-\d{2}$"); // e.g. 2024-03
        }
        other => panic!("unknown mode {other}"),
    }
}

fn assert_single_report(mode: &str, result: &ComboResult, ctx: &str) {
    let report: RiskReport = serde_json::from_str(&result.report_json).unwrap();
    let input = read(&example("data/patients.csv"));
    let (_, in_rows) = parse_csv(&input);
    assert_eq!(report.rows_read, in_rows.len() as u64, "{ctx}");
    assert_eq!(report.rows_written, in_rows.len() as u64, "{ctx}");
    assert!(!report.limitations.is_empty(), "{ctx}: limitations must be embedded");

    // Pattern findings must match what the current sample data contains.
    let expected = expected_patterns(&column(&input, "notes"));
    assert_eq!(pattern_total(&report, "iban"), expected.ibans, "{ctx}: iban count");
    assert_eq!(pattern_total(&report, "phone"), expected.phones, "{ctx}: phone count");
    assert_eq!(pattern_total(&report, "email_text"), expected.emails, "{ctx}: email count");
    if expected.phones > 0 {
        assert!(
            report.warnings.iter().any(|w| w.contains("action: detect")),
            "{ctx}: detect-only matches must be flagged"
        );
    }
    for phone in &expected.surviving_phones {
        // detect leaves values in place
        assert!(
            result.patients_csv.contains(phone.as_str()),
            "{ctx}: detected phone '{phone}' must remain in the output"
        );
    }
    match mode {
        "pseudonymize" => assert!(
            report.direct_identifiers.iter().all(|f| f.action == "tokenized"),
            "{ctx}"
        ),
        _ => assert!(
            report
                .direct_identifiers
                .iter()
                .all(|f| f.action == "removed" || f.action == "redacted"),
            "{ctx}"
        ),
    }
}

fn assert_chain_invariants(mode: &str, result: &ComboResult, ctx: &str) {
    let report: ChainReport = serde_json::from_str(&result.report_json).unwrap();
    assert!(report.completed, "{ctx}: chain must complete");
    assert_eq!(report.jobs.len(), 2, "{ctx}");
    assert!(
        report.jobs.iter().all(|j| matches!(j.outcome, JobOutcome::Succeeded { .. })),
        "{ctx}"
    );
    assert!(report.warnings.is_empty(), "{ctx}: warnings: {:?}", report.warnings);

    let visits_out = result.visits_csv.as_ref().expect("chain produces visits output");
    if mode == "pseudonymize" {
        // Foreign keys must survive: P00x in visits maps to the same token as
        // P00x in patients (recomputed from the current inputs, row by row).
        let token_of: HashMap<String, String> = column(&read(&example("data/patients.csv")), "patient_id")
            .into_iter()
            .zip(column(&result.patients_csv, "patient_id"))
            .collect();
        let original_refs = column(&read(&example("data/visits.csv")), "patient_ref");
        let output_refs = column(visits_out, "patient_ref");
        for (orig, token) in original_refs.iter().zip(&output_refs) {
            if let Some(expected) = token_of.get(orig) {
                assert_eq!(token, expected, "{ctx}: foreign key '{orig}' broke");
            }
        }
    } else {
        // Both identifier columns are removed from visits in anonymize mode.
        let (headers, _) = parse_csv(visits_out);
        assert_eq!(headers, ["visit_date", "ward", "cost_eur"], "{ctx}");
    }
}

#[test]
fn every_feature_in_every_combination() {
    let tmp = tempfile::tempdir().unwrap();
    let mut results: HashMap<(String, String, String), ComboResult> = HashMap::new();

    for mode in MODES {
        for style in STYLES {
            for engine in ENGINES {
                let ctx = format!("{mode}/{style}/{engine}");
                let dir = tmp.path().join(ctx.replace('/', "-"));

                let first = run_combo(mode, style, engine, &dir.join("run1"));
                let second = run_combo(mode, style, engine, &dir.join("run2"));
                assert_eq!(first.patients_csv, second.patients_csv, "{ctx}: not deterministic");
                assert_eq!(first.visits_csv, second.visits_csv, "{ctx}: not deterministic");

                assert_patients_invariants(mode, &first.patients_csv, &ctx);
                match style {
                    "single" => assert_single_report(mode, &first, &ctx),
                    _ => assert_chain_invariants(mode, &first, &ctx),
                }
                results.insert((mode.into(), style.into(), engine.into()), first);
            }
        }
    }

    // Native and wasm engines must be byte-identical for every combination.
    for mode in MODES {
        for style in STYLES {
            let ctx = format!("{mode}/{style}");
            let native = &results[&(mode.into(), style.into(), "native".into())];
            let wasm = &results[&(mode.into(), style.into(), "wasm".into())];
            assert_eq!(native.patients_csv, wasm.patients_csv, "{ctx}: engine parity (patients)");
            assert_eq!(native.visits_csv, wasm.visits_csv, "{ctx}: engine parity (visits)");
            if style == "single" {
                // RiskReport contains no paths, so it must match exactly too.
                assert_eq!(native.report_json, wasm.report_json, "{ctx}: engine parity (report)");
            }
        }
    }
}
