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
fn anonymize_through_wasm_sandbox_matches_native() {
    // Build the worker module (cached by cargo after the first run).
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let status = std::process::Command::new("cargo")
        .args(["build", "-p", "deident-worker", "--target", "wasm32-wasip1", "--release"])
        .current_dir(&root)
        .status()
        .unwrap();
    assert!(status.success(), "worker wasm build failed");
    let worker = root.join("target/wasm32-wasip1/release/deident-worker.wasm");

    let tmp = tempfile::tempdir().unwrap();
    let native_out = tmp.path().join("native.csv");
    let wasm_out = tmp.path().join("wasm.csv");

    for (engine_args, out) in [
        (vec!["--engine", "native"], &native_out),
        (vec!["--engine", "wasm", "--worker", worker.to_str().unwrap()], &wasm_out),
    ] {
        deident()
            .arg("anonymize")
            .arg(example("data/patients.csv"))
            .arg("--policy")
            .arg(example("policies/patients.yaml"))
            .arg("--out")
            .arg(out)
            .args(engine_args)
            .assert()
            .success();
    }

    assert_eq!(
        std::fs::read(&native_out).unwrap(),
        std::fs::read(&wasm_out).unwrap(),
        "wasm and native engines must produce identical output"
    );
}

#[test]
fn chain_pseudonymize_links_tokens_and_writes_report() {
    let tmp = tempfile::tempdir().unwrap();
    // Manifest in a temp dir referencing the example data/policies by
    // absolute path; outputs stay in the temp dir.
    let manifest = tmp.path().join("chain.yaml");
    std::fs::write(
        &manifest,
        format!(
            r#"
version: 1
name: cli-chain-test
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
            patients_policy = example("policies/patients.yaml").display(),
            visits = example("data/visits.csv").display(),
            visits_policy = example("policies/visits.yaml").display(),
        ),
    )
    .unwrap();
    let report_path = tmp.path().join("chain-report.json");

    deident()
        .arg("chain")
        .arg(&manifest)
        .arg("--mode")
        .arg("pseudonymize")
        .arg("--report")
        .arg(&report_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("2 of 2 job(s) succeeded"));

    let patients = std::fs::read_to_string(tmp.path().join("out/patients.csv")).unwrap();
    let visits = std::fs::read_to_string(tmp.path().join("out/visits.csv")).unwrap();
    // P001 is row 1 in patients.csv and referenced by V100/V101 in visits.csv.
    let p001_token = patients.lines().nth(1).unwrap().split(',').next().unwrap();
    let v100_ref = visits.lines().nth(1).unwrap().split(',').nth(1).unwrap();
    assert!(p001_token.starts_with("pid_"));
    assert_eq!(p001_token, v100_ref, "cross-file join must survive");

    let report: deident_types::ChainReport =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    assert!(report.completed);
    assert_eq!(report.jobs.len(), 2);
}

#[test]
fn anonymize_redacts_iban_pattern_in_notes() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out.csv");
    deident()
        .arg("anonymize")
        .arg(example("data/patients.csv"))
        .arg("--policy")
        .arg(example("policies/patients.yaml"))
        .arg("--out")
        .arg(&out)
        .assert()
        .success()
        .stdout(predicate::str::contains("pattern 'iban' in notes: 1 match(es) redacted"));
    let csv = std::fs::read_to_string(&out).unwrap();
    assert!(!csv.contains("DE89370400440532013000"), "IBAN must not survive");
    assert!(csv.contains("[IBAN]"));
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

/// The vault → export → reverse workflow, including a pattern-inserted mock
/// that lives *inside* a free-text value (whole-cell lookup alone misses it).
#[test]
fn vault_export_and_reverse_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("p.yaml");
    std::fs::write(
        &policy,
        r#"
version: 1
dataset: vault-round-trip
key: { inline: "cli-test-secret-0123456789abcdef01234567" }
on_unlisted: error
fields:
  - name: patient_id
    class: direct_identifier
    pseudonymize: { prefix: "pid_" }
  - name: notes
    class: utility
patterns:
  - name: iban
    builtin: iban
    fields: [notes]
    action: mock
"#,
    )
    .unwrap();
    let input = tmp.path().join("in.csv");
    std::fs::write(
        &input,
        "patient_id,notes\nP001,refund to DE89370400440532013000\nP002,none\n",
    )
    .unwrap();
    let out = tmp.path().join("out.csv");
    let vault = tmp.path().join("v.jsonl");

    deident()
        .arg("pseudonymize")
        .arg(&input)
        .arg("--policy")
        .arg(&policy)
        .arg("--out")
        .arg(&out)
        .arg("--vault")
        .arg(&vault)
        .arg("--engine")
        .arg("native")
        .assert()
        .success()
        .stdout(predicate::str::contains("1 match(es) mocked"))
        .stdout(predicate::str::contains("re-identification material"));

    let transformed = std::fs::read_to_string(&out).unwrap();
    assert!(!transformed.contains("P001"), "id must be tokenized");
    assert!(
        !transformed.contains("DE89370400440532013000"),
        "the original IBAN must not survive"
    );
    assert!(
        transformed.contains("refund to DE"),
        "the mock must keep the IBAN shape in place: {transformed}"
    );

    // The vault must not contain plaintext.
    let vault_raw = std::fs::read_to_string(&vault).unwrap();
    assert!(!vault_raw.contains("P001"));
    assert!(!vault_raw.contains("DE89370400440532013000"));
    assert!(vault_raw.contains("deident-vault"), "header stays readable");

    // Export lists both the column token and the pattern mock.
    deident()
        .arg("vault")
        .arg("export")
        .arg(&vault)
        .arg("--policy")
        .arg(&policy)
        .assert()
        .success()
        .stdout(predicate::str::contains("patient_id,pid_"))
        .stdout(predicate::str::contains("pattern:iban,"));

    // Reversal must restore the file exactly, embedded mock included.
    let restored = tmp.path().join("back.csv");
    deident()
        .arg("reverse")
        .arg(&out)
        .arg("--vault")
        .arg(&vault)
        .arg("--policy")
        .arg(&policy)
        .arg("--out")
        .arg(&restored)
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(&restored).unwrap(),
        std::fs::read_to_string(&input).unwrap(),
        "reverse must reproduce the original byte for byte"
    );
}

#[test]
fn reverse_with_the_wrong_key_fails_loudly() {
    let tmp = tempfile::tempdir().unwrap();
    let write_policy = |path: &std::path::Path, secret: &str| {
        std::fs::write(
            path,
            format!(
                "version: 1\ndataset: wrong-key\nkey: {{ inline: \"{secret}\" }}\n\
                 fields:\n  - {{ name: id, class: direct_identifier }}\n"
            ),
        )
        .unwrap();
    };
    let good = tmp.path().join("good.yaml");
    let bad = tmp.path().join("bad.yaml");
    // Both must clear the 32-byte key-material floor.
    write_policy(&good, "right-secret-0123456789abcdef0123456789");
    write_policy(&bad, "wrong-secret-0123456789abcdef0123456789");
    let input = tmp.path().join("in.csv");
    std::fs::write(&input, "id\nP001\n").unwrap();
    let vault = tmp.path().join("v.jsonl");

    deident()
        .arg("pseudonymize")
        .arg(&input)
        .arg("--policy")
        .arg(&good)
        .arg("--out")
        .arg(tmp.path().join("out.csv"))
        .arg("--vault")
        .arg(&vault)
        .arg("--engine")
        .arg("native")
        .assert()
        .success();

    deident()
        .arg("vault")
        .arg("export")
        .arg(&vault)
        .arg("--policy")
        .arg(&bad)
        .assert()
        .failure()
        .stderr(predicate::str::contains("wrong key"));
}

#[test]
fn lint_reports_and_can_deny() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("risky.yaml");
    std::fs::write(
        &policy,
        "version: 1\ndataset: risky\nkey: { inline: \"s-0123456789abcdef0123456789abcdef\" }\non_unlisted: keep\n\
         fields:\n  - { name: id, class: direct_identifier }\n  - { name: zip, class: quasi_identifier }\n",
    )
    .unwrap();

    deident()
        .arg("lint")
        .arg(&policy)
        .arg("--mode")
        .arg("anonymize")
        .assert()
        .success()
        .stdout(predicate::str::contains("qi-without-strategy"))
        .stdout(predicate::str::contains("unlisted-columns-kept"));

    // --deny turns warnings into a non-zero exit.
    deident().arg("lint").arg(&policy).arg("--deny").assert().failure();

    // A job refuses to run under --deny-lints.
    deident()
        .arg("anonymize")
        .arg(example("data/patients.csv"))
        .arg("--policy")
        .arg(&policy)
        .arg("--out")
        .arg(tmp.path().join("out.csv"))
        .arg("--deny-lints")
        .assert()
        .failure()
        .stderr(predicate::str::contains("--deny-lints"));
}

#[test]
fn audit_log_records_metadata_only() {
    let tmp = tempfile::tempdir().unwrap();
    let log = tmp.path().join("audit.jsonl");
    for _ in 0..2 {
        deident()
            .arg("anonymize")
            .arg(example("data/patients.csv"))
            .arg("--policy")
            .arg(example("policies/patients.yaml"))
            .arg("--out")
            .arg(tmp.path().join("out.csv"))
            .arg("--engine")
            .arg("native")
            .arg("--audit-log")
            .arg(&log)
            .assert()
            .success();
    }
    let raw = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 2, "one append-only record per job");
    let record: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(record["status"], "succeeded");
    assert_eq!(record["mode"], "anonymize");
    assert_eq!(record["rows_read"], 12);
    assert!(record["policy_hash"].as_str().unwrap().len() == 32);
    // Metadata only: no cell values from the dataset.
    assert!(!raw.contains("Alice"), "audit log must not contain data");
    assert!(!raw.contains("81549"));
}

#[test]
fn converts_between_formats_while_transforming() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out.jsonl");
    deident()
        .arg("anonymize")
        .arg(example("data/patients.csv"))
        .arg("--policy")
        .arg(example("policies/patients.yaml"))
        .arg("--out")
        .arg(&out)
        .arg("--engine")
        .arg("native")
        .assert()
        .success();
    let raw = std::fs::read_to_string(&out).unwrap();
    let first: serde_json::Value = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
    assert!(first.get("patient_id").is_none(), "identifier must be gone");
    assert_eq!(first["age"], "30-39", "generalized values are strings");
    assert!(!raw.contains("Alice"));
}

/// End-to-end DICOM de-identification over a generated study.
#[test]
fn dicom_deidentifies_a_study_and_reports_honestly() {
    let tmp = tempfile::tempdir().unwrap();
    let study = tmp.path().join("study");
    let out = tmp.path().join("deid");
    let report_path = tmp.path().join("report.json");
    deident_dicom::synthetic::write_study(&study, 2).unwrap();

    let policy = tmp.path().join("dicom.yaml");
    std::fs::write(
        &policy,
        "version: 1\nkind: dicom\ndataset: cli-dicom-test\n\
         key: { inline: \"cli-dicom-secret-0123456789abcdef0123456\" }\nprofile: basic\n\
         patterns:\n  - { name: iban, builtin: iban, action: redact }\n",
    )
    .unwrap();

    deident()
        .arg("dicom")
        .arg(&study)
        .arg("--policy")
        .arg(&policy)
        .arg("--out")
        .arg(&out)
        .arg("--report")
        .arg(&report_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("2 instance(s) written"))
        // The pixel caveat must never be omitted from a DICOM run.
        .stdout(predicate::str::contains("pixel data was NOT modified"))
        .stdout(predicate::str::contains("not full conformance"));

    // No planted PHI may survive in any output byte.
    for entry in std::fs::read_dir(&out).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        for phi in [
            deident_dicom::synthetic::PHI.patient_name,
            deident_dicom::synthetic::PHI.patient_id,
            deident_dicom::synthetic::PHI.study_uid,
            "DE89370400440532013000",
        ] {
            assert!(
                !bytes.windows(phi.len()).any(|w| w == phi.as_bytes()),
                "PHI survived: {phi}"
            );
        }
    }

    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    assert_eq!(report["instances_written"], 2);
    assert_eq!(report["instances_failed"], 0);
    // 1 study + 1 series + 2 SOP UIDs.
    assert_eq!(report["distinct_uids_remapped"], 4);
}

/// Every artifact must record the build that produced it. A privacy report is
/// evidence, and detection patterns change between versions — "no identifiers
/// found" only means something alongside the version that looked.
#[test]
fn reports_and_audit_records_carry_the_tool_version() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out.csv");
    let report_path = tmp.path().join("report.json");
    let audit_path = tmp.path().join("audit.jsonl");

    deident()
        .arg("anonymize")
        .arg(example("data/patients.csv"))
        .arg("--policy")
        .arg(example("policies/patients.yaml"))
        .arg("--out")
        .arg(&out)
        .arg("--report")
        .arg(&report_path)
        .arg("--audit-log")
        .arg(&audit_path)
        .arg("--engine")
        .arg("native")
        .assert()
        .success();

    let expected = env!("CARGO_PKG_VERSION");
    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    assert_eq!(
        report["tool_version"], expected,
        "the risk report must state which build produced it"
    );

    let audit_line = std::fs::read_to_string(&audit_path).unwrap();
    let record: serde_json::Value =
        serde_json::from_str(audit_line.lines().next().unwrap()).unwrap();
    assert_eq!(
        record["tool_version"], expected,
        "the audit record must state which build ran the job"
    );

    // And the binary agrees with the crate it was built from.
    deident()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(expected));
}

/// Writing the output over the input used to truncate the source before a byte
/// was read, then report success on the now-empty file. Data loss with exit 0.
#[test]
fn refuses_to_write_output_over_the_input() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("data.csv");
    std::fs::copy(example("data/patients.csv"), &target).unwrap();
    let original = std::fs::read(&target).unwrap();

    for command in ["pseudonymize", "anonymize"] {
        deident()
            .arg(command)
            .arg(&target)
            .arg("--policy")
            .arg(example("policies/patients.yaml"))
            .arg("--out")
            .arg(&target)
            .arg("--engine")
            .arg("native")
            .assert()
            .failure()
            .stderr(predicate::str::contains("refusing to write the output over the input"));
        assert_eq!(
            std::fs::read(&target).unwrap(),
            original,
            "{command}: the source file must be untouched"
        );
    }

    // A relative path naming the same file must be caught too.
    let dir = tmp.path();
    deident()
        .current_dir(dir)
        .arg("anonymize")
        .arg("./data.csv")
        .arg("--policy")
        .arg(example("policies/patients.yaml"))
        .arg("--out")
        .arg("data.csv")
        .arg("--engine")
        .arg("native")
        .assert()
        .failure();
    assert_eq!(std::fs::read(&target).unwrap(), original);
}

/// A DICOM vault was write-only: `vault export` parsed only the tabular dialect
/// and rejected the very policy that produced the vault.
#[test]
fn dicom_vault_can_be_exported_with_its_own_policy() {
    let tmp = tempfile::tempdir().unwrap();
    let study = tmp.path().join("study");
    deident_dicom::synthetic::write_study(&study, 1).unwrap();
    let policy = tmp.path().join("dicom.yaml");
    std::fs::write(
        &policy,
        "version: 1\nkind: dicom\ndataset: vault-dialect-test\n\
         key: { inline: \"dialect-secret-0123456789abcdef012345678\" }\nprofile: basic\n",
    )
    .unwrap();
    let vault = tmp.path().join("v.jsonl");

    deident()
        .arg("dicom")
        .arg(&study)
        .arg("--policy")
        .arg(&policy)
        .arg("--out")
        .arg(tmp.path().join("deid"))
        .arg("--vault")
        .arg(&vault)
        .assert()
        .success();

    deident()
        .arg("vault")
        .arg("export")
        .arg(&vault)
        .arg("--policy")
        .arg(&policy)
        .assert()
        .success()
        .stdout(predicate::str::contains("dicom:uid"));
}

/// Chained runs must be lintable: `--deny-lints` was previously unavailable and
/// no lint output appeared at all for the recommended multi-file path.
#[test]
fn chain_runs_policy_lints() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("risky.yaml");
    std::fs::write(
        &policy,
        "version: 1\ndataset: risky\nkey: { inline: \"s-0123456789abcdef0123456789abcdef\" }\non_unlisted: keep\n\
         fields:\n  - { name: patient_id, class: direct_identifier }\n  \
         - { name: age, class: quasi_identifier }\n",
    )
    .unwrap();
    let manifest = tmp.path().join("chain.yaml");
    std::fs::write(
        &manifest,
        format!(
            "version: 1\nname: lint-chain\njobs:\n  - name: p\n    input: {}\n    \
             policy: {}\n    output: out/p.csv\n",
            example("data/patients.csv").display(),
            policy.display()
        ),
    )
    .unwrap();

    deident()
        .arg("chain")
        .arg(&manifest)
        .arg("--mode")
        .arg("anonymize")
        .arg("--deny-lints")
        .assert()
        .failure()
        .stderr(predicate::str::contains("--deny-lints"));
}

/// A colliding mock must never be reversed to a guess.
///
/// `555-021-678` and `555-031-074` are two originals found by exhaustive search
/// to produce the same phone mock under this secret — they collided after ~31k
/// values, which is what the birthday bound predicts for a 9-digit space. Before
/// this was handled, `reverse` restored whichever entry happened to win the map
/// insert, silently returning one person's phone number for both rows.
#[test]
fn reverse_refuses_a_colliding_mock_instead_of_guessing() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("p.yaml");
    std::fs::write(
        &policy,
        r#"
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
"#,
    )
    .unwrap();
    let input = tmp.path().join("in.csv");
    std::fs::write(&input, "id,phone\nAlice,555-021-678\nBob,555-031-074\n").unwrap();
    let out = tmp.path().join("out.csv");
    let vault = tmp.path().join("v.jsonl");

    deident()
        .arg("pseudonymize")
        .arg(&input)
        .arg("--policy")
        .arg(&policy)
        .arg("--out")
        .arg(&out)
        .arg("--vault")
        .arg(&vault)
        .assert()
        .success()
        .stdout(predicate::str::contains("COLLIDING mock values"));

    let restored = tmp.path().join("back.csv");
    deident()
        .arg("reverse")
        .arg(&out)
        .arg("--vault")
        .arg(&vault)
        .arg("--policy")
        .arg(&policy)
        .arg("--out")
        .arg(&restored)
        .assert()
        // A partial re-identification must not look like a clean one to a script.
        .failure()
        .stderr(predicate::str::contains("cannot be reversed unambiguously"));

    let restored = std::fs::read_to_string(&restored).unwrap();
    assert!(
        !restored.contains("555-021-678") && !restored.contains("555-031-074"),
        "an ambiguous mock must be left alone, not resolved to a guess:\n{restored}"
    );
    // The unambiguous column tokens are still reversed.
    assert!(restored.contains("Alice") && restored.contains("Bob"), "{restored}");
}

/// The catalog listing must stay in sync with the code it prints, so the test
/// asserts against `detect::ALL` rather than a hand-written expectation.
#[test]
fn detectors_lists_the_whole_catalog_in_execution_order() {
    let output = deident().arg("detectors").assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    let mut cursor = 0;
    for builtin in deident_core::detect::ALL {
        let name = builtin.name();
        let at = stdout[cursor..]
            .find(name)
            .unwrap_or_else(|| panic!("detector '{name}' missing from the listing:\n{stdout}"));
        // Execution order is load-bearing (an earlier detector consumes text a
        // later one would match), so the listing must not reorder it.
        cursor += at + name.len();
    }
    assert!(stdout.contains(&format!("{} detector(s) listed", deident_core::detect::ALL.len())));
    assert!(
        stdout.contains("prefer `action: detect`"),
        "a listing including heuristics must carry the caveat"
    );
}

#[test]
fn detectors_filters_by_class_and_emits_json() {
    deident()
        .args(["detectors", "--class", "heuristic"])
        .assert()
        .success()
        .stdout(predicate::str::contains("person_name"))
        // A class filter must exclude the other classes entirely.
        .stdout(predicate::str::contains("iban").not())
        .stdout(predicate::str::contains("0 validated beyond their pattern"));

    let output = deident()
        .args(["detectors", "--class", "precise", "--json"])
        .assert()
        .success();
    let rows: Vec<serde_json::Value> =
        serde_json::from_slice(&output.get_output().stdout).unwrap();
    let precise = deident_core::detect::ALL
        .iter()
        .filter(|b| b.precision() == deident_core::Precision::Precise)
        .count();
    assert_eq!(rows.len(), precise);

    // `mockable: false` is the difference between a usable `action: mock` and a
    // policy that fails at run time, so it must be reported accurately.
    let mac = rows.iter().find(|r| r["name"] == "mac_address").unwrap();
    assert_eq!(mac["mockable"], serde_json::json!(true));
    assert_eq!(mac["validated_by"], serde_json::json!("MAC octet parse"));
    let ifsc = rows.iter().find(|r| r["name"] == "ifsc").unwrap();
    assert_eq!(ifsc["mockable"], serde_json::json!(false));
    assert_eq!(ifsc["validated_by"], serde_json::Value::Null);
}
