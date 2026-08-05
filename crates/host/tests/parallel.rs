//! Integration tests for parallel execution.
//!
//! The load-bearing property is **equivalence with a single job**: splitting a
//! dataset across sandboxes is an execution detail, so a split run must produce
//! the same bytes and the same risk figures as an unsplit one. If it does not,
//! the split is silently changing the privacy result.

use deident_host::{Engine, NativeEngine, ParallelOptions, run_many, run_split};
use deident_types::{JobOutcome, JobRequest, Mode, RiskReport};

const POLICY: &str = r#"
version: 1
dataset: split-test
key: { inline: "split-test-secret-0123456789abcdef012345" }
fields:
  - name: patient_id
    class: direct_identifier
    pseudonymize: { prefix: "pid_" }
  - name: city
    class: quasi_identifier
  - name: age
    class: quasi_identifier
    anonymize: { strategy: bucket, width: 10 }
  - name: notes
    class: sensitive
patterns:
  # An additive figure: chunk pattern counts must total the single-job count.
  - name: email
    builtin: email
    fields: [notes]
    action: redact
"#;

/// 40 rows over 4 cities and a narrow age range, so quasi-identifier tuples
/// genuinely repeat *across* chunk boundaries — the case that would break a
/// naive per-chunk statistics merge.
fn fixture_csv() -> String {
    let cities = ["Berlin", "Hamburg", "Munich", "Cologne"];
    let mut csv = String::from("patient_id,city,age,notes\n");
    for i in 0..40u32 {
        csv.push_str(&format!(
            "P{i:03},{},{},contact me at user{i}@example.com\n",
            cities[(i % 4) as usize],
            30 + (i % 5),
        ));
    }
    csv
}

fn request(dir: &std::path::Path, name: &str, input: &std::path::Path) -> JobRequest {
    JobRequest {
        job_id: name.to_string(),
        mode: Mode::Pseudonymize,
        policy_yaml: POLICY.to_string(),
        input_path: input.to_string_lossy().into_owned(),
        output_path: dir
            .join(format!("{name}-out.csv"))
            .to_string_lossy()
            .into_owned(),
        report_path: None,
        vault_path: None,
    }
}

fn report(outcome: JobOutcome) -> RiskReport {
    match outcome {
        JobOutcome::Succeeded { report } => *report,
        JobOutcome::Failed { error } => panic!("job failed: {error}"),
    }
}

#[test]
fn a_split_run_produces_the_same_bytes_as_a_single_job() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("in.csv");
    std::fs::write(&input, fixture_csv()).unwrap();
    let engine = NativeEngine;

    let single = request(tmp.path(), "single", &input);
    engine.run(&single).unwrap();

    for chunks in [2usize, 3, 7, 40] {
        let split = request(tmp.path(), &format!("split{chunks}"), &input);
        let options = ParallelOptions {
            chunks,
            max_concurrency: 4,
        };
        let response = run_split(&split, &engine, &options).unwrap();
        assert!(
            matches!(response.outcome, JobOutcome::Succeeded { .. }),
            "split into {chunks} failed"
        );

        assert_eq!(
            std::fs::read(&single.output_path).unwrap(),
            std::fs::read(&split.output_path).unwrap(),
            "split into {chunks} chunks changed the output bytes"
        );
    }
}

#[test]
fn the_merged_report_matches_the_single_job_report() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("in.csv");
    std::fs::write(&input, fixture_csv()).unwrap();
    let engine = NativeEngine;

    let single = request(tmp.path(), "single", &input);
    let expected = report(engine.run(&single).unwrap().outcome);

    let mut split = request(tmp.path(), "split", &input);
    let report_path = tmp.path().join("split.json");
    split.report_path = Some(report_path.to_string_lossy().into_owned());
    let actual = report(
        run_split(
            &split,
            &engine,
            &ParallelOptions {
                chunks: 5,
                max_concurrency: 4,
            },
        )
        .unwrap()
        .outcome,
    );

    assert_eq!(actual.rows_read, expected.rows_read);
    assert_eq!(actual.rows_written, expected.rows_written);

    // The statistics trap: these are recomputed over the merged output, never
    // summed. Summing would report 40 unique rows instead of 0.
    let want = expected.quasi_identifiers.as_ref().expect("single-job statistics");
    let got = actual.quasi_identifiers.as_ref().expect("merged statistics");
    assert_eq!(got.fields, want.fields);
    assert_eq!(
        got.unique_rows, want.unique_rows,
        "merged unique_rows must match the single-job figure"
    );
    assert_eq!(got.equivalence_classes, want.equivalence_classes);
    assert_eq!(got.min_class_size, want.min_class_size);
    assert_eq!(got.max_class_size, want.max_class_size);
    assert_eq!(got.unique_row_ratio, want.unique_row_ratio);
    assert_eq!(
        got.k_thresholds
            .iter()
            .map(|t| (t.k, t.rows_at_or_above))
            .collect::<Vec<_>>(),
        want.k_thresholds
            .iter()
            .map(|t| (t.k, t.rows_at_or_above))
            .collect::<Vec<_>>(),
    );

    // Pattern findings are additive, so they must total the same.
    let total = |r: &RiskReport| r.patterns.iter().map(|p| p.matches).sum::<u64>();
    assert_eq!(total(&actual), total(&expected));

    // A split run must still honour --report; the chunks run without one, so the
    // merged report is written by run_split itself.
    let on_disk: RiskReport =
        serde_json::from_slice(&std::fs::read(&report_path).expect("merged report file")).unwrap();
    assert_eq!(
        on_disk.quasi_identifiers.as_ref().map(|q| q.unique_rows),
        Some(got.unique_rows),
        "the report on disk must be the merged one"
    );
    assert_eq!(on_disk.rows_written, actual.rows_written);

    assert!(
        actual.warnings.iter().any(|w| w.contains("parallel chunks")),
        "a split run must disclose that it was chunked: {:?}",
        actual.warnings
    );
}

#[test]
fn splitting_jsonl_also_round_trips() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("in.jsonl");
    let mut jsonl = String::new();
    for i in 0..20u32 {
        jsonl.push_str(&format!(
            "{{\"patient_id\":\"P{i:03}\",\"city\":\"Berlin\",\"age\":{},\"notes\":\"x\"}}\n",
            30 + (i % 5)
        ));
    }
    std::fs::write(&input, jsonl).unwrap();
    let engine = NativeEngine;

    let mut single = request(tmp.path(), "single", &input);
    single.output_path = tmp.path().join("single.jsonl").to_string_lossy().into_owned();
    engine.run(&single).unwrap();

    let mut split = request(tmp.path(), "split", &input);
    split.output_path = tmp.path().join("split.jsonl").to_string_lossy().into_owned();
    run_split(
        &split,
        &engine,
        &ParallelOptions {
            chunks: 4,
            max_concurrency: 2,
        },
    )
    .unwrap();

    assert_eq!(
        std::fs::read(&single.output_path).unwrap(),
        std::fs::read(&split.output_path).unwrap(),
    );
}

#[test]
fn one_chunk_is_just_a_single_job() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("in.csv");
    std::fs::write(&input, fixture_csv()).unwrap();

    let split = request(tmp.path(), "one", &input);
    let response = run_split(
        &split,
        &NativeEngine,
        &ParallelOptions {
            chunks: 1,
            max_concurrency: 4,
        },
    )
    .unwrap();
    let report = report(response.outcome);
    assert!(
        !report.warnings.iter().any(|w| w.contains("parallel chunks")),
        "an unsplit run must not claim it was chunked"
    );
}

#[test]
fn splitting_refuses_parquet_and_vaults() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("in.csv");
    std::fs::write(&input, fixture_csv()).unwrap();
    let options = ParallelOptions {
        chunks: 2,
        max_concurrency: 2,
    };

    let mut parquet = request(tmp.path(), "pq", &input);
    parquet.output_path = tmp.path().join("out.parquet").to_string_lossy().into_owned();
    let err = run_split(&parquet, &NativeEngine, &options).unwrap_err();
    assert!(
        err.to_string().contains("line-oriented"),
        "unexpected error: {err:#}"
    );

    let mut vaulted = request(tmp.path(), "vault", &input);
    vaulted.vault_path = Some(tmp.path().join("v.bin").to_string_lossy().into_owned());
    let err = run_split(&vaulted, &NativeEngine, &options).unwrap_err();
    assert!(err.to_string().contains("--vault"), "unexpected error: {err:#}");
}

#[test]
fn many_datasets_run_at_once_and_come_back_in_order() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = NativeEngine;

    // Each dataset holds a distinct row count, so a reordered result set is
    // detectable from the reports alone.
    let mut requests = Vec::new();
    for n in 1..=6u32 {
        let input = tmp.path().join(format!("in{n}.csv"));
        let mut csv = String::from("patient_id,city,age,notes\n");
        for i in 0..n {
            csv.push_str(&format!("P{i:03},Berlin,40,x\n"));
        }
        std::fs::write(&input, csv).unwrap();
        requests.push(request(tmp.path(), &format!("job{n}"), &input));
    }

    let responses = run_many(&requests, &engine, 4);
    assert_eq!(responses.len(), 6);
    for (index, response) in responses.into_iter().enumerate() {
        let response = response.unwrap();
        assert_eq!(response.job_id, format!("job{}", index + 1));
        assert_eq!(report(response.outcome).rows_written, index as u64 + 1);
    }
}

#[test]
fn a_failing_dataset_does_not_sink_its_neighbours() {
    let tmp = tempfile::tempdir().unwrap();
    let good = tmp.path().join("good.csv");
    std::fs::write(&good, fixture_csv()).unwrap();

    let mut requests = vec![request(tmp.path(), "good", &good)];
    // A missing input is an engine-level failure, not a job-level one.
    requests.push(request(tmp.path(), "missing", &tmp.path().join("nope.csv")));
    requests.push(request(tmp.path(), "good2", &good));

    let responses = run_many(&requests, &NativeEngine, 3);
    assert!(matches!(
        responses[0].as_ref().unwrap().outcome,
        JobOutcome::Succeeded { .. }
    ));
    let second = responses[1].as_ref().unwrap();
    assert!(
        matches!(second.outcome, JobOutcome::Failed { .. }),
        "a missing input must fail its own job"
    );
    assert!(matches!(
        responses[2].as_ref().unwrap().outcome,
        JobOutcome::Succeeded { .. }
    ));
}
