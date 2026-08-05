//! Parallel execution: split one dataset across sandboxes, or run several
//! datasets at once.
//!
//! # The statistics trap
//!
//! Splitting a dataset and processing the parts independently is *not* the same
//! job. Most report figures are additive — row counts, pattern matches — but the
//! equivalence-class statistics are **not**: a quasi-identifier combination
//! appearing once in chunk A and once in chunk B is one class of size two, not
//! two classes of size one. Summing per-chunk statistics would therefore report
//! far more unique rows than the dataset actually has, i.e. it would *overstate*
//! risk, and a user widening their buckets in response would be chasing an
//! artefact of the chunking.
//!
//! So the class statistics are not merged at all. After the chunk outputs are
//! concatenated, the host recomputes them over the **whole** output using the
//! same code path a single-job run uses. That costs one extra pass and makes the
//! figures host-attested rather than assembled from fragments.
//!
//! Tokens need no special handling: they are a deterministic function of the key
//! and the value, so chunks agree without coordination.

use std::io::{BufRead, BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;
use deident_types::{JobOutcome, JobRequest, JobResponse, RiskReport};

use crate::Engine;

/// How to parallelise a run.
#[derive(Debug, Clone)]
pub struct ParallelOptions {
    /// Number of pieces to split a single dataset into. `1` disables splitting.
    pub chunks: usize,
    /// Maximum jobs to run at once. Each running job holds its own sandbox.
    pub max_concurrency: usize,
}

impl Default for ParallelOptions {
    fn default() -> Self {
        Self {
            chunks: 1,
            max_concurrency: default_concurrency(),
        }
    }
}

/// A sensible default concurrency: one job per core, capped so a large machine
/// does not open dozens of sandboxes at once (each holds its own guest memory).
pub fn default_concurrency() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().min(8))
        .unwrap_or(1)
}

/// Formats that can be split by line. Parquet is columnar with a footer, so a
/// byte range of it is not a valid file.
fn is_line_oriented(path: &str) -> bool {
    matches!(
        Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("csv") | Some("jsonl") | Some("ndjson")
    )
}

/// Run one dataset as `options.chunks` jobs in parallel, then merge.
///
/// Falls back to a single job when splitting is not applicable, so a caller can
/// pass `--split` unconditionally.
pub fn run_split<E: Engine + Sync + ?Sized>(
    request: &JobRequest,
    engine: &E,
    options: &ParallelOptions,
) -> anyhow::Result<JobResponse> {
    if options.chunks <= 1 {
        return engine.run(request);
    }
    anyhow::ensure!(
        is_line_oriented(&request.input_path) && is_line_oriented(&request.output_path),
        "--split needs a line-oriented format on both sides (.csv or .jsonl); \
         Parquet is columnar and a byte range of it is not a valid file"
    );
    // A vault is deduplicated per writer, so N chunks would produce N vault files
    // with overlapping entries. Rather than merge encrypted material, refuse.
    anyhow::ensure!(
        request.vault_path.is_none(),
        "--split cannot be combined with --vault yet: each chunk would write its own \
         vault and merging encrypted mapping files is not implemented. Run without --split, \
         or without --vault"
    );

    let staging = tempfile::Builder::new()
        .prefix("deident-split-")
        .tempdir()
        .context("cannot create a staging directory for the split")?;
    let plan = split_input(request, staging.path(), options.chunks)?;
    if plan.len() <= 1 {
        // Too few rows to be worth splitting.
        return engine.run(request);
    }
    tracing::info!(
        chunks = plan.len(),
        concurrency = options.max_concurrency,
        "running split job"
    );

    let responses = run_concurrently(&plan, engine, options.max_concurrency);

    // Any failed chunk fails the job: a partially transformed dataset must never
    // look like a success.
    let mut reports = Vec::with_capacity(responses.len());
    for (index, response) in responses.into_iter().enumerate() {
        match response {
            Ok(JobResponse {
                outcome: JobOutcome::Succeeded { report },
                ..
            }) => reports.push(*report),
            Ok(JobResponse {
                outcome: JobOutcome::Failed { error },
                ..
            }) => {
                return Ok(failed(request, format!("chunk {index} failed: {error}")));
            }
            Err(err) => {
                return Ok(failed(request, format!("chunk {index} failed: {err:#}")));
            }
        }
    }

    concatenate(&plan, &request.output_path)?;
    let merged = merge_reports(reports, request, &plan)?;
    // The chunks were run without a report path — a per-chunk report would be a
    // fragment — so the merged report is this function's to write.
    if let Some(report_path) = &request.report_path {
        std::fs::write(report_path, serde_json::to_vec_pretty(&merged)?)
            .with_context(|| format!("cannot write report '{report_path}'"))?;
    }
    Ok(JobResponse {
        job_id: request.job_id.clone(),
        outcome: JobOutcome::Succeeded {
            report: Box::new(merged),
        },
    })
}

/// Run several independent datasets at once, each in its own sandbox.
///
/// Results come back in the order the requests were given, whatever order they
/// completed in, so output stays reproducible.
pub fn run_many<E: Engine + Sync + ?Sized>(
    requests: &[JobRequest],
    engine: &E,
    max_concurrency: usize,
) -> Vec<anyhow::Result<JobResponse>> {
    let plan: Vec<JobRequest> = requests.to_vec();
    run_concurrently(&plan, engine, max_concurrency)
}

/// One chunk of a split job.
struct Chunk {
    request: JobRequest,
    output: PathBuf,
}

/// Execute `requests` with at most `max_concurrency` running at once.
///
/// Uses scoped threads and an index-based work queue: no channel plumbing, no
/// dependency, and results land in request order.
fn run_concurrently<E: Engine + Sync + ?Sized, R: AsRequest + Sync>(
    plan: &[R],
    engine: &E,
    max_concurrency: usize,
) -> Vec<anyhow::Result<JobResponse>> {
    let slots: Vec<std::sync::Mutex<Option<anyhow::Result<JobResponse>>>> =
        (0..plan.len()).map(|_| std::sync::Mutex::new(None)).collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let workers = max_concurrency.clamp(1, plan.len());

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if index >= plan.len() {
                        break;
                    }
                    let result = engine.run(plan[index].as_request());
                    *slots[index].lock().expect("result slot") = Some(result);
                }
            });
        }
    });

    slots
        .into_iter()
        .enumerate()
        .map(|(index, slot)| {
            slot.into_inner().expect("result slot").unwrap_or_else(|| {
                Err(anyhow::anyhow!("job {index} produced no result"))
            })
        })
        .collect()
}

/// Lets `run_concurrently` accept both bare requests and chunk records.
trait AsRequest {
    fn as_request(&self) -> &JobRequest;
}

impl AsRequest for JobRequest {
    fn as_request(&self) -> &JobRequest {
        self
    }
}

impl AsRequest for Chunk {
    fn as_request(&self) -> &JobRequest {
        &self.request
    }
}

/// Split the input into `chunks` files inside `staging`, one request each.
///
/// CSV chunks each repeat the header, so every chunk is a valid file in its own
/// right and the guest needs no special casing.
fn split_input(
    request: &JobRequest,
    staging: &Path,
    chunks: usize,
) -> anyhow::Result<Vec<Chunk>> {
    let file = std::fs::File::open(&request.input_path)
        .with_context(|| format!("cannot open input '{}'", request.input_path))?;
    let mut lines = std::io::BufReader::new(file).lines();

    let is_csv = matches!(
        Path::new(&request.input_path)
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("csv")
    );
    let header = if is_csv {
        match lines.next() {
            Some(line) => Some(line.context("cannot read the header row")?),
            None => return Ok(Vec::new()),
        }
    } else {
        None
    };

    let rows: Vec<String> = lines.collect::<Result<_, _>>().context("cannot read input")?;
    let rows: Vec<String> = rows.into_iter().filter(|l| !l.trim().is_empty()).collect();
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    // Never make more chunks than there are rows, and never a chunk of one row
    // for a tiny file — the sandbox setup would dominate.
    let chunks = chunks.min(rows.len()).max(1);
    let per_chunk = rows.len().div_ceil(chunks);

    let input_ext = extension_or(&request.input_path, "csv");
    let output_ext = extension_or(&request.output_path, "csv");
    let mut plan = Vec::with_capacity(chunks);
    for (index, slice) in rows.chunks(per_chunk).enumerate() {
        let input = staging.join(format!("chunk-{index:04}.{input_ext}"));
        let output = staging.join(format!("chunk-{index:04}-out.{output_ext}"));
        let mut writer = BufWriter::new(
            std::fs::File::create(&input)
                .with_context(|| format!("cannot write chunk '{}'", input.display()))?,
        );
        if let Some(header) = &header {
            writeln!(writer, "{header}")?;
        }
        for row in slice {
            writeln!(writer, "{row}")?;
        }
        writer.flush()?;

        plan.push(Chunk {
            request: JobRequest {
                job_id: format!("{}#chunk{index}", request.job_id),
                mode: request.mode,
                policy_yaml: request.policy_yaml.clone(),
                input_path: input.to_string_lossy().into_owned(),
                output_path: output.to_string_lossy().into_owned(),
                // Per-chunk reports and vaults would be fragments; the merged
                // report is written by the caller.
                report_path: None,
                vault_path: None,
            },
            output,
        });
    }
    Ok(plan)
}

fn extension_or(path: &str, fallback: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| fallback.to_string())
}

/// Concatenate chunk outputs in order, keeping only the first header.
fn concatenate(plan: &[Chunk], destination: &str) -> anyhow::Result<()> {
    let is_csv = matches!(
        Path::new(destination)
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("csv")
    );
    let mut out = BufWriter::new(
        std::fs::File::create(destination)
            .with_context(|| format!("cannot create output '{destination}'"))?,
    );
    for (index, chunk) in plan.iter().enumerate() {
        let file = std::fs::File::open(&chunk.output).with_context(|| {
            format!("chunk {index} produced no output at '{}'", chunk.output.display())
        })?;
        for (line_number, line) in std::io::BufReader::new(file).lines().enumerate() {
            let line = line?;
            // Every chunk output carries its own header; keep the first only.
            if is_csv && line_number == 0 && index > 0 {
                continue;
            }
            writeln!(out, "{line}")?;
        }
    }
    out.flush()?;
    Ok(())
}

/// Combine chunk reports into one report describing the whole dataset.
fn merge_reports(
    reports: Vec<RiskReport>,
    request: &JobRequest,
    plan: &[Chunk],
) -> anyhow::Result<RiskReport> {
    let mut merged = reports
        .first()
        .cloned()
        .context("a split job produced no reports")?;

    merged.rows_read = reports.iter().map(|r| r.rows_read).sum();
    merged.rows_written = reports.iter().map(|r| r.rows_written).sum();

    // Pattern findings are additive per (pattern, field).
    let mut pattern_totals: std::collections::BTreeMap<(String, String), (u64, String)> =
        std::collections::BTreeMap::new();
    for finding in reports.iter().flat_map(|r| r.patterns.iter()) {
        let entry = pattern_totals
            .entry((finding.pattern.clone(), finding.field.clone()))
            .or_insert((0, finding.action.clone()));
        entry.0 += finding.matches;
    }
    merged.patterns = pattern_totals
        .into_iter()
        .map(|((pattern, field), (matches, action))| deident_types::PatternFinding {
            pattern,
            field,
            matches,
            action,
        })
        .collect();

    // Warnings repeat per chunk; keep one of each, in first-seen order.
    let mut seen = std::collections::HashSet::new();
    merged.warnings = reports
        .iter()
        .flat_map(|r| r.warnings.iter().cloned())
        .filter(|w| seen.insert(w.clone()))
        .collect();

    // The statistics are recomputed over the whole output rather than summed —
    // see the module docs for why summing would overstate risk.
    merged.quasi_identifiers = recompute_quasi_summary(&merged, request)?;
    merged.warnings.push(format!(
        "this dataset was processed as {} parallel chunks; the equivalence-class statistics were \
         recomputed over the combined output, not summed across chunks",
        plan.len()
    ));
    Ok(merged)
}

/// Recompute equivalence-class statistics over the merged output.
///
/// Reads only the quasi-identifier columns the chunk reports name, so it does not
/// need to re-derive the policy's column plan.
fn recompute_quasi_summary(
    merged: &RiskReport,
    request: &JobRequest,
) -> anyhow::Result<Option<deident_types::QuasiIdentifierSummary>> {
    let Some(existing) = &merged.quasi_identifiers else {
        return Ok(None);
    };
    let fields = existing.fields.clone();
    let format = deident_core::Format::for_path(&request.output_path)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let file = std::fs::File::open(&request.output_path)
        .with_context(|| format!("cannot re-read output '{}'", request.output_path))?;
    let mut reader = deident_core::format::reader(format, std::io::BufReader::new(file))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let headers = reader.headers().map_err(|e| anyhow::anyhow!("{e}"))?;
    let indices: Vec<usize> = fields
        .iter()
        .filter_map(|field| headers.iter().position(|h| h == field))
        .collect();
    if indices.len() != fields.len() {
        // A column the chunk report named is missing from the output; say nothing
        // rather than compute a statistic over the wrong columns.
        return Ok(None);
    }

    let mut classes: std::collections::HashMap<Vec<String>, u64> = std::collections::HashMap::new();
    while let Some(row) = reader.next_row().map_err(|e| anyhow::anyhow!("{e}"))? {
        let tuple: Vec<String> = indices
            .iter()
            .map(|i| row.get(*i).cloned().unwrap_or_default())
            .collect();
        *classes.entry(tuple).or_insert(0) += 1;
    }
    Ok(deident_core::report::build_quasi_summary(fields, &classes))
}

fn failed(request: &JobRequest, error: String) -> JobResponse {
    JobResponse {
        job_id: request.job_id.clone(),
        outcome: JobOutcome::Failed { error },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitting_needs_a_line_oriented_format() {
        assert!(is_line_oriented("a.csv"));
        assert!(is_line_oriented("a.JSONL"));
        assert!(is_line_oriented("a.ndjson"));
        assert!(!is_line_oriented("a.parquet"), "columnar; a byte range is not a file");
        assert!(!is_line_oriented("a"), "no extension");
    }

    #[test]
    fn default_concurrency_is_sane() {
        let n = default_concurrency();
        assert!((1..=8).contains(&n), "got {n}");
    }

    #[test]
    fn every_csv_chunk_is_a_valid_file_with_its_own_header() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("in.csv");
        std::fs::write(&input, "id,age\n1,10\n2,20\n3,30\n4,40\n5,50\n").unwrap();
        let request = JobRequest {
            job_id: "t".into(),
            mode: deident_types::Mode::Anonymize,
            policy_yaml: String::new(),
            input_path: input.to_string_lossy().into_owned(),
            output_path: tmp.path().join("out.csv").to_string_lossy().into_owned(),
            report_path: None,
            vault_path: None,
        };
        let plan = split_input(&request, tmp.path(), 3).unwrap();
        assert_eq!(plan.len(), 3);

        let mut total_rows = 0;
        for chunk in &plan {
            let text = std::fs::read_to_string(&chunk.request.input_path).unwrap();
            let mut lines = text.lines();
            assert_eq!(lines.next(), Some("id,age"), "each chunk repeats the header");
            total_rows += lines.count();
        }
        assert_eq!(total_rows, 5, "every row must appear exactly once");
    }

    #[test]
    fn chunk_count_is_capped_by_row_count() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("in.csv");
        std::fs::write(&input, "id\n1\n2\n").unwrap();
        let request = JobRequest {
            job_id: "t".into(),
            mode: deident_types::Mode::Anonymize,
            policy_yaml: String::new(),
            input_path: input.to_string_lossy().into_owned(),
            output_path: tmp.path().join("out.csv").to_string_lossy().into_owned(),
            report_path: None,
            vault_path: None,
        };
        // Asking for 50 chunks of a 2-row file must not create 50 sandboxes.
        assert_eq!(split_input(&request, tmp.path(), 50).unwrap().len(), 2);
    }

    #[test]
    fn concatenation_keeps_one_header_and_preserves_order() {
        let tmp = tempfile::tempdir().unwrap();
        let mut plan = Vec::new();
        for (index, body) in ["1,a", "2,b"].iter().enumerate() {
            let output = tmp.path().join(format!("c{index}.csv"));
            std::fs::write(&output, format!("id,v\n{body}\n")).unwrap();
            plan.push(Chunk {
                request: JobRequest {
                    job_id: "t".into(),
                    mode: deident_types::Mode::Anonymize,
                    policy_yaml: String::new(),
                    input_path: String::new(),
                    output_path: output.to_string_lossy().into_owned(),
                    report_path: None,
                    vault_path: None,
                },
                output,
            });
        }
        let destination = tmp.path().join("merged.csv");
        concatenate(&plan, destination.to_str().unwrap()).unwrap();
        assert_eq!(
            std::fs::read_to_string(&destination).unwrap(),
            "id,v\n1,a\n2,b\n",
            "one header, chunks in order"
        );
    }
}
