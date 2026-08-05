//! Structured per-job audit log (JSONL, append-only).
//!
//! One line per job, written by the host after the job finishes. The log is
//! deliberately **metadata only**: job identity, policy fingerprint, engine
//! and limits, row counts and outcome. It never contains dataset values, so
//! it can be retained and shipped to a SIEM without inheriting the
//! sensitivity of the data it describes.
//!
//! The policy fingerprint is a BLAKE3 hash of the exact policy text used, so
//! an auditor can prove which policy produced an output without the log
//! carrying the policy (which may hold an inline secret).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use deident_types::{JobOutcome, JobRequest, JobResponse, Mode};
use serde::{Deserialize, Serialize};

/// One audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// RFC 3339-ish UTC timestamp (second resolution).
    pub timestamp: String,
    /// Version of deident that ran the job — an audit trail must record which
    /// build produced an output, since behaviour changes between versions.
    pub tool_version: String,
    pub job_id: String,
    pub mode: Mode,
    /// `native` or `wasm`.
    pub engine: String,
    /// Dataset name from the policy.
    pub dataset: Option<String>,
    /// BLAKE3 hash of the policy text (hex, 32 chars).
    pub policy_hash: String,
    pub input_path: String,
    pub output_path: String,
    pub status: String,
    pub rows_read: Option<u64>,
    pub rows_written: Option<u64>,
    /// Number of report warnings (details stay in the report).
    pub warnings: Option<usize>,
    pub error: Option<String>,
    /// Sandbox limits in effect, when the wasm engine ran the job.
    pub limits: Option<AuditLimits>,
    /// Whether the report was authored by the host or taken from the guest.
    ///
    /// A guest-attested report is a *claim*: a compromised worker could state
    /// clean row counts over untransformed data. Recording the provenance lets a
    /// downstream consumer weigh it.
    pub report_provenance: String,
}

/// Sandbox limits recorded alongside a job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLimits {
    pub max_memory_bytes: usize,
    pub timeout_ms: u64,
    pub fuel: Option<u64>,
}

/// Append-only JSONL audit sink.
#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    /// Append records to `path`, creating it if needed.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Build a record from a job and append it.
    pub fn record(
        &self,
        request: &JobRequest,
        response: &JobResponse,
        engine: &str,
        limits: Option<AuditLimits>,
        provenance: &str,
    ) -> anyhow::Result<()> {
        self.append(&build_record(request, response, engine, limits, provenance))
    }

    /// Append a prepared record as one JSON line.
    pub fn append(&self, record: &AuditRecord) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(&line)?;
        file.flush()?;
        Ok(())
    }
}

/// Fingerprint of a policy document: the first 32 hex chars of a BLAKE3 hash
/// taken **after removing the key block**.
///
/// Hashing the raw text would commit to `key.inline`, turning this log — which
/// the module documents as safe to ship to a SIEM — into an offline key-recovery
/// oracle: guess a secret, rebuild the YAML, compare 128 bits. SIEM readers are a
/// far wider audience than policy-file readers, which is the whole point of
/// exporting logs.
///
/// The fingerprint still identifies the policy, because everything that decides
/// what happens to the data is still hashed.
pub fn policy_hash(policy_yaml: &str) -> String {
    let canonical = match deident_core::Policy::from_yaml(policy_yaml) {
        Ok(mut policy) => {
            policy.key = None;
            serde_yaml::to_string(&policy).unwrap_or_else(|_| policy_yaml.to_string())
        }
        // Unparsable policies never run, so a raw hash of one leaks nothing that
        // a successful job would.
        Err(_) => policy_yaml.to_string(),
    };
    blake3::hash(canonical.as_bytes()).to_hex()[..32].to_string()
}

/// Longest failure message an audit record will carry.
const MAX_AUDIT_ERROR: usize = 300;

/// Trim a failure message for the audit log.
///
/// Failure text is assembled from whatever went wrong, so it can quote a policy
/// value or a fragment of the input — a serde error naming an unexpected enum
/// variant, a format error naming a column. The audit log is a long-lived file,
/// often kept where the data is not, so it records a bounded, single-line
/// summary; the operator still sees the full message on stderr and in the job
/// report.
fn audit_error(error: &str) -> String {
    let single_line: String = error
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let count = single_line.chars().count();
    if count <= MAX_AUDIT_ERROR {
        return single_line;
    }
    let kept: String = single_line.chars().take(MAX_AUDIT_ERROR).collect();
    format!("{kept}… (truncated, {count} characters)")
}

fn build_record(
    request: &JobRequest,
    response: &JobResponse,
    engine: &str,
    limits: Option<AuditLimits>,
    provenance: &str,
) -> AuditRecord {
    let (status, dataset, rows_read, rows_written, warnings, error) = match &response.outcome {
        JobOutcome::Succeeded { report } => (
            "succeeded",
            Some(report.dataset.clone()),
            Some(report.rows_read),
            Some(report.rows_written),
            Some(report.warnings.len()),
            None,
        ),
        JobOutcome::Failed { error } => {
            ("failed", None, None, None, None, Some(audit_error(error)))
        }
    };
    AuditRecord {
        timestamp: utc_timestamp(),
        tool_version: deident_types::VERSION.to_string(),
        report_provenance: provenance.to_string(),
        job_id: request.job_id.clone(),
        mode: request.mode,
        engine: engine.to_string(),
        dataset,
        policy_hash: policy_hash(&request.policy_yaml),
        input_path: request.input_path.clone(),
        output_path: request.output_path.clone(),
        status: status.to_string(),
        rows_read,
        rows_written,
        warnings,
        error,
    limits,
    }
}

/// UTC timestamp as `YYYY-MM-DDTHH:MM:SSZ`, computed without a date crate
/// (civil-from-days, proleptic Gregorian).
fn utc_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod error_tests {
    use super::*;

    #[test]
    fn a_short_error_is_kept_verbatim() {
        assert_eq!(audit_error("cannot open input"), "cannot open input");
    }

    #[test]
    fn newlines_never_break_the_jsonl_shape() {
        assert_eq!(audit_error("line one\nline two\r\tx"), "line one line two  x");
    }

    #[test]
    fn a_long_error_cannot_dump_the_policy_into_the_log() {
        let error = format!("invalid policy YAML: {}", "secret-ish-value ".repeat(80));
        let recorded = audit_error(&error);
        assert!(recorded.chars().count() < 340, "{}", recorded.chars().count());
        assert!(recorded.contains("truncated"));
        assert!(recorded.starts_with("invalid policy YAML:"), "keeps the useful prefix");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_has_expected_shape() {
        let ts = utc_timestamp();
        assert_eq!(ts.len(), 20, "{ts}");
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.as_bytes()[4], b'-');
        assert_eq!(ts.as_bytes()[10], b'T');
        // Sanity: this code was written well after 2020 and before 2100.
        let year: i32 = ts[..4].parse().unwrap();
        assert!((2020..2100).contains(&year), "{ts}");
    }

    #[test]
    fn policy_hash_is_stable_and_sensitive() {
        assert_eq!(policy_hash("version: 1"), policy_hash("version: 1"));
        assert_ne!(policy_hash("version: 1"), policy_hash("version: 2"));
        assert_eq!(policy_hash("x").len(), 32);
    }

    /// The fingerprint must not commit to the secret, or the audit log becomes a
    /// key-recovery oracle for anyone with SIEM access.
    #[test]
    fn policy_hash_ignores_the_key_block() {
        let with = |secret: &str| {
            format!(
                "version: 1\ndataset: d\nkey:\n  inline: \"{secret}\"\n\
                 fields:\n  - {{ name: id, class: utility }}\n"
            )
        };
        assert_eq!(
            policy_hash(&with("secret-one-0123456789abcdef0123456")),
            policy_hash(&with("secret-two-0123456789abcdef0123456")),
            "two policies differing only in their secret must fingerprint alike"
        );
        // But a change that affects the DATA must change the fingerprint.
        let a = "version: 1\ndataset: d\nfields:\n  - { name: id, class: utility }\n";
        let b = "version: 1\ndataset: d\nfields:\n  - { name: id, class: direct_identifier }\n";
        assert_ne!(policy_hash(a), policy_hash(b));
    }
}
