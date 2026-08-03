//! Shared data models for the deident privacy transformation engine.
//!
//! These types cross the host/worker boundary (serialized as JSON), so they
//! must stay free of any host-only or guest-only logic.

use serde::{Deserialize, Serialize};

/// Transformation mode of a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Reversible, deterministic tokenization of direct identifiers.
    /// Output remains personal data; reversal requires separately protected
    /// key/mapping material.
    Pseudonymize,
    /// Irreversible removal/generalization/suppression aimed at reducing
    /// re-identification risk ("risk-assessed anonymization").
    Anonymize,
}

/// A single dataset job handed to an execution engine (native or wasm).
///
/// All paths are plain strings so the same request works with guest-side
/// paths inside a preopened sandbox directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRequest {
    /// Unique id for correlation in logs/audit trails.
    pub job_id: String,
    pub mode: Mode,
    /// The policy document, inlined as YAML so workers need no extra file
    /// capability beyond the job workspace.
    pub policy_yaml: String,
    /// Path to the input CSV.
    pub input_path: String,
    /// Path the transformed CSV is written to.
    pub output_path: String,
    /// Optional path for the JSON risk report.
    pub report_path: Option<String>,
}

/// Result of a job as reported by an execution engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResponse {
    pub job_id: String,
    pub outcome: JobOutcome,
}

/// Success/failure outcome of a job.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum JobOutcome {
    Succeeded { report: RiskReport },
    Failed { error: String },
}

/// Machine-readable summary of what a job did and the residual-risk signals
/// it could measure.
///
/// This report supports a risk assessment; it never certifies anonymization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskReport {
    /// Dataset name from the policy.
    pub dataset: String,
    pub mode: Mode,
    pub rows_read: u64,
    pub rows_written: u64,
    /// What happened to each direct identifier column.
    pub direct_identifiers: Vec<DirectIdentifierFinding>,
    /// Equivalence-class statistics over the (transformed) quasi-identifier
    /// columns, when any are present.
    pub quasi_identifiers: Option<QuasiIdentifierSummary>,
    /// Non-fatal issues encountered while running the job.
    pub warnings: Vec<String>,
    /// Fixed limitations language embedded in every report.
    pub limitations: Vec<String>,
}

/// Action taken for one direct identifier column.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectIdentifierFinding {
    pub field: String,
    /// e.g. "tokenized", "removed", "redacted".
    pub action: String,
}

/// Grouping statistics over quasi-identifier value tuples after
/// transformation. Smaller classes mean higher re-identification risk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuasiIdentifierSummary {
    /// Quasi-identifier columns included in the grouping (input order).
    pub fields: Vec<String>,
    /// Number of distinct value combinations (equivalence classes).
    pub equivalence_classes: u64,
    pub min_class_size: u64,
    pub max_class_size: u64,
    pub mean_class_size: f64,
    /// Rows whose quasi-identifier combination is unique (class size 1).
    pub unique_rows: u64,
    pub unique_row_ratio: f64,
    /// Share of rows in classes of at least size k, for a few useful k.
    pub k_thresholds: Vec<KThreshold>,
}

/// Rows covered by equivalence classes of size >= k.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KThreshold {
    pub k: u64,
    pub rows_at_or_above: u64,
    pub ratio: f64,
}
