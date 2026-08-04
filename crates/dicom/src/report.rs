//! De-identification reports for DICOM instances and studies.

use serde::{Deserialize, Serialize};

/// Fixed limitations language embedded in every DICOM report.
///
/// These are the claims the implementation can and cannot support. They are not
/// configurable on purpose.
pub const LIMITATIONS: &[&str] = &[
    "This report supports a risk assessment; it does not certify or guarantee de-identification.",
    "Coverage is a curated core of DICOM PS3.15 Annex E plus structural rules (person-name VRs, identity UIDs, private tags, curve/overlay groups). It is NOT full Annex E conformance — extend the policy's tag list for attributes your data requires.",
    "Burned-in pixel data is NOT modified. Any patient details rendered into the image pixels survive de-identification; the pixel_risk section reports the signals that suggest this may be the case.",
    "Pseudonymized values, remapped UIDs and shifted dates are reversible with the key material, which must be protected separately from the output.",
    "UID remapping intentionally breaks references from outside the processed set (for example a PACS or a report citing the original UIDs).",
];

/// What happened to one attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagFinding {
    /// Standard keyword, or `(gggg,eeee)` when unknown.
    pub tag: String,
    /// Numeric tag, always present for machine consumers.
    pub numeric: String,
    /// Past-tense action label.
    pub action: String,
    /// How many attribute instances were affected (>1 when the tag occurs
    /// inside repeated sequence items).
    pub occurrences: u64,
}

/// Signals that the pixel data may contain burned-in identifiers.
///
/// This is a risk assessment, not a detection: no pixels are inspected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PixelRisk {
    /// True when the instance carries pixel data at all.
    pub has_pixel_data: bool,
    /// Value of `BurnedInAnnotation`, when present.
    pub burned_in_annotation: Option<String>,
    /// Modality, which drives much of the risk assessment.
    pub modality: Option<String>,
    /// `low` | `elevated` | `high` | `unknown`.
    pub level: String,
    /// Why that level was chosen.
    pub reasons: Vec<String>,
}

/// Result of de-identifying one instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DicomReport {
    /// Dataset/identity scope from the policy.
    pub dataset: String,
    /// Source path, for correlation.
    pub source: String,
    pub sop_class_uid: Option<String>,
    /// Attributes examined, including those inside sequences.
    pub attributes_examined: u64,
    /// Attributes the policy acted on.
    pub attributes_modified: u64,
    /// Private attributes encountered.
    pub private_attributes: u64,
    /// Deepest sequence nesting reached.
    pub max_sequence_depth: u32,
    pub tags: Vec<TagFinding>,
    /// Distinct UIDs remapped.
    pub uids_remapped: u64,
    pub pixel_risk: PixelRisk,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

impl DicomReport {
    /// Fixed limitations text as owned strings.
    pub fn limitations() -> Vec<String> {
        LIMITATIONS.iter().map(|s| s.to_string()).collect()
    }
}

/// Aggregate result of de-identifying a directory of instances.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StudyReport {
    pub dataset: String,
    pub root: String,
    pub instances_read: u64,
    pub instances_written: u64,
    pub instances_failed: u64,
    /// Files skipped because they are not DICOM.
    pub non_dicom_skipped: u64,
    /// Per-instance outcomes.
    pub instances: Vec<InstanceOutcome>,
    /// Distinct UID mappings across the whole run — the number that matters for
    /// checking that a study stayed internally consistent.
    pub distinct_uids_remapped: u64,
    /// Highest pixel-risk level seen in the run.
    pub highest_pixel_risk: String,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

/// One instance's outcome inside a study run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum InstanceOutcome {
    Succeeded {
        source: String,
        output: String,
        report: Box<DicomReport>,
    },
    Failed {
        source: String,
        error: String,
    },
    Skipped {
        source: String,
        reason: String,
    },
}

/// Rank pixel-risk levels so a study can report the worst one seen.
pub fn risk_rank(level: &str) -> u8 {
    match level {
        "high" => 3,
        "elevated" => 2,
        "unknown" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limitations_state_the_hard_boundaries() {
        let text = LIMITATIONS.join(" ");
        assert!(text.contains("does not certify"));
        assert!(text.contains("NOT full Annex E conformance"));
        assert!(
            text.contains("Burned-in pixel data is NOT modified"),
            "the pixel limitation must be explicit"
        );
        assert!(text.contains("reversible with the key material"));
    }

    #[test]
    fn risk_levels_are_ordered() {
        assert!(risk_rank("high") > risk_rank("elevated"));
        assert!(risk_rank("elevated") > risk_rank("unknown"));
        assert!(risk_rank("unknown") > risk_rank("low"));
    }
}
