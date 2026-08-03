//! Risk report computation.
//!
//! The statistics here support a risk assessment; they do not certify or
//! guarantee anonymization.

use std::collections::HashMap;

use deident_types::{KThreshold, QuasiIdentifierSummary};

/// k values reported for "share of rows in classes of at least size k".
const K_LEVELS: [u64; 3] = [2, 5, 10];

/// Fixed limitations language embedded in every report.
pub const LIMITATIONS: &[&str] = &[
    "This report supports a risk assessment; it does not certify or guarantee anonymization.",
    "Re-identification risk depends on external data and context this tool cannot observe.",
    "Pseudonymized output remains personal data: it is reversible with the key material, which must be protected separately from the output.",
    "Statistics cover only fields marked as quasi-identifiers in the policy; unmarked fields may still carry identifying signal.",
];

/// Build equivalence-class statistics from counts per quasi-identifier tuple.
/// Returns `None` when there are no quasi-identifier columns or no rows.
pub fn build_quasi_summary(
    fields: Vec<String>,
    classes: &HashMap<Vec<String>, u64>,
) -> Option<QuasiIdentifierSummary> {
    if fields.is_empty() || classes.is_empty() {
        return None;
    }
    let total_rows: u64 = classes.values().sum();
    let class_count = classes.len() as u64;
    let unique_rows = classes.values().filter(|&&c| c == 1).count() as u64;
    let k_thresholds = K_LEVELS
        .iter()
        .map(|&k| {
            let rows: u64 = classes.values().filter(|&&c| c >= k).sum();
            KThreshold {
                k,
                rows_at_or_above: rows,
                ratio: rows as f64 / total_rows as f64,
            }
        })
        .collect();
    Some(QuasiIdentifierSummary {
        fields,
        equivalence_classes: class_count,
        min_class_size: *classes.values().min().expect("non-empty"),
        max_class_size: *classes.values().max().expect("non-empty"),
        mean_class_size: total_rows as f64 / class_count as f64,
        unique_rows,
        unique_row_ratio: unique_rows as f64 / total_rows as f64,
        k_thresholds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_math_on_known_classes() {
        let mut classes = HashMap::new();
        classes.insert(vec!["a".into()], 5u64);
        classes.insert(vec!["b".into()], 2u64);
        classes.insert(vec!["c".into()], 1u64);
        let s = build_quasi_summary(vec!["qi".into()], &classes).unwrap();
        assert_eq!(s.equivalence_classes, 3);
        assert_eq!(s.min_class_size, 1);
        assert_eq!(s.max_class_size, 5);
        assert_eq!(s.unique_rows, 1);
        assert!((s.mean_class_size - 8.0 / 3.0).abs() < 1e-9);
        assert!((s.unique_row_ratio - 1.0 / 8.0).abs() < 1e-9);
        // k=2 covers 7 of 8 rows, k=5 covers 5, k=10 covers 0
        assert_eq!(s.k_thresholds[0].rows_at_or_above, 7);
        assert_eq!(s.k_thresholds[1].rows_at_or_above, 5);
        assert_eq!(s.k_thresholds[2].rows_at_or_above, 0);
    }

    #[test]
    fn empty_inputs_give_none() {
        assert!(build_quasi_summary(vec![], &HashMap::new()).is_none());
        assert!(build_quasi_summary(vec!["x".into()], &HashMap::new()).is_none());
    }
}
