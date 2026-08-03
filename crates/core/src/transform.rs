//! Anonymization value transforms.
//!
//! Every transform is deterministic. Values that cannot be parsed for a
//! numeric/date strategy are suppressed to `*` by the engine (counted as a
//! warning) rather than failing the whole job.

use crate::policy::{AnonymizeCfg, DateGranularity};

/// Marker error: the value did not fit the configured strategy and should be
/// suppressed.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidValue;

/// Placeholder written for values a strategy could not interpret.
pub const SUPPRESSED: &str = "*";

/// Apply an anonymization strategy to a single cell value.
///
/// Empty cells pass through unchanged so missing data stays missing.
/// `Remove` is handled at column level by the engine and never reaches here.
pub fn apply(cfg: &AnonymizeCfg, value: &str) -> Result<String, InvalidValue> {
    if value.is_empty() {
        return Ok(String::new());
    }
    match cfg {
        AnonymizeCfg::Remove => Ok(String::new()),
        AnonymizeCfg::Redact { replacement } => Ok(replacement.clone()),
        AnonymizeCfg::Bucket { width } => bucket(value, *width),
        AnonymizeCfg::DateTruncate { granularity } => date_truncate(value, *granularity),
        AnonymizeCfg::KeepPrefix { chars, pad } => Ok(keep_prefix(value, *chars, *pad)),
    }
}

/// Generalize a numeric value into a half-open decade-style range label,
/// e.g. width 10: 34 -> "30-39". Floats are floored first.
fn bucket(value: &str, width: i64) -> Result<String, InvalidValue> {
    let trimmed = value.trim();
    let n: i64 = trimmed
        .parse::<i64>()
        .or_else(|_| trimmed.parse::<f64>().map(|f| f.floor() as i64))
        .map_err(|_| InvalidValue)?;
    let lo = n.div_euclid(width) * width;
    Ok(format!("{}-{}", lo, lo + width - 1))
}

/// Truncate an ISO-style date (`YYYY-MM-DD...`) to `YYYY` or `YYYY-MM`.
fn date_truncate(value: &str, granularity: DateGranularity) -> Result<String, InvalidValue> {
    let v = value.trim();
    let bytes = v.as_bytes();
    let digits = |range: std::ops::Range<usize>| {
        bytes
            .get(range)
            .is_some_and(|s| s.iter().all(u8::is_ascii_digit))
    };
    if !digits(0..4) {
        return Err(InvalidValue);
    }
    match granularity {
        DateGranularity::Year => Ok(v[0..4].to_string()),
        DateGranularity::YearMonth => {
            if bytes.get(4) == Some(&b'-') && digits(5..7) {
                Ok(v[0..7].to_string())
            } else {
                Err(InvalidValue)
            }
        }
    }
}

/// Keep the first `keep` characters and pad the remainder to the original
/// length, e.g. ("81549", 3, '*') -> "815**".
fn keep_prefix(value: &str, keep: usize, pad: char) -> String {
    let total = value.chars().count();
    let mut out: String = value.chars().take(keep).collect();
    for _ in total.min(keep)..total {
        out.push(pad);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_generalizes_integers_and_floats() {
        assert_eq!(bucket("34", 10).unwrap(), "30-39");
        assert_eq!(bucket("30", 10).unwrap(), "30-39");
        assert_eq!(bucket("39.9", 10).unwrap(), "30-39");
        assert_eq!(bucket("0", 10).unwrap(), "0-9");
        assert_eq!(bucket("-3", 10).unwrap(), "-10--1");
        assert_eq!(bucket("17", 5).unwrap(), "15-19");
    }

    #[test]
    fn bucket_rejects_non_numeric() {
        assert_eq!(bucket("n/a", 10), Err(InvalidValue));
    }

    #[test]
    fn date_truncate_year_and_month() {
        assert_eq!(date_truncate("2024-03-14", DateGranularity::Year).unwrap(), "2024");
        assert_eq!(
            date_truncate("2024-03-14", DateGranularity::YearMonth).unwrap(),
            "2024-03"
        );
        // timestamps with a date prefix still work
        assert_eq!(
            date_truncate("2024-03-14T09:30:00Z", DateGranularity::YearMonth).unwrap(),
            "2024-03"
        );
        assert_eq!(date_truncate("14.03.2024", DateGranularity::Year), Err(InvalidValue));
        assert_eq!(date_truncate("2024/03", DateGranularity::YearMonth), Err(InvalidValue));
    }

    #[test]
    fn keep_prefix_pads_to_original_length() {
        assert_eq!(keep_prefix("81549", 3, '*'), "815**");
        assert_eq!(keep_prefix("81", 3, '*'), "81");
        assert_eq!(keep_prefix("81549", 0, 'x'), "xxxxx");
    }

    #[test]
    fn empty_values_pass_through() {
        let cfg = AnonymizeCfg::Bucket { width: 10 };
        assert_eq!(apply(&cfg, "").unwrap(), "");
    }
}
