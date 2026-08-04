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

/// Generalize a numeric value into a decade-style range label,
/// e.g. width 10: 34 -> "30-39". Floats are floored first.
///
/// Every step is fallible on purpose. `inf`, `NaN` and values near the `i64`
/// bounds are exactly what numpy/R write for missing floats and what sentinel
/// columns contain, and the contract for this module is that a bad cell is
/// suppressed with a warning rather than aborting the job — so an unrepresentable
/// value must return `InvalidValue`, never panic and never emit a nonsense label
/// like `9223372036854775800--9223372036854775807`.
fn bucket(value: &str, width: i64) -> Result<String, InvalidValue> {
    let trimmed = value.trim();
    let n: i64 = match trimmed.parse::<i64>() {
        Ok(n) => n,
        Err(_) => {
            let float = trimmed.parse::<f64>().map_err(|_| InvalidValue)?;
            // Rejects inf and NaN, and floats outside the i64 range (`as i64`
            // would saturate them silently).
            if !float.is_finite() {
                return Err(InvalidValue);
            }
            let floored = float.floor();
            if floored < i64::MIN as f64 || floored > i64::MAX as f64 {
                return Err(InvalidValue);
            }
            floored as i64
        }
    };
    let lo = n
        .div_euclid(width)
        .checked_mul(width)
        .ok_or(InvalidValue)?;
    let hi = lo
        .checked_add(width)
        .and_then(|v| v.checked_sub(1))
        .ok_or(InvalidValue)?;
    Ok(format!("{lo}-{hi}"))
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
    // Four leading digits are not enough: a zip code, an order number or any
    // numeric id would become a plausible-looking "year". Require the value to
    // either end there or continue with a date separator, so a non-date is
    // suppressed (and warned about) instead of silently mangled.
    if !matches!(bytes.get(4), None | Some(b'-') | Some(b'/') | Some(b'.')) {
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

    /// These inputs used to panic in debug builds and emit reversed ranges in
    /// release builds. They must be suppressed like any other bad value.
    #[test]
    fn bucket_rejects_non_finite_and_unrepresentable_values() {
        for hostile in [
            "inf", "-inf", "Inf", "NaN", "nan", "1e30", "-1e30",
            "9223372036854775807", "-9223372036854775808",
        ] {
            assert_eq!(
                bucket(hostile, 10),
                Err(InvalidValue),
                "must suppress {hostile:?} instead of panicking or emitting a bogus range"
            );
        }
        // A huge but valid width must not overflow either.
        assert_eq!(bucket("5", i64::MAX), Ok("0-9223372036854775806".to_string()));
    }

    #[test]
    fn date_truncate_rejects_bare_numbers_that_merely_start_with_four_digits() {
        // A zip code, an order number or a numeric id must not become a "year".
        for not_a_date in ["10001", "123456789", "20240001", "2024x"] {
            assert_eq!(
                date_truncate(not_a_date, DateGranularity::Year),
                Err(InvalidValue),
                "{not_a_date:?} is not a date"
            );
        }
        // Real dates and bare years still work.
        assert_eq!(date_truncate("2024", DateGranularity::Year).unwrap(), "2024");
        assert_eq!(date_truncate("2024-03-14", DateGranularity::Year).unwrap(), "2024");
        assert_eq!(date_truncate("2024/03/14", DateGranularity::Year).unwrap(), "2024");
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
