//! YAML policy schema: field classification and per-mode transform config.

use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// A dataset policy: classifies fields and configures how each mode treats them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Schema version; currently only `1`.
    pub version: u32,
    /// Dataset name; scopes key derivation so tokens are stable per
    /// dataset/policy but differ across datasets.
    pub dataset: String,
    /// Where the pseudonymization secret comes from. Required for
    /// pseudonymize jobs, unused for anonymize jobs.
    #[serde(default)]
    pub key: Option<KeySource>,
    /// What to do with input columns the policy does not list.
    /// Deny-by-default: `error`.
    #[serde(default)]
    pub on_unlisted: UnlistedAction,
    pub fields: Vec<FieldPolicy>,
}

/// Source of the pseudonymization secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySource {
    /// Name of an environment variable holding the secret (preferred).
    #[serde(default)]
    pub env: Option<String>,
    /// Inline fallback secret. Demos/tests only — a warning is recorded in
    /// the report whenever it is used.
    #[serde(default)]
    pub inline: Option<String>,
}

/// Handling of input columns not listed in the policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnlistedAction {
    /// Fail the job (default).
    #[default]
    Error,
    /// Keep the column unchanged and record a warning.
    Keep,
    /// Drop the column and record a warning.
    Remove,
}

/// Privacy classification of a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldClass {
    /// Directly identifies a person (name, email, national id, ...).
    DirectIdentifier,
    /// Identifying in combination with other fields (age, zip, dates, ...).
    QuasiIdentifier,
    /// Sensitive payload (diagnosis, salary, ...); kept, but tracked.
    Sensitive,
    /// Analytic utility only.
    Utility,
}

/// Policy for a single field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldPolicy {
    pub name: String,
    pub class: FieldClass,
    /// Pseudonymize-mode options. Direct identifiers are tokenized by
    /// default even without this block.
    #[serde(default)]
    pub pseudonymize: Option<PseudonymizeCfg>,
    /// Anonymize-mode strategy. Direct identifiers default to `remove`;
    /// quasi-identifiers without a strategy are kept and flagged as a warning.
    #[serde(default)]
    pub anonymize: Option<AnonymizeCfg>,
}

/// Options for deterministic tokenization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PseudonymizeCfg {
    /// Prefix prepended to the token, e.g. `pid_`.
    #[serde(default)]
    pub prefix: Option<String>,
}

/// Anonymization strategy for a field, tagged by `strategy` in YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "strategy", rename_all = "snake_case", deny_unknown_fields)]
pub enum AnonymizeCfg {
    /// Drop the column entirely.
    Remove,
    /// Replace every value with a fixed replacement string.
    Redact {
        #[serde(default = "default_replacement")]
        replacement: String,
    },
    /// Generalize numeric values into ranges of `width`, e.g. 34 -> "30-39".
    Bucket { width: i64 },
    /// Truncate ISO dates (YYYY-MM-DD...) to year or year-month.
    DateTruncate { granularity: DateGranularity },
    /// Keep the first `chars` characters, pad the rest, e.g. 81549 -> "815**".
    KeepPrefix {
        chars: usize,
        #[serde(default = "default_pad")]
        pad: char,
    },
}

impl AnonymizeCfg {
    /// Short action label used in reports and CLI summaries.
    pub fn action_name(&self) -> &'static str {
        match self {
            AnonymizeCfg::Remove => "removed",
            AnonymizeCfg::Redact { .. } => "redacted",
            AnonymizeCfg::Bucket { .. } => "bucketed",
            AnonymizeCfg::DateTruncate { .. } => "date-truncated",
            AnonymizeCfg::KeepPrefix { .. } => "prefix-truncated",
        }
    }
}

/// Target granularity for date truncation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DateGranularity {
    Year,
    YearMonth,
}

fn default_replacement() -> String {
    "REDACTED".to_string()
}

fn default_pad() -> char {
    '*'
}

impl Policy {
    /// Parse and validate a policy from YAML.
    pub fn from_yaml(yaml: &str) -> Result<Self, CoreError> {
        let policy: Policy = serde_yaml::from_str(yaml)?;
        policy.validate()?;
        Ok(policy)
    }

    /// Structural checks beyond what serde enforces.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.version != 1 {
            return Err(CoreError::Policy(format!(
                "unsupported policy version {} (expected 1)",
                self.version
            )));
        }
        if self.dataset.trim().is_empty() {
            return Err(CoreError::Policy("dataset name must not be empty".into()));
        }
        let mut seen = std::collections::HashSet::new();
        for field in &self.fields {
            if !seen.insert(field.name.as_str()) {
                return Err(CoreError::Policy(format!(
                    "field '{}' is listed more than once",
                    field.name
                )));
            }
            if let Some(AnonymizeCfg::Bucket { width }) = &field.anonymize
                && *width <= 0
            {
                return Err(CoreError::Policy(format!(
                    "field '{}': bucket width must be positive",
                    field.name
                )));
            }
        }
        Ok(())
    }

    /// Look up the policy entry for a column name, if any.
    pub fn field(&self, name: &str) -> Option<&FieldPolicy> {
        self.fields.iter().find(|f| f.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
version: 1
dataset: demo
fields:
  - name: email
    class: direct_identifier
  - name: age
    class: quasi_identifier
    anonymize: { strategy: bucket, width: 10 }
"#;

    #[test]
    fn parses_minimal_policy() {
        let p = Policy::from_yaml(MINIMAL).unwrap();
        assert_eq!(p.dataset, "demo");
        assert_eq!(p.on_unlisted, UnlistedAction::Error);
        assert_eq!(p.field("email").unwrap().class, FieldClass::DirectIdentifier);
        assert!(matches!(
            p.field("age").unwrap().anonymize,
            Some(AnonymizeCfg::Bucket { width: 10 })
        ));
    }

    #[test]
    fn rejects_unknown_keys() {
        let yaml = "version: 1\ndataset: demo\nsurprise: true\nfields: []\n";
        assert!(Policy::from_yaml(yaml).is_err());
    }

    #[test]
    fn rejects_duplicate_fields() {
        let yaml = r#"
version: 1
dataset: demo
fields:
  - { name: a, class: utility }
  - { name: a, class: sensitive }
"#;
        assert!(Policy::from_yaml(yaml).is_err());
    }

    #[test]
    fn rejects_nonpositive_bucket_width() {
        let yaml = r#"
version: 1
dataset: demo
fields:
  - name: age
    class: quasi_identifier
    anonymize: { strategy: bucket, width: 0 }
"#;
        assert!(Policy::from_yaml(yaml).is_err());
    }
}
