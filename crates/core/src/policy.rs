//! YAML policy schema: field classification and per-mode transform config.

use serde::{Deserialize, Serialize};

pub use crate::detect::{BuiltinPattern, Validator};
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
    /// Content-pattern rules applied to cell values (e.g. IBANs embedded in
    /// free text). Run in both modes, after the column-level transform.
    #[serde(default)]
    pub patterns: Vec<PatternRule>,
    /// Enable whole groups of built-in detectors without listing each one.
    /// Expanded into `patterns` at run time; an explicit `patterns` entry with
    /// the same name always wins.
    #[serde(default)]
    pub presets: Vec<PresetRule>,
}

/// Enables every built-in detector of a precision class.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresetRule {
    pub preset: PatternPreset,
    /// Action for every rule the preset expands to.
    pub action: PatternAction,
    /// Columns to scan; omitted = every column in the output.
    #[serde(default)]
    pub fields: Option<Vec<String>>,
    /// Redaction label override (`action: redact` only); defaults to the
    /// per-detector `[NAME]`.
    #[serde(default)]
    pub replacement: Option<String>,
}

/// A group of built-in detectors, grouped by how much their matches can be
/// trusted. See [`crate::detect::Precision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternPreset {
    /// Distinctive, mostly checksum-verified: email, IBAN, card, IP, URL,
    /// API key, IFSC. Safe to act on automatically.
    Precise,
    /// Recognisable shape shared with innocent data: phone, SSN, date of birth,
    /// passport, licence plate. Expect some false positives.
    Moderate,
    /// NER stand-ins: person name, address, organization, medical term. Expect
    /// false positives **and** false negatives — prefer `detect`.
    Heuristic,
    /// Everything. Combine with `action: detect` for a survey pass.
    All,
}

impl PatternPreset {
    /// The detectors this preset covers.
    pub fn builtins(&self) -> Vec<BuiltinPattern> {
        crate::detect::ALL
            .iter()
            .copied()
            .filter(|b| match self {
                PatternPreset::All => true,
                PatternPreset::Precise => b.precision() == crate::detect::Precision::Precise,
                PatternPreset::Moderate => b.precision() == crate::detect::Precision::Moderate,
                PatternPreset::Heuristic => b.precision() == crate::detect::Precision::Heuristic,
            })
            .collect()
    }
}

/// Source of the pseudonymization secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySource {
    /// Name of an environment variable holding the secret (preferred).
    #[serde(default)]
    pub env: Option<String>,
    /// Inline secret. Demos and tests only — a warning is recorded in the report
    /// whenever it is used.
    #[serde(default)]
    pub inline: Option<String>,
    /// Permit falling back to `inline` when `env` is unset or empty.
    ///
    /// Off by default: a silent fallback turns a misconfigured deployment into a
    /// successful job whose tokens anyone with the policy file can reverse, and
    /// changes every token value in the process. Opting in makes that a decision
    /// rather than an accident.
    #[serde(default)]
    pub allow_inline_fallback: bool,
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
    /// Identity domain the token is derived in; defaults to the column name.
    /// Give columns in *different* files (e.g. `patient_id` and
    /// `patient_ref`) the same domain so the same value yields the same
    /// token across a chained run and joins keep working.
    #[serde(default)]
    pub domain: Option<String>,
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

/// A content-pattern rule: find matches of a regex (or a built-in pattern)
/// inside cell values and detect, redact or tokenize them.
///
/// Pattern rules run in **both modes** — an IBAN in a free-text column needs
/// handling regardless of whether the job pseudonymizes or anonymizes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatternRule {
    /// Rule name; also the token domain (`pattern:<name>`) and the default
    /// redaction label (`[<NAME>]`).
    pub name: String,
    /// Custom regular expression. Exactly one of `regex`/`builtin` must be set.
    #[serde(default)]
    pub regex: Option<String>,
    /// Built-in heuristic pattern. Exactly one of `regex`/`builtin` must be set.
    #[serde(default)]
    pub builtin: Option<BuiltinPattern>,
    /// Columns to scan; omitted = every column that appears in the output.
    #[serde(default)]
    pub fields: Option<Vec<String>>,
    pub action: PatternAction,
    /// Replacement text for `action: redact` (default `[<NAME>]`).
    #[serde(default)]
    pub replacement: Option<String>,
    /// Token prefix for `action: token`.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Shape to imitate for `action: mock`. Defaults to the `builtin` shape,
    /// so it is only required when mocking a custom `regex` rule.
    #[serde(default)]
    pub mock: Option<MockShapeCfg>,
    /// Checksum validation applied to every match, suppressing false positives.
    /// Defaults to the built-in's own validator (Luhn for cards, mod-97 for
    /// IBANs, allocation rules for SSNs); set `none` to disable, or add one to a
    /// custom `regex` rule.
    #[serde(default)]
    pub validate: Option<Validator>,
}

impl PatternRule {
    /// The effective regex source for this rule.
    pub fn regex_source(&self) -> &str {
        match (&self.regex, &self.builtin) {
            (Some(re), _) => re,
            (None, Some(builtin)) => builtin.regex_source(),
            (None, None) => unreachable!("validated: one of regex/builtin is set"),
        }
    }

    /// The mock shape for `action: mock`: the explicit `mock:` selector, or
    /// the shape implied by `builtin:`.
    pub fn mock_shape(&self) -> Option<crate::mock::MockShape> {
        self.mock
            .map(Into::into)
            .or_else(|| self.builtin.and_then(crate::mock::MockShape::for_builtin))
    }

    /// Checksum validation for this rule: the explicit override, else the
    /// built-in's default, else none.
    pub fn validator(&self) -> Validator {
        self.validate
            .or_else(|| self.builtin.map(|b| b.validator()))
            .unwrap_or_default()
    }

    /// Precision class, used to warn when a heuristic rule is set to modify data.
    pub fn precision(&self) -> Option<crate::detect::Precision> {
        self.builtin.map(|b| b.precision())
    }
}

/// What to do with pattern matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternAction {
    /// Only count matches for the risk report; values stay in the output.
    Detect,
    /// Replace each match with a fixed label.
    Redact,
    /// Replace each match with a deterministic keyed token (requires a key
    /// source; the affected output is pseudonymous, i.e. reversible with the
    /// key material).
    Token,
    /// Replace each match with a deterministic, structurally valid fake value
    /// of the same shape (requires a key source; like `token`, the result is
    /// pseudonymous rather than anonymous).
    Mock,
}

impl PatternAction {
    /// Past-tense label used in reports.
    pub fn action_name(&self) -> &'static str {
        match self {
            PatternAction::Detect => "detected",
            PatternAction::Redact => "redacted",
            PatternAction::Token => "tokenized",
            PatternAction::Mock => "mocked",
        }
    }

    /// Whether this action derives values from the dataset key.
    pub fn needs_key(&self) -> bool {
        matches!(self, PatternAction::Token | PatternAction::Mock)
    }
}

/// Mock shape selector in policy YAML.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MockShapeCfg {
    Iban,
    Email,
    Phone,
    CreditCard,
}

impl From<MockShapeCfg> for crate::mock::MockShape {
    fn from(cfg: MockShapeCfg) -> Self {
        match cfg {
            MockShapeCfg::Iban => crate::mock::MockShape::Iban,
            MockShapeCfg::Email => crate::mock::MockShape::Email,
            MockShapeCfg::Phone => crate::mock::MockShape::Phone,
            MockShapeCfg::CreditCard => crate::mock::MockShape::CreditCard,
        }
    }
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
        let mut pattern_names = std::collections::HashSet::new();
        for pattern in &self.patterns {
            if !pattern_names.insert(pattern.name.as_str()) {
                return Err(CoreError::Policy(format!(
                    "pattern '{}' is listed more than once",
                    pattern.name
                )));
            }
            match (&pattern.regex, &pattern.builtin) {
                (Some(_), Some(_)) | (None, None) => {
                    return Err(CoreError::Policy(format!(
                        "pattern '{}': exactly one of 'regex' or 'builtin' must be set",
                        pattern.name
                    )));
                }
                _ => {}
            }
            if let Err(err) = regex::Regex::new(pattern.regex_source()) {
                return Err(CoreError::Policy(format!(
                    "pattern '{}': invalid regex: {err}",
                    pattern.name
                )));
            }
            if pattern.replacement.is_some() && pattern.action != PatternAction::Redact {
                return Err(CoreError::Policy(format!(
                    "pattern '{}': 'replacement' is only valid with action: redact",
                    pattern.name
                )));
            }
            if pattern.prefix.is_some() && pattern.action != PatternAction::Token {
                return Err(CoreError::Policy(format!(
                    "pattern '{}': 'prefix' is only valid with action: token",
                    pattern.name
                )));
            }
            if pattern.mock.is_some() && pattern.action != PatternAction::Mock {
                return Err(CoreError::Policy(format!(
                    "pattern '{}': 'mock' is only valid with action: mock",
                    pattern.name
                )));
            }
            if pattern.action == PatternAction::Mock && pattern.mock_shape().is_none() {
                // Reached when a detector has no format-preserving equivalent
                // (there is no "valid fake" medical term) or a custom regex gave
                // no shape.
                return Err(CoreError::Policy(format!(
                    "pattern '{}': action: mock needs a shape — set 'mock' explicitly or use a \
                     'builtin' pattern",
                    pattern.name
                )));
            }
        }
        for preset in &self.presets {
            if preset.replacement.is_some() && preset.action != PatternAction::Redact {
                return Err(CoreError::Policy(
                    "preset 'replacement' is only valid with action: redact".into(),
                ));
            }
            if preset.action == PatternAction::Mock {
                return Err(CoreError::Policy(
                    "presets cannot use action: mock — most detectors have no \
                     format-preserving equivalent; name the rules explicitly instead"
                        .into(),
                ));
            }
        }
        // Expanded rules must validate too (catches an unusable combination
        // before a job starts rather than mid-run).
        for rule in self.effective_patterns() {
            if let Err(err) = regex::Regex::new(rule.regex_source()) {
                return Err(CoreError::Policy(format!(
                    "pattern '{}': invalid regex: {err}",
                    rule.name
                )));
            }
        }
        Ok(())
    }

    /// All pattern rules in execution order: expanded presets first, then the
    /// explicit `patterns` list.
    ///
    /// A preset never overrides an explicit rule of the same name, so a policy
    /// can enable a whole class and still tune one member of it.
    pub fn effective_patterns(&self) -> Vec<PatternRule> {
        let explicit: std::collections::HashSet<&str> =
            self.patterns.iter().map(|p| p.name.as_str()).collect();
        let mut rules: Vec<PatternRule> = Vec::new();
        for preset in &self.presets {
            for builtin in preset.preset.builtins() {
                if explicit.contains(builtin.name()) {
                    continue;
                }
                if rules.iter().any(|r| r.name == builtin.name()) {
                    continue;
                }
                rules.push(PatternRule {
                    name: builtin.name().to_string(),
                    regex: None,
                    builtin: Some(builtin),
                    fields: preset.fields.clone(),
                    action: preset.action,
                    replacement: preset.replacement.clone(),
                    prefix: None,
                    mock: None,
                    validate: None,
                });
            }
        }
        rules.extend(self.patterns.iter().cloned());
        rules
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
