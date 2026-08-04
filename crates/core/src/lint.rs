//! Policy lints: risky-but-valid policy patterns, reported before a job runs.
//!
//! Validation ([`Policy::validate`](crate::Policy::validate)) rejects policies
//! that cannot run. Lints are the layer above: the policy is legal, but it
//! probably does not do what its author intended — a quasi-identifier with no
//! generalization strategy, a secret pasted into the file, deny-by-default
//! turned off. Lints never block a job on their own; the CLI can escalate
//! them with `--deny-lints`.

use serde::{Deserialize, Serialize};

use crate::policy::{AnonymizeCfg, FieldClass, PatternAction, Policy};
use deident_types::Mode;

/// How seriously to take a lint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LintLevel {
    /// Likely a privacy problem: data stays identifying, or key material is
    /// exposed.
    Warning,
    /// Worth a look, but legitimate in many setups.
    Advice,
}

impl LintLevel {
    pub fn label(&self) -> &'static str {
        match self {
            LintLevel::Warning => "warning",
            LintLevel::Advice => "advice",
        }
    }
}

/// One lint finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lint {
    /// Stable kebab-case rule id, e.g. `qi-without-strategy`.
    pub rule: String,
    pub level: LintLevel,
    /// Field or pattern the lint refers to, when it is specific to one.
    pub subject: Option<String>,
    pub message: String,
}

impl Lint {
    fn new(rule: &str, level: LintLevel, subject: Option<&str>, message: String) -> Self {
        Self {
            rule: rule.to_string(),
            level,
            subject: subject.map(str::to_string),
            message,
        }
    }
}

/// Column-name fragments that suggest free text, which can carry identifiers
/// that column-level rules never see.
const FREE_TEXT_HINTS: [&str; 8] = [
    "note", "comment", "description", "text", "remark", "memo", "free", "message",
];

/// Lint a policy. `mode` restricts the rules to those relevant for one mode;
/// `None` reports everything.
pub fn lint(policy: &Policy, mode: Option<Mode>) -> Vec<Lint> {
    let mut lints = Vec::new();
    let for_mode = |m: Mode| mode.is_none_or(|requested| requested == m);

    // --- key material ---------------------------------------------------
    let tokenizes =
        for_mode(Mode::Pseudonymize) || policy.patterns.iter().any(|p| p.action.needs_key());
    if let Some(key) = &policy.key
        && key.inline.is_some()
        && tokenizes
    {
        let message = if key.env.is_some() {
            "policy carries an inline key as a fallback; it is used whenever the environment \
             variable is unset, which silently changes every token — remove it outside demos"
        } else {
            "policy carries the pseudonymization secret inline; anyone with the policy file can \
             reverse every token — use key.env with a separately managed secret"
        };
        lints.push(Lint::new(
            "inline-key",
            LintLevel::Warning,
            None,
            message.to_string(),
        ));
    }
    if policy.key.is_none() && for_mode(Mode::Pseudonymize) {
        lints.push(Lint::new(
            "missing-key-source",
            LintLevel::Warning,
            None,
            "no key source configured; pseudonymize jobs with this policy will fail".to_string(),
        ));
    }

    // --- deny-by-default ------------------------------------------------
    match policy.on_unlisted {
        crate::policy::UnlistedAction::Keep => lints.push(Lint::new(
            "unlisted-columns-kept",
            LintLevel::Warning,
            None,
            "on_unlisted: keep passes unreviewed columns through unchanged; new columns in the \
             source data will leak untouched into the output"
                .to_string(),
        )),
        crate::policy::UnlistedAction::Remove => lints.push(Lint::new(
            "unlisted-columns-removed",
            LintLevel::Advice,
            None,
            "on_unlisted: remove silently drops unreviewed columns; use `error` if you want new \
             source columns to be classified deliberately"
                .to_string(),
        )),
        crate::policy::UnlistedAction::Error => {}
    }

    // --- field classification -------------------------------------------
    let direct_identifiers = policy
        .fields
        .iter()
        .filter(|f| f.class == FieldClass::DirectIdentifier)
        .count();
    let quasi_identifiers: Vec<&crate::policy::FieldPolicy> = policy
        .fields
        .iter()
        .filter(|f| f.class == FieldClass::QuasiIdentifier)
        .collect();

    if !policy.fields.is_empty() && direct_identifiers == 0 {
        lints.push(Lint::new(
            "no-direct-identifiers",
            LintLevel::Advice,
            None,
            "no field is classified as direct_identifier; check that identifying columns are not \
             classified as utility or sensitive"
                .to_string(),
        ));
    }
    if !policy.fields.is_empty() && quasi_identifiers.is_empty() {
        lints.push(Lint::new(
            "no-quasi-identifiers",
            LintLevel::Advice,
            None,
            "no field is classified as quasi_identifier; the report cannot compute \
             equivalence-class statistics, so residual re-identification risk stays unmeasured"
                .to_string(),
        ));
    }

    for field in &policy.fields {
        match (&field.class, &field.anonymize) {
            (FieldClass::QuasiIdentifier, None) if for_mode(Mode::Anonymize) => {
                lints.push(Lint::new(
                    "qi-without-strategy",
                    LintLevel::Warning,
                    Some(&field.name),
                    "quasi-identifier has no anonymize strategy and is kept unchanged; add \
                     generalization (bucket, date_truncate, keep_prefix) or suppression (remove)"
                        .to_string(),
                ));
            }
            (FieldClass::DirectIdentifier, Some(cfg)) if for_mode(Mode::Anonymize) => {
                if let AnonymizeCfg::KeepPrefix { chars, .. } = cfg
                    && *chars > 0
                {
                    lints.push(Lint::new(
                        "direct-identifier-partially-kept",
                        LintLevel::Warning,
                        Some(&field.name),
                        format!(
                            "direct identifier keeps its first {chars} character(s) in anonymize \
                             mode; prefer remove or redact"
                        ),
                    ));
                }
            }
            _ => {}
        }

        if let Some(AnonymizeCfg::Bucket { width }) = &field.anonymize
            && *width == 1
            && for_mode(Mode::Anonymize)
        {
            lints.push(Lint::new(
                "ineffective-bucket",
                LintLevel::Warning,
                Some(&field.name),
                "bucket width 1 does not generalize anything (each value keeps its own class)"
                    .to_string(),
            ));
        }

        // Free-text columns can hide identifiers that column rules never see.
        let looks_free_text = FREE_TEXT_HINTS
            .iter()
            .any(|hint| field.name.to_ascii_lowercase().contains(hint));
        let kept = !matches!(field.anonymize, Some(AnonymizeCfg::Remove));
        let covered = policy.patterns.iter().any(|p| {
            p.fields
                .as_ref()
                .is_none_or(|fields| fields.contains(&field.name))
        });
        if looks_free_text
            && kept
            && !covered
            && matches!(field.class, FieldClass::Utility | FieldClass::Sensitive)
        {
            lints.push(Lint::new(
                "free-text-without-patterns",
                LintLevel::Warning,
                Some(&field.name),
                "column looks like free text but no pattern rule scans it; identifiers embedded \
                 in the text (IBANs, emails, phone numbers) pass through untouched"
                    .to_string(),
            ));
        }
    }

    // --- pattern rules ---------------------------------------------------
    let effective = policy.effective_patterns();
    let mut seen_builtins: std::collections::HashMap<&str, &str> =
        std::collections::HashMap::new();
    for pattern in &effective {
        if let Some(builtin) = pattern.builtin
            && let Some(first) = seen_builtins.insert(builtin.name(), pattern.name.as_str())
        {
            lints.push(Lint::new(
                "duplicate-builtin-detector",
                LintLevel::Warning,
                Some(&pattern.name),
                format!(
                    "rules '{first}' and '{}' both use the '{}' detector. Rules run in order over                      the same value, so the first one's replacement hides the matches the second                      would have made — keep one rule per detector",
                    pattern.name,
                    builtin.name()
                ),
            ));
        }
    }
    for pattern in &effective {
        if pattern.precision() == Some(crate::detect::Precision::Heuristic)
            && pattern.action != PatternAction::Detect
        {
            lints.push(Lint::new(
                "heuristic-pattern-modifies-data",
                LintLevel::Warning,
                Some(&pattern.name),
                format!(
                    "'{}' is a heuristic detector standing in for named entity recognition: it \
                     produces false positives AND false negatives. With action: {:?} it will \
                     corrupt innocent values and still miss real ones — prefer action: detect and \
                     review the findings",
                    pattern.name, pattern.action
                ),
            ));
        }
    }
    for pattern in &policy.patterns {
        if pattern.action == PatternAction::Detect {
            lints.push(Lint::new(
                "detect-only-pattern",
                LintLevel::Advice,
                Some(&pattern.name),
                "pattern only counts matches; matching values stay in the output unchanged"
                    .to_string(),
            ));
        }
        if pattern.action.needs_key() && mode == Some(Mode::Anonymize) {
            lints.push(Lint::new(
                "reversible-pattern-in-anonymize",
                LintLevel::Advice,
                Some(&pattern.name),
                format!(
                    "pattern inserts reversible {} into an anonymize output; the affected values \
                     stay pseudonymous rather than anonymized",
                    if pattern.action == PatternAction::Mock {
                        "mock values"
                    } else {
                        "tokens"
                    }
                ),
            ));
        }
    }

    lints
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(policy_yaml: &str, mode: Option<Mode>) -> Vec<String> {
        let policy = Policy::from_yaml(policy_yaml).unwrap();
        lint(&policy, mode).into_iter().map(|l| l.rule).collect()
    }

    #[test]
    fn flags_inline_key_and_relaxed_unlisted() {
        let found = rules(
            r#"
version: 1
dataset: d
key: { inline: "s" }
on_unlisted: keep
fields:
  - { name: id, class: direct_identifier }
  - { name: age, class: quasi_identifier, anonymize: { strategy: bucket, width: 10 } }
"#,
            Some(Mode::Pseudonymize),
        );
        assert!(found.contains(&"inline-key".to_string()));
        assert!(found.contains(&"unlisted-columns-kept".to_string()));
    }

    #[test]
    fn flags_quasi_identifier_without_strategy_only_in_anonymize() {
        let yaml = r#"
version: 1
dataset: d
key: { env: K }
fields:
  - { name: id, class: direct_identifier }
  - { name: zip, class: quasi_identifier }
"#;
        assert!(rules(yaml, Some(Mode::Anonymize)).contains(&"qi-without-strategy".to_string()));
        assert!(!rules(yaml, Some(Mode::Pseudonymize)).contains(&"qi-without-strategy".to_string()));
    }

    #[test]
    fn flags_uncovered_free_text_and_weak_generalization() {
        let found = rules(
            r#"
version: 1
dataset: d
key: { env: K }
fields:
  - { name: id, class: direct_identifier }
  - { name: age, class: quasi_identifier, anonymize: { strategy: bucket, width: 1 } }
  - { name: notes, class: utility }
"#,
            Some(Mode::Anonymize),
        );
        assert!(found.contains(&"free-text-without-patterns".to_string()));
        assert!(found.contains(&"ineffective-bucket".to_string()));
    }

    #[test]
    fn clean_policy_has_no_warnings() {
        let policy = Policy::from_yaml(
            r#"
version: 1
dataset: d
key: { env: DEIDENT_KEY }
on_unlisted: error
fields:
  - { name: id, class: direct_identifier }
  - { name: age, class: quasi_identifier, anonymize: { strategy: bucket, width: 10 } }
  - { name: notes, class: utility }
patterns:
  - { name: iban, builtin: iban, fields: [notes], action: redact }
"#,
        )
        .unwrap();
        let warnings: Vec<_> = lint(&policy, Some(Mode::Anonymize))
            .into_iter()
            .filter(|l| l.level == LintLevel::Warning)
            .collect();
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    }
}
