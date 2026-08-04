//! DICOM de-identification policy.
//!
//! A DICOM policy addresses **tags**, not columns, so it is a separate dialect
//! from the tabular policy. It combines three layers, applied in this order of
//! precedence:
//!
//! 1. explicit per-tag rules from `tags:` (highest),
//! 2. the selected built-in profile's curated table,
//! 3. structural rules that catch whole classes of attribute (every person-name
//!    VR, every UID, every private tag).
//!
//! The structural layer is deliberate: reproducing all ~500 rows of DICOM
//! PS3.15 Annex E from memory would be error-prone, and a missed row means PHI
//! survives. Rules keyed on VR and tag structure catch classes rather than
//! instances, and the curated table then handles the well-established core
//! exactly.

use std::collections::BTreeMap;

use dicom_core::header::VR;
use dicom_core::Tag;
use serde::{Deserialize, Serialize};

use crate::error::DicomError;
use crate::profile;

/// What to do with one attribute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum TagAction {
    /// Delete the attribute (Annex E action `X`).
    Remove,
    /// Keep the attribute but make it zero-length (Annex E action `Z`).
    Empty,
    /// Replace with a fixed literal (Annex E action `D`, fixed dummy).
    Replace { value: String },
    /// Replace with a deterministic keyed pseudonym, optionally shaped to look
    /// like real data (Annex E action `D`, consistent dummy).
    Pseudonymize {
        #[serde(default)]
        prefix: Option<String>,
        /// Token domain; defaults to the tag's keyword so the same value maps
        /// to the same pseudonym across a study.
        #[serde(default)]
        domain: Option<String>,
        /// Imitate a value shape instead of emitting a hex token.
        #[serde(default)]
        mock: Option<MockShapeCfg>,
    },
    /// Replace with a new, internally consistent UID (Annex E action `U`).
    Uid,
    /// Shift a date/time by a deterministic per-subject offset, preserving
    /// intervals.
    DateShift {
        /// Maximum shift magnitude in days; the actual offset is derived from
        /// the key and `domain`.
        #[serde(default = "default_max_shift_days")]
        max_days: i64,
        /// Offset domain — give every date of one patient the same domain so
        /// their timeline stays internally consistent.
        #[serde(default)]
        domain: Option<String>,
    },
    /// Truncate a date to year or year-month.
    DateTruncate { granularity: DateGranularity },
    /// Run the policy's pattern rules over the text value (Annex E action `C`).
    CleanText,
    /// Leave the attribute untouched (Annex E action `K`).
    Keep,
}

impl TagAction {
    /// Past-tense label used in reports.
    pub fn action_name(&self) -> &'static str {
        match self {
            TagAction::Remove => "removed",
            TagAction::Empty => "emptied",
            TagAction::Replace { .. } => "replaced",
            TagAction::Pseudonymize { .. } => "pseudonymized",
            TagAction::Uid => "uid-remapped",
            TagAction::DateShift { .. } => "date-shifted",
            TagAction::DateTruncate { .. } => "date-truncated",
            TagAction::CleanText => "text-cleaned",
            TagAction::Keep => "kept",
        }
    }

    /// Whether this action needs the dataset key.
    pub fn needs_key(&self) -> bool {
        matches!(
            self,
            TagAction::Pseudonymize { .. } | TagAction::Uid | TagAction::DateShift { .. }
        )
    }

    /// Whether the result is reversible with the key material.
    pub fn is_reversible(&self) -> bool {
        matches!(
            self,
            TagAction::Pseudonymize { .. } | TagAction::Uid | TagAction::DateShift { .. }
        )
    }
}

fn default_max_shift_days() -> i64 {
    3650
}

/// Date truncation granularity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DateGranularity {
    Year,
    YearMonth,
}

/// Mock shapes usable for `pseudonymize`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MockShapeCfg {
    /// `Doe^Jane` style person name.
    PersonName,
    Email,
    Phone,
}

/// One explicit tag rule.
///
/// Note: no `deny_unknown_fields` here — serde rejects that attribute in
/// combination with `flatten`. Typos are still caught, because each [`TagAction`]
/// variant carries `deny_unknown_fields` itself, so an unexpected key inside a
/// rule fails to parse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagRule {
    /// Tag keyword (`PatientName`) or explicit `(0010,0010)` / `0010,0010`.
    pub tag: String,
    #[serde(flatten)]
    pub action: TagAction,
}

/// Built-in profile selection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    /// Curated DICOM PS3.15 Annex E "Basic Application Level Confidentiality
    /// Profile" core, plus the structural rules. **Not full conformance** — see
    /// the crate docs.
    #[default]
    Basic,
    /// Structural rules only; every other attribute is kept. For callers who
    /// want to drive everything from explicit `tags:` entries.
    Structural,
    /// No built-in rules at all; `tags:` is the whole policy.
    None,
}

/// Structural rules — the safety net that catches classes of attribute rather
/// than named instances.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuralRules {
    /// Every attribute whose VR is `PN` (person name).
    #[serde(default = "yes")]
    pub person_names: bool,
    /// Every UID-valued attribute in the known identity set.
    #[serde(default = "yes")]
    pub uids: bool,
    /// Private attributes (odd group numbers) — unknown vendor semantics.
    #[serde(default = "yes")]
    pub private_tags: bool,
    /// Curve (5xxx) and overlay (6xxx) groups, which can carry annotations.
    #[serde(default = "yes")]
    pub curves_and_overlays: bool,
    /// Keep private attributes instead of removing them. Opt-in and risky:
    /// vendor private blocks are a documented PHI hiding place.
    #[serde(default)]
    pub retain_safe_private: bool,
}

impl Default for StructuralRules {
    fn default() -> Self {
        Self {
            person_names: true,
            uids: true,
            private_tags: true,
            curves_and_overlays: true,
            retain_safe_private: false,
        }
    }
}

fn yes() -> bool {
    true
}

/// A DICOM de-identification policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DicomPolicy {
    /// Schema version; currently only `1`.
    pub version: u32,
    /// Marks this document as the DICOM dialect.
    pub kind: PolicyKind,
    /// Identity scope for tokens, UIDs and date offsets — share it across every
    /// instance of a study so remapping stays consistent.
    pub dataset: String,
    /// Key source, reusing the tabular policy's model.
    #[serde(default)]
    pub key: Option<deident_core::policy::KeySource>,
    #[serde(default)]
    pub profile: ProfileKind,
    #[serde(default)]
    pub structural: StructuralRules,
    /// Explicit per-tag rules; these win over profile and structural rules.
    #[serde(default)]
    pub tags: Vec<TagRule>,
    /// Pattern rules used by `clean_text` actions, reusing the tabular engine's
    /// content-pattern model.
    #[serde(default)]
    pub patterns: Vec<deident_core::policy::PatternRule>,
}

/// Discriminator so a tabular policy cannot be passed to the DICOM path by
/// mistake (and vice versa).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyKind {
    Dicom,
}

impl DicomPolicy {
    /// Parse and validate a policy from YAML.
    pub fn from_yaml(yaml: &str) -> Result<Self, DicomError> {
        let policy: DicomPolicy = serde_yaml::from_str(yaml)
            .map_err(|e| DicomError::Policy(format!("invalid DICOM policy: {e}")))?;
        policy.validate()?;
        Ok(policy)
    }

    /// Structural checks beyond what serde enforces.
    pub fn validate(&self) -> Result<(), DicomError> {
        if self.version != 1 {
            return Err(DicomError::Policy(format!(
                "unsupported DICOM policy version {} (expected 1)",
                self.version
            )));
        }
        if self.dataset.trim().is_empty() {
            return Err(DicomError::Policy("dataset must not be empty".into()));
        }
        let mut seen = std::collections::HashSet::new();
        for rule in &self.tags {
            let tag = parse_tag(&rule.tag)?;
            if !seen.insert(tag) {
                return Err(DicomError::Policy(format!(
                    "tag '{}' is listed more than once",
                    rule.tag
                )));
            }
            if let TagAction::DateShift { max_days, .. } = &rule.action
                && *max_days <= 0
            {
                return Err(DicomError::Policy(format!(
                    "tag '{}': date_shift max_days must be positive",
                    rule.tag
                )));
            }
        }
        // Reuse the tabular validator for the pattern rules by wrapping them in
        // a minimal tabular policy — one implementation, one set of rules.
        if !self.patterns.is_empty() {
            let probe = deident_core::Policy {
                version: 1,
                dataset: self.dataset.clone(),
                key: self.key.clone(),
                on_unlisted: Default::default(),
                fields: Vec::new(),
                patterns: self.patterns.clone(),
            };
            probe
                .validate()
                .map_err(|e| DicomError::Policy(e.to_string()))?;
        }
        Ok(())
    }

    /// Resolve the policy into a flat tag → action map plus the structural
    /// fallbacks, ready for the engine.
    pub fn resolve(&self) -> Result<ResolvedPolicy, DicomError> {
        let mut explicit: BTreeMap<Tag, TagAction> = BTreeMap::new();
        // Profile first, so explicit rules can override it.
        if self.profile == ProfileKind::Basic {
            for (tag, action) in profile::basic_profile() {
                explicit.insert(tag, action);
            }
        }
        for rule in &self.tags {
            explicit.insert(parse_tag(&rule.tag)?, rule.action.clone());
        }
        Ok(ResolvedPolicy {
            explicit,
            structural: self.structural.clone(),
            structural_enabled: self.profile != ProfileKind::None,
        })
    }
}

/// A policy flattened for execution.
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    explicit: BTreeMap<Tag, TagAction>,
    structural: StructuralRules,
    structural_enabled: bool,
}

impl ResolvedPolicy {
    /// The action for one attribute, or `None` to leave it untouched.
    ///
    /// Precedence: explicit/profile rule → structural rule → keep.
    pub fn action_for(&self, tag: Tag, vr: VR) -> Option<&TagAction> {
        if let Some(action) = self.explicit.get(&tag) {
            return Some(action);
        }
        if !self.structural_enabled {
            return None;
        }
        if is_private(tag) {
            return if self.structural.private_tags && !self.structural.retain_safe_private {
                Some(&TagAction::Remove)
            } else {
                None
            };
        }
        if self.structural.curves_and_overlays && is_curve_or_overlay(tag) {
            return Some(&TagAction::Remove);
        }
        if self.structural.person_names && vr == VR::PN {
            return Some(&TagAction::Empty);
        }
        if self.structural.uids && profile::is_identity_uid(tag) {
            return Some(&TagAction::Uid);
        }
        None
    }

    /// Tags with an explicit or profile-level rule (for reporting coverage).
    pub fn explicit_tags(&self) -> impl Iterator<Item = (&Tag, &TagAction)> {
        self.explicit.iter()
    }
}

/// Private attributes live in odd-numbered groups (PS3.5 §7.8). Groups 0001,
/// 0003, 0005, 0007 and FFFF are illegal, and the group-length elements
/// `(gggg,0000)` are not themselves private data.
pub fn is_private(tag: Tag) -> bool {
    tag.group() % 2 == 1
        && tag.element() != 0x0000
        && !matches!(tag.group(), 0x0001 | 0x0003 | 0x0005 | 0x0007 | 0xFFFF)
}

/// Curve (5xxx) and overlay (6xxx) groups can carry burned-in annotations and
/// digitised signals.
pub fn is_curve_or_overlay(tag: Tag) -> bool {
    let group = tag.group();
    (0x5000..=0x50FF).contains(&group) || (0x6000..=0x60FF).contains(&group)
}

/// Parse a tag from a keyword (`PatientName`) or a numeric form
/// (`(0010,0010)`, `0010,0010`, `00100010`).
pub fn parse_tag(text: &str) -> Result<Tag, DicomError> {
    let trimmed = text.trim();
    let numeric = trimmed
        .trim_start_matches('(')
        .trim_end_matches(')')
        .replace([',', ' '], "");
    if numeric.len() == 8 && numeric.chars().all(|c| c.is_ascii_hexdigit()) {
        let group = u16::from_str_radix(&numeric[..4], 16)
            .map_err(|e| DicomError::Policy(format!("bad tag group in '{text}': {e}")))?;
        let element = u16::from_str_radix(&numeric[4..], 16)
            .map_err(|e| DicomError::Policy(format!("bad tag element in '{text}': {e}")))?;
        return Ok(Tag(group, element));
    }
    profile::tag_by_keyword(trimmed).ok_or_else(|| {
        DicomError::Policy(format!(
            "unknown DICOM tag '{text}': use a standard keyword (e.g. PatientName) \
             or a numeric tag (e.g. (0010,0010))"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tags_in_every_accepted_form() {
        let expected = Tag(0x0010, 0x0010);
        for form in ["PatientName", "(0010,0010)", "0010,0010", "00100010", " (0010, 0010) "] {
            assert_eq!(parse_tag(form).unwrap(), expected, "form: {form}");
        }
        assert!(parse_tag("NotATag").is_err());
        assert!(parse_tag("(00ZZ,0010)").is_err());
    }

    #[test]
    fn identifies_private_and_overlay_groups() {
        assert!(is_private(Tag(0x0009, 0x0010)), "odd group is private");
        assert!(!is_private(Tag(0x0010, 0x0010)), "even group is standard");
        assert!(!is_private(Tag(0x0009, 0x0000)), "group length is not private data");
        assert!(!is_private(Tag(0x0001, 0x0010)), "illegal group is not private data");
        assert!(is_curve_or_overlay(Tag(0x6000, 0x3000)));
        assert!(is_curve_or_overlay(Tag(0x5012, 0x0010)));
        assert!(!is_curve_or_overlay(Tag(0x7FE0, 0x0010)), "pixel data is not an overlay");
    }

    #[test]
    fn explicit_rules_override_the_profile() {
        let policy = DicomPolicy::from_yaml(
            r#"
version: 1
kind: dicom
dataset: study-1
key: { inline: "s" }
profile: basic
tags:
  - tag: PatientName
    action: replace
    value: "ANON^ANON"
"#,
        )
        .unwrap();
        let resolved = policy.resolve().unwrap();
        // The basic profile empties PatientName; the explicit rule replaces it.
        assert_eq!(
            resolved.action_for(Tag(0x0010, 0x0010), VR::PN),
            Some(&TagAction::Replace {
                value: "ANON^ANON".into()
            })
        );
    }

    #[test]
    fn structural_rules_catch_unlisted_classes() {
        let policy = DicomPolicy::from_yaml(
            "version: 1\nkind: dicom\ndataset: d\nprofile: structural\n",
        )
        .unwrap();
        let resolved = policy.resolve().unwrap();
        // An unlisted person-name attribute is still caught by VR.
        assert_eq!(
            resolved.action_for(Tag(0x0008, 0x0090), VR::PN),
            Some(&TagAction::Empty),
            "referring physician name"
        );
        // Private tags are removed.
        assert_eq!(
            resolved.action_for(Tag(0x0009, 0x1001), VR::LO),
            Some(&TagAction::Remove)
        );
        // A benign standard attribute is untouched.
        assert_eq!(resolved.action_for(Tag(0x0028, 0x0010), VR::US), None);
    }

    #[test]
    fn retain_safe_private_disables_private_removal() {
        let policy = DicomPolicy::from_yaml(
            "version: 1\nkind: dicom\ndataset: d\nprofile: structural\n\
             structural: { retain_safe_private: true }\n",
        )
        .unwrap();
        let resolved = policy.resolve().unwrap();
        assert_eq!(resolved.action_for(Tag(0x0009, 0x1001), VR::LO), None);
    }

    #[test]
    fn rejects_wrong_dialect_and_bad_values() {
        // A tabular policy must not parse as a DICOM policy.
        assert!(DicomPolicy::from_yaml("version: 1\ndataset: d\nfields: []\n").is_err());
        assert!(
            DicomPolicy::from_yaml(
                "version: 1\nkind: dicom\ndataset: d\ntags:\n  - tag: StudyDate\n    \
                 action: date_shift\n    max_days: 0\n"
            )
            .is_err()
        );
        assert!(
            DicomPolicy::from_yaml(
                "version: 1\nkind: dicom\ndataset: d\ntags:\n  - { tag: PatientName, action: remove }\n  \
                 - { tag: \"(0010,0010)\", action: empty }\n"
            )
            .is_err(),
            "the same tag twice, under two spellings, must be rejected"
        );
    }
}
