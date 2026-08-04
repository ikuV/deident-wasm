//! Catalog of built-in entity detectors.
//!
//! Each entry pairs a regex with an honest **precision class** and an optional
//! checksum validator. That combination is the point: a loose regex gives recall,
//! and a validator then removes the false positives it would otherwise create —
//! a 13-digit order number matches the card pattern but fails Luhn, so it is not
//! reported as a card.
//!
//! # On NER
//!
//! Person names, addresses, organizations and medical terms genuinely need named
//! entity recognition. This crate has no ML model, so those detectors are
//! **heuristics**: title-based or suffix-based patterns and a small gazetteer.
//! They will miss real entities and flag innocent text. They are classified
//! [`Precision::Heuristic`], default to `detect` in presets, and every report
//! says so. Treat them as "find candidates for a human to review", never as
//! "this text is now clean".
//!
//! Note the regex crate has no lookaround, so every pattern here is written
//! without it — which also guarantees linear-time matching.

use serde::{Deserialize, Serialize};

/// How much to trust a detector's matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Precision {
    /// Distinctive syntax, usually checksum-verified. Safe to act on
    /// automatically.
    Precise,
    /// Recognisable shape, but the shape is shared with innocent data. Expect
    /// some false positives.
    Moderate,
    /// A stand-in for NER. Expect **both** false positives and false negatives;
    /// suitable for review, not for unattended redaction.
    Heuristic,
}

impl Precision {
    pub fn label(&self) -> &'static str {
        match self {
            Precision::Precise => "precise",
            Precision::Moderate => "moderate",
            Precision::Heuristic => "heuristic",
        }
    }
}

/// Post-match checksum validation, used to suppress false positives.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Validator {
    /// Accept every match.
    #[default]
    None,
    /// Luhn (mod 10) — payment cards.
    Luhn,
    /// ISO 7064 mod-97-10 — IBANs.
    IbanMod97,
    /// US Social Security Number allocation rules.
    SsnUs,
}

impl Validator {
    /// Whether a matched string passes this validator.
    pub fn accepts(&self, matched: &str) -> bool {
        match self {
            Validator::None => true,
            Validator::Luhn => crate::mock::luhn_valid(matched),
            Validator::IbanMod97 => crate::mock::iban_valid(matched),
            Validator::SsnUs => ssn_us_valid(matched),
        }
    }
}

/// US SSN allocation rules: area 000, 666 and 900–999 are never issued, the
/// group must not be 00, and the serial must not be 0000.
fn ssn_us_valid(matched: &str) -> bool {
    let digits: Vec<u8> = matched.bytes().filter(u8::is_ascii_digit).collect();
    if digits.len() != 9 {
        return false;
    }
    let number = |slice: &[u8]| -> u32 {
        slice
            .iter()
            .fold(0u32, |acc, b| acc * 10 + u32::from(b - b'0'))
    };
    let area = number(&digits[0..3]);
    let group = number(&digits[3..5]);
    let serial = number(&digits[5..9]);
    area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
}

/// A built-in entity detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuiltinPattern {
    // --- precise (distinctive syntax, mostly checksum-verified) ---------
    Email,
    Iban,
    CreditCard,
    IpAddress,
    Url,
    ApiKey,
    Ifsc,
    // --- moderate (recognisable shape, shared with innocent data) -------
    Phone,
    Ssn,
    DateOfBirth,
    Passport,
    LicensePlate,
    // --- heuristic (NER stand-ins) --------------------------------------
    PersonName,
    Address,
    Organization,
    MedicalTerm,
}

/// Every built-in, in catalog order.
pub const ALL: &[BuiltinPattern] = &[
    BuiltinPattern::Email,
    BuiltinPattern::Iban,
    BuiltinPattern::CreditCard,
    BuiltinPattern::IpAddress,
    BuiltinPattern::Url,
    BuiltinPattern::ApiKey,
    BuiltinPattern::Ifsc,
    BuiltinPattern::Phone,
    BuiltinPattern::Ssn,
    BuiltinPattern::DateOfBirth,
    BuiltinPattern::Passport,
    BuiltinPattern::LicensePlate,
    BuiltinPattern::PersonName,
    BuiltinPattern::Address,
    BuiltinPattern::Organization,
    BuiltinPattern::MedicalTerm,
];

impl BuiltinPattern {
    /// Stable rule name used in reports and as the default redaction label.
    pub fn name(&self) -> &'static str {
        match self {
            BuiltinPattern::Email => "email",
            BuiltinPattern::Iban => "iban",
            BuiltinPattern::CreditCard => "credit_card",
            BuiltinPattern::IpAddress => "ip_address",
            BuiltinPattern::Url => "url",
            BuiltinPattern::ApiKey => "api_key",
            BuiltinPattern::Ifsc => "ifsc",
            BuiltinPattern::Phone => "phone",
            BuiltinPattern::Ssn => "ssn",
            BuiltinPattern::DateOfBirth => "date_of_birth",
            BuiltinPattern::Passport => "passport",
            BuiltinPattern::LicensePlate => "license_plate",
            BuiltinPattern::PersonName => "person_name",
            BuiltinPattern::Address => "address",
            BuiltinPattern::Organization => "organization",
            BuiltinPattern::MedicalTerm => "medical_term",
        }
    }

    pub fn precision(&self) -> Precision {
        match self {
            BuiltinPattern::Email
            | BuiltinPattern::Iban
            | BuiltinPattern::CreditCard
            | BuiltinPattern::IpAddress
            | BuiltinPattern::Url
            | BuiltinPattern::ApiKey
            | BuiltinPattern::Ifsc => Precision::Precise,
            BuiltinPattern::Phone
            | BuiltinPattern::Ssn
            | BuiltinPattern::DateOfBirth
            | BuiltinPattern::Passport
            | BuiltinPattern::LicensePlate => Precision::Moderate,
            BuiltinPattern::PersonName
            | BuiltinPattern::Address
            | BuiltinPattern::Organization
            | BuiltinPattern::MedicalTerm => Precision::Heuristic,
        }
    }

    /// Checksum validation applied to every match of this detector.
    pub fn validator(&self) -> Validator {
        match self {
            BuiltinPattern::CreditCard => Validator::Luhn,
            BuiltinPattern::Iban => Validator::IbanMod97,
            BuiltinPattern::Ssn => Validator::SsnUs,
            _ => Validator::None,
        }
    }

    /// One-line description for reports and `--explain`-style output.
    pub fn description(&self) -> &'static str {
        match self {
            BuiltinPattern::Email => "email address",
            BuiltinPattern::Iban => "IBAN (mod-97 verified, accepts grouped and lowercase forms)",
            BuiltinPattern::CreditCard => "payment card number (Luhn verified)",
            BuiltinPattern::IpAddress => "IPv4 or IPv6 address",
            BuiltinPattern::Url => "URL",
            BuiltinPattern::ApiKey => "API key or access token of a known vendor shape",
            BuiltinPattern::Ifsc => "Indian IFSC code, optionally with an account number",
            BuiltinPattern::Phone => "telephone number in international or national form",
            BuiltinPattern::Ssn => "US Social Security Number (allocation rules verified)",
            BuiltinPattern::DateOfBirth => "date in numeric or month-name form",
            BuiltinPattern::Passport => "passport number",
            BuiltinPattern::LicensePlate => "vehicle registration plate",
            BuiltinPattern::PersonName => {
                "person name — HEURISTIC stand-in for NER; titles are reliable, bare names are not"
            }
            BuiltinPattern::Address => "postal address — HEURISTIC, keys on street-type words",
            BuiltinPattern::Organization => {
                "organization — HEURISTIC, keys on corporate/institutional suffixes"
            }
            BuiltinPattern::MedicalTerm => {
                "medical condition — HEURISTIC, small curated gazetteer, far from exhaustive"
            }
        }
    }

    /// The regex source for this detector.
    ///
    /// Written without lookaround (unsupported by the `regex` crate), which also
    /// guarantees linear-time matching on untrusted input.
    pub fn regex_source(&self) -> &'static str {
        match self {
            // Unicode-aware local part, so `müller@example.de` matches whole
            // rather than leaving `mü` behind.
            BuiltinPattern::Email => {
                r"[\w.!#$%&'*+/=?^`{|}~-]+@[\w-]+(?:\.[\w-]+)+"
            }
            // Two alternatives, compact first. A single space-tolerant
            // repetition would greedily absorb the words after the IBAN
            // ("DE89...013000 or mail ada"); the checksum would then reject the
            // over-match and a REAL IBAN would go undetected — a false negative
            // caused by being too permissive. The grouped alternative therefore
            // requires the ISO 13616 print convention of four-character groups.
            BuiltinPattern::Iban => {
                r"(?i)\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b|\b[A-Z]{2}[0-9]{2}(?: [A-Z0-9]{4}){2,6}(?: [A-Z0-9]{1,4})?\b"
            }
            // 13–19 digits with optional space/dash grouping (covers Amex 4-6-5);
            // Luhn-verified.
            BuiltinPattern::CreditCard => r"\b\d(?:[ -]?\d){12,18}\b",
            // IPv4 with octet ranges enforced, plus IPv6 in full, compressed
            // and loopback forms.
            //
            // Alternative ORDER matters: the regex crate is leftmost-first, so a
            // shorter alternative placed earlier wins and truncates the match —
            // an earlier version matched `2001:db8::` out of `2001:db8::1` and
            // left a stray `1` in output that had been reported as redacted.
            BuiltinPattern::IpAddress => {
                r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b|(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}(?::[0-9A-Fa-f]{1,4}){1,7}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?"
            }
            BuiltinPattern::Url => {
                r"\b(?:https?|ftps?)://[^\s<>\x22'`\]]+|\bwww\.[\w-]+(?:\.[\w-]+)+[^\s<>\x22'`\]]*"
            }
            // Known vendor token shapes. Deliberately specific: a generic
            // "long random string" pattern would flag every hash and token.
            BuiltinPattern::ApiKey => {
                r"\b(?:sk|pk|rk)[-_](?:live|test|prod)[-_][A-Za-z0-9]{8,}|\bAKIA[0-9A-Z]{16}\b|\bASIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}|\bxox[baprs]-[A-Za-z0-9-]{10,}|\bAIza[0-9A-Za-z_-]{35}\b|\bglpat-[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9]{20,}"
            }
            // IFSC is four letters, a zero, then six alphanumerics; an adjacent
            // account number is captured when present.
            BuiltinPattern::Ifsc => {
                r"\b[A-Z]{4}0[A-Z0-9]{6}\b(?:[\s,:;/-]{0,3}\d{9,18}\b)?"
            }
            // Requires a `+` country code or a leading 0 trunk prefix, so it no
            // longer swallows ISO dates, IBAN digit runs or plain amounts.
            BuiltinPattern::Phone => {
                r"\+\d{1,3}[\s.-]?(?:\(\d{1,4}\)[\s.-]?)?\d{2,4}(?:[\s.-]?\d{2,5}){1,4}|\b0\d{1,4}[\s.-]\d{2,5}(?:[\s.-]?\d{2,5}){1,3}\b"
            }
            BuiltinPattern::Ssn => r"\b\d{3}[- ]\d{2}[- ]\d{4}\b",
            // Numeric d/m/y and y-m-d, plus English month-name forms.
            BuiltinPattern::DateOfBirth => {
                r"\b\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}\b|\b\d{4}[/.-]\d{1,2}[/.-]\d{1,2}\b|(?i)\b(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t|tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}\b|(?i)\b\d{1,2}(?:st|nd|rd|th)?\s+(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t|tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\.?,?\s+\d{4}\b"
            }
            // One or two letters followed by 6–8 digits, the shape most national
            // passport numbers share.
            BuiltinPattern::Passport => r"\b[A-Z]{1,2}[0-9]{6,8}\b",
            // Indian-style `MH 12 AB 1234` and its unspaced variants.
            BuiltinPattern::LicensePlate => {
                r"\b[A-Z]{2}[\s-]?\d{1,2}[\s-]?[A-Z]{1,3}[\s-]?\d{1,4}\b"
            }
            // Titles are the reliable signal; the second alternative catches
            // bare capitalised bigrams and is the main source of false positives.
            BuiltinPattern::PersonName => {
                r"\b(?:Dr|Doctor|Prof|Professor|Mr|Mrs|Ms|Miss|Sr|Sra|Herr|Frau|Shri|Smt|Sri)\.?\s+\p{Lu}\p{L}+(?:\s+\p{Lu}\p{L}+){0,2}\b|\b\p{Lu}\p{L}+\s+\p{Lu}\p{L}+(?:\s+\p{Lu}\p{L}+)?\b"
            }
            BuiltinPattern::Address => {
                r"(?i)\b\d{1,5}[/-]?[A-Za-z]?\s+(?:[\p{Lu}][\p{L}.'-]*\s+){0,4}(?:road|rd|street|st|marg|nagar|lane|ln|avenue|ave|boulevard|blvd|drive|dr|colony|sector|block|strasse|straße|str|weg|platz|gasse|allee)\b(?:[\s,]+\d{5,6}\b)?"
            }
            BuiltinPattern::Organization => {
                r"\b(?:\p{Lu}[\p{L}&'.-]*\s+){0,4}(?:Hospital|Hospitals|Clinic|Clinics|Bank|Ltd|Limited|Pvt|Private|Inc|LLC|LLP|GmbH|AG|NV|BV|PLC|Corp|Corporation|Company|Institute|Institut|University|Universität|College|Foundation|Trust|Laboratories|Laboratory|Labs|Pharma|Pharmaceuticals|Healthcare|Klinik|Klinikum|Praxis)\b"
            }
            BuiltinPattern::MedicalTerm => MEDICAL_TERM_REGEX,
        }
    }

    /// A value this detector must match, used by the test suite to guard every
    /// pattern against silent breakage.
    pub fn example(&self) -> &'static str {
        match self {
            BuiltinPattern::Email => "user@example.com",
            BuiltinPattern::Iban => "DE89 3704 0044 0532 0130 00",
            BuiltinPattern::CreditCard => "4532-1234-5678-9014",
            BuiltinPattern::IpAddress => "192.168.1.1",
            BuiltinPattern::Url => "https://internal.company.com",
            BuiltinPattern::ApiKey => "AKIAIOSFODNN7EXAMPLE",
            BuiltinPattern::Ifsc => "HDFC0001234 000123456789",
            BuiltinPattern::Phone => "+91 98765 43210",
            BuiltinPattern::Ssn => "123-45-6789",
            BuiltinPattern::DateOfBirth => "15/03/1990",
            BuiltinPattern::Passport => "J1234567",
            BuiltinPattern::LicensePlate => "MH 12 AB 1234",
            BuiltinPattern::PersonName => "Dr. Priya Sharma",
            BuiltinPattern::Address => "123 MG Road, Pune 411001",
            BuiltinPattern::Organization => "Apollo Hospital",
            BuiltinPattern::MedicalTerm => "cardiac arrest",
        }
    }
}

/// Curated gazetteer of common conditions and events.
///
/// Deliberately small and openly incomplete: a real clinical vocabulary is
/// SNOMED/ICD-scale and cannot live in a regex. Extend with a custom `regex:`
/// rule for the terms your data uses.
const MEDICAL_TERM_REGEX: &str = r"(?i)\b(?:diabetes|diabetic|hypertension|hypotension|cardiac arrest|myocardial infarction|heart attack|heart failure|arrhythmia|atrial fibrillation|angina|stroke|cerebral infarction|asthma|copd|emphysema|pneumonia|bronchitis|tuberculosis|hepatitis|cirrhosis|hiv|aids|cancer|carcinoma|sarcoma|lymphoma|leukaemia|leukemia|melanoma|tumour|tumor|metastasis|chemotherapy|radiotherapy|epilepsy|seizure|migraine|dementia|alzheimer'?s|parkinson'?s|multiple sclerosis|depression|anxiety disorder|bipolar disorder|schizophrenia|psychosis|anorexia|bulimia|obesity|osteoporosis|arthritis|rheumatoid arthritis|lupus|psoriasis|eczema|anaemia|anemia|sepsis|meningitis|appendicitis|pancreatitis|gastritis|ulcer|reflux|ibs|crohn'?s|colitis|kidney failure|renal failure|dialysis|hypothyroidism|hyperthyroidism|pregnancy|miscarriage|covid-?19|influenza|measles|fracture|concussion|overdose|self-harm|substance abuse|alcoholism)\b";

#[cfg(test)]
mod tests {
    use super::*;

    /// Every pattern must compile and match its own documented example. This is
    /// the guard against a regex that silently stops working.
    #[test]
    fn every_builtin_compiles_and_matches_its_example() {
        for builtin in ALL {
            let regex = regex::Regex::new(builtin.regex_source())
                .unwrap_or_else(|e| panic!("{}: regex does not compile: {e}", builtin.name()));
            let example = builtin.example();
            let found = regex
                .find(example)
                .unwrap_or_else(|| panic!("{}: does not match its example {example:?}", builtin.name()));
            assert!(
                builtin.validator().accepts(found.as_str()),
                "{}: example {example:?} matched {:?} but failed its own validator",
                builtin.name(),
                found.as_str()
            );
        }
    }

    #[test]
    fn every_builtin_has_a_unique_name() {
        let mut names = std::collections::HashSet::new();
        for builtin in ALL {
            assert!(names.insert(builtin.name()), "duplicate name {}", builtin.name());
        }
        assert_eq!(names.len(), 16, "all sixteen detectors present");
    }

    fn matches(builtin: BuiltinPattern, text: &str) -> Vec<String> {
        let regex = regex::Regex::new(builtin.regex_source()).unwrap();
        regex
            .find_iter(text)
            .map(|m| m.as_str().to_string())
            .filter(|m| builtin.validator().accepts(m))
            .collect()
    }

    #[test]
    fn iban_accepts_grouped_and_lowercase_forms() {
        // The audit found the old pattern missed exactly these.
        for form in [
            "DE89370400440532013000",
            "DE89 3704 0044 0532 0130 00",
            "de89370400440532013000",
        ] {
            assert!(!matches(BuiltinPattern::Iban, form).is_empty(), "missed {form}");
        }
        // A wrong check digit must be rejected by mod-97 despite matching shape.
        assert!(matches(BuiltinPattern::Iban, "DE89370400440532013001").is_empty());
    }

    /// Regression: a permissive grouped-IBAN pattern used to swallow the words
    /// after the IBAN, so the checksum rejected the over-match and the real
    /// identifier was missed entirely.
    #[test]
    fn iban_does_not_absorb_following_words() {
        for text in [
            "pay to DE89370400440532013000 or mail ada@example.com",
            "DE89 3704 0044 0532 0130 00 and more words here",
            "ref de89370400440532013000 lowercase",
        ] {
            let found = matches(BuiltinPattern::Iban, text);
            assert_eq!(
                found.len(),
                1,
                "exactly one IBAN expected in {text:?}, got {found:?}"
            );
            assert!(
                !found[0].contains("or ") && !found[0].contains("and "),
                "match absorbed neighbouring words: {:?}",
                found[0]
            );
        }
    }

    #[test]
    fn credit_card_requires_luhn() {
        assert!(!matches(BuiltinPattern::CreditCard, "4111 1111 1111 1111").is_empty());
        assert!(!matches(BuiltinPattern::CreditCard, "3782 822463 10005").is_empty(), "Amex 4-6-5");
        // A plain 13-digit reference number must NOT be reported as a card.
        assert!(
            matches(BuiltinPattern::CreditCard, "order 1234567890123 shipped").is_empty(),
            "Luhn must suppress non-card digit runs"
        );
    }

    #[test]
    fn ssn_rejects_never_issued_ranges() {
        assert!(!matches(BuiltinPattern::Ssn, "123-45-6789").is_empty());
        for invalid in ["000-45-6789", "666-45-6789", "900-45-6789", "123-00-6789", "123-45-0000"] {
            assert!(matches(BuiltinPattern::Ssn, invalid).is_empty(), "accepted {invalid}");
        }
    }

    #[test]
    fn phone_no_longer_swallows_dates_ibans_or_amounts() {
        // The audit found the old phone pattern matched all of these.
        for innocent in ["2024-03-14", "89370400440532013000", "1 234 567"] {
            assert!(
                matches(BuiltinPattern::Phone, innocent).is_empty(),
                "phone must not match {innocent:?}"
            );
        }
        for real in ["+1-555-0123", "+91 98765 43210", "+49 89 5551234", "089 5551234"] {
            assert!(!matches(BuiltinPattern::Phone, real).is_empty(), "missed {real}");
        }
    }

    #[test]
    fn email_matches_whole_address_including_unicode() {
        let found = matches(BuiltinPattern::Email, "contact müller@example.de now");
        assert_eq!(
            found,
            vec!["müller@example.de"],
            "the whole address must match, not a suffix"
        );
    }

    #[test]
    fn ip_addresses_cover_v4_and_v6_but_not_version_numbers() {
        // Each address must match in FULL: a truncated match leaves a fragment
        // of the address in output that was reported as redacted.
        for (text, expected) in [
            ("server 192.168.1.1 here", "192.168.1.1"),
            ("server 2001:db8::1 here", "2001:db8::1"),
            ("loopback ::1 here", "::1"),
            ("compressed 2001:db8:: end", "2001:db8::"),
            (
                "full 2001:0db8:0000:0000:0000:ff00:0042:8329 addr",
                "2001:0db8:0000:0000:0000:ff00:0042:8329",
            ),
        ] {
            let found = matches(BuiltinPattern::IpAddress, text);
            assert_eq!(found, vec![expected.to_string()], "in {text:?}");
        }
        assert!(
            matches(BuiltinPattern::IpAddress, "999.999.999.999").is_empty(),
            "octet ranges must be enforced"
        );
        assert!(
            matches(BuiltinPattern::IpAddress, "meeting at 12:30 only").is_empty(),
            "a clock time is not an address"
        );
    }

    #[test]
    fn api_keys_cover_known_vendor_shapes() {
        for key in [
            "sk-live_abcdefgh12345678",
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_abcdefghijklmnopqrstuvwxyz012345",
            "xoxb-123456789012-abcdefghijkl",
            "glpat-abcdefghijklmnopqrst",
        ] {
            assert!(!matches(BuiltinPattern::ApiKey, key).is_empty(), "missed {key}");
        }
        assert!(
            matches(BuiltinPattern::ApiKey, "a plain sentence of words").is_empty(),
            "must not flag ordinary prose"
        );
    }

    #[test]
    fn dates_of_birth_cover_numeric_and_month_name_forms() {
        for date in [
            "15/03/1990",
            "15.03.1990",
            "1990-03-15",
            "March 15, 1990",
            "15 March 1990",
            "Mar 15 1990",
        ] {
            assert!(
                !matches(BuiltinPattern::DateOfBirth, date).is_empty(),
                "missed {date}"
            );
        }
    }

    #[test]
    fn heuristics_match_their_targets_and_are_labelled_as_heuristics() {
        assert!(!matches(BuiltinPattern::PersonName, "Dr. Priya Sharma").is_empty());
        assert!(!matches(BuiltinPattern::PersonName, "John Smith").is_empty());
        assert!(!matches(BuiltinPattern::Address, "123 MG Road, Pune 411001").is_empty());
        assert!(!matches(BuiltinPattern::Organization, "Apollo Hospital").is_empty());
        assert!(!matches(BuiltinPattern::Organization, "HDFC Bank").is_empty());
        assert!(!matches(BuiltinPattern::MedicalTerm, "history of diabetes").is_empty());
        assert!(!matches(BuiltinPattern::MedicalTerm, "cardiac arrest").is_empty());

        // The point of the precision class: these are not safe to auto-redact.
        for heuristic in [
            BuiltinPattern::PersonName,
            BuiltinPattern::Address,
            BuiltinPattern::Organization,
            BuiltinPattern::MedicalTerm,
        ] {
            assert_eq!(heuristic.precision(), Precision::Heuristic);
        }
        // And the honest downside is real: a bare capitalised bigram is a name
        // to this detector, whether or not it is one.
        assert!(
            !matches(BuiltinPattern::PersonName, "Follow Up").is_empty(),
            "documenting the known false-positive behaviour"
        );
    }

    #[test]
    fn precise_detectors_are_the_checksum_verified_ones() {
        assert_eq!(BuiltinPattern::Iban.validator(), Validator::IbanMod97);
        assert_eq!(BuiltinPattern::CreditCard.validator(), Validator::Luhn);
        assert_eq!(BuiltinPattern::Ssn.validator(), Validator::SsnUs);
        assert_eq!(BuiltinPattern::Email.validator(), Validator::None);
    }
}
