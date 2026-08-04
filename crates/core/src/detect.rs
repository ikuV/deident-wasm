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

/// Post-match validation, used to suppress false positives.
///
/// A validator must be **conservative**: it may only reject what is definitely
/// not the thing it checks. Over-strict validation produces false *negatives* —
/// a real identifier silently passing through — which is far worse than a false
/// positive a human can dismiss. Every rejection is counted and reported, so an
/// over-strict validator is at least visible.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Validator {
    /// Accept every match.
    #[default]
    None,
    /// Luhn (mod 10) only.
    Luhn,
    /// Luhn plus payment-card length and issuer-prefix plausibility.
    CardBrand,
    /// ISO 7064 mod-97-10 — IBANs.
    IbanMod97,
    /// US Social Security Number allocation rules.
    SsnUs,
    /// Parse as an actual IP address (`std::net::IpAddr`), which is exact where
    /// a regex can only approximate.
    IpAddress,
    /// A real calendar date: rejects `31/02/1990` and `2024-13-45`.
    CalendarDate,
    /// RFC-shaped email syntax: single `@`, length limits, alphabetic TLD.
    EmailSyntax,
    /// URL syntax: known scheme, plausible host, no whitespace.
    UrlSyntax,
    /// E.164 limits: 7–15 digits and no leading zero in the country code.
    PhoneE164,
}

impl Validator {
    /// Whether a matched string passes this validator.
    pub fn accepts(&self, matched: &str) -> bool {
        match self {
            Validator::None => true,
            Validator::Luhn => crate::mock::luhn_valid(matched),
            Validator::CardBrand => card_brand_valid(matched),
            Validator::IbanMod97 => crate::mock::iban_valid(matched),
            Validator::SsnUs => ssn_us_valid(matched),
            Validator::IpAddress => matched.parse::<std::net::IpAddr>().is_ok(),
            Validator::CalendarDate => calendar_date_valid(matched),
            Validator::EmailSyntax => email_syntax_valid(matched),
            Validator::UrlSyntax => url_syntax_valid(matched),
            Validator::PhoneE164 => phone_e164_valid(matched),
        }
    }

    /// Short name used in the "rejected N matches" warning.
    pub fn label(&self) -> &'static str {
        match self {
            Validator::None => "none",
            Validator::Luhn => "Luhn",
            Validator::CardBrand => "Luhn + card length/prefix",
            Validator::IbanMod97 => "IBAN mod-97",
            Validator::SsnUs => "SSN allocation rules",
            Validator::IpAddress => "IP address parse",
            Validator::CalendarDate => "calendar date",
            Validator::EmailSyntax => "email syntax",
            Validator::UrlSyntax => "URL syntax",
            Validator::PhoneE164 => "E.164 limits",
        }
    }
}

/// Luhn, plus the length and issuer prefix a payment card actually has.
///
/// Luhn alone accepts roughly one in ten arbitrary digit strings, so a long
/// order or case number frequently passes it. Requiring a real card length
/// (13–19) and a major-industry leading digit of 2–6 removes most of that.
///
/// The trade-off is explicit: a card from an issuer outside that range would be
/// missed. Every major scheme falls inside it (Visa 4, Mastercard 2/5, Amex 3,
/// Discover/UnionPay 6, JCB/Diners 3), and the rejection is reported either way.
fn card_brand_valid(matched: &str) -> bool {
    let digits: Vec<u8> = matched.bytes().filter(u8::is_ascii_digit).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    if !(b'2'..=b'6').contains(&digits[0]) {
        return false;
    }
    // A run of one repeated digit is a placeholder, not a card, even when it
    // happens to satisfy Luhn.
    if digits.iter().all(|d| *d == digits[0]) {
        return false;
    }
    crate::mock::luhn_valid(matched)
}

/// Days in a month, honouring the Gregorian leap rule.
fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        _ => 0,
    }
}

/// Whether a matched date string denotes a real calendar date.
///
/// Ambiguous numeric forms are accepted if **either** day/month reading is valid,
/// because `03/04/1990` is a real date under both conventions and guessing wrong
/// would reject a genuine identifier. Deliberately says nothing about whether the
/// date is a plausible *birth* date: this detector matches dates generally, and
/// rejecting a future date would drop appointment dates a user wants removed.
fn calendar_date_valid(matched: &str) -> bool {
    const MONTHS: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let lower = matched.to_ascii_lowercase();

    // Month-name form: find the month, then the two numbers around it.
    if let Some(month) = MONTHS.iter().position(|m| lower.contains(m)) {
        let numbers: Vec<i64> = lower
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse().ok())
            .collect();
        let (day, year) = match numbers.as_slice() {
            [a, b] if *a > 31 => (*b, *a),
            [a, b] => (*a, *b),
            _ => return false,
        };
        return (1..=days_in_month(year, month as u32 + 1) as i64).contains(&day);
    }

    let numbers: Vec<i64> = matched
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();
    let [a, b, c] = numbers.as_slice() else {
        return false;
    };
    let valid = |year: i64, month: i64, day: i64| {
        (1..=12).contains(&month)
            && (1..=days_in_month(year, month as u32) as i64).contains(&day)
    };
    if *a > 31 {
        // Year first: YYYY-MM-DD.
        valid(*a, *b, *c)
    } else {
        // Ambiguous: accept either reading.
        valid(*c, *b, *a) || valid(*c, *a, *b)
    }
}

/// Structural email validation: one `@`, RFC 5321 length limits, a dotted domain
/// and an alphabetic top-level label.
fn email_syntax_valid(matched: &str) -> bool {
    if matched.len() > 254 {
        return false;
    }
    let Some((local, domain)) = matched.split_once('@') else {
        return false;
    };
    if domain.contains('@') || local.is_empty() || local.len() > 64 {
        return false;
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return false;
    }
    if domain.is_empty() || domain.len() > 255 || domain.contains("..") {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
        return false;
    }
    let tld = labels.last().expect("checked non-empty");
    tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic())
}

/// Structural URL validation: a known scheme (or a `www.` host), a plausible
/// host, and no whitespace.
fn url_syntax_valid(matched: &str) -> bool {
    if matched.chars().any(char::is_whitespace) {
        return false;
    }
    let rest = ["http://", "https://", "ftp://", "ftps://"]
        .iter()
        .find_map(|scheme| matched.strip_prefix(*scheme))
        .or_else(|| matched.strip_prefix("www.").map(|_| matched))
        ;
    let Some(rest) = rest else {
        return false;
    };
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .trim_start_matches("www.");
    let host = host.split('@').next_back().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        return false;
    }
    host == "localhost"
        || host.parse::<std::net::IpAddr>().is_ok()
        || (host.contains('.')
            && !host.starts_with('.')
            && !host.ends_with('.')
            && !host.contains("..")
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
}

/// E.164 limits: at most 15 digits, at least 7, and no country code beginning
/// with zero. Conservative on purpose — national dialling conventions vary far
/// too much to validate a number's *body*.
fn phone_e164_valid(matched: &str) -> bool {
    let digits: Vec<u8> = matched.bytes().filter(u8::is_ascii_digit).collect();
    if !(7..=15).contains(&digits.len()) {
        return false;
    }
    // No country calling code starts with 0, so `+0…` is never a real number.
    if matched.trim_start().starts_with('+') && digits.first() == Some(&b'0') {
        return false;
    }
    true
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

/// Every built-in, in **execution order**.
///
/// Order is load-bearing, not cosmetic. Rules run in sequence over the same
/// value and each sees the previous rule's output, so a greedy detector placed
/// early consumes text a more specific one would have matched — and the report
/// then attributes the match to the wrong detector, or reports zero of the
/// specific kind for a file full of them.
///
/// The rule is therefore **most specific first, greediest last** within each
/// precision class:
/// - `ssn` and `date_of_birth` precede `phone`, which otherwise swallowed
///   `012-34-5678` and `05.12.1990` and left `13.` fragments behind.
/// - `organization` and `medical_term` precede `person_name`, whose
///   capitalised-bigram alternative otherwise claimed `Apollo Hospital` and
///   `Cardiac Arrest`.
pub const ALL: &[BuiltinPattern] = &[
    // Precise: distinctive syntax, mostly checksum-verified.
    BuiltinPattern::Email,
    BuiltinPattern::Iban,
    BuiltinPattern::CreditCard,
    BuiltinPattern::IpAddress,
    BuiltinPattern::Url,
    BuiltinPattern::ApiKey,
    BuiltinPattern::Ifsc,
    // Moderate: specific digit shapes first, general phone shape last.
    BuiltinPattern::Ssn,
    BuiltinPattern::DateOfBirth,
    BuiltinPattern::LicensePlate,
    BuiltinPattern::Passport,
    BuiltinPattern::Phone,
    // Heuristic: keyword-anchored first, bare-bigram name last.
    BuiltinPattern::Address,
    BuiltinPattern::Organization,
    BuiltinPattern::MedicalTerm,
    BuiltinPattern::PersonName,
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
            BuiltinPattern::CreditCard => Validator::CardBrand,
            BuiltinPattern::Iban => Validator::IbanMod97,
            BuiltinPattern::Ssn => Validator::SsnUs,
            BuiltinPattern::IpAddress => Validator::IpAddress,
            BuiltinPattern::DateOfBirth => Validator::CalendarDate,
            BuiltinPattern::Email => Validator::EmailSyntax,
            BuiltinPattern::Url => Validator::UrlSyntax,
            BuiltinPattern::Phone => Validator::PhoneE164,
            // No checksum or structural rule exists for these: a passport number
            // and a licence plate carry no check digit, an API key is opaque, and
            // the heuristics are heuristics. Claiming verification here would be
            // dishonest.
            BuiltinPattern::ApiKey
            | BuiltinPattern::Ifsc
            | BuiltinPattern::Passport
            | BuiltinPattern::LicensePlate
            | BuiltinPattern::PersonName
            | BuiltinPattern::Address
            | BuiltinPattern::Organization
            | BuiltinPattern::MedicalTerm => Validator::None,
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
                // `/ ? # & =` are excluded on purpose: they are not valid in an
                // unquoted local part, and including them let the pattern eat
                // `//alice@host` out of a URL, leaving `https:[EMAIL]` behind and
                // preventing the `url` detector from ever matching.
                r"[\w.!$%&'*+^`{|}~-]+@[\w-]+(?:\.[\w-]+)+"
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
                concat!(
                    // IPv4-in-IPv6 FIRST: `::ffff:203.0.113.42` and
                    // `64:ff9b::192.0.2.33` are what nginx, Java and Docker
                    // actually log. Without this alternative the `::` form
                    // matched `::ffff:203` and left `.0.113.42` in output that
                    // the report called redacted.
                    r"(?:[0-9A-Fa-f]{1,4}:){1,6}(?:[0-9A-Fa-f]{1,4})?:",
                    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}",
                    r"|::(?:[Ff]{4}:)?",
                    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}",
                    // Plain IPv4.
                    r"|\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
                    // Pure IPv6: full, compressed-with-tail, compressed-trailing,
                    // leading `::`. Longest first — see the note above.
                    r"|(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}",
                    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}(?::[0-9A-Fa-f]{1,4}){1,7}",
                    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:",
                    r"|::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?",
                )
            }
            BuiltinPattern::Url => {
                r"\b(?:https?|ftps?)://[^\s<>\x22'`\]]+|\bwww\.[\w-]+(?:\.[\w-]+)+[^\s<>\x22'`\]]*"
            }
            // Known vendor token shapes. Deliberately specific: a generic
            // "long random string" pattern would flag every hash and token.
            BuiltinPattern::ApiKey => {
                concat!(
                    r"\b(?:sk|pk|rk)[-_](?:live|test|prod)[-_][A-Za-z0-9]{8,}",
                    r"|\bAKIA[0-9A-Z]{16}\b|\bASIA[0-9A-Z]{16}\b",
                    r"|\bgithub_pat_[A-Za-z0-9_]{20,}",
                    r"|\bgh[pousr]_[A-Za-z0-9]{20,}",
                    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}",
                    r"|\bAIza[0-9A-Za-z_-]{35}\b",
                    r"|\bglpat-[A-Za-z0-9_-]{20,}",
                    // Modern OpenAI/Anthropic keys interleave `-`/`_` segments
                    // (`sk-proj-`, `sk-ant-api03-`), so the tail must allow them.
                    r"|\bsk-[A-Za-z0-9][A-Za-z0-9_-]{19,}",
                )
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
                concat!(
                    // Number BEFORE the street word (UK/US/India). The postcode
                    // and city tail is optional and tolerates a city name, so
                    // `123 MG Road, Pune 411001` matches in full.
                    r"(?i)\b\d{1,5}[/-]?[a-z]?\s+(?:[\p{L}][\p{L}.'-]*\s+){0,4}",
                    r"(?:road|rd|street|st|marg|nagar|lane|ln|avenue|ave|boulevard|blvd|drive|colony|sector|block)\b",
                    r"(?:[\s,]+[\p{L}][\p{L}.'-]{2,}){0,2}(?:[\s,]+\d{4,6}\b)?",
                    // Number AFTER the street word — every German, Austrian,
                    // Swiss, Dutch and Scandinavian address. Without this the
                    // whole German half of the vocabulary was unreachable.
                    r"|(?i)\b[\p{L}][\p{L}.'-]*(?:strasse|straße|str\.?|weg|platz|gasse|allee|damm|ufer|ring)\s+\d{1,4}[a-z]?",
                    r"(?:[\s,]+\d{4,5}\b(?:[\s,]+[\p{L}][\p{L}.'-]{2,})?)?",
                )
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
    fn detectors_are_wired_to_the_right_validator() {
        assert_eq!(BuiltinPattern::Iban.validator(), Validator::IbanMod97);
        assert_eq!(BuiltinPattern::CreditCard.validator(), Validator::CardBrand);
        assert_eq!(BuiltinPattern::Ssn.validator(), Validator::SsnUs);
        assert_eq!(BuiltinPattern::Email.validator(), Validator::EmailSyntax);
        assert_eq!(BuiltinPattern::IpAddress.validator(), Validator::IpAddress);
        assert_eq!(BuiltinPattern::DateOfBirth.validator(), Validator::CalendarDate);
        // Opaque or checksum-free values must NOT claim verification.
        for unverifiable in [
            BuiltinPattern::ApiKey,
            BuiltinPattern::Passport,
            BuiltinPattern::LicensePlate,
            BuiltinPattern::PersonName,
        ] {
            assert_eq!(unverifiable.validator(), Validator::None);
        }
    }
}

#[cfg(test)]
mod validator_tests {
    use super::*;

    /// Each validator must accept real values and reject specific fakes. Both
    /// directions matter: an over-strict validator produces false negatives,
    /// which is the worse failure.
    #[test]
    fn ip_validation_is_exact_where_a_regex_can_only_approximate() {
        let v = Validator::IpAddress;
        for good in ["192.168.1.1", "2001:db8::1", "::1", "8.8.8.8"] {
            assert!(v.accepts(good), "rejected real address {good}");
        }
        for bad in ["1:2:3:4:5:6:7:8:9", "2001:db8:::1", "12:30", "256.1.1.1"] {
            assert!(!v.accepts(bad), "accepted non-address {bad}");
        }
    }

    #[test]
    fn calendar_dates_reject_impossible_days_and_months() {
        let v = Validator::CalendarDate;
        for good in [
            "15/03/1990",
            "03/15/1990",   // the other convention
            "1990-03-15",
            "29/02/2000",   // leap year
            "March 15, 1990",
            "15 March 1990",
        ] {
            assert!(v.accepts(good), "rejected real date {good}");
        }
        for bad in [
            "31/02/1990",   // February has no 31st
            "2024-13-45",
            "45/45/1990",
            "31 February 1990",
            "29/02/1900",   // 1900 is not a leap year
        ] {
            assert!(!v.accepts(bad), "accepted impossible date {bad}");
        }
    }

    #[test]
    fn card_validation_goes_beyond_luhn() {
        let v = Validator::CardBrand;
        for good in ["4111 1111 1111 1111", "3782 822463 10005", "5555555555554444"] {
            assert!(v.accepts(good), "rejected real card {good}");
        }
        // These DO satisfy Luhn but are not payment cards: the leading digit is
        // outside the major-industry range 2-6. Plain Luhn accepts them, which is
        // exactly the false-positive source the upgrade removes.
        for luhn_but_not_a_card in ["1234567890128", "9123456789012348"] {
            assert!(
                Validator::Luhn.accepts(luhn_but_not_a_card),
                "test premise: {luhn_but_not_a_card} must satisfy Luhn"
            );
            assert!(
                !v.accepts(luhn_but_not_a_card),
                "{luhn_but_not_a_card} passes Luhn but is not card-shaped"
            );
        }
        assert!(!v.accepts("18"), "too short");
        assert!(
            !v.accepts("0000000000000000"),
            "a run of one digit is a placeholder"
        );
    }

    #[test]
    fn email_syntax_enforces_rfc_limits() {
        let v = Validator::EmailSyntax;
        for good in ["user@example.com", "a.b+c@sub.example.co.uk", "müller@example.de"] {
            assert!(v.accepts(good), "rejected real address {good}");
        }
        for bad in [
            "user@@example.com",
            "user@example",          // no dot in the domain
            "user@example.c",        // one-character TLD
            "user@example.12",       // numeric TLD
            ".user@example.com",
            "us..er@example.com",
            "user@exa..mple.com",
        ] {
            assert!(!v.accepts(bad), "accepted malformed address {bad}");
        }
    }

    #[test]
    fn url_syntax_requires_a_scheme_and_plausible_host() {
        let v = Validator::UrlSyntax;
        for good in [
            "https://internal.company.com",
            "http://localhost:8080/x",
            "https://192.168.1.1/admin",
            "www.example.com/path",
        ] {
            assert!(v.accepts(good), "rejected real URL {good}");
        }
        for bad in ["https://", "http://.example.com", "https://exa mple.com"] {
            assert!(!v.accepts(bad), "accepted malformed URL {bad}");
        }
    }

    #[test]
    fn phone_validation_applies_e164_limits() {
        let v = Validator::PhoneE164;
        for good in ["+1-555-0123", "+91 98765 43210", "+49 89 5551234", "089 5551234"] {
            assert!(v.accepts(good), "rejected real number {good}");
        }
        // 16+ digits exceeds E.164; a country code never starts with zero.
        assert!(!v.accepts("+1234567890123456"), "too many digits");
        assert!(!v.accepts("+0123456789"), "country code cannot start with 0");
        assert!(!v.accepts("12345"), "too few digits");
    }

    /// The catalog must stay honest: a detector claims verification only when a
    /// validator actually runs for it.
    #[test]
    fn verified_detectors_are_exactly_those_with_a_validator() {
        let verified: Vec<&str> = ALL
            .iter()
            .filter(|b| b.validator() != Validator::None)
            .map(|b| b.name())
            .collect();
        assert_eq!(
            verified,
            vec![
                "email",
                "iban",
                "credit_card",
                "ip_address",
                "url",
                "ssn",
                "date_of_birth",
                "phone",
            ],
            "eight of sixteen detectors are validated; the rest have no checksum \
             or structural rule and must not claim one"
        );
    }
}
