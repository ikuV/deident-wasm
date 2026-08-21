//! Format-preserving mock values.
//!
//! A mock replaces a matched value with a *different* value of the same shape
//! that passes the usual structural checks — an IBAN with correct mod-97 check
//! digits, a card number with a valid Luhn digit, a phone number keeping its
//! punctuation. Useful when downstream systems validate their input and would
//! reject `[IBAN]` or a hex token.
//!
//! Mocks are derived from the same keyed hash as tokens, so they are
//! deterministic and stable: the same input value always yields the same mock
//! within a dataset, and joins on the mocked column keep working.
//!
//! **Mocks are not anonymization by themselves.** A mock is a pseudonym with a
//! prettier shape: anyone holding the key material can recompute the mapping,
//! and the engine records it in the mapping vault exactly like a token.

use crate::detect::BuiltinPattern;

/// Shape a mock value should imitate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockShape {
    Iban,
    Email,
    Phone,
    CreditCard,
    MacAddress,
}

impl MockShape {
    /// The shape implied by a built-in pattern, when one exists.
    ///
    /// Most detectors have no format-preserving mock: there is no meaningful
    /// "fake but valid" version of a medical term or a person's address, so
    /// those rules must use `redact` or `token` instead.
    pub fn for_builtin(builtin: BuiltinPattern) -> Option<Self> {
        Some(match builtin {
            BuiltinPattern::Iban => MockShape::Iban,
            BuiltinPattern::Email => MockShape::Email,
            BuiltinPattern::Phone => MockShape::Phone,
            BuiltinPattern::CreditCard => MockShape::CreditCard,
            BuiltinPattern::MacAddress => MockShape::MacAddress,
            _ => return None,
        })
    }
}

/// Deterministic pseudo-random bytes for `value` in `domain`.
fn material(key: &[u8; 32], domain: &str, value: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"mock");
    hasher.update(&[0x1f]);
    hasher.update(domain.as_bytes());
    hasher.update(&[0x1f]);
    hasher.update(value.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Digits derived from `material`, one per output digit.
fn digits(material: &[u8], count: usize) -> Vec<u8> {
    (0..count)
        .map(|i| material[i % material.len()].wrapping_add((i / material.len()) as u8) % 10)
        .collect()
}

/// Build a mock value of `shape` for `original`.
pub fn generate(shape: MockShape, key: &[u8; 32], domain: &str, original: &str) -> String {
    let material = material(key, domain, original);
    match shape {
        MockShape::Iban => iban(&material, original),
        MockShape::Email => email(&material, original),
        MockShape::Phone => phone(&material, original),
        MockShape::CreditCard => credit_card(&material, original),
        MockShape::MacAddress => mac_address(&material, original),
    }
}

/// MAC address keeping the original's separator style and letter case.
///
/// The first octet always has the locally-administered bit set and the
/// multicast bit cleared (`x2`, `x6`, `xa`, `xe`), which is the IEEE-reserved
/// space for addresses nobody assigns. A mock therefore can never collide with
/// a real vendor OUI — the same reasoning as using `example.com` for email
/// mocks — while still parsing as a unicast address for anything that validates
/// its input.
fn mac_address(material: &[u8], original: &str) -> String {
    let mut octets = [0u8; 6];
    for (i, octet) in octets.iter_mut().enumerate() {
        *octet = material[i % material.len()].wrapping_add((i / material.len()) as u8);
    }
    octets[0] = (octets[0] & 0xfe) | 0x02;

    let uppercase = original
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .all(|c| c.is_ascii_uppercase());
    let hex = |byte: u8| {
        if uppercase {
            format!("{byte:02X}")
        } else {
            format!("{byte:02x}")
        }
    };

    // Cisco dotted form is three groups of two octets; otherwise keep the
    // original's separator, defaulting to the colon convention.
    if original.contains('.') {
        return format!(
            "{}{}.{}{}.{}{}",
            hex(octets[0]),
            hex(octets[1]),
            hex(octets[2]),
            hex(octets[3]),
            hex(octets[4]),
            hex(octets[5]),
        );
    }
    let separator = if original.contains('-') { "-" } else { ":" };
    octets
        .iter()
        .map(|b| hex(*b))
        .collect::<Vec<_>>()
        .join(separator)
}

/// IBAN with the original's country code and length, and recomputed mod-97
/// check digits (so structural validators accept it).
fn iban(material: &[u8], original: &str) -> String {
    let compact: String = original.chars().filter(|c| !c.is_whitespace()).collect();
    let country: String = compact.chars().take(2).collect();
    let country = if country.len() == 2 && country.chars().all(|c| c.is_ascii_uppercase()) {
        country
    } else {
        "DE".to_string()
    };
    let bban_len = compact.len().max(15).saturating_sub(4);
    let bban: String = digits(material, bban_len)
        .into_iter()
        .map(|d| char::from(b'0' + d))
        .collect();
    let check = iban_check_digits(&country, &bban);
    format!("{country}{check:02}{bban}")
}

/// mod-97-10 check digits (ISO 7064) for `country` + `bban`.
fn iban_check_digits(country: &str, bban: &str) -> u32 {
    // Rearrange: BBAN + country + "00", then letters -> numbers (A=10..Z=35).
    let mut remainder: u32 = 0;
    let rearranged = format!("{bban}{country}00");
    for ch in rearranged.chars() {
        let value = if ch.is_ascii_digit() {
            ch as u32 - '0' as u32
        } else {
            ch.to_ascii_uppercase() as u32 - 'A' as u32 + 10
        };
        // Feed one or two decimal digits at a time to stay inside u32.
        remainder = if value >= 10 {
            (remainder * 100 + value) % 97
        } else {
            (remainder * 10 + value) % 97
        };
    }
    98 - remainder
}

/// Email in a documentation domain (RFC 2606 `example.com`), keeping nothing
/// of the original local part.
fn email(material: &[u8], _original: &str) -> String {
    let local: String = material
        .iter()
        .take(10)
        .map(|b| char::from(b'a' + (b % 26)))
        .collect();
    format!("{local}@example.com")
}

/// Phone number preserving the original's punctuation and digit count.
fn phone(material: &[u8], original: &str) -> String {
    let digit_count = original.chars().filter(char::is_ascii_digit).count();
    let mut replacement = digits(material, digit_count.max(1)).into_iter();
    let mut first = true;
    original
        .chars()
        .map(|c| {
            if c.is_ascii_digit() {
                // Keep a leading non-zero so the result still reads as a number.
                let d = replacement.next().unwrap_or(0);
                let d = if first {
                    first = false;
                    d.max(1)
                } else {
                    d
                };
                char::from(b'0' + d)
            } else {
                c
            }
        })
        .collect()
}

/// Card number with the original's length and separators, ending in a valid
/// Luhn check digit. The IIN range is forced into the 999x test space so the
/// result cannot collide with a real issuer.
fn credit_card(material: &[u8], original: &str) -> String {
    let digit_count = original.chars().filter(char::is_ascii_digit).count();
    if digit_count < 2 {
        return original.to_string();
    }
    let mut body: Vec<u8> = digits(material, digit_count - 1);
    // Force the leading digits into the 999x range so a generated number can
    // never fall inside a real issuer's IIN space.
    let lead = body.len().min(3);
    body[..lead].fill(9);
    let check = luhn_check_digit(&body);
    body.push(check);

    let mut digits_iter = body.into_iter();
    original
        .chars()
        .map(|c| {
            if c.is_ascii_digit() {
                char::from(b'0' + digits_iter.next().unwrap_or(0))
            } else {
                c
            }
        })
        .collect()
}

/// Luhn check digit for a payload that will be followed by it.
fn luhn_check_digit(body: &[u8]) -> u8 {
    let sum: u32 = body
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            let d = u32::from(d);
            // The check digit sits at position 0, so payload doubling starts here.
            if i % 2 == 0 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    ((10 - (sum % 10)) % 10) as u8
}

/// Whether `value` satisfies the Luhn checksum (used by tests and callers
/// that want to verify generated cards).
pub fn luhn_valid(value: &str) -> bool {
    let digits: Vec<u32> = value.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 2 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Whether `value` satisfies the IBAN mod-97 checksum.
pub fn iban_valid(value: &str) -> bool {
    let compact: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() < 5 {
        return false;
    }
    let (head, tail) = compact.split_at(4);
    let rearranged = format!("{tail}{head}");
    let mut remainder: u32 = 0;
    for ch in rearranged.chars() {
        let value = if ch.is_ascii_digit() {
            ch as u32 - '0' as u32
        } else if ch.is_ascii_alphabetic() {
            ch.to_ascii_uppercase() as u32 - 'A' as u32 + 10
        } else {
            return false;
        };
        remainder = if value >= 10 {
            (remainder * 100 + value) % 97
        } else {
            (remainder * 10 + value) % 97
        };
    }
    remainder == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        crate::key::derive_dataset_key(b"secret", "ds")
    }

    #[test]
    fn iban_mock_is_valid_and_deterministic() {
        let original = "DE89370400440532013000";
        let a = generate(MockShape::Iban, &key(), "iban", original);
        let b = generate(MockShape::Iban, &key(), "iban", original);
        assert_eq!(a, b, "mocks must be deterministic");
        assert_ne!(a, original, "mock must differ from the original");
        assert_eq!(a.len(), original.len(), "length must be preserved");
        assert!(a.starts_with("DE"), "country code preserved: {a}");
        assert!(iban_valid(&a), "generated IBAN must pass mod-97: {a}");
        // A different original yields a different mock.
        assert_ne!(a, generate(MockShape::Iban, &key(), "iban", "DE02120300000000202051"));
    }

    #[test]
    fn credit_card_mock_passes_luhn_and_keeps_shape() {
        let original = "4111 1111 1111 1111";
        let mock = generate(MockShape::CreditCard, &key(), "card", original);
        assert_eq!(mock.len(), original.len());
        assert_eq!(
            mock.chars().filter(|c| *c == ' ').count(),
            3,
            "separators preserved: {mock}"
        );
        assert!(luhn_valid(&mock), "generated card must pass Luhn: {mock}");
        assert!(mock.starts_with("99"), "test IIN range: {mock}");
        assert_ne!(mock, original);
    }

    #[test]
    fn phone_mock_keeps_punctuation_and_digit_count() {
        let original = "+49 89 5551234";
        let mock = generate(MockShape::Phone, &key(), "phone", original);
        assert!(mock.starts_with('+'));
        assert_eq!(
            mock.chars().filter(char::is_ascii_digit).count(),
            original.chars().filter(char::is_ascii_digit).count()
        );
        assert_eq!(mock.chars().filter(|c| *c == ' ').count(), 2);
        assert_ne!(mock, original);
    }

    #[test]
    fn email_mock_uses_documentation_domain() {
        let mock = generate(MockShape::Email, &key(), "email", "ada@real-company.example");
        assert!(mock.ends_with("@example.com"), "{mock}");
        assert!(!mock.starts_with("ada@"));
    }

    #[test]
    fn mac_mock_keeps_the_written_form_and_is_locally_administered() {
        for original in ["00:1A:2B:3C:4D:5E", "00-1a-2b-3c-4d-5e", "001a.2b3c.4d5e"] {
            let mock = generate(MockShape::MacAddress, &key(), "mac_address", original);
            assert_ne!(mock, original, "a mock must differ from its input");
            assert_eq!(
                mock.chars().map(|c| if c.is_ascii_hexdigit() { 'x' } else { c }).collect::<String>(),
                original.chars().map(|c| if c.is_ascii_hexdigit() { 'x' } else { c }).collect::<String>(),
                "separator layout must survive for {original}"
            );
            assert!(
                crate::detect::Validator::MacAddress.accepts(&mock),
                "mock {mock} must pass the detector's own validator"
            );
            // Locally administered and unicast: the mock can never collide with
            // a real vendor OUI.
            let first = u8::from_str_radix(&mock[0..2], 16).unwrap();
            assert_eq!(first & 0x03, 0x02, "{mock} is not locally-administered unicast");
        }
        // Deterministic, and case follows the input.
        let upper = generate(MockShape::MacAddress, &key(), "mac_address", "00:1A:2B:3C:4D:5E");
        assert_eq!(
            upper,
            generate(MockShape::MacAddress, &key(), "mac_address", "00:1A:2B:3C:4D:5E")
        );
        assert!(upper.chars().filter(|c| c.is_ascii_alphabetic()).all(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn mocks_differ_per_domain() {
        let value = "DE89370400440532013000";
        assert_ne!(
            generate(MockShape::Iban, &key(), "a", value),
            generate(MockShape::Iban, &key(), "b", value)
        );
    }

    #[test]
    fn luhn_reference_values() {
        assert!(luhn_valid("4111111111111111"));
        assert!(!luhn_valid("4111111111111112"));
    }

    #[test]
    fn iban_reference_values() {
        assert!(iban_valid("DE89370400440532013000"));
        assert!(!iban_valid("DE89370400440532013001"));
    }
}
