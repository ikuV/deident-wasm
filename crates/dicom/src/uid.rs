//! Deterministic UID generation.
//!
//! Replacement UIDs use the `2.25.<decimal>` arc, which DICOM PS3.5 §B.2 and
//! ISO/IEC 9834-8 reserve for UUID-derived OIDs: any 128-bit value rendered as
//! an unsigned decimal integer under `2.25.` is a valid, collision-resistant
//! UID that needs no registered organisational root. That matters here because
//! deident has no org root to hand out.
//!
//! The 128-bit value is a keyed hash of the original UID, so remapping is
//! **deterministic and consistent**: the same StudyInstanceUID becomes the same
//! replacement in every instance of that study, in this run and the next, which
//! is what keeps a de-identified study internally navigable.

/// Maximum length of a DICOM UI value (PS3.5 Table 6.2-1).
pub const MAX_UID_LEN: usize = 64;

/// Prefix for UUID-derived UIDs.
const UUID_ARC: &str = "2.25.";

/// Deterministically derive a replacement UID for `original`.
///
/// `domain` separates independent UID spaces so, for example, a study UID and a
/// series UID with the same original text still map to different values.
pub fn derive_uid(key: &[u8; 32], domain: &str, original: &str) -> String {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"dicom-uid");
    hasher.update(&[0x1f]);
    hasher.update(domain.as_bytes());
    hasher.update(&[0x1f]);
    hasher.update(original.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    let value = u128::from_be_bytes(bytes);
    let uid = format!("{UUID_ARC}{value}");
    debug_assert!(uid.len() <= MAX_UID_LEN, "derived UID too long: {uid}");
    uid
}

/// Whether a string is a structurally valid DICOM UID: non-empty, at most 64
/// characters, dot-separated numeric components with no leading zeros (except a
/// component that is exactly `0`), and no trailing dot.
pub fn is_valid_uid(uid: &str) -> bool {
    if uid.is_empty() || uid.len() > MAX_UID_LEN {
        return false;
    }
    let mut components = 0;
    for component in uid.split('.') {
        components += 1;
        if component.is_empty() || !component.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        if component.len() > 1 && component.starts_with('0') {
            return false;
        }
    }
    components >= 2
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        deident_core::key::derive_dataset_key(b"secret", "study")
    }

    #[test]
    fn derived_uids_are_valid_and_deterministic() {
        let original = "1.2.840.113619.2.55.3.604688119.868.1234567890.123";
        let a = derive_uid(&key(), "study", original);
        let b = derive_uid(&key(), "study", original);
        assert_eq!(a, b, "must be deterministic");
        assert_ne!(a, original);
        assert!(a.starts_with("2.25."), "{a}");
        assert!(is_valid_uid(&a), "generated UID must be valid: {a}");
        assert!(a.len() <= MAX_UID_LEN, "len {} for {a}", a.len());
    }

    #[test]
    fn different_originals_and_domains_diverge() {
        let k = key();
        assert_ne!(
            derive_uid(&k, "study", "1.2.3"),
            derive_uid(&k, "study", "1.2.4")
        );
        assert_ne!(
            derive_uid(&k, "study", "1.2.3"),
            derive_uid(&k, "series", "1.2.3")
        );
    }

    #[test]
    fn every_derived_uid_stays_within_the_length_limit() {
        // 2.25. + up to 39 decimal digits = 44 characters worst case; check a
        // spread of inputs actually respects it.
        let k = key();
        for i in 0..500 {
            let uid = derive_uid(&k, "study", &format!("1.2.840.{i}"));
            assert!(is_valid_uid(&uid), "invalid: {uid}");
            assert!(uid.len() <= MAX_UID_LEN);
        }
    }

    #[test]
    fn validates_uid_syntax() {
        assert!(is_valid_uid("1.2.840.10008.1.2.1"));
        assert!(is_valid_uid("2.25.0"));
        assert!(!is_valid_uid(""), "empty");
        assert!(!is_valid_uid("1"), "single component");
        assert!(!is_valid_uid("1.2."), "trailing dot");
        assert!(!is_valid_uid("1..2"), "empty component");
        assert!(!is_valid_uid("1.02"), "leading zero");
        assert!(!is_valid_uid("1.2.a"), "non-numeric");
        assert!(!is_valid_uid(&"1.".repeat(40)), "too long");
    }
}
