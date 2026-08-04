//! Built-in confidentiality profile.
//!
//! This is a **curated core** of the DICOM PS3.15 Annex E "Basic Application
//! Level Confidentiality Profile", not the complete ~500-row table, and it is
//! documented as such everywhere it is surfaced. The design bet is that a small
//! exact table plus the structural rules in [`crate::policy`] (every `PN` VR,
//! every identity UID, every private tag, curve/overlay groups) covers more real
//! PHI than a large table transcribed imperfectly — and fails safe when it is
//! wrong, because the structural layer removes rather than keeps.
//!
//! Callers extend coverage through their policy's `tags:` list, which takes
//! precedence over everything here.

use dicom_core::Tag;
use dicom_dictionary_std::tags;

use crate::policy::{DateGranularity, MockShapeCfg, TagAction};

/// Tags whose values identify an entity in the DICOM information model and must
/// be remapped consistently (Annex E action `U`).
///
/// Note that `SOPClassUID`, `TransferSyntaxUID` and `ImplementationClassUID` are
/// deliberately absent: they name *formats and software*, not subjects, and
/// remapping them would make the file unreadable.
const IDENTITY_UIDS: &[Tag] = &[
    tags::STUDY_INSTANCE_UID,
    tags::SERIES_INSTANCE_UID,
    tags::SOP_INSTANCE_UID,
    tags::FRAME_OF_REFERENCE_UID,
    tags::SYNCHRONIZATION_FRAME_OF_REFERENCE_UID,
    tags::CONCATENATION_UID,
    tags::DIMENSION_ORGANIZATION_UID,
    tags::PALETTE_COLOR_LOOKUP_TABLE_UID,
    tags::REFERENCED_SOP_INSTANCE_UID,
    tags::REFERENCED_FRAME_OF_REFERENCE_UID,
    tags::IRRADIATION_EVENT_UID,
    tags::STORAGE_MEDIA_FILE_SET_UID,
    tags::FIDUCIAL_UID,
    tags::INSTANCE_CREATOR_UID,
    tags::DEVICE_UID,
];

/// Whether a tag holds a subject/study identity UID that should be remapped.
pub fn is_identity_uid(tag: Tag) -> bool {
    IDENTITY_UIDS.contains(&tag)
}

/// The curated Basic Profile table: attribute → action.
///
/// Grouped by why each entry is here, so the rationale survives review.
///
/// Retired DICOM attributes are included deliberately — `dicom-dictionary-std`
/// marks them deprecated, but archived studies still carry them, and an archive
/// is exactly where decades-old PHI lives. Removing an attribute that no longer
/// gets written costs nothing; missing one that is still present costs a leak.
#[allow(deprecated)]
pub fn basic_profile() -> Vec<(Tag, TagAction)> {
    let empty = || TagAction::Empty;
    let remove = || TagAction::Remove;
    let clean = || TagAction::CleanText;
    let pseudonym = |domain: &str, prefix: &str| TagAction::Pseudonymize {
        prefix: Some(prefix.to_string()),
        domain: Some(domain.to_string()),
        mock: None,
    };

    let mut rules: Vec<(Tag, TagAction)> = vec![
        // --- Patient identity -------------------------------------------
        (
            tags::PATIENT_NAME,
            TagAction::Pseudonymize {
                prefix: None,
                domain: Some("patient".to_string()),
                mock: Some(MockShapeCfg::PersonName),
            },
        ),
        (tags::PATIENT_ID, pseudonym("patient", "PID-")),
        (tags::OTHER_PATIENT_I_DS_SEQUENCE, remove()),
        (tags::OTHER_PATIENT_NAMES, empty()),
        (tags::PATIENT_BIRTH_NAME, empty()),
        (tags::PATIENT_MOTHER_BIRTH_NAME, empty()),
        (tags::PATIENT_BIRTH_DATE, TagAction::DateTruncate {
            granularity: DateGranularity::Year,
        }),
        (tags::PATIENT_BIRTH_TIME, remove()),
        (tags::PATIENT_ADDRESS, remove()),
        (tags::PATIENT_TELEPHONE_NUMBERS, remove()),
        (tags::PATIENT_TELECOM_INFORMATION, remove()),
        (tags::PATIENT_INSURANCE_PLAN_CODE_SEQUENCE, remove()),
        (tags::MILITARY_RANK, remove()),
        (tags::BRANCH_OF_SERVICE, remove()),
        (tags::MEDICAL_RECORD_LOCATOR, remove()),
        (tags::PATIENT_RELIGIOUS_PREFERENCE, remove()),
        (tags::COUNTRY_OF_RESIDENCE, remove()),
        (tags::REGION_OF_RESIDENCE, remove()),
        (tags::PATIENT_COMMENTS, remove()),
        (tags::ETHNIC_GROUP, remove()),
        (tags::OCCUPATION, remove()),
        (tags::RESPONSIBLE_PERSON, empty()),
        (tags::RESPONSIBLE_ORGANIZATION, empty()),
        // Retained because they are clinically load-bearing and not directly
        // identifying on their own — but they ARE quasi-identifiers, which the
        // report states explicitly.
        (tags::PATIENT_SEX, TagAction::Keep),
        (tags::PATIENT_AGE, TagAction::Keep),
        // --- Other people ------------------------------------------------
        (tags::REFERRING_PHYSICIAN_NAME, empty()),
        (tags::REFERRING_PHYSICIAN_ADDRESS, remove()),
        (tags::REFERRING_PHYSICIAN_TELEPHONE_NUMBERS, remove()),
        (tags::REFERRING_PHYSICIAN_IDENTIFICATION_SEQUENCE, remove()),
        (tags::PERFORMING_PHYSICIAN_NAME, empty()),
        (tags::PERFORMING_PHYSICIAN_IDENTIFICATION_SEQUENCE, remove()),
        (tags::NAME_OF_PHYSICIANS_READING_STUDY, empty()),
        (tags::PHYSICIANS_OF_RECORD, empty()),
        (tags::PHYSICIANS_OF_RECORD_IDENTIFICATION_SEQUENCE, remove()),
        (tags::OPERATORS_NAME, empty()),
        (tags::OPERATOR_IDENTIFICATION_SEQUENCE, remove()),
        (tags::REQUESTING_PHYSICIAN, empty()),
        (tags::SCHEDULED_PERFORMING_PHYSICIAN_NAME, empty()),
        (tags::CONTENT_CREATOR_NAME, empty()),
        (tags::VERIFYING_OBSERVER_NAME, empty()),
        (tags::REVIEWER_NAME, empty()),
        (tags::AUTHOR_OBSERVER_SEQUENCE, remove()),
        // --- Institution / device ----------------------------------------
        (tags::INSTITUTION_NAME, remove()),
        (tags::INSTITUTION_ADDRESS, remove()),
        (tags::INSTITUTIONAL_DEPARTMENT_NAME, remove()),
        (tags::INSTITUTION_CODE_SEQUENCE, remove()),
        (tags::STATION_NAME, remove()),
        (tags::DEVICE_SERIAL_NUMBER, remove()),
        (tags::PLATE_ID, remove()),
        (tags::DETECTOR_ID, remove()),
        (tags::CASSETTE_ID, remove()),
        (tags::GANTRY_ID, remove()),
        // --- Identifiers and accession numbers ---------------------------
        (tags::ACCESSION_NUMBER, pseudonym("accession", "ACC-")),
        (tags::STUDY_ID, pseudonym("study", "ST-")),
        (tags::PERFORMED_PROCEDURE_STEP_ID, remove()),
        (tags::SCHEDULED_PROCEDURE_STEP_ID, remove()),
        (tags::REQUESTED_PROCEDURE_ID, remove()),
        (tags::FILLER_ORDER_NUMBER_IMAGING_SERVICE_REQUEST, remove()),
        (tags::PLACER_ORDER_NUMBER_IMAGING_SERVICE_REQUEST, remove()),
        (tags::ADMISSION_ID, remove()),
        (tags::ISSUER_OF_ADMISSION_ID_SEQUENCE, remove()),
        (tags::ISSUER_OF_PATIENT_ID, remove()),
        // --- Free text that routinely carries PHI ------------------------
        (tags::STUDY_DESCRIPTION, clean()),
        (tags::SERIES_DESCRIPTION, clean()),
        (tags::IMAGE_COMMENTS, clean()),
        (tags::ADDITIONAL_PATIENT_HISTORY, remove()),
        (tags::ADMITTING_DIAGNOSES_DESCRIPTION, clean()),
        (tags::PATIENT_STATE, remove()),
        (tags::VISIT_COMMENTS, remove()),
        (tags::SERVICE_EPISODE_DESCRIPTION, remove()),
        (tags::STUDY_COMMENTS, remove()),
        (tags::REQUESTED_PROCEDURE_COMMENTS, remove()),
        (tags::REQUESTED_PROCEDURE_DESCRIPTION, clean()),
        (tags::PERFORMED_PROCEDURE_STEP_DESCRIPTION, clean()),
        (tags::SCHEDULED_PROCEDURE_STEP_DESCRIPTION, clean()),
        (tags::PROTOCOL_NAME, clean()),
        (tags::DERIVATION_DESCRIPTION, clean()),
        (tags::TEXT_VALUE, clean()),
        (tags::CONTENT_DESCRIPTION, clean()),
        (tags::ACQUISITION_COMMENTS, remove()),
        (tags::REASON_FOR_STUDY, clean()),
        (tags::REASON_FOR_VISIT, clean()),
        // --- Dates and times ---------------------------------------------
        // Shifted rather than removed so intervals survive; one offset per
        // patient keeps a subject's timeline internally consistent.
        (tags::STUDY_DATE, date_shift("patient")),
        (tags::SERIES_DATE, date_shift("patient")),
        (tags::ACQUISITION_DATE, date_shift("patient")),
        (tags::CONTENT_DATE, date_shift("patient")),
        (tags::ACQUISITION_DATE_TIME, date_shift("patient")),
        (tags::INSTANCE_CREATION_DATE, date_shift("patient")),
        (tags::PERFORMED_PROCEDURE_STEP_START_DATE, date_shift("patient")),
        (tags::SCHEDULED_PROCEDURE_STEP_START_DATE, date_shift("patient")),
        (tags::ADMITTING_DATE, date_shift("patient")),
        (tags::PATIENT_BIRTH_DATE_IN_ALTERNATIVE_CALENDAR, remove()),
        (tags::PATIENT_DEATH_DATE_IN_ALTERNATIVE_CALENDAR, remove()),
        // --- Structured / provenance -------------------------------------
        (tags::CONTENT_SEQUENCE, remove()),
        (tags::REFERENCED_PATIENT_SEQUENCE, remove()),
        (tags::SOURCE_IMAGE_SEQUENCE, remove()),
        (tags::DERIVATION_CODE_SEQUENCE, remove()),
        (tags::ORIGINAL_ATTRIBUTES_SEQUENCE, remove()),
        (tags::MODIFIED_ATTRIBUTES_SEQUENCE, remove()),
        (tags::ACQUISITION_CONTEXT_SEQUENCE, remove()),
        (tags::VERIFYING_OBSERVER_SEQUENCE, remove()),
        (tags::SPECIMEN_ACCESSION_NUMBER, remove()),
        (tags::CURRENT_PATIENT_LOCATION, remove()),
        (tags::PATIENT_INSTITUTION_RESIDENCE, remove()),
    ];

    // UID identity tags get the `U` action from one list, so the table and the
    // structural rule cannot disagree.
    for tag in IDENTITY_UIDS {
        rules.push((*tag, TagAction::Uid));
    }
    rules
}

fn date_shift(domain: &str) -> TagAction {
    TagAction::DateShift {
        max_days: 3650,
        domain: Some(domain.to_string()),
    }
}

/// Look up a tag by its standard DICOM keyword.
pub fn tag_by_keyword(keyword: &str) -> Option<Tag> {
    use dicom_dictionary_std::StandardDataDictionary;
    use dicom_core::dictionary::DataDictionary;
    StandardDataDictionary
        .by_name(keyword)
        .map(|entry| entry.tag.inner())
}

/// Human-readable keyword for a tag, falling back to its numeric form.
pub fn keyword_of(tag: Tag) -> String {
    use dicom_dictionary_std::StandardDataDictionary;
    use dicom_core::dictionary::DataDictionary;
    StandardDataDictionary
        .by_tag(tag)
        .map(|entry| entry.alias.to_string())
        .unwrap_or_else(|| format!("({:04X},{:04X})", tag.group(), tag.element()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_covers_the_obvious_identifiers() {
        let table = basic_profile();
        let has = |tag: Tag| table.iter().any(|(t, _)| *t == tag);
        for tag in [
            tags::PATIENT_NAME,
            tags::PATIENT_ID,
            tags::PATIENT_BIRTH_DATE,
            tags::PATIENT_ADDRESS,
            tags::INSTITUTION_NAME,
            tags::ACCESSION_NUMBER,
            tags::REFERRING_PHYSICIAN_NAME,
            tags::STUDY_INSTANCE_UID,
            tags::STUDY_DATE,
        ] {
            assert!(has(tag), "profile must cover {}", keyword_of(tag));
        }
    }

    #[test]
    fn profile_has_no_conflicting_duplicates() {
        let table = basic_profile();
        let mut seen: std::collections::HashMap<Tag, TagAction> = std::collections::HashMap::new();
        for (tag, action) in table {
            if let Some(existing) = seen.get(&tag) {
                assert_eq!(
                    *existing,
                    action,
                    "conflicting actions for {}",
                    keyword_of(tag)
                );
            }
            seen.insert(tag, action);
        }
    }

    #[test]
    fn format_and_software_uids_are_never_remapped() {
        // Remapping these would make the file unreadable or misrepresent it.
        for tag in [
            tags::SOP_CLASS_UID,
            tags::TRANSFER_SYNTAX_UID,
            tags::IMPLEMENTATION_CLASS_UID,
            tags::REFERENCED_SOP_CLASS_UID,
        ] {
            assert!(
                !is_identity_uid(tag),
                "{} must not be remapped",
                keyword_of(tag)
            );
        }
        assert!(is_identity_uid(tags::STUDY_INSTANCE_UID));
        assert!(is_identity_uid(tags::SOP_INSTANCE_UID));
    }

    #[test]
    fn keyword_round_trips() {
        assert_eq!(tag_by_keyword("PatientName"), Some(tags::PATIENT_NAME));
        assert_eq!(keyword_of(tags::PATIENT_NAME), "PatientName");
        assert_eq!(tag_by_keyword("NoSuchKeyword"), None);
        // Unknown tags fall back to a numeric rendering.
        assert_eq!(keyword_of(Tag(0x0009, 0x1001)), "(0009,1001)");
    }
}
