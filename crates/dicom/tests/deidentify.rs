//! Integration tests for DICOM de-identification.
//!
//! Every test runs against synthetic instances with **known planted PHI**
//! (public DICOM is already de-identified and so cannot prove a de-identifier
//! works), then asserts what survived.

use dicom_core::Tag;
use dicom_dictionary_std::tags;
use deident_dicom::engine::RunOptions;
use deident_dicom::synthetic::{self, InstanceOptions, NESTED_NAME_TAG, PHI, PRIVATE_TAG};
use deident_dicom::{DicomPolicy, deidentify_directory, deidentify_file};

const BASIC_POLICY: &str = r#"
version: 1
kind: dicom
dataset: test-study
key: { inline: "dicom-test-secret-0123456789abcdef012345" }
profile: basic
patterns:
  - { name: iban, builtin: iban, action: redact }
  - { name: email, builtin: email, action: redact }
"#;

fn policy(yaml: &str) -> DicomPolicy {
    DicomPolicy::from_yaml(yaml).expect("policy must parse")
}

/// Normalize a DICOM value: padding must not affect comparisons.
fn norm(raw: &str) -> String {
    raw.trim_matches(|c: char| c.is_whitespace() || c == '\0').to_string()
}

fn value_of(path: &std::path::Path, tag: Tag) -> Option<String> {
    let object = dicom_object::open_file(path).expect("output must be readable DICOM");
    object
        .element(tag)
        .ok()
        .and_then(|e| e.to_str().ok())
        .map(|s| norm(&s))
}

/// Individual values of a (possibly multi-valued) attribute. DICOM separates
/// values with a backslash.
fn multi_values(path: &std::path::Path, tag: Tag) -> Vec<String> {
    let object = dicom_object::open_file(path).expect("readable DICOM");
    let raw = object
        .element(tag)
        .expect("attribute present")
        .to_str()
        .expect("string value")
        .to_string();
    raw.split('\\').map(norm).collect()
}

/// Every byte of the output file, for leak checks.
fn raw_bytes(path: &std::path::Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[test]
fn no_planted_phi_survives_anywhere_in_the_file() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("in.dcm");
    let output = tmp.path().join("out.dcm");
    synthetic::write_instance(&input, &InstanceOptions::default()).unwrap();

    let report = deidentify_file(&input, &output, &policy(BASIC_POLICY), &RunOptions::default())
        .expect("de-identification must succeed");

    // Byte-level check over the whole output, not just the attributes we expect
    // to have handled — this is what catches PHI hiding somewhere unplanned.
    let bytes = raw_bytes(&output);
    for phi in [
        PHI.patient_name,
        PHI.patient_id,
        PHI.address,
        PHI.phone,
        PHI.institution,
        PHI.referring_physician,
        PHI.accession,
        PHI.birth_date,
        PHI.nested_observer,
        PHI.private_value,
        PHI.study_uid,
        PHI.series_uid,
        PHI.sop_instance_uid,
        "DE89370400440532013000",
        "alice.muster@example.com",
    ] {
        assert!(
            !contains(&bytes, phi),
            "PHI survived into the output: {phi:?}"
        );
    }

    assert!(report.attributes_modified > 0);
    assert!(!report.limitations.is_empty());
    assert!(
        report
            .limitations
            .iter()
            .any(|l| l.contains("Burned-in pixel data is NOT modified")),
        "the pixel limitation must always be present"
    );
}

#[test]
fn output_stays_a_readable_dicom_instance() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("in.dcm");
    let output = tmp.path().join("out.dcm");
    synthetic::write_instance(&input, &InstanceOptions::default()).unwrap();
    deidentify_file(&input, &output, &policy(BASIC_POLICY), &RunOptions::default()).unwrap();

    let object = dicom_object::open_file(&output).expect("must still parse");
    // Format-identifying UIDs must NOT be remapped, or the file becomes unreadable.
    assert_eq!(
        norm(&object.element(tags::SOP_CLASS_UID).unwrap().to_str().unwrap()),
        dicom_dictionary_std::uids::CT_IMAGE_STORAGE,
        "SOPClassUID must survive remapping"
    );
    // Pixel data and image geometry are untouched.
    assert!(object.element(tags::PIXEL_DATA).is_ok(), "pixel data preserved");
    assert_eq!(
        norm(&object.element(tags::ROWS).unwrap().to_str().unwrap()),
        "2"
    );
    // Clinically load-bearing quasi-identifiers are deliberately retained.
    assert_eq!(value_of(&output, tags::PATIENT_SEX).as_deref(), Some("F"));
}

#[test]
fn identity_uids_are_remapped_to_valid_uids_and_the_meta_header_follows() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("in.dcm");
    let output = tmp.path().join("out.dcm");
    synthetic::write_instance(&input, &InstanceOptions::default()).unwrap();
    deidentify_file(&input, &output, &policy(BASIC_POLICY), &RunOptions::default()).unwrap();

    let object = dicom_object::open_file(&output).unwrap();
    let sop = norm(&object.element(tags::SOP_INSTANCE_UID).unwrap().to_str().unwrap());
    let study = norm(&object.element(tags::STUDY_INSTANCE_UID).unwrap().to_str().unwrap());
    assert_ne!(sop, PHI.sop_instance_uid);
    assert_ne!(study, PHI.study_uid);
    for uid in [&sop, &study] {
        assert!(
            deident_dicom::uid::is_valid_uid(uid),
            "replacement must be a valid UID: {uid}"
        );
        assert!(uid.starts_with("2.25."), "{uid}");
    }
    // The file-meta group duplicates the SOP Instance UID; a stale header would
    // reintroduce the original identifier for readers that trust it.
    assert_eq!(
        norm(&object.meta().media_storage_sop_instance_uid),
        sop,
        "file-meta SOP Instance UID must match the dataset"
    );
}

#[test]
fn phi_nested_inside_a_sequence_is_reached() {
    // Keep the sequence itself, so the recursion path (not removal) is what
    // must handle the nested name.
    let keep_sequence = r#"
version: 1
kind: dicom
dataset: test-study
key: { inline: "dicom-test-secret-0123456789abcdef012345" }
profile: basic
tags:
  - { tag: VerifyingObserverSequence, action: keep }
"#;
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("in.dcm");
    let output = tmp.path().join("out.dcm");
    synthetic::write_instance(&input, &InstanceOptions::default()).unwrap();

    let report =
        deidentify_file(&input, &output, &policy(keep_sequence), &RunOptions::default()).unwrap();
    assert!(
        report.max_sequence_depth >= 1,
        "the traversal must have descended into the sequence"
    );

    let object = dicom_object::open_file(&output).unwrap();
    let sequence = object
        .element(tags::VERIFYING_OBSERVER_SEQUENCE)
        .expect("sequence retained");
    let items = sequence.items().expect("a sequence");
    assert_eq!(items.len(), 1, "the item must survive");
    let nested = items[0]
        .element(NESTED_NAME_TAG)
        .ok()
        .and_then(|e| e.to_str().ok())
        .map(|s| norm(&s))
        .unwrap_or_default();
    assert_ne!(
        nested, PHI.nested_observer,
        "the nested person name must have been de-identified"
    );
    assert!(
        !contains(&raw_bytes(&output), PHI.nested_observer),
        "nested PHI must not survive anywhere in the file"
    );
}

#[test]
fn private_attributes_are_removed_by_default_and_retained_on_request() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("in.dcm");
    synthetic::write_instance(&input, &InstanceOptions::default()).unwrap();

    // Default: removed.
    let removed = tmp.path().join("removed.dcm");
    let report =
        deidentify_file(&input, &removed, &policy(BASIC_POLICY), &RunOptions::default()).unwrap();
    assert!(report.private_attributes >= 1, "the private tag was seen");
    assert!(
        dicom_object::open_file(&removed)
            .unwrap()
            .element(PRIVATE_TAG)
            .is_err(),
        "private attribute must be gone"
    );

    // Opt-in retention keeps it, and warns.
    let retain = r#"
version: 1
kind: dicom
dataset: test-study
key: { inline: "dicom-test-secret-0123456789abcdef012345" }
profile: basic
structural: { retain_safe_private: true }
"#;
    let kept = tmp.path().join("kept.dcm");
    let report = deidentify_file(&input, &kept, &policy(retain), &RunOptions::default()).unwrap();
    assert!(
        dicom_object::open_file(&kept).unwrap().element(PRIVATE_TAG).is_ok(),
        "retain_safe_private must keep the attribute"
    );
    assert!(
        report.warnings.iter().any(|w| w.contains("retain_safe_private")),
        "retaining private attributes must be warned about: {:?}",
        report.warnings
    );
}

#[test]
fn free_text_patterns_clean_embedded_identifiers() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("in.dcm");
    let output = tmp.path().join("out.dcm");
    synthetic::write_instance(&input, &InstanceOptions::default()).unwrap();
    deidentify_file(&input, &output, &policy(BASIC_POLICY), &RunOptions::default()).unwrap();

    let description = value_of(&output, tags::STUDY_DESCRIPTION).unwrap_or_default();
    assert!(
        description.contains("[IBAN]") && description.contains("[EMAIL]"),
        "embedded identifiers must be redacted in place: {description:?}"
    );
    assert!(
        description.contains("Follow-up"),
        "the surrounding text should survive: {description:?}"
    );
}

#[test]
fn dates_shift_together_and_birth_dates_truncate() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("in.dcm");
    let output = tmp.path().join("out.dcm");
    synthetic::write_instance(&input, &InstanceOptions::default()).unwrap();
    deidentify_file(&input, &output, &policy(BASIC_POLICY), &RunOptions::default()).unwrap();

    let study = value_of(&output, tags::STUDY_DATE).unwrap();
    let series = value_of(&output, tags::SERIES_DATE).unwrap();
    assert_ne!(study, PHI.study_date, "study date must move");
    assert_eq!(study.len(), 8, "must stay a valid DA: {study}");
    assert_eq!(
        study, series,
        "two dates that were equal must stay equal (one offset per patient)"
    );

    // Birth date is truncated to the year, not shifted.
    let birth = value_of(&output, tags::PATIENT_BIRTH_DATE).unwrap();
    assert_eq!(birth, "19850101", "year kept, month/day removed");
}

#[test]
fn results_are_deterministic() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("in.dcm");
    synthetic::write_instance(&input, &InstanceOptions::default()).unwrap();
    let first = tmp.path().join("a.dcm");
    let second = tmp.path().join("b.dcm");
    for out in [&first, &second] {
        deidentify_file(&input, out, &policy(BASIC_POLICY), &RunOptions::default()).unwrap();
    }
    assert_eq!(
        raw_bytes(&first),
        raw_bytes(&second),
        "the same input and policy must produce byte-identical output"
    );
}

#[test]
fn a_study_remaps_uids_consistently_across_files() {
    let tmp = tempfile::tempdir().unwrap();
    let study_dir = tmp.path().join("study");
    let out_dir = tmp.path().join("deid");
    synthetic::write_study(&study_dir, 3).unwrap();

    let report =
        deidentify_directory(&study_dir, &out_dir, &policy(BASIC_POLICY), &RunOptions::default())
            .unwrap();
    assert_eq!(report.instances_written, 3);
    assert_eq!(report.instances_failed, 0);
    // 1 study + 1 series + 3 SOP = 5 distinct originals.
    assert_eq!(report.distinct_uids_remapped, 5, "run-wide distinct UID count");

    let mut studies = std::collections::HashSet::new();
    let mut sops = std::collections::HashSet::new();
    for entry in std::fs::read_dir(&out_dir).unwrap() {
        let path = entry.unwrap().path();
        studies.insert(value_of(&path, tags::STUDY_INSTANCE_UID).unwrap());
        sops.insert(value_of(&path, tags::SOP_INSTANCE_UID).unwrap());
        assert!(!contains(&raw_bytes(&path), PHI.patient_name));
    }
    assert_eq!(
        studies.len(),
        1,
        "every instance must land in the same de-identified study"
    );
    assert_eq!(sops.len(), 3, "instances must stay distinct");
}

#[test]
fn non_dicom_files_are_skipped_not_fatal() {
    let tmp = tempfile::tempdir().unwrap();
    let study_dir = tmp.path().join("study");
    let out_dir = tmp.path().join("deid");
    synthetic::write_study(&study_dir, 1).unwrap();
    std::fs::write(study_dir.join("README.txt"), "not dicom").unwrap();

    let report =
        deidentify_directory(&study_dir, &out_dir, &policy(BASIC_POLICY), &RunOptions::default())
            .unwrap();
    assert_eq!(report.instances_written, 1);
    assert_eq!(report.non_dicom_skipped, 1);
    assert_eq!(report.instances_failed, 0);
    assert!(report.warnings.iter().any(|w| w.contains("skipped")));
}

#[test]
fn pixel_risk_reflects_the_annotation_flag_and_modality() {
    let tmp = tempfile::tempdir().unwrap();
    let cases = [
        // (modality, BurnedInAnnotation, pixel data, expected level)
        ("CT", Some("NO"), true, "low"),
        ("CT", Some("YES"), true, "high"),
        ("US", Some("NO"), true, "elevated"),
        ("US", None, true, "high"),
        ("CT", None, true, "unknown"),
        ("CT", Some("NO"), false, "low"),
    ];
    for (i, (modality, burned_in, pixels, expected)) in cases.iter().enumerate() {
        let input = tmp.path().join(format!("in-{i}.dcm"));
        let output = tmp.path().join(format!("out-{i}.dcm"));
        synthetic::write_instance(
            &input,
            &InstanceOptions {
                modality: modality.to_string(),
                burned_in_annotation: burned_in.map(str::to_string),
                with_pixel_data: *pixels,
                ..Default::default()
            },
        )
        .unwrap();
        let report =
            deidentify_file(&input, &output, &policy(BASIC_POLICY), &RunOptions::default()).unwrap();
        assert_eq!(
            report.pixel_risk.level, *expected,
            "modality {modality}, annotation {burned_in:?}, pixels {pixels}"
        );
        assert!(!report.pixel_risk.reasons.is_empty(), "a reason is required");
        if *expected != "low" {
            assert!(
                report.warnings.iter().any(|w| w.contains("NOT modified")),
                "elevated pixel risk must warn that pixels were not touched"
            );
        }
    }
}

#[test]
fn the_vault_records_reversible_mappings_and_holds_no_plaintext() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("in.dcm");
    let output = tmp.path().join("out.dcm");
    let vault_path = tmp.path().join("vault.jsonl");
    synthetic::write_instance(&input, &InstanceOptions::default()).unwrap();

    deidentify_file(
        &input,
        &output,
        &policy(BASIC_POLICY),
        &RunOptions {
            vault_path: Some(vault_path.clone()),
        },
    )
    .unwrap();

    let raw = std::fs::read_to_string(&vault_path).unwrap();
    assert!(raw.contains("deident-vault"), "header is readable");
    assert!(!raw.contains(PHI.patient_id), "vault must be encrypted");
    assert!(!raw.contains(PHI.study_uid));

    // Decrypt and confirm the UID and patient mappings are recoverable.
    let key = deident_core::vault::derive_vault_key(
        b"dicom-test-secret-0123456789abcdef012345",
        "test-study",
    );
    let entries =
        deident_core::vault::read_vault(std::io::BufReader::new(
            std::fs::File::open(&vault_path).unwrap(),
        ), &key)
        .expect("vault must decrypt with the derived key");
    assert!(
        entries.iter().any(|e| e.original == PHI.study_uid),
        "the study UID mapping must be recorded for authorized reversal"
    );
    assert!(
        entries.iter().any(|e| e.original == PHI.patient_id),
        "the patient id mapping must be recorded"
    );
}

#[test]
fn a_tabular_policy_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("in.dcm");
    synthetic::write_instance(&input, &InstanceOptions::default()).unwrap();
    // The tabular dialect has no `kind: dicom`, so it must not be usable here.
    assert!(
        DicomPolicy::from_yaml(
            "version: 1\ndataset: d\nfields:\n  - { name: x, class: utility }\n"
        )
        .is_err(),
        "a tabular policy must not parse as a DICOM policy"
    );
}

/// `clean_text` only removes what its patterns match, so a field that matched
/// nothing is in the output verbatim. That must be surfaced — silence would let
/// a reader assume the field was sanitized.
#[test]
fn clean_text_that_matched_nothing_is_reported() {
    let no_patterns = r#"
version: 1
kind: dicom
dataset: test-study
key: { inline: "dicom-test-secret-0123456789abcdef012345" }
profile: none
tags:
  - { tag: StudyDescription, action: clean_text }
patterns:
  - { name: iban, builtin: iban, action: redact }
"#;
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("in.dcm");
    let output = tmp.path().join("out.dcm");
    // A description with no IBAN and no email: nothing for the rules to match.
    let options = InstanceOptions {
        sop_instance_uid: "1.2.3.4.5".to_string(),
        ..Default::default()
    };
    synthetic::write_instance(&input, &options).unwrap();

    let report = deidentify_file(&input, &output, &policy(no_patterns), &RunOptions::default())
        .unwrap();
    // The planted description *does* contain an IBAN, so this one is cleaned.
    assert!(
        report.tags.iter().any(|t| t.action == "text-cleaned"),
        "the IBAN in the description must be cleaned: {:?}",
        report.tags
    );

    // Now a description with nothing to match.
    let plain = tmp.path().join("plain.dcm");
    let plain_out = tmp.path().join("plain-out.dcm");
    {
        let mut object = synthetic::instance(&InstanceOptions::default());
        object.put(dicom_core::DataElement::new(
            tags::STUDY_DESCRIPTION,
            dicom_core::VR::LO,
            dicom_core::value::PrimitiveValue::from("MR Knee routine"),
        ));
        object.write_to_file(&plain).unwrap();
    }
    let report =
        deidentify_file(&plain, &plain_out, &policy(no_patterns), &RunOptions::default()).unwrap();
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("clean_text matched no pattern") && w.contains("StudyDescription")),
        "a clean_text field that matched nothing must be surfaced: {:?}",
        report.warnings
    );
}

/// DICOM attributes are frequently multi-valued (`ID-1\ID-2\ID-3`). Treating the
/// joined string as one scalar collapsed the attribute, so values 2..n were
/// destroyed rather than de-identified.
///
/// `OtherPatientIDs` is retired but still present in archived studies, and is a
/// convenient multi-valued identifier to test with.
#[allow(deprecated)]
#[test]
fn multi_valued_attributes_are_de_identified_value_by_value() {
    let policy_yaml = r#"
version: 1
kind: dicom
dataset: vm-test
key: { inline: "vm-secret-0123456789abcdef0123456789abcd" }
profile: basic
tags:
  - { tag: OtherPatientIDs, action: pseudonymize, domain: opid, prefix: "OP-" }
  - { tag: CalibrationDate, action: date_shift, max_days: 3650, domain: patient }
"#;
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("in.dcm");
    let output = tmp.path().join("out.dcm");
    synthetic::write_instance(&input, &InstanceOptions::default()).unwrap();

    deidentify_file(&input, &output, &policy(policy_yaml), &RunOptions::default()).unwrap();

    // Multiplicity must survive, and no original value may remain.
    let values = multi_values(&output, tags::OTHER_PATIENT_I_DS);
    assert_eq!(values.len(), 3, "all three values must survive: {values:?}");
    for original in ["OPID-1", "OPID-2", "OPID-3"] {
        assert!(
            !values.iter().any(|v| v == original),
            "{original} survived de-identification: {values:?}"
        );
    }
    assert_eq!(
        values.iter().collect::<std::collections::HashSet<_>>().len(),
        3,
        "distinct inputs must give distinct pseudonyms: {values:?}"
    );

    // date_shift used to shift only the first value and leave the rest as
    // original dates, while reporting the attribute as shifted.
    let shifted = multi_values(&output, tags::CALIBRATION_DATE);
    assert_eq!(shifted.len(), 3, "{shifted:?}");
    for original in ["20240314", "20240415", "20240516"] {
        assert!(
            !shifted.iter().any(|v| v == original),
            "original date {original} survived: {shifted:?}"
        );
    }
    // One offset per subject, so the intervals between the values are preserved.
    let day = |d: &str| -> i64 {
        let (y, m, dd) = (
            d[0..4].parse::<i64>().unwrap(),
            d[4..6].parse::<i64>().unwrap(),
            d[6..8].parse::<i64>().unwrap(),
        );
        let y2 = if m <= 2 { y - 1 } else { y };
        let era = y2.div_euclid(400);
        let yoe = y2 - era * 400;
        let mp = (m + 9) % 12;
        let doy = (153 * mp + 2) / 5 + dd - 1;
        era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
    };
    assert_eq!(day(&shifted[1]) - day(&shifted[0]), 32, "interval preserved");
    assert_eq!(day(&shifted[2]) - day(&shifted[1]), 31, "interval preserved");

    // No planted value may appear anywhere in the file.
    let bytes = raw_bytes(&output);
    for phi in ["OPID-1", "OPID-2", "OPID-3", "20240415", "20240516"] {
        assert!(!contains(&bytes, phi), "{phi} survived in the file");
    }
}

/// The same UID must map to the same replacement whichever attribute or file it
/// appears in — including when it sits inside a multi-valued attribute.
#[test]
fn multi_valued_uids_remap_consistently_and_are_counted_individually() {
    use dicom_core::{DataElement, VR, value::PrimitiveValue};

    let policy_yaml = r#"
version: 1
kind: dicom
dataset: vm-uid-test
key: { inline: "vm-uid-secret-0123456789abcdef0123456789" }
profile: basic
"#;
    let tmp = tempfile::tempdir().unwrap();
    let study = tmp.path().join("study");
    let out = tmp.path().join("deid");
    std::fs::create_dir_all(&study).unwrap();

    // a.dcm references two UIDs in one attribute; b.dcm references the first
    // one alone. The shared UID must get the same replacement in both.
    for (name, referenced) in [("a.dcm", "1.2.9.1\\1.2.9.2"), ("b.dcm", "1.2.9.1")] {
        let mut object = synthetic::instance(&InstanceOptions {
            sop_instance_uid: format!("1.2.3.{name}").replace(".dcm", ""),
            ..Default::default()
        });
        object.put(DataElement::new(
            tags::REFERENCED_SOP_INSTANCE_UID,
            VR::UI,
            PrimitiveValue::from(referenced),
        ));
        object.write_to_file(study.join(name)).unwrap();
    }

    let report =
        deidentify_directory(&study, &out, &policy(policy_yaml), &RunOptions::default()).unwrap();
    assert_eq!(report.instances_written, 2);

    let referenced_of =
        |name: &str| multi_values(&out.join(name), tags::REFERENCED_SOP_INSTANCE_UID);
    let a = referenced_of("a.dcm");
    let b = referenced_of("b.dcm");
    assert_eq!(a.len(), 2, "both references must survive: {a:?}");
    assert_eq!(b.len(), 1);
    assert_eq!(
        a[0], b[0],
        "the same original UID must get the same replacement across files"
    );
    assert_ne!(a[0], a[1], "different UIDs must not collide");
    for uid in a.iter().chain(&b) {
        assert!(deident_dicom::uid::is_valid_uid(uid), "invalid UID: {uid}");
    }
}

/// The file-meta group used to keep the ORIGINAL SOP Instance UID unless the
/// action was exactly `uid` — reintroducing the identifier the sync exists to
/// remove.
#[test]
fn file_meta_follows_the_dataset_for_any_action() {
    for action in ["pseudonymize", "replace\n    value: \"1.2.3.4.5.6\""] {
        let policy_yaml = format!(
            "version: 1\nkind: dicom\ndataset: meta-test\nkey: {{ inline: \"s-0123456789abcdef0123456789abcdef\" }}\n\
             profile: basic\ntags:\n  - tag: SOPInstanceUID\n    action: {action}\n"
        );
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("in.dcm");
        let output = tmp.path().join("out.dcm");
        synthetic::write_instance(&input, &InstanceOptions::default()).unwrap();
        deidentify_file(&input, &output, &policy(&policy_yaml), &RunOptions::default()).unwrap();

        let object = dicom_object::open_file(&output).unwrap();
        let dataset = norm(&object.element(tags::SOP_INSTANCE_UID).unwrap().to_str().unwrap());
        let meta = norm(&object.meta().media_storage_sop_instance_uid);
        assert_eq!(meta, dataset, "action {action:?}: header must match dataset");
        assert_ne!(
            meta, PHI.sop_instance_uid,
            "action {action:?}: the original UID must not survive in the header"
        );
    }
}

/// Only `remove` used to be honoured on a sequence; every other action was
/// dropped after recursion, so `empty` did nothing and reported "0 modified".
#[test]
fn actions_on_a_sequence_are_applied_or_explained() {
    let empty_sequence = r#"
version: 1
kind: dicom
dataset: seq-test
key: { inline: "seq-secret-0123456789abcdef0123456789" }
profile: basic
tags:
  - { tag: VerifyingObserverSequence, action: empty }
"#;
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("in.dcm");
    let output = tmp.path().join("out.dcm");
    synthetic::write_instance(&input, &InstanceOptions::default()).unwrap();

    let report =
        deidentify_file(&input, &output, &policy(empty_sequence), &RunOptions::default()).unwrap();
    let object = dicom_object::open_file(&output).unwrap();
    let items = object
        .element(tags::VERIFYING_OBSERVER_SEQUENCE)
        .expect("the sequence itself is retained")
        .items()
        .expect("a sequence");
    assert!(items.is_empty(), "`empty` must drop the sequence's items");
    assert!(
        report.tags.iter().any(|t| t.tag == "VerifyingObserverSequence"),
        "the action must be reported: {:?}",
        report.tags
    );
    assert!(!contains(&raw_bytes(&output), PHI.nested_observer));

    // A value-level action cannot apply to a sequence, and must say so rather
    // than appear to have worked.
    let text_on_sequence = empty_sequence.replace("action: empty", "action: clean_text");
    let out2 = tmp.path().join("out2.dcm");
    let report =
        deidentify_file(&input, &out2, &policy(&text_on_sequence), &RunOptions::default()).unwrap();
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("cannot apply to a sequence")),
        "an inapplicable action must be surfaced: {:?}",
        report.warnings
    );
}

/// Writing text into a binary VR reinterprets the bytes: `Rows` came back as
/// 28526\24948\30062, destroying the image geometry while the report said
/// "replaced".
#[test]
fn text_actions_refuse_binary_attributes_instead_of_corrupting_them() {
    let policy_yaml = r#"
version: 1
kind: dicom
dataset: vr-test
key: { inline: "vr-secret-0123456789abcdef0123456789ab" }
profile: basic
tags:
  - { tag: Rows, action: replace, value: "notanumber" }
  - { tag: BitsAllocated, action: pseudonymize }
"#;
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("in.dcm");
    let output = tmp.path().join("out.dcm");
    synthetic::write_instance(&input, &InstanceOptions::default()).unwrap();

    let report =
        deidentify_file(&input, &output, &policy(policy_yaml), &RunOptions::default()).unwrap();

    // `pseudonymize` is a value-level action and must be refused with a warning.
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("BitsAllocated") && w.contains("binary")),
        "a text action on a binary VR must warn: {:?}",
        report.warnings
    );
    // Geometry survives intact.
    assert_eq!(value_of(&output, tags::BITS_ALLOCATED).as_deref(), Some("8"));
}

/// A date near a calendar bound must not shift into an impossible year: a `DA`
/// value is exactly eight digits.
#[test]
fn date_shift_never_emits_an_out_of_range_year() {
    use dicom_core::{DataElement, VR, value::PrimitiveValue};
    let policy_yaml = r#"
version: 1
kind: dicom
dataset: da-test
key: { inline: "da-secret-0123456789abcdef0123456789ab" }
profile: basic
tags:
  - { tag: StudyDate, action: date_shift, max_days: 3650, domain: patient }
"#;
    let tmp = tempfile::tempdir().unwrap();
    for (i, extreme) in ["00010102", "99991231"].iter().enumerate() {
        let input = tmp.path().join(format!("in{i}.dcm"));
        let output = tmp.path().join(format!("out{i}.dcm"));
        let mut object = synthetic::instance(&InstanceOptions::default());
        object.put(DataElement::new(
            tags::STUDY_DATE,
            VR::DA,
            PrimitiveValue::from(*extreme),
        ));
        object.write_to_file(&input).unwrap();

        deidentify_file(&input, &output, &policy(policy_yaml), &RunOptions::default()).unwrap();
        // Either dropped, or a valid 8-digit DA — never something like -0080804.
        if let Some(value) = value_of(&output, tags::STUDY_DATE) {
            assert_eq!(value.len(), 8, "invalid DA emitted for {extreme}: {value:?}");
            assert!(
                value.bytes().all(|b| b.is_ascii_digit()),
                "invalid DA emitted for {extreme}: {value:?}"
            );
        }
    }
}
