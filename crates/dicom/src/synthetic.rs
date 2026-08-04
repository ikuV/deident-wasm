//! Synthetic DICOM instances carrying known PHI, for tests and examples.
//!
//! Public DICOM datasets are already de-identified, which makes them useless for
//! proving that a de-identifier works — there is no PHI left to check you
//! removed. So the fixtures here are generated with identifiers planted in known
//! attributes, including inside a nested sequence and in a private block, so a
//! test can assert exactly what survived.
//!
//! These are structurally valid enough to round-trip through `dicom-object`.
//! They are not clinically meaningful images.

use dicom_core::value::{DataSetSequence, PrimitiveValue, Value};
use dicom_core::{DataElement, Tag, VR};
use dicom_dictionary_std::{tags, uids};
use dicom_object::mem::InMemDicomObject;
use dicom_object::{FileDicomObject, FileMetaTableBuilder};

/// The PHI planted in a generated instance, so tests can assert its absence.
pub struct PlantedPhi {
    pub patient_name: &'static str,
    pub patient_id: &'static str,
    pub birth_date: &'static str,
    pub address: &'static str,
    pub phone: &'static str,
    pub institution: &'static str,
    pub referring_physician: &'static str,
    pub accession: &'static str,
    /// Free text containing an embedded IBAN and email.
    pub study_description: &'static str,
    /// A name nested inside a sequence item.
    pub nested_observer: &'static str,
    /// A multi-valued (VM 3) identifier attribute — `ID-1\\ID-2\\ID-3`.
    pub other_patient_ids: &'static str,
    /// A multi-valued (VM 3) date attribute.
    pub multi_dates: &'static str,
    /// Value of a private attribute.
    pub private_value: &'static str,
    pub study_uid: &'static str,
    pub series_uid: &'static str,
    pub sop_instance_uid: &'static str,
    pub study_date: &'static str,
}

/// The exact PHI values used by [`instance`].
pub const PHI: PlantedPhi = PlantedPhi {
    patient_name: "Muster^Alice^Marie",
    patient_id: "PAT-000123",
    birth_date: "19850627",
    address: "Hauptstrasse 5, 81549 Muenchen",
    phone: "+49 89 5551234",
    institution: "Klinikum Musterstadt",
    referring_physician: "Beispiel^Bruno",
    accession: "ACC-20240314-77",
    study_description: "Follow-up, refund to DE89370400440532013000, contact alice.muster@example.com",
    nested_observer: "Demo^Carla",
    other_patient_ids: "OPID-1\\OPID-2\\OPID-3",
    multi_dates: "20240314\\20240415\\20240516",
    private_value: "Muster^Alice (vendor copy)",
    study_uid: "1.2.840.113619.2.55.3.604688119.868.1700000000.1",
    series_uid: "1.2.840.113619.2.55.3.604688119.868.1700000000.2",
    sop_instance_uid: "1.2.840.113619.2.55.3.604688119.868.1700000000.3",
    study_date: "20240314",
};

/// A private attribute tag used by the fixtures (odd group ⇒ private).
pub const PRIVATE_TAG: Tag = Tag(0x0009, 0x1001);
/// Tag of the nested person name inside `VerifyingObserverSequence`.
pub const NESTED_NAME_TAG: Tag = tags::VERIFYING_OBSERVER_NAME;

/// Options for generating an instance.
#[derive(Debug, Clone)]
pub struct InstanceOptions {
    /// `SOPInstanceUID`; vary it to build a multi-instance series.
    pub sop_instance_uid: String,
    /// `Modality`, which drives the pixel-risk assessment.
    pub modality: String,
    /// Include a small `PixelData` attribute.
    pub with_pixel_data: bool,
    /// Value for `BurnedInAnnotation`, if any.
    pub burned_in_annotation: Option<String>,
}

impl Default for InstanceOptions {
    fn default() -> Self {
        Self {
            sop_instance_uid: PHI.sop_instance_uid.to_string(),
            modality: "CT".to_string(),
            with_pixel_data: true,
            burned_in_annotation: Some("NO".to_string()),
        }
    }
}

fn text(tag: Tag, vr: VR, value: &str) -> DataElement<InMemDicomObject> {
    DataElement::new(tag, vr, PrimitiveValue::from(value))
}

/// Build a PHI-laden instance in memory.
///
/// Uses a retired attribute (`OtherPatientIDs`) on purpose: retired attributes
/// still appear in archived studies, which is exactly where decades-old PHI
/// lives, and it is a convenient multi-valued identifier for tests.
#[allow(deprecated)]
pub fn instance(options: &InstanceOptions) -> FileDicomObject<InMemDicomObject> {
    let mut object = InMemDicomObject::new_empty();

    // Identity and format attributes the file needs to be readable.
    object.put(text(tags::SOP_CLASS_UID, VR::UI, uids::CT_IMAGE_STORAGE));
    object.put(text(tags::SOP_INSTANCE_UID, VR::UI, &options.sop_instance_uid));
    object.put(text(tags::STUDY_INSTANCE_UID, VR::UI, PHI.study_uid));
    object.put(text(tags::SERIES_INSTANCE_UID, VR::UI, PHI.series_uid));
    object.put(text(tags::MODALITY, VR::CS, &options.modality));

    // Direct identifiers.
    object.put(text(tags::PATIENT_NAME, VR::PN, PHI.patient_name));
    object.put(text(tags::PATIENT_ID, VR::LO, PHI.patient_id));
    object.put(text(tags::PATIENT_BIRTH_DATE, VR::DA, PHI.birth_date));
    object.put(text(tags::PATIENT_ADDRESS, VR::LO, PHI.address));
    object.put(text(tags::PATIENT_TELEPHONE_NUMBERS, VR::SH, PHI.phone));
    object.put(text(tags::INSTITUTION_NAME, VR::LO, PHI.institution));
    object.put(text(
        tags::REFERRING_PHYSICIAN_NAME,
        VR::PN,
        PHI.referring_physician,
    ));
    object.put(text(tags::ACCESSION_NUMBER, VR::SH, PHI.accession));
    object.put(text(
        tags::STUDY_DESCRIPTION,
        VR::LO,
        PHI.study_description,
    ));
    object.put(text(tags::STUDY_DATE, VR::DA, PHI.study_date));
    object.put(text(tags::SERIES_DATE, VR::DA, PHI.study_date));

    // Retained-but-quasi-identifying attributes.
    object.put(text(tags::PATIENT_SEX, VR::CS, "F"));
    object.put(text(tags::PATIENT_AGE, VR::AS, "039Y"));

    // A person name nested inside a sequence item — the case a non-recursive
    // implementation misses.
    let mut item = InMemDicomObject::new_empty();
    item.put(text(NESTED_NAME_TAG, VR::PN, PHI.nested_observer));
    item.put(text(tags::VERIFICATION_DATE_TIME, VR::DT, "20240314103000"));
    object.put(DataElement::new(
        tags::VERIFYING_OBSERVER_SEQUENCE,
        VR::SQ,
        Value::Sequence(DataSetSequence::from(vec![item])),
    ));

    // Multi-valued attributes: the backslash is a value separator, and every
    // value must be de-identified independently.
    object.put(text(tags::OTHER_PATIENT_I_DS, VR::LO, PHI.other_patient_ids));
    object.put(text(tags::CALIBRATION_DATE, VR::DA, PHI.multi_dates));

    // A private attribute holding a copy of the patient name.
    object.put(text(PRIVATE_TAG, VR::LO, PHI.private_value));

    if let Some(burned_in) = &options.burned_in_annotation {
        object.put(text(tags::BURNED_IN_ANNOTATION, VR::CS, burned_in));
    }

    if options.with_pixel_data {
        // Minimal 2x2 8-bit greyscale image, enough for pixel-risk assessment
        // to see that pixel data exists.
        object.put(text(tags::PHOTOMETRIC_INTERPRETATION, VR::CS, "MONOCHROME2"));
        object.put(DataElement::new(
            tags::ROWS,
            VR::US,
            PrimitiveValue::from(2_u16),
        ));
        object.put(DataElement::new(
            tags::COLUMNS,
            VR::US,
            PrimitiveValue::from(2_u16),
        ));
        object.put(DataElement::new(
            tags::BITS_ALLOCATED,
            VR::US,
            PrimitiveValue::from(8_u16),
        ));
        object.put(DataElement::new(
            tags::BITS_STORED,
            VR::US,
            PrimitiveValue::from(8_u16),
        ));
        object.put(DataElement::new(
            tags::HIGH_BIT,
            VR::US,
            PrimitiveValue::from(7_u16),
        ));
        object.put(DataElement::new(
            tags::PIXEL_REPRESENTATION,
            VR::US,
            PrimitiveValue::from(0_u16),
        ));
        object.put(DataElement::new(
            tags::SAMPLES_PER_PIXEL,
            VR::US,
            PrimitiveValue::from(1_u16),
        ));
        object.put(DataElement::new(
            tags::PIXEL_DATA,
            VR::OB,
            PrimitiveValue::from(vec![0u8, 64, 128, 255]),
        ));
    }

    let meta = FileMetaTableBuilder::new()
        .media_storage_sop_class_uid(uids::CT_IMAGE_STORAGE)
        .media_storage_sop_instance_uid(&options.sop_instance_uid)
        .transfer_syntax(uids::EXPLICIT_VR_LITTLE_ENDIAN)
        .implementation_class_uid("1.2.826.0.1.3680043.9.7133.1.1")
        .build()
        .expect("file meta table must build");
    object.with_exact_meta(meta)
}

/// Write a PHI-laden instance to `path`.
pub fn write_instance(path: &std::path::Path, options: &InstanceOptions) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    instance(options)
        .write_to_file(path)
        .map_err(|e| std::io::Error::other(e.to_string()))
}

/// Write a small study: several instances sharing one study/series, so UID
/// consistency across files can be checked.
pub fn write_study(dir: &std::path::Path, instances: usize) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut written = Vec::new();
    for i in 0..instances {
        let path = dir.join(format!("instance-{i:03}.dcm"));
        let options = InstanceOptions {
            sop_instance_uid: format!("{}.{}", PHI.sop_instance_uid, i + 1),
            ..Default::default()
        };
        write_instance(&path, &options)?;
        written.push(path);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_instance_round_trips_and_contains_the_planted_phi() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("in.dcm");
        write_instance(&path, &InstanceOptions::default()).unwrap();

        let read = dicom_object::open_file(&path).expect("must be readable DICOM");
        let value = |tag: Tag| read.element(tag).unwrap().to_str().unwrap().trim().to_string();
        assert_eq!(value(tags::PATIENT_NAME), PHI.patient_name);
        assert_eq!(value(tags::PATIENT_ID), PHI.patient_id);
        assert_eq!(value(tags::STUDY_INSTANCE_UID), PHI.study_uid);
        assert!(read.element(tags::PIXEL_DATA).is_ok(), "pixel data present");
        assert!(read.element(PRIVATE_TAG).is_ok(), "private tag present");
        // The nested name must really be nested.
        let sequence = read.element(tags::VERIFYING_OBSERVER_SEQUENCE).unwrap();
        let items = sequence.items().expect("a sequence");
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0]
                .element(NESTED_NAME_TAG)
                .unwrap()
                .to_str()
                .unwrap()
                .trim(),
            PHI.nested_observer
        );
    }

    #[test]
    fn study_instances_share_study_and_series_uids() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = write_study(tmp.path(), 3).unwrap();
        assert_eq!(paths.len(), 3);
        let mut sops = std::collections::HashSet::new();
        for path in &paths {
            let read = dicom_object::open_file(path).unwrap();
            let get = |tag: Tag| read.element(tag).unwrap().to_str().unwrap().trim().to_string();
            assert_eq!(get(tags::STUDY_INSTANCE_UID), PHI.study_uid);
            assert_eq!(get(tags::SERIES_INSTANCE_UID), PHI.series_uid);
            assert!(sops.insert(get(tags::SOP_INSTANCE_UID)), "SOP UIDs must differ");
        }
    }
}
