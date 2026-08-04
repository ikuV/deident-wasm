//! Compare an original and de-identified instance WITHOUT printing values.
//!
//! Reports only whether each attribute changed, plus byte-level checks on the
//! pixel data — so a real file can be verified without copying PHI anywhere.
use dicom_dictionary_std::tags;
use dicom_core::Tag;

fn main() {
    let mut args = std::env::args().skip(1);
    let before = dicom_object::open_file(args.next().unwrap()).unwrap();
    let after = dicom_object::open_file(args.next().unwrap()).unwrap();

    let val = |o: &dicom_object::DefaultDicomObject, t: Tag| {
        o.element(t).ok().and_then(|e| e.to_str().ok())
            .map(|s| s.trim_matches(|c: char| c.is_whitespace() || c == '\0').to_string())
    };

    println!("--- identifiers (must all be CHANGED or GONE):");
    for (label, tag) in [
        ("PatientName", tags::PATIENT_NAME),
        ("PatientID", tags::PATIENT_ID),
        ("PatientBirthDate", tags::PATIENT_BIRTH_DATE),
        ("InstitutionName", tags::INSTITUTION_NAME),
        ("StudyDate", tags::STUDY_DATE),
        ("StudyDescription", tags::STUDY_DESCRIPTION),
        ("StudyInstanceUID", tags::STUDY_INSTANCE_UID),
        ("SeriesInstanceUID", tags::SERIES_INSTANCE_UID),
        ("SOPInstanceUID", tags::SOP_INSTANCE_UID),
    ] {
        let (b, a) = (val(&before, tag), val(&after, tag));
        let verdict = match (&b, &a) {
            (Some(x), Some(y)) if x == y => "*** UNCHANGED ***",
            (Some(_), Some(_)) => "changed",
            (Some(_), None) => "removed",
            (None, _) => "was absent",
        };
        println!("  {label:20} {verdict}");
    }

    println!("--- must be PRESERVED (or the file breaks):");
    for (label, tag) in [
        ("SOPClassUID", tags::SOP_CLASS_UID),
        ("Modality", tags::MODALITY),
        ("Rows", tags::ROWS),
        ("Columns", tags::COLUMNS),
        ("NumberOfFrames", tags::NUMBER_OF_FRAMES),
        ("BitsAllocated", tags::BITS_ALLOCATED),
        ("PatientSex", tags::PATIENT_SEX),
    ] {
        let (b, a) = (val(&before, tag), val(&after, tag));
        println!("  {label:20} {}", if b == a && b.is_some() { "preserved" } else { "*** LOST/CHANGED ***" });
    }

    let px = |o: &dicom_object::DefaultDicomObject| {
        o.element(tags::PIXEL_DATA).ok().and_then(|e| e.to_bytes().ok().map(|b| b.to_vec()))
    };
    match (px(&before), px(&after)) {
        (Some(b), Some(a)) => println!(
            "--- pixel data: {} bytes -> {} bytes, byte-identical: {}",
            b.len(), a.len(), b == a),
        _ => println!("--- pixel data: MISSING in one side"),
    }
    println!("transfer syntax preserved: {}",
        before.meta().transfer_syntax().trim() == after.meta().transfer_syntax().trim());
    let sop_after = val(&after, tags::SOP_INSTANCE_UID).unwrap_or_default();
    println!("meta SOP UID matches dataset: {}",
        after.meta().media_storage_sop_instance_uid.trim_matches(|c: char| c.is_whitespace() || c=='\0') == sop_after);
    println!("private attributes: {} -> {}",
        before.tags().filter(|t| t.group()%2==1 && t.element()!=0).count(),
        after.tags().filter(|t| t.group()%2==1 && t.element()!=0).count());
}
