//! Structural inspection of a DICOM file.
//!
//! Deliberately reports whether identifying attributes are PRESENT and their
//! length — never their values — so a file can be characterised without copying
//! PHI into logs or a terminal.
use dicom_dictionary_std::tags;

fn main() {
    let path = std::env::args().nth(1).expect("usage: inspect <file.dcm>");
    let o = dicom_object::open_file(&path).expect("must be readable DICOM");
    println!("transfer syntax : {}", o.meta().transfer_syntax().trim());
    println!("media sop class : {}", o.meta().media_storage_sop_class_uid.trim());
    let show = |label: &str, tag| {
        match o.element(tag) {
            Ok(e) => {
                let len = e.to_str().map(|s| s.trim().len()).unwrap_or(0);
                println!("{label:24} present, {len} char(s){}", if len == 0 { " (already empty)" } else { "" });
            }
            Err(_) => println!("{label:24} absent"),
        }
    };
    for (label, tag) in [
        ("PatientName", tags::PATIENT_NAME),
        ("PatientID", tags::PATIENT_ID),
        ("PatientBirthDate", tags::PATIENT_BIRTH_DATE),
        ("PatientSex", tags::PATIENT_SEX),
        ("InstitutionName", tags::INSTITUTION_NAME),
        ("ReferringPhysicianName", tags::REFERRING_PHYSICIAN_NAME),
        ("StudyDate", tags::STUDY_DATE),
        ("StudyDescription", tags::STUDY_DESCRIPTION),
        ("AccessionNumber", tags::ACCESSION_NUMBER),
        ("Modality", tags::MODALITY),
        ("BurnedInAnnotation", tags::BURNED_IN_ANNOTATION),
        ("SpecificCharacterSet", tags::SPECIFIC_CHARACTER_SET),
    ] { show(label, tag); }

    let mut private = 0usize;
    let mut sequences = 0usize;
    let mut total = 0usize;
    for tag in o.tags() {
        total += 1;
        if tag.group() % 2 == 1 && tag.element() != 0 { private += 1; }
        if let Ok(e) = o.element(tag)
            && e.items().is_some()
        {
            sequences += 1;
        }
    }
    println!("--- structure: {total} top-level attributes, {private} private, {sequences} sequence(s)");
    match o.element(tags::PIXEL_DATA) {
        Ok(px) => println!("pixel data: present, VR {:?}, declared length {:?}", px.vr(), px.header().len),
        Err(_) => println!("pixel data: absent"),
    }
    for (l, t) in [("Rows", tags::ROWS), ("Columns", tags::COLUMNS), ("BitsAllocated", tags::BITS_ALLOCATED), ("NumberOfFrames", tags::NUMBER_OF_FRAMES)] {
        if let Ok(e) = o.element(t) { println!("{l}: {}", e.to_str().unwrap().trim()); }
    }
}
