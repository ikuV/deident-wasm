//! Generate synthetic PHI-laden DICOM instances for testing a de-identifier.
//!
//! Public DICOM datasets are already de-identified, so they cannot demonstrate
//! that de-identification works — there is no PHI left to remove. These
//! fixtures carry known identifiers in known attributes, including one nested
//! inside a sequence and one in a private block.
//!
//!     cargo run -p deident-dicom --example gen_fixtures -- ./study 3
//!
//! The values planted are listed in `deident_dicom::synthetic::PHI`.

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args
        .next()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("dicom-fixtures"));
    let count: usize = args.next().and_then(|n| n.parse().ok()).unwrap_or(3);

    std::fs::create_dir_all(&dir).expect("cannot create output directory");
    let written = deident_dicom::synthetic::write_study(&dir, count)
        .expect("cannot write fixtures");
    println!(
        "Wrote {} PHI-laden instance(s) to {} — one study, one series, distinct SOP UIDs.",
        written.len(),
        dir.display()
    );
    println!("These contain deliberately planted identifiers; do not mix them with real data.");
}
