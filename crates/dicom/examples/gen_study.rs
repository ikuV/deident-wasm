fn main() {
    let dir = std::path::PathBuf::from(std::env::args().nth(1).unwrap());
    std::fs::create_dir_all(&dir).unwrap();
    deident_dicom::synthetic::write_study(&dir, 3).unwrap();
    println!("wrote study to {}", dir.display());
}
