//! Error type for DICOM operations.

/// Errors produced while loading DICOM policies or de-identifying instances.
#[derive(Debug, thiserror::Error)]
pub enum DicomError {
    #[error("DICOM policy error: {0}")]
    Policy(String),
    #[error("cannot read DICOM object '{path}': {source}")]
    Read {
        path: String,
        #[source]
        source: Box<dicom_object::ReadError>,
    },
    #[error("cannot write DICOM object '{path}': {source}")]
    Write {
        path: String,
        #[source]
        source: Box<dicom_object::WriteError>,
    },
    #[error("de-identification failed: {0}")]
    Transform(String),
    #[error("key error: {0}")]
    Key(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
