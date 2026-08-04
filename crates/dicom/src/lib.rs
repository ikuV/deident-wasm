//! DICOM metadata de-identification.
//!
//! Extends the deident engine from tabular datasets to DICOM instances, reusing
//! its key derivation, tokenization, mock generation, mapping vault and audit
//! log. A DICOM object is a nested, tag-keyed attribute tree rather than rows of
//! cells, so it gets its own policy dialect ([`policy::DicomPolicy`]) and job
//! entry point ([`deidentify_file`], [`deidentify_directory`]).
//!
//! # Scope and honest limits
//!
//! - This implements a **curated core** of the DICOM PS3.15 Annex E Basic
//!   Application Level Confidentiality Profile, plus structural rules that catch
//!   whole classes of attribute (every person-name VR, every identity UID, every
//!   private tag, curve/overlay groups). It is **not** full Annex E conformance,
//!   and every report says so.
//! - **Burned-in pixel PHI is detected and flagged, never removed.** Ultrasound
//!   frames, secondary captures and scanned documents routinely render patient
//!   details into the pixels; cleaning that needs OCR and cannot be made
//!   reliable, so this crate refuses to claim it.
//! - UID remapping deliberately breaks references to anything outside the
//!   processed set.
//! - The DICOM parser runs in-process, not inside the wasm sandbox.

/// Version of the deident tooling, recorded in every report for provenance.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod engine;
pub mod error;
pub mod policy;
pub mod profile;
pub mod report;
pub mod synthetic;
pub mod uid;

pub use engine::{deidentify_directory, deidentify_file};
pub use error::DicomError;
pub use policy::DicomPolicy;
pub use report::{DicomReport, StudyReport};
