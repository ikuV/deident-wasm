//! Core of the deident privacy transformation engine.
//!
//! Provides the policy schema, deterministic tokenization, anonymization
//! transforms, the streaming CSV job engine and risk-report computation.
//! This crate compiles for both native targets and `wasm32-wasip1`, so the
//! exact same transformation logic runs in-process and inside the sandbox.
//!
//! Terminology guardrails: anonymization here is *risk-assessed*, never
//! guaranteed; pseudonymized data remains personal data.

pub mod engine;
pub mod error;
pub mod key;
pub mod policy;
pub mod report;
pub mod runner;
pub mod transform;
pub mod vault;

pub use engine::run_csv_job;
pub use error::CoreError;
pub use policy::Policy;
