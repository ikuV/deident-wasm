//! Error type for core operations.

/// Errors produced while loading policies or running jobs.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("policy error: {0}")]
    Policy(String),
    #[error("key error: {0}")]
    Key(String),
    #[error("invalid policy YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("vault error: {0}")]
    Vault(String),
}
