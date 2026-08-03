//! Mapping vault: records original-value -> token mappings produced during
//! pseudonymization so authorized parties can reverse tokens later.
//!
//! The vault content is as sensitive as the original data and must be stored
//! and protected separately from the transformed output.
//!
//! TODO(roadmap, Phase 4): encrypted file-backed vault (AEAD + KDF) behind
//! this same trait.

use crate::error::CoreError;

/// One recorded mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingEntry {
    pub field: String,
    pub original: String,
    pub token: String,
}

/// Sink for pseudonym mappings.
pub trait MappingVault {
    /// Record one mapping. Implementations may deduplicate.
    fn record(&mut self, entry: MappingEntry) -> Result<(), CoreError>;
}

/// Discards all mappings (default: tokens are recomputable from the key).
pub struct NoopVault;

impl MappingVault for NoopVault {
    fn record(&mut self, _entry: MappingEntry) -> Result<(), CoreError> {
        Ok(())
    }
}

/// Collects deduplicated mappings in memory; used by tests and as a staging
/// buffer for future persistent vaults.
#[derive(Default)]
pub struct InMemoryVault {
    entries: std::collections::BTreeMap<(String, String), String>,
}

impl InMemoryVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// All recorded mappings, ordered by (field, original).
    pub fn entries(&self) -> impl Iterator<Item = MappingEntry> + '_ {
        self.entries.iter().map(|((field, original), token)| MappingEntry {
            field: field.clone(),
            original: original.clone(),
            token: token.clone(),
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl MappingVault for InMemoryVault {
    fn record(&mut self, entry: MappingEntry) -> Result<(), CoreError> {
        self.entries
            .insert((entry.field, entry.original), entry.token);
        Ok(())
    }
}
