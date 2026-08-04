//! Mapping vault: records original-value → token mappings produced during
//! pseudonymization so authorized parties can reverse tokens later.
//!
//! Vault content is as sensitive as the original data — it *is* the
//! re-identification table. [`EncryptedVault`] therefore encrypts every entry
//! with XChaCha20-Poly1305 under a key derived from the same secret as the
//! tokens (different KDF context), and the file must still be stored and
//! access-controlled separately from the transformed output.
//!
//! Nonces are **synthetic**: derived from the key and the plaintext rather
//! than randomly. That makes vault files reproducible and, more importantly,
//! keeps appends safe — re-recording the same mapping reuses the same
//! (nonce, plaintext) pair instead of risking nonce reuse across runs. The
//! trade-off is that identical entries produce identical ciphertext, which
//! reveals that two lines map the same value. For a deterministic mapping
//! table that equality is inherent to the design, not new leakage.

use std::io::{BufRead, Write};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// KDF context for vault encryption keys (distinct from the token context, so
/// the vault key cannot be used to forge tokens or vice versa).
const VAULT_KDF_CONTEXT: &str = "deident-wasm/v1/vault/";
/// Nonce derivation context.
const NONCE_CONTEXT: &str = "deident-wasm/v1/vault-nonce/";
/// Current vault file format version.
const VAULT_FORMAT_VERSION: u32 = 1;

/// One recorded mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingEntry {
    /// Token domain the mapping belongs to (column name, or `pattern:<rule>`).
    pub field: String,
    pub original: String,
    pub token: String,
}

/// Sink for pseudonym mappings.
pub trait MappingVault {
    /// Record one mapping. Implementations may deduplicate.
    fn record(&mut self, entry: MappingEntry) -> Result<(), CoreError>;

    /// Flush any buffered state. Called once when a job finishes.
    fn finish(&mut self) -> Result<(), CoreError> {
        Ok(())
    }
}

/// Discards all mappings (default: tokens are recomputable from the key).
pub struct NoopVault;

impl MappingVault for NoopVault {
    fn record(&mut self, _entry: MappingEntry) -> Result<(), CoreError> {
        Ok(())
    }
}

/// Collects deduplicated mappings in memory; used by tests and as a staging
/// buffer for persistent vaults.
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

/// Header line of a vault file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultHeader {
    format: String,
    version: u32,
    dataset: String,
    cipher: String,
    kdf: String,
}

/// One encrypted line of a vault file.
#[derive(Debug, Serialize, Deserialize)]
struct VaultLine {
    /// Synthetic nonce (hex).
    n: String,
    /// Ciphertext + authentication tag (hex).
    c: String,
}

/// Derive the vault encryption key for a dataset from the raw secret.
pub fn derive_vault_key(secret: &[u8], dataset: &str) -> [u8; 32] {
    blake3::derive_key(&format!("{VAULT_KDF_CONTEXT}{dataset}"), secret)
}

/// Encrypting, append-only vault writer.
///
/// Entries are deduplicated in memory for the lifetime of the writer, then
/// written as one encrypted JSON line each on [`MappingVault::finish`].
pub struct EncryptedVault<W: Write> {
    writer: W,
    cipher: XChaCha20Poly1305,
    nonce_key: [u8; 32],
    dataset: String,
    entries: std::collections::BTreeMap<(String, String), String>,
    header_written: bool,
}

impl<W: Write> EncryptedVault<W> {
    /// Create a vault writer over `writer` using `vault_key` (see
    /// [`derive_vault_key`]).
    pub fn new(writer: W, vault_key: &[u8; 32], dataset: &str) -> Self {
        Self {
            writer,
            cipher: XChaCha20Poly1305::new(Key::from_slice(vault_key)),
            nonce_key: *vault_key,
            dataset: dataset.to_string(),
            entries: std::collections::BTreeMap::new(),
            header_written: false,
        }
    }

    fn header(&self) -> VaultHeader {
        VaultHeader {
            format: "deident-vault".to_string(),
            version: VAULT_FORMAT_VERSION,
            dataset: self.dataset.clone(),
            cipher: "xchacha20poly1305".to_string(),
            kdf: "blake3-derive-key".to_string(),
        }
    }

    fn write_line(&mut self, entry: &MappingEntry) -> Result<(), CoreError> {
        let plaintext = serde_json::to_vec(entry)
            .map_err(|e| CoreError::Vault(format!("cannot serialize mapping: {e}")))?;
        let aad = aad(&self.dataset);
        let nonce = synthetic_nonce(&self.nonce_key, &plaintext);
        let ciphertext = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| CoreError::Vault("encryption failed".into()))?;
        let line = VaultLine {
            n: hex(&nonce),
            c: hex(&ciphertext),
        };
        let mut buf = serde_json::to_vec(&line)
            .map_err(|e| CoreError::Vault(format!("cannot serialize vault line: {e}")))?;
        buf.push(b'\n');
        self.writer
            .write_all(&buf)
            .map_err(|e| CoreError::Vault(format!("cannot write vault: {e}")))
    }
}

impl<W: Write> MappingVault for EncryptedVault<W> {
    fn record(&mut self, entry: MappingEntry) -> Result<(), CoreError> {
        self.entries
            .insert((entry.field, entry.original), entry.token);
        Ok(())
    }

    fn finish(&mut self) -> Result<(), CoreError> {
        if !self.header_written {
            let mut header = serde_json::to_vec(&self.header())
                .map_err(|e| CoreError::Vault(format!("cannot serialize vault header: {e}")))?;
            header.push(b'\n');
            self.writer
                .write_all(&header)
                .map_err(|e| CoreError::Vault(format!("cannot write vault: {e}")))?;
            self.header_written = true;
        }
        let entries: Vec<MappingEntry> = std::mem::take(&mut self.entries)
            .into_iter()
            .map(|((field, original), token)| MappingEntry {
                field,
                original,
                token,
            })
            .collect();
        for entry in &entries {
            self.write_line(entry)?;
        }
        self.writer
            .flush()
            .map_err(|e| CoreError::Vault(format!("cannot flush vault: {e}")))
    }
}

/// Read and decrypt every mapping from a vault file.
///
/// Fails if the key is wrong, the file was tampered with, or the format
/// version is unknown — authentication is part of the AEAD, so a modified
/// line cannot decrypt silently.
pub fn read_vault<R: BufRead>(
    reader: R,
    vault_key: &[u8; 32],
) -> Result<Vec<MappingEntry>, CoreError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(vault_key));
    let mut lines = reader.lines();
    let header_line = lines
        .next()
        .transpose()
        .map_err(|e| CoreError::Vault(format!("cannot read vault: {e}")))?
        .ok_or_else(|| CoreError::Vault("vault file is empty".into()))?;
    let header: VaultHeader = serde_json::from_str(&header_line)
        .map_err(|e| CoreError::Vault(format!("invalid vault header: {e}")))?;
    if header.format != "deident-vault" {
        return Err(CoreError::Vault(format!(
            "not a deident vault file (format: {})",
            header.format
        )));
    }
    if header.version != VAULT_FORMAT_VERSION {
        return Err(CoreError::Vault(format!(
            "unsupported vault format version {} (expected {VAULT_FORMAT_VERSION})",
            header.version
        )));
    }
    let aad = aad(&header.dataset);

    let mut entries = Vec::new();
    for (i, line) in lines.enumerate() {
        let line = line.map_err(|e| CoreError::Vault(format!("cannot read vault: {e}")))?;
        if line.trim().is_empty() {
            continue;
        }
        let parsed: VaultLine = serde_json::from_str(&line)
            .map_err(|e| CoreError::Vault(format!("invalid vault line {}: {e}", i + 2)))?;
        let nonce = unhex(&parsed.n)
            .ok_or_else(|| CoreError::Vault(format!("invalid nonce on line {}", i + 2)))?;
        let ciphertext = unhex(&parsed.c)
            .ok_or_else(|| CoreError::Vault(format!("invalid ciphertext on line {}", i + 2)))?;
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| {
                CoreError::Vault(format!(
                    "cannot decrypt vault line {} — wrong key or tampered file",
                    i + 2
                ))
            })?;
        entries.push(
            serde_json::from_slice(&plaintext)
                .map_err(|e| CoreError::Vault(format!("invalid mapping on line {}: {e}", i + 2)))?,
        );
    }
    Ok(entries)
}

/// Additional authenticated data binding a line to its vault.
fn aad(dataset: &str) -> String {
    format!("deident-vault/v{VAULT_FORMAT_VERSION}/{dataset}")
}

/// Synthetic (deterministic) 24-byte nonce for `plaintext` under `key`.
fn synthetic_nonce(key: &[u8; 32], plaintext: &[u8]) -> [u8; 24] {
    let mut hasher = blake3::Hasher::new_derive_key(NONCE_CONTEXT);
    hasher.update(key);
    hasher.update(plaintext);
    let mut nonce = [0u8; 24];
    hasher.finalize_xof().fill(&mut nonce);
    nonce
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).expect("nibble"));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).expect("nibble"));
    }
    out
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = char::from(pair[0]).to_digit(16)?;
            let lo = char::from(pair[1]).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<MappingEntry> {
        vec![
            MappingEntry {
                field: "patient_id".into(),
                original: "P001".into(),
                token: "pid_abc".into(),
            },
            MappingEntry {
                field: "pattern:iban".into(),
                original: "DE89370400440532013000".into(),
                token: "DE02999...".into(),
            },
        ]
    }

    fn write_vault(key: &[u8; 32]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut vault = EncryptedVault::new(&mut buf, key, "ds");
            for entry in entries() {
                vault.record(entry).unwrap();
            }
            vault.finish().unwrap();
        }
        buf
    }

    #[test]
    fn round_trips_through_encryption() {
        let key = derive_vault_key(b"secret", "ds");
        let raw = write_vault(&key);
        let mut decrypted = read_vault(raw.as_slice(), &key).unwrap();
        decrypted.sort_by(|a, b| a.field.cmp(&b.field));
        let mut expected = entries();
        expected.sort_by(|a, b| a.field.cmp(&b.field));
        assert_eq!(decrypted, expected);
    }

    #[test]
    fn plaintext_never_appears_in_the_file() {
        let key = derive_vault_key(b"secret", "ds");
        let raw = String::from_utf8(write_vault(&key)).unwrap();
        assert!(!raw.contains("P001"), "original value leaked");
        assert!(!raw.contains("pid_abc"), "token leaked");
        assert!(!raw.contains("DE89370400440532013000"));
        assert!(raw.contains("deident-vault"), "header must be readable");
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let raw = write_vault(&derive_vault_key(b"secret", "ds"));
        let err = read_vault(raw.as_slice(), &derive_vault_key(b"other-secret", "ds")).unwrap_err();
        assert!(err.to_string().contains("wrong key"), "{err}");
    }

    #[test]
    fn tampering_is_detected() {
        let key = derive_vault_key(b"secret", "ds");
        let raw = String::from_utf8(write_vault(&key)).unwrap();
        let mut lines: Vec<String> = raw.lines().map(str::to_string).collect();
        // Flip one hex nibble of the first entry's ciphertext.
        let last = lines[1].clone();
        let idx = last.find("\"c\":\"").unwrap() + 5;
        let mut bytes: Vec<char> = last.chars().collect();
        bytes[idx] = if bytes[idx] == 'a' { 'b' } else { 'a' };
        lines[1] = bytes.into_iter().collect();
        let tampered = lines.join("\n");
        assert!(read_vault(tampered.as_bytes(), &key).is_err());
    }

    #[test]
    fn vault_key_differs_from_token_key() {
        assert_ne!(
            derive_vault_key(b"secret", "ds"),
            crate::key::derive_dataset_key(b"secret", "ds")
        );
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0u8, 15, 16, 255, 128];
        assert_eq!(unhex(&hex(&bytes)).unwrap(), bytes);
        assert!(unhex("xyz").is_none());
    }
}
