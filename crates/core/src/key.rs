//! Key resolution and deterministic tokenization.
//!
//! Tokens are BLAKE3 keyed hashes of `field \x1f value` under a key derived
//! from the configured secret and the dataset name. The same value therefore
//! maps to the same token within one dataset/policy (stable pseudonyms), but
//! to different tokens across fields and datasets.

use crate::error::CoreError;
use crate::policy::Policy;

/// Domain-separation context prefix for key derivation.
const KDF_CONTEXT_PREFIX: &str = "deident-wasm/v1/pseudonym/";

/// Resolve the raw secret material from the policy's key source. Prefers the
/// environment variable; falls back to the inline secret with a warning
/// pushed to `warnings`.
///
/// Callers derive purpose-specific keys from this — [`derive_dataset_key`]
/// for tokens, [`crate::vault::derive_vault_key`] for vault encryption — so
/// the two never share key material.
pub fn resolve_secret(policy: &Policy, warnings: &mut Vec<String>) -> Result<Vec<u8>, CoreError> {
    let Some(source) = &policy.key else {
        return Err(CoreError::Key(
            "pseudonymization requires a key source in the policy (key.env or key.inline)".into(),
        ));
    };
    if let Some(var) = &source.env {
        match std::env::var(var) {
            Ok(secret) if !secret.is_empty() => return Ok(secret.into_bytes()),
            _ if source.inline.is_none() => {
                return Err(CoreError::Key(format!(
                    "environment variable '{var}' is not set (and no inline fallback is configured)"
                )));
            }
            _ => {}
        }
    }
    if let Some(inline) = &source.inline {
        warnings.push(
            "pseudonymization key was taken from the policy's inline value; \
             configure key.env with a separately managed secret for production use"
                .into(),
        );
        tracing::warn!("using inline pseudonymization key from policy (demo/test use only)");
        return Ok(inline.as_bytes().to_vec());
    }
    Err(CoreError::Key(
        "key source declares neither env nor inline".into(),
    ))
}

/// Resolve the dataset-scoped tokenization key from the policy's key source.
pub fn resolve_dataset_key(
    policy: &Policy,
    warnings: &mut Vec<String>,
) -> Result<[u8; 32], CoreError> {
    let secret = resolve_secret(policy, warnings)?;
    Ok(derive_dataset_key(&secret, &policy.dataset))
}

/// Derive the per-dataset key from raw secret material.
pub fn derive_dataset_key(secret: &[u8], dataset: &str) -> [u8; 32] {
    let context = format!("{KDF_CONTEXT_PREFIX}{dataset}");
    blake3::derive_key(&context, secret)
}

/// Deterministic token for `value` in column `field`: 128-bit keyed hash,
/// hex-encoded, with an optional display prefix.
pub fn token(key: &[u8; 32], field: &str, value: &str, prefix: Option<&str>) -> String {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(field.as_bytes());
    hasher.update(&[0x1f]);
    hasher.update(value.as_bytes());
    let hex = hasher.finalize().to_hex();
    format!("{}{}", prefix.unwrap_or(""), &hex[..32])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_deterministic() {
        let key = derive_dataset_key(b"secret", "ds");
        assert_eq!(token(&key, "email", "a@b.c", None), token(&key, "email", "a@b.c", None));
    }

    #[test]
    fn tokens_differ_per_field_dataset_and_value() {
        let key = derive_dataset_key(b"secret", "ds");
        let other_key = derive_dataset_key(b"secret", "other-ds");
        let base = token(&key, "email", "a@b.c", None);
        assert_ne!(base, token(&key, "name", "a@b.c", None), "field separation");
        assert_ne!(base, token(&key, "email", "x@b.c", None), "value separation");
        assert_ne!(base, token(&other_key, "email", "a@b.c", None), "dataset separation");
    }

    #[test]
    fn prefix_is_prepended() {
        let key = derive_dataset_key(b"secret", "ds");
        let t = token(&key, "id", "P001", Some("pid_"));
        assert!(t.starts_with("pid_"));
        assert_eq!(t.len(), 4 + 32);
    }
}
