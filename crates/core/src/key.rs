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

/// Minimum length of accepted key material, in bytes.
///
/// Tokens are a fast keyed hash, so a short or guessable secret makes the
/// published output an offline brute-force oracle: an attacker takes one token, a
/// handful of candidate plaintexts, and tries candidate secrets at millions per
/// second per core. Recovering the secret also recovers the vault key, since both
/// derive from it. 32 bytes is the floor at which that attack stops being cheap.
pub const MIN_SECRET_BYTES: usize = 32;

/// Resolve the raw secret material from the policy's key source.
///
/// Prefers the environment variable. If that variable is declared but unset or
/// empty, this **fails closed** rather than using the policy's inline value —
/// see the note inside. The result is length-checked against
/// [`MIN_SECRET_BYTES`].
///
/// Callers derive purpose-specific keys from this — [`derive_dataset_key`] for
/// tokens, [`crate::vault::derive_vault_key`] for vault encryption — so the two
/// never share key material.
pub fn resolve_secret(policy: &Policy, warnings: &mut Vec<String>) -> Result<Vec<u8>, CoreError> {
    let Some(source) = &policy.key else {
        return Err(CoreError::Key(
            "pseudonymization requires a key source in the policy (key.env or key.inline)".into(),
        ));
    };

    let secret = if let Some(var) = &source.env {
        match std::env::var(var) {
            Ok(secret) if !secret.is_empty() => secret.into_bytes(),
            // FAIL CLOSED. Previously an unset or empty variable silently fell
            // through to the inline value, so a renamed variable or an expired CI
            // secret produced a successful job whose tokens anyone with the
            // policy file could reverse — and silently changed every token,
            // breaking joins against earlier exports. The fallback is now opt-in.
            _ => match &source.inline {
                Some(inline) if source.allow_inline_fallback => {
                    warnings.push(format!(
                        "environment variable '{var}' is unset or empty, so the policy's INLINE \
                         key was used (allow_inline_fallback is set). Anyone holding the policy \
                         file can reverse every token in this output"
                    ));
                    tracing::warn!(
                        variable = %var,
                        "falling back to the policy's inline key — demo/test use only"
                    );
                    inline.as_bytes().to_vec()
                }
                Some(_) => {
                    return Err(CoreError::Key(format!(
                        "environment variable '{var}' is not set or is empty. The policy has an \
                         inline key, but falling back to it would silently change every token and \
                         put the secret in the policy file — set \
                         `key.allow_inline_fallback: true` if that is genuinely what you want"
                    )));
                }
                None => {
                    return Err(CoreError::Key(format!(
                        "environment variable '{var}' is not set (and no inline fallback is configured)"
                    )));
                }
            },
        }
    } else if let Some(inline) = &source.inline {
        warnings.push(
            "pseudonymization key was taken from the policy's inline value; \
             configure key.env with a separately managed secret for production use"
                .into(),
        );
        tracing::warn!("using inline pseudonymization key from policy (demo/test use only)");
        inline.as_bytes().to_vec()
    } else {
        return Err(CoreError::Key(
            "key source declares neither env nor inline".into(),
        ));
    };

    check_secret_strength(&secret, warnings)?;
    Ok(secret)
}

/// Enforce a minimum amount of key material and warn about low-entropy input.
///
/// The length floor is a hard error because it is objective. Entropy can only be
/// estimated, so a passphrase-looking secret is warned about rather than
/// rejected: refusing it outright would break working deployments over a guess.
fn check_secret_strength(secret: &[u8], warnings: &mut Vec<String>) -> Result<(), CoreError> {
    if secret.len() < MIN_SECRET_BYTES {
        return Err(CoreError::Key(format!(
            "key material is {} bytes; at least {MIN_SECRET_BYTES} are required. Tokens are a fast \
             keyed hash, so a short secret makes the published output brute-forceable — and the \
             same secret protects the mapping vault. Generate one with e.g. \
             `openssl rand -hex 32`",
            secret.len()
        )));
    }
    let looks_random = secret
        .iter()
        .all(|b| b.is_ascii_hexdigit() || b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
    let distinct = secret.iter().collect::<std::collections::HashSet<_>>().len();
    if !looks_random || distinct < 12 {
        warnings.push(format!(
            "key material is long enough but looks like a passphrase rather than random bytes \
             ({distinct} distinct byte values). Prefer 32+ random bytes, e.g. `openssl rand -hex 32`"
        ));
    }
    Ok(())
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

#[cfg(test)]
mod strength_tests {
    use super::*;
    use crate::policy::{KeySource, Policy};

    fn policy(key: KeySource) -> Policy {
        Policy {
            version: 1,
            dataset: "d".into(),
            key: Some(key),
            on_unlisted: Default::default(),
            fields: Vec::new(),
            patterns: Vec::new(),
            presets: Vec::new(),
        }
    }

    /// A declared-but-unset env var must FAIL rather than silently substituting
    /// the inline value: that turned a misconfigured deployment into a successful
    /// job whose tokens anyone holding the policy could reverse.
    #[test]
    fn missing_env_var_fails_closed_unless_the_fallback_is_opted_into() {
        let long = "x".repeat(40);
        let strict = policy(KeySource {
            env: Some("DEIDENT_TEST_ABSENT_VAR".into()),
            inline: Some(long.clone()),
            allow_inline_fallback: false,
        });
        let err = resolve_secret(&strict, &mut Vec::new()).expect_err("must fail closed");
        assert!(
            err.to_string().contains("allow_inline_fallback"),
            "the error must name the opt-in: {err}"
        );

        let permissive = policy(KeySource {
            env: Some("DEIDENT_TEST_ABSENT_VAR".into()),
            inline: Some(long.clone()),
            allow_inline_fallback: true,
        });
        let mut warnings = Vec::new();
        let secret = resolve_secret(&permissive, &mut warnings).expect("opted in");
        assert_eq!(secret, long.as_bytes());
        assert!(
            warnings.iter().any(|w| w.contains("INLINE")),
            "using the fallback must be loud: {warnings:?}"
        );
    }

    #[test]
    fn short_key_material_is_rejected_with_actionable_advice() {
        let short = policy(KeySource {
            env: None,
            inline: Some("too-short".into()),
            allow_inline_fallback: false,
        });
        let err = resolve_secret(&short, &mut Vec::new()).expect_err("must reject");
        let message = err.to_string();
        assert!(message.contains("at least 32"), "{message}");
        assert!(message.contains("openssl rand"), "must say how to fix it: {message}");
    }

    /// Entropy can only be estimated, so a long passphrase warns rather than
    /// failing — refusing it outright would break working deployments on a guess.
    #[test]
    fn low_entropy_material_warns_but_is_accepted() {
        let passphrase = policy(KeySource {
            env: None,
            inline: Some("correct horse battery staple correct horse".into()),
            allow_inline_fallback: false,
        });
        let mut warnings = Vec::new();
        resolve_secret(&passphrase, &mut warnings).expect("long enough, so accepted");
        assert!(
            warnings.iter().any(|w| w.contains("passphrase")),
            "low entropy must be surfaced: {warnings:?}"
        );

        // 32 random hex bytes draw no entropy warning.
        let random = policy(KeySource {
            env: None,
            inline: Some("9f2c4a7e1b8d6053af21c9e4b70d8a3f".into()),
            allow_inline_fallback: false,
        });
        let mut warnings = Vec::new();
        resolve_secret(&random, &mut warnings).unwrap();
        assert!(
            !warnings.iter().any(|w| w.contains("passphrase")),
            "random hex should not warn: {warnings:?}"
        );
    }
}
