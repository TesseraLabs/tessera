//! Detached Ed25519 signature verification performed before `dlopen`.

use std::path::Path;

use openssl::pkey::{Id, PKey};
use openssl::sign::Verifier;

/// Detached signature verification failure.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    /// Signature file is absent or unreadable.
    #[error("cannot read detached signature: {0}")]
    Read(#[from] std::io::Error),
    /// Signature file has an unsupported or malformed format.
    #[error("malformed detached signature")]
    Malformed,
    /// No verification keys were embedded in this release build.
    #[error("no plugin verification keys embedded")]
    NoKeys,
    /// Signature does not match any embedded key.
    #[error("signature did not match an embedded key")]
    Invalid,
}

fn embedded_keys() -> Vec<[u8; 32]> {
    option_env!("TESSERA_PLUGIN_PUBKEYS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|raw| {
            let bytes = hex::decode(raw.trim()).ok()?;
            bytes.try_into().ok()
        })
        .collect()
}

fn parse_signature(bytes: &[u8]) -> Result<[u8; 64], SignatureError> {
    let text = std::str::from_utf8(bytes).map_err(|_| SignatureError::Malformed)?;
    let encoded = text
        .trim()
        .strip_prefix("ed25519:")
        .ok_or(SignatureError::Malformed)?;
    let raw = hex::decode(encoded).map_err(|_| SignatureError::Malformed)?;
    raw.try_into().map_err(|_| SignatureError::Malformed)
}

/// Verify `<plugin>.sig` over the exact shared-library bytes.
///
/// The signature format is `ed25519:<128 lowercase-or-uppercase hex chars>`.
/// The algorithm prefix is mandatory so a future ABI can add ГОСТ without
/// interpreting an old signature ambiguously.
///
/// # Errors
///
/// Returns [`SignatureError`] when the signature cannot be read, parsed, or
/// verified by any embedded public key.
pub fn verify_detached_signature(plugin: &Path, signature: &Path) -> Result<(), SignatureError> {
    verify_with_keys(plugin, signature, &embedded_keys())
}

fn verify_with_keys(
    plugin: &Path,
    signature: &Path,
    keys: &[[u8; 32]],
) -> Result<(), SignatureError> {
    let body = std::fs::read(plugin)?;
    let signature = parse_signature(&std::fs::read(signature)?)?;
    if keys.is_empty() {
        return Err(SignatureError::NoKeys);
    }
    for key in keys {
        let Ok(pkey) = PKey::public_key_from_raw_bytes(key.as_slice(), Id::ED25519) else {
            continue;
        };
        let Ok(mut verifier) = Verifier::new_without_digest(&pkey) else {
            continue;
        };
        if verifier.verify_oneshot(&signature, &body).unwrap_or(false) {
            return Ok(());
        }
    }
    Err(SignatureError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::sign::Signer;

    #[test]
    fn signature_requires_algorithm_identifier() {
        assert!(matches!(
            parse_signature(&[b'0'; 128]),
            Err(SignatureError::Malformed)
        ));
    }

    #[test]
    fn signature_rejects_wrong_length() {
        assert!(matches!(
            parse_signature(b"ed25519:00"),
            Err(SignatureError::Malformed)
        ));
    }

    #[test]
    fn verifies_valid_and_rejects_foreign_signature() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let plugin = temp.path().join("plugin.so");
        let signature_path = temp.path().join("plugin.so.sig");
        std::fs::write(&plugin, b"plugin bytes")?;

        let key = PKey::generate_ed25519()?;
        let mut signer = Signer::new_without_digest(&key)?;
        let signature = signer.sign_oneshot_to_vec(b"plugin bytes")?;
        std::fs::write(
            &signature_path,
            format!("ed25519:{}", hex::encode(signature)),
        )?;
        let public_bytes = key.raw_public_key()?;
        let public: [u8; 32] = public_bytes.as_slice().try_into()?;
        verify_with_keys(&plugin, &signature_path, &[public])?;

        std::fs::write(&plugin, b"plugin bytes modified")?;
        if !matches!(
            verify_with_keys(&plugin, &signature_path, &[public]),
            Err(SignatureError::Invalid)
        ) {
            return Err(std::io::Error::other("modified plugin was not rejected").into());
        }

        let foreign = PKey::generate_ed25519()?;
        let foreign_bytes = foreign.raw_public_key()?;
        let foreign_public: [u8; 32] = foreign_bytes.as_slice().try_into()?;
        if !matches!(
            verify_with_keys(&plugin, &signature_path, &[foreign_public]),
            Err(SignatureError::Invalid)
        ) {
            return Err(std::io::Error::other("foreign key was not rejected").into());
        }
        Ok(())
    }

    #[test]
    fn rejects_missing_signature_and_empty_trust_store() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let plugin = temp.path().join("plugin.so");
        std::fs::write(&plugin, b"plugin bytes")?;
        if !matches!(
            verify_with_keys(&plugin, &temp.path().join("missing.sig"), &[]),
            Err(SignatureError::Read(_))
        ) {
            return Err(std::io::Error::other("missing signature was not rejected").into());
        }

        let signature_path = temp.path().join("plugin.so.sig");
        std::fs::write(&signature_path, format!("ed25519:{}", "00".repeat(64)))?;
        if !matches!(
            verify_with_keys(&plugin, &signature_path, &[]),
            Err(SignatureError::NoKeys)
        ) {
            return Err(std::io::Error::other("empty trust store was not rejected").into());
        }
        Ok(())
    }
}
