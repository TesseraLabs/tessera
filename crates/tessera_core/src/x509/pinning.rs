//! Trust-anchor `SubjectPublicKeyInfo` pinning.
//! See `T08` in the stage-2 plan.
//!
//! Operators may pin the SHA-256 of the trust anchor's `SubjectPublicKeyInfo`
//! (SPKI) so that an attacker who silently swaps the anchor in `/etc` cannot
//! trick the PAM into trusting a forged chain.

use super::{Certificate, TrustError};
use sha2::{Digest, Sha256};

/// 32-byte SHA-256 of an SPKI block.
pub type SpkiPin = [u8; 32];

/// Computes the SHA-256 of `cert`'s `SubjectPublicKeyInfo`.
///
/// The hash is taken over the DER-encoded public-key blob (the same byte
/// stream that `openssl x509 -pubkey -noout` produces, minus the PEM
/// header/footer).  Two certificates with identical public keys therefore
/// hash identically even if their other fields differ.
///
/// # Errors
///
/// Returns [`TrustError::Openssl`] if libcrypto cannot extract the public key.
pub fn spki_sha256(cert: &Certificate) -> Result<SpkiPin, TrustError> {
    let pk = cert.public_key()?;
    let der = pk.public_key_to_der().map_err(TrustError::Openssl)?;
    let mut h = Sha256::new();
    h.update(&der);
    let out = h.finalize();
    let mut pin = [0u8; 32];
    pin.copy_from_slice(&out);
    Ok(pin)
}

/// Verifies that `anchor`'s SPKI hash is in `pins`.
///
/// An empty `pins` slice means pinning is disabled and this function returns
/// `Ok(())` without inspecting the anchor.  Callers that wish to enforce
/// "pinning must be on" should validate `pins.is_empty()` themselves.
///
/// # Errors
///
/// * [`TrustError::PinMismatch`] if no pin matches.
/// * [`TrustError::Openssl`] if the anchor's public key cannot be extracted.
pub fn verify_pinning(anchor: &Certificate, pins: &[SpkiPin]) -> Result<(), TrustError> {
    if pins.is_empty() {
        return Ok(());
    }
    let actual = spki_sha256(anchor)?;
    if pins.contains(&actual) {
        Ok(())
    } else {
        Err(TrustError::PinMismatch)
    }
}
