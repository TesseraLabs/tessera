//! GOST R 34.10-2012 challenge-response.
//!
//! Generates a 32-byte nonce, signs it with GOST 2012-256 / 2012-512 (the
//! digest is paired with the key length per TC26's recommendation, i.e.
//! Streebog-256 for a 256-bit key and Streebog-512 for a 512-bit key),
//! then verifies the signature with the matching public key.
//!
//! The nonce and the signature are held in [`zeroize::Zeroizing`] so the
//! bytes are wiped from memory before the function returns.
//!
//! This module assumes that [`crate::gost::engine::ensure_loaded`] has
//! already succeeded — callers must guarantee the engine is pinned, or the
//! `Signer::new` call below will fail with an OpenSSL error.  The
//! dispatcher in [`super::challenge_response`] enforces that contract.

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use rand::TryRng;
use zeroize::Zeroizing;

use super::error::CryptoError;
use super::rsa_pss::NONCE_SIZE;

/// Round-trip a freshly generated nonce through GOST sign + verify.
///
/// `hash_md` MUST be one of the digests returned by
/// [`crate::gost::algorithms::gost_2012_256_md`] /
/// [`crate::gost::algorithms::gost_2012_512_md`] — i.e. the engine-provided
/// Streebog handles.  Passing a non-GOST digest will produce an OpenSSL
/// error from `Signer::new`.
///
/// # Errors
///
/// * [`CryptoError::Rng`] — `OsRng` failed to fill the nonce.
/// * [`CryptoError::Openssl`] — OpenSSL-side failure during signing or
///   verification setup (typically: engine not pinned, key type/digest
///   mismatch).
/// * [`CryptoError::BadSignature`] — the produced signature did not verify
///   under the supplied public key.
pub fn challenge_response_gost(
    pub_key: &PKey<Public>,
    priv_key: &PKey<Private>,
    hash_md: MessageDigest,
) -> Result<(), CryptoError> {
    let mut nonce = Zeroizing::new(vec![0_u8; NONCE_SIZE]);
    rand::rngs::SysRng
        .try_fill_bytes(&mut nonce[..])
        .map_err(|e| CryptoError::Rng(e.to_string()))?;

    let mut signer = Signer::new(hash_md, priv_key)?;
    signer.update(&nonce)?;
    let sig = Zeroizing::new(signer.sign_to_vec()?);

    let mut verifier = Verifier::new(hash_md, pub_key)?;
    verifier.update(&nonce)?;
    if !verifier.verify(&sig)? {
        return Err(CryptoError::BadSignature);
    }
    Ok(())
}
