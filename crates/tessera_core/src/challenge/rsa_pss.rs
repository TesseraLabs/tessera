//! RSA-PSS challenge-response.
//!
//! Generates a 32-byte nonce, signs it with `RSASSA-PSS-SHA256` (salt length
//! 32 bytes, MGF1=SHA-256), then verifies the signature with the matching
//! public key.  Both the nonce and the signature are held in
//! [`zeroize::Zeroizing`] so they are wiped from memory before the function
//! returns.

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Signer, Verifier};
use rand::TryRng;
use zeroize::Zeroizing;

use super::error::CryptoError;

/// Size in bytes of the random nonce used for the round-trip.
pub(crate) const NONCE_SIZE: usize = 32;

/// Same value as [`NONCE_SIZE`] but typed as `i32` so it can be passed to
/// `RsaPssSaltlen::custom` without a fallible `usize -> i32` conversion.
const NONCE_SIZE_I32: i32 = 32;

/// Round-trip a freshly generated nonce through RSA-PSS sign + verify.
///
/// # Errors
///
/// * [`CryptoError::Rng`] — `OsRng` failed to fill the nonce.
/// * [`CryptoError::Openssl`] — any OpenSSL-side failure during signing or
///   verification setup.
/// * [`CryptoError::BadSignature`] — the produced signature did not verify
///   under the supplied public key (would indicate the keys are mismatched or
///   the OpenSSL backend is misbehaving).
pub fn challenge_response_rsa_pss(
    pub_key: &PKey<Public>,
    priv_key: &PKey<Private>,
) -> Result<(), CryptoError> {
    let mut nonce = Zeroizing::new(vec![0_u8; NONCE_SIZE]);
    rand::rngs::SysRng
        .try_fill_bytes(&mut nonce[..])
        .map_err(|e| CryptoError::Rng(e.to_string()))?;

    let mut signer = Signer::new(MessageDigest::sha256(), priv_key)?;
    signer.set_rsa_padding(Padding::PKCS1_PSS)?;
    signer.set_rsa_pss_saltlen(RsaPssSaltlen::custom(NONCE_SIZE_I32))?;
    signer.set_rsa_mgf1_md(MessageDigest::sha256())?;
    signer.update(&nonce)?;
    let sig = Zeroizing::new(signer.sign_to_vec()?);

    let mut verifier = Verifier::new(MessageDigest::sha256(), pub_key)?;
    verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
    verifier.set_rsa_pss_saltlen(RsaPssSaltlen::custom(NONCE_SIZE_I32))?;
    verifier.set_rsa_mgf1_md(MessageDigest::sha256())?;
    verifier.update(&nonce)?;
    if !verifier.verify(&sig)? {
        return Err(CryptoError::BadSignature);
    }
    Ok(())
}
