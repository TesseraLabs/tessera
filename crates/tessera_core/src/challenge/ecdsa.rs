//! ECDSA challenge-response.
//!
//! Generates a 32-byte nonce, signs it with ECDSA over a curve-derived hash
//! (SHA-256 for P-256, SHA-384 for P-384), then verifies the signature with
//! the matching public key.  Nonce and signature are held in
//! [`zeroize::Zeroizing`] so the bytes are wiped on drop.

use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use rand::TryRng;
use zeroize::Zeroizing;

use super::error::CryptoError;
use super::rsa_pss::NONCE_SIZE;

/// Round-trip a freshly generated nonce through ECDSA sign + verify.
///
/// The hash algorithm is selected based on the curve embedded in `pub_key`:
///
/// * P-256 (`prime256v1`) → SHA-256
/// * P-384 (`secp384r1`) → SHA-384
///
/// Any other curve, including unnamed/explicit curves, is rejected with
/// [`CryptoError::UnsupportedKey`].
///
/// # Errors
///
/// * [`CryptoError::Rng`] — `OsRng` failed to fill the nonce.
/// * [`CryptoError::Openssl`] — OpenSSL-side failure during signing or
///   verification setup.
/// * [`CryptoError::UnsupportedKey`] — the EC key has no named curve or uses
///   a curve outside the supported set.
/// * [`CryptoError::BadSignature`] — the produced signature did not verify
///   under the supplied public key.
pub fn challenge_response_ecdsa(
    pub_key: &PKey<Public>,
    priv_key: &PKey<Private>,
) -> Result<(), CryptoError> {
    let md = ec_digest(pub_key)?;

    let mut nonce = Zeroizing::new(vec![0_u8; NONCE_SIZE]);
    rand::rngs::SysRng
        .try_fill_bytes(&mut nonce[..])
        .map_err(|e| CryptoError::Rng(e.to_string()))?;

    let mut signer = Signer::new(md, priv_key)?;
    signer.update(&nonce)?;
    let sig = Zeroizing::new(signer.sign_to_vec()?);

    let mut verifier = Verifier::new(md, pub_key)?;
    verifier.update(&nonce)?;
    if !verifier.verify(&sig)? {
        return Err(CryptoError::BadSignature);
    }
    Ok(())
}

/// Pick the ECDSA hash algorithm that pairs with the curve of `pk`.
fn ec_digest(pk: &PKey<Public>) -> Result<MessageDigest, CryptoError> {
    let ec = pk.ec_key()?;
    let curve_nid = ec
        .group()
        .curve_name()
        .ok_or(CryptoError::UnsupportedKey("EC w/o named curve"))?;
    match curve_nid {
        Nid::X9_62_PRIME256V1 => Ok(MessageDigest::sha256()),
        Nid::SECP384R1 => Ok(MessageDigest::sha384()),
        _ => Err(CryptoError::UnsupportedKey("EC curve not supported")),
    }
}
