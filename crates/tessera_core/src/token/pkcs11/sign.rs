//! Token-side challenge-response (Task T12).
//!
//! [`pkcs11_challenge_response`] generates a fresh 32-byte nonce, signs
//! it on the token via `C_Sign`, and verifies the signature on the host
//! using the public key embedded in the supplied end-entity certificate.
//! It mirrors the in-process challenge-response under
//! `crate::challenge::*` but never touches private-key bytes — those
//! remain on the token.
//!
//! ## Mechanism dispatch
//!
//! The behaviour depends on which [`TokenSignMechanism`] variant
//! [`super::mechanism::select_mechanism`] picked:
//!
//! - [`TokenSignMechanism::RawSign`] — token does the digest, host
//!   passes the raw nonce in.  RSA-PSS / ECDSA-SHA256 / ECDSA-SHA384
//!   all land here.
//! - [`TokenSignMechanism::PreHashed`] — host hashes the nonce locally
//!   first; relevant for GOST once cryptoki gains a mechanism variant.
//!
//! ## Signature verification on the host
//!
//! For RSA we re-apply PSS parameters (salt length 32, MGF1 SHA-256)
//! on the verifier so the result lines up byte-for-byte with what the
//! token produced.  For ECDSA we use the matching curve digest **and**
//! re-encode the raw `r || s` byte string returned by `C_Sign` into
//! DER (`Ecdsa-Sig-Value`, RFC 3279) — OpenSSL's `Verifier::verify`
//! refuses the raw layout that PKCS#11 mandates.  The verification
//! result feeds into `CryptoError::BadSignature` on failure, which the
//! caller maps to `PAM_AUTH_ERR`.
//!
//! No PIN, nonce, or signature byte ever lands in a log line; the
//! nonce/sig/digest buffers all live in [`Zeroizing`].

use cryptoki::object::{KeyType, ObjectHandle};
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::{PKey, Public};
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Verifier};
use rand::TryRng;
use zeroize::Zeroizing;

use super::error::Pkcs11Error;
use super::locking::with_global_lock;
use super::mechanism::TokenSignMechanism;
use super::session::Pkcs11Session;
use crate::challenge::CryptoError;
use crate::x509::Certificate;

/// Length in bytes of the random challenge.  Matches `crate::challenge::rsa_pss::NONCE_SIZE`.
const NONCE_SIZE: usize = 32;
/// Salt length in bytes for RSA-PSS.  Matches the in-process verifier.
const RSA_PSS_SALT_LEN: i32 = 32;

/// Map a token-side `Pkcs11Error` from `session.sign` into a
/// [`CryptoError`].  Keeps the public type from leaking PKCS#11 specifics
/// into callers that already know about [`CryptoError`].
fn pkcs11_to_crypto(e: Pkcs11Error) -> CryptoError {
    match e {
        Pkcs11Error::Cryptoki(inner) => CryptoError::Rng(format!("token sign failed: {inner}")),
        other => CryptoError::Rng(format!("token sign failed: {other}")),
    }
}

/// Sign a fresh nonce on the token and verify the result on the host.
///
/// `key_type` is consumed by the host-side verifier to pick PSS parameters
/// for RSA (versus a plain `Verifier::new` for ECDSA / GOST).  The
/// public key is extracted from `end_entity` so it always matches the
/// presented certificate, not whatever the token might claim.
///
/// # Errors
///
/// - [`CryptoError::Rng`] — RNG failure, or `session.sign` returned an
///   error from the token (the inner message identifies which).
/// - [`CryptoError::Openssl`] — OpenSSL API failure during host hashing
///   or verifier setup.
/// - [`CryptoError::BadSignature`] — host-side verification rejected the
///   signature (would indicate a key/cert mismatch on the token, or a
///   token misbehaviour).
pub fn pkcs11_challenge_response(
    session: &Pkcs11Session,
    key_handle: ObjectHandle,
    key_type: KeyType,
    mechanism: &TokenSignMechanism,
    end_entity: &Certificate,
) -> Result<(), CryptoError> {
    // 1. Random nonce.
    let mut nonce = Zeroizing::new(vec![0_u8; NONCE_SIZE]);
    rand::rngs::SysRng
        .try_fill_bytes(&mut nonce[..])
        .map_err(|e| CryptoError::Rng(e.to_string()))?;

    // 2. Token sign — feed raw nonce or pre-hashed digest as required.
    let inner = session
        .raw()
        .ok_or_else(|| CryptoError::Rng("pkcs11 session has been logged out".into()))?;
    let mode = session.locking_mode();

    let signature: Zeroizing<Vec<u8>> = match mechanism {
        TokenSignMechanism::RawSign { mechanism: m, .. } => {
            let sig = with_global_lock(mode, || inner.sign(m, key_handle, &nonce))
                .map_err(|source| pkcs11_to_crypto(Pkcs11Error::Cryptoki(source)))?;
            Zeroizing::new(sig)
        }
        TokenSignMechanism::PreHashed {
            mechanism: m,
            host_hash,
        } => {
            let digest = host_hash_nonce(*host_hash, &nonce)?;
            let sig = with_global_lock(mode, || inner.sign(m, key_handle, &digest))
                .map_err(|source| pkcs11_to_crypto(Pkcs11Error::Cryptoki(source)))?;
            Zeroizing::new(sig)
        }
    };

    // 3. Verify on the host using the cert's public key.
    let pubkey = end_entity.public_key().map_err(|e| match e {
        crate::x509::TrustError::Openssl(s) => CryptoError::Rng(format!("pubkey extract: {s}")),
        other => CryptoError::Rng(format!("pubkey extract: {other}")),
    })?;
    let host_hash = mechanism.host_hash();
    verify_on_host(&pubkey, key_type, host_hash, &nonce, &signature)?;
    Ok(())
}

/// Hash `nonce` on the host using `digest` and return a `Zeroizing` buffer.
fn host_hash_nonce(digest: MessageDigest, nonce: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut hasher = Hasher::new(digest)?;
    hasher.update(nonce)?;
    let out = hasher.finish()?;
    Ok(Zeroizing::new(out.to_vec()))
}

/// Run the host-side verification.
///
/// Splits per-`KeyType` because:
///
/// - RSA needs PSS parameters wired into the verifier.
/// - ECDSA signatures returned by PKCS#11 `C_Sign` are raw `r || s`
///   byte strings (each half = curve size in bytes), but
///   [`openssl::sign::Verifier::verify`] expects a DER-encoded
///   `ECDSA-Sig` structure.  We re-encode here before handing the
///   signature to OpenSSL; otherwise valid hardware-token signatures
///   over P-256/P-384 would be rejected as `BadSignature`.
/// - GOST keeps the plain hash + verify path.
fn verify_on_host(
    pubkey: &PKey<Public>,
    key_type: KeyType,
    host_hash: MessageDigest,
    nonce: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let mut verifier = Verifier::new(host_hash, pubkey)?;
    if key_type == KeyType::RSA {
        verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
        verifier.set_rsa_pss_saltlen(RsaPssSaltlen::custom(RSA_PSS_SALT_LEN))?;
        verifier.set_rsa_mgf1_md(host_hash)?;
    }
    verifier.update(nonce)?;

    let ok = if key_type == KeyType::EC {
        let der = ecdsa_raw_to_der(signature)?;
        verifier.verify(&der)?
    } else {
        verifier.verify(signature)?
    };

    if ok {
        Ok(())
    } else {
        Err(CryptoError::BadSignature)
    }
}

/// Convert a raw `r || s` ECDSA signature (as produced by PKCS#11
/// `C_Sign` with `CKM_ECDSA*`) into a DER-encoded `ECDSA-Sig`
/// structure suitable for [`openssl::sign::Verifier::verify`].
///
/// The PKCS#11 spec (v2.40 §2.3.1) defines the ECDSA signature as the
/// concatenation of `r` and `s`, each padded to the byte length of the
/// curve order (32 bytes for P-256, 48 bytes for P-384, 66 for P-521).
/// OpenSSL's `EVP_DigestVerify*` family expects the DER `Ecdsa-Sig-Value`
/// from RFC 3279 instead, so without this conversion every valid token
/// signature would be rejected as `BadSignature`.
///
/// # Errors
///
/// - [`CryptoError::BadSignature`] — the input length is empty or odd
///   (cannot be split into `r` and `s` halves of equal length).
/// - [`CryptoError::Openssl`] — the OpenSSL `BIGNUM` / `EcdsaSig` APIs
///   failed to construct the DER blob.
fn ecdsa_raw_to_der(raw: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        return Err(CryptoError::BadSignature);
    }
    let half = raw.len() / 2;
    let (r_bytes, s_bytes) = raw.split_at(half);
    let r = BigNum::from_slice(r_bytes)?;
    let s = BigNum::from_slice(s_bytes)?;
    let sig = EcdsaSig::from_private_components(r, s)?;
    let der = sig.to_der()?;
    Ok(der)
}

/// Verify an ECDSA signature delivered as raw `r || s` (PKCS#11 layout)
/// against `pubkey` for `data` using `host_hash` as the digest.
///
/// This is the public-facing wrapper that the round-trip unit tests
/// exercise; the production code path inside [`verify_on_host`] performs
/// the same DER conversion before calling [`Verifier::verify`].
///
/// # Errors
///
/// - [`CryptoError::Openssl`] — DER conversion failed or OpenSSL
///   verifier setup returned an error.
/// - [`CryptoError::BadSignature`] — the signature did not verify.
#[cfg(test)]
fn verify_ecdsa_with_raw_signature(
    pubkey: &PKey<Public>,
    host_hash: MessageDigest,
    data: &[u8],
    raw_signature: &[u8],
) -> Result<(), CryptoError> {
    verify_on_host(pubkey, KeyType::EC, host_hash, data, raw_signature)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::err_expect,
        clippy::panic,
        clippy::unwrap_used,
        clippy::indexing_slicing
    )]

    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::{Hasher, MessageDigest};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;

    /// Build a P-256 key pair plus the matching public-only `PKey<Public>`.
    fn p256_keypair() -> (EcKey<openssl::pkey::Private>, PKey<Public>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("p256 group");
        let priv_ec = EcKey::generate(&group).expect("ec gen");
        let pub_der = priv_ec.public_key_to_der().expect("pub der");
        let pubkey = PKey::public_key_from_der(&pub_der).expect("pkey");
        (priv_ec, pubkey)
    }

    /// Hash `data` with `md` and produce a raw `r || s` ECDSA signature
    /// using `priv_ec`.  Mirrors what a PKCS#11 token returns from
    /// `C_Sign` with `CKM_ECDSA_SHA256`.
    fn raw_ecdsa_sign(
        priv_ec: &EcKey<openssl::pkey::Private>,
        md: MessageDigest,
        data: &[u8],
        component_len: usize,
    ) -> Vec<u8> {
        let mut hasher = Hasher::new(md).expect("hasher");
        hasher.update(data).expect("update");
        let digest = hasher.finish().expect("finish");
        let sig = EcdsaSig::sign(&digest, priv_ec).expect("ecdsa sign");
        let mut r = sig.r().to_vec();
        let mut s = sig.s().to_vec();
        // PKCS#11 demands fixed-width `r` and `s` left-padded with zeros.
        let mut r_padded = vec![0_u8; component_len - r.len()];
        r_padded.append(&mut r);
        let mut s_padded = vec![0_u8; component_len - s.len()];
        s_padded.append(&mut s);
        let mut raw = Vec::with_capacity(component_len * 2);
        raw.extend_from_slice(&r_padded);
        raw.extend_from_slice(&s_padded);
        raw
    }

    #[test]
    fn ecdsa_raw_to_der_rejects_empty() {
        let err = ecdsa_raw_to_der(&[]).err().expect("must fail");
        assert!(matches!(err, CryptoError::BadSignature), "got {err:?}");
    }

    #[test]
    fn ecdsa_raw_to_der_rejects_odd_length() {
        let err = ecdsa_raw_to_der(&[0_u8; 31]).err().expect("must fail");
        assert!(matches!(err, CryptoError::BadSignature), "got {err:?}");
    }

    #[test]
    fn ecdsa_raw_to_der_round_trip_p256() {
        // 64-byte raw signature: r and s as 32-byte big-endian halves.
        let mut raw = Vec::with_capacity(64);
        raw.extend_from_slice(&[0x11_u8; 32]);
        raw.extend_from_slice(&[0x22_u8; 32]);
        let der = ecdsa_raw_to_der(&raw).expect("to_der");
        let parsed = EcdsaSig::from_der(&der).expect("from_der");
        let r_back = parsed.r().to_vec();
        let s_back = parsed.s().to_vec();
        // BIGNUM strips leading zeros; the bytes themselves must match.
        assert_eq!(r_back, vec![0x11_u8; 32]);
        assert_eq!(s_back, vec![0x22_u8; 32]);
    }

    #[test]
    fn verify_ecdsa_with_raw_signature_accepts_p256_round_trip() {
        let (priv_ec, pubkey) = p256_keypair();
        let data = b"pkcs11 challenge nonce, 32 bytes_x";
        let raw = raw_ecdsa_sign(&priv_ec, MessageDigest::sha256(), data, 32);
        assert_eq!(raw.len(), 64, "P-256 raw sig must be exactly 64 bytes");
        verify_ecdsa_with_raw_signature(&pubkey, MessageDigest::sha256(), data, &raw)
            .expect("p256 round-trip must verify");
    }

    #[test]
    fn verify_ecdsa_with_raw_signature_rejects_corrupted_first_bytes() {
        let (priv_ec, pubkey) = p256_keypair();
        let data = b"pkcs11 challenge nonce, 32 bytes_x";
        let mut raw = raw_ecdsa_sign(&priv_ec, MessageDigest::sha256(), data, 32);
        // Flip the first 4 bytes of `r` — still a valid BIGNUM, but the
        // signature no longer matches the digest under `pubkey`.
        for b in &mut raw[..4] {
            *b ^= 0xFF;
        }
        let err = verify_ecdsa_with_raw_signature(&pubkey, MessageDigest::sha256(), data, &raw)
            .err()
            .expect("corrupted signature must fail");
        assert!(matches!(err, CryptoError::BadSignature), "got {err:?}");
    }

    #[test]
    fn verify_ecdsa_with_raw_signature_p384_round_trip() {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).expect("p384 group");
        let priv_ec = EcKey::generate(&group).expect("ec gen");
        let pub_der = priv_ec.public_key_to_der().expect("pub der");
        let pubkey = PKey::public_key_from_der(&pub_der).expect("pkey");
        let data = b"pkcs11 challenge nonce, 32 bytes_x";
        let raw = raw_ecdsa_sign(&priv_ec, MessageDigest::sha384(), data, 48);
        assert_eq!(raw.len(), 96, "P-384 raw sig must be exactly 96 bytes");
        verify_ecdsa_with_raw_signature(&pubkey, MessageDigest::sha384(), data, &raw)
            .expect("p384 round-trip must verify");
    }

    #[test]
    fn verify_ecdsa_with_raw_signature_rejects_swapped_r_s() {
        // Signs with the right key but swaps `r` and `s` halves: still
        // 64 bytes, both bignums valid, but the resulting (s, r) pair
        // is not a valid signature for `data` under `pubkey`.
        let (priv_ec, pubkey) = p256_keypair();
        let data = b"pkcs11 challenge nonce, 32 bytes_x";
        let raw = raw_ecdsa_sign(&priv_ec, MessageDigest::sha256(), data, 32);
        let mut swapped = Vec::with_capacity(64);
        swapped.extend_from_slice(&raw[32..]);
        swapped.extend_from_slice(&raw[..32]);
        let err = verify_ecdsa_with_raw_signature(&pubkey, MessageDigest::sha256(), data, &swapped)
            .err()
            .expect("swapped halves must fail");
        assert!(matches!(err, CryptoError::BadSignature), "got {err:?}");
    }
}
