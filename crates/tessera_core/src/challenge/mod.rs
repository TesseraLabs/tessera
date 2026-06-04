//! Challenge-response subsystem.
//!
//! The dispatcher [`challenge_response`] inspects the public key embedded in
//! the end-entity certificate and routes to the matching round-trip
//! implementation:
//!
//! * RSA → [`rsa_pss::challenge_response_rsa_pss`]
//! * EC (P-256/P-384) → [`ecdsa::challenge_response_ecdsa`]
//! * GOST 2012-256 / 2012-512 → [`gost::challenge_response_gost`]
//!
//! For GOST keys the gost-engine must be pinned before
//! `Signer::new`/`Verifier::new` can resolve the digest NID; the
//! dispatcher takes care of that via [`crate::gost::engine::ensure_loaded_with_path`]
//! using an optional path argument supplied by the caller.

pub mod ecdsa;
pub mod error;
pub mod gost;
pub mod rsa_pss;

pub use error::CryptoError;

use std::path::Path;

use openssl::pkey::{Id, PKey, Private};

use crate::gost::engine::ensure_loaded_with_path;
use crate::x509::{Certificate, TrustError};

/// Hardcoded NID for `id-tc26-gost3410-12-256` (GOST R 34.10-2012 256-bit
/// public key).  Stable across all libcrypto versions that ship the
/// `obj_mac.h` table.
const NID_ID_GOST_R3410_2012_256: i32 = 979;
/// Hardcoded NID for `id-tc26-gost3410-12-512` (GOST R 34.10-2012 512-bit
/// public key).
const NID_ID_GOST_R3410_2012_512: i32 = 980;

/// Round-trip a fresh nonce through sign + verify, picking the algorithm based
/// on the public key type embedded in `end_entity`.
///
/// `gost_engine_path` is forwarded to
/// [`crate::gost::engine::ensure_loaded_with_path`] when the key turns out
/// to be GOST-typed; for non-GOST keys it is ignored and the engine
/// `OnceLock` stays cold.
///
/// # Errors
///
/// Propagates [`CryptoError`] from the underlying per-algorithm helper.  If
/// the certificate's public key is neither RSA, ECDSA on a supported curve,
/// nor GOST 2012-256/512, returns [`CryptoError::UnsupportedKey`].
pub fn challenge_response(
    end_entity: &Certificate,
    key: &PKey<Private>,
    gost_engine_path: Option<&Path>,
) -> Result<(), CryptoError> {
    let pub_key = end_entity.public_key().map_err(|e| match e {
        TrustError::Openssl(s) => CryptoError::Openssl(s),
        _ => CryptoError::UnsupportedKey("cannot extract pubkey"),
    })?;
    let id = pub_key.id();
    if id == Id::RSA {
        return rsa_pss::challenge_response_rsa_pss(&pub_key, key);
    }
    if id == Id::EC {
        return ecdsa::challenge_response_ecdsa(&pub_key, key);
    }
    if id == Id::ED25519 {
        return Err(CryptoError::UnsupportedKey("Ed25519 not in stage-2 scope"));
    }
    let raw = id.as_raw();
    if raw == NID_ID_GOST_R3410_2012_256 {
        ensure_loaded_with_path(gost_engine_path)
            .map_err(|source| CryptoError::EngineLoadFailed { source })?;
        let md = crate::gost::algorithms::gost_2012_256_md()
            .map_err(|source| CryptoError::EngineLoadFailed { source })?;
        return gost::challenge_response_gost(&pub_key, key, md);
    }
    if raw == NID_ID_GOST_R3410_2012_512 {
        ensure_loaded_with_path(gost_engine_path)
            .map_err(|source| CryptoError::EngineLoadFailed { source })?;
        let md = crate::gost::algorithms::gost_2012_512_md()
            .map_err(|source| CryptoError::EngineLoadFailed { source })?;
        return gost::challenge_response_gost(&pub_key, key, md);
    }
    Err(CryptoError::UnsupportedKey("unknown"))
}
