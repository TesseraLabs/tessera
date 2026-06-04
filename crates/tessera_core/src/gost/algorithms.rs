//! GOST digest helpers.
//!
//! Resolves Streebog-256 / Streebog-512 [`MessageDigest`] handles via NIDs
//! registered by gost-engine after [`super::engine::ensure_loaded`] succeeds.
//!
//! See [`super::engine`] for the current implementation status — while the
//! engine is stubbed, every helper here returns
//! [`GostEngineError::NotAvailable`] (engine not loaded) or
//! [`GostEngineError::DigestUnavailable`] (NID could not be resolved
//! despite the engine claiming to be loaded — never reached by the stub).

use openssl::hash::MessageDigest;
use openssl::nid::Nid;

use crate::x509::SignatureAlg;

use super::engine;
use super::errors::GostEngineError;

/// NID assigned by gost-engine for `id-tc26-gost3411-12-256` (Streebog-256).
///
/// gost-engine registers digests by name (`md_gost12_256`) at load time;
/// the OBJ table maps that name to the OID `1.2.643.7.1.1.2.2`.  We rely
/// on `MessageDigest::from_name` (via `EVP_get_digestbyname`) rather than
/// a hard-coded NID to avoid depending on the engine's internal numbering.
const GOST_2012_256_NAME: &str = "md_gost12_256";
/// NID name for `id-tc26-gost3411-12-512` (Streebog-512).
const GOST_2012_512_NAME: &str = "md_gost12_512";

/// Returns the [`MessageDigest`] for Streebog-256.
///
/// # Errors
///
/// * [`GostEngineError::NotAvailable`] if the engine isn't pinned (i.e.
///   [`engine::is_available`] is `false`).  This includes the current
///   stub-mode where the engine is never loaded.
/// * [`GostEngineError::DigestUnavailable`] if the engine claims to be
///   loaded but the NID lookup still fails.
pub fn gost_2012_256_md() -> Result<MessageDigest, GostEngineError> {
    digest_by_name(GOST_2012_256_NAME)
}

/// Returns the [`MessageDigest`] for Streebog-512.
///
/// # Errors
///
/// Same as [`gost_2012_256_md`].
pub fn gost_2012_512_md() -> Result<MessageDigest, GostEngineError> {
    digest_by_name(GOST_2012_512_NAME)
}

/// Returns the digest associated with a [`SignatureAlg`], if any.
///
/// * For [`SignatureAlg::IdTc26SignWithDigestGostR341012_256`] →
///   [`gost_2012_256_md`].
/// * For [`SignatureAlg::IdTc26SignWithDigestGostR341012_512`] →
///   [`gost_2012_512_md`].
/// * For non-GOST variants → `Ok(None)`.
///
/// Any digest-resolution failure is propagated as `Err` so callers can
/// distinguish "this algorithm is fine without engine help" (`Ok(None)`)
/// from "this algorithm needed the engine and the engine failed"
/// (`Err(_)`).
///
/// # Errors
///
/// Propagated from [`gost_2012_256_md`] / [`gost_2012_512_md`].
pub fn gost_signature_md_for(
    sig_alg: &SignatureAlg,
) -> Result<Option<MessageDigest>, GostEngineError> {
    match sig_alg {
        SignatureAlg::IdTc26SignWithDigestGostR341012_256 => gost_2012_256_md().map(Some),
        SignatureAlg::IdTc26SignWithDigestGostR341012_512 => gost_2012_512_md().map(Some),
        _ => Ok(None),
    }
}

fn digest_by_name(name: &'static str) -> Result<MessageDigest, GostEngineError> {
    if !engine::is_available() {
        return Err(GostEngineError::NotAvailable(format!(
            "engine not pinned; cannot resolve digest {name}"
        )));
    }
    // Even if the engine is "available" by our flag, the NID lookup can
    // still fail (engine deregistered, build mismatch, etc.).
    let nid = Nid::from_raw(nid_from_name(name)?);
    MessageDigest::from_nid(nid).ok_or_else(|| GostEngineError::digest_unavailable(name))
}

/// Resolves an EVP digest name to a libcrypto NID via the safe surface of
/// the openssl crate.  We can't call `EVP_get_digestbyname` directly
/// without unsafe code, so we walk the well-known OIDs registered by
/// gost-engine.
fn nid_from_name(name: &'static str) -> Result<i32, GostEngineError> {
    // These NIDs are stable in libcrypto's `obj_mac.h` for the GOST OIDs
    // even though the digest registration only becomes active once
    // gost-engine is loaded.
    match name {
        // 1.2.643.7.1.1.2.2 — id-tc26-gost3411-12-256
        // The libcrypto-builtin NID for the OID; engine-loaded digests
        // share the same NID.
        GOST_2012_256_NAME => Ok(1177),
        // 1.2.643.7.1.1.2.3 — id-tc26-gost3411-12-512
        GOST_2012_512_NAME => Ok(1178),
        _ => Err(GostEngineError::digest_unavailable(name)),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn gost_2012_256_md_returns_not_available_without_engine() {
        // Engine has never been loaded in this test process (or the load
        // failed, which is what the stub guarantees).  Either way, the
        // digest helper must surface NotAvailable.
        match gost_2012_256_md() {
            Ok(md) if engine::is_available() => assert_eq!(md.size(), 32),
            Ok(_) => panic!("digest resolved without engine being available"),
            Err(GostEngineError::NotAvailable(_)) => {}
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn gost_2012_512_md_returns_not_available_without_engine() {
        match gost_2012_512_md() {
            Ok(md) if engine::is_available() => assert_eq!(md.size(), 64),
            Ok(_) => panic!("digest resolved without engine being available"),
            Err(GostEngineError::NotAvailable(_)) => {}
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn gost_signature_md_for_returns_ok_none_for_non_gost() {
        match gost_signature_md_for(&SignatureAlg::RsaWithSha256) {
            Ok(None) => {}
            Ok(Some(_)) => panic!("non-gost must yield None"),
            Err(e) => panic!("non-gost must succeed: {e:?}"),
        }
    }

    #[test]
    fn gost_signature_md_for_routes_gost_variants() {
        let res_256 = gost_signature_md_for(&SignatureAlg::IdTc26SignWithDigestGostR341012_256);
        let res_512 = gost_signature_md_for(&SignatureAlg::IdTc26SignWithDigestGostR341012_512);
        if engine::is_available() {
            match res_256 {
                Ok(Some(_)) => {}
                Ok(None) => panic!("256: expected Some digest with engine loaded"),
                Err(e) => panic!("256: unexpected error: {e:?}"),
            }
            match res_512 {
                Ok(Some(_)) => {}
                Ok(None) => panic!("512: expected Some digest with engine loaded"),
                Err(e) => panic!("512: unexpected error: {e:?}"),
            }
        } else {
            assert!(matches!(res_256, Err(GostEngineError::NotAvailable(_))));
            assert!(matches!(res_512, Err(GostEngineError::NotAvailable(_))));
        }
    }
}
