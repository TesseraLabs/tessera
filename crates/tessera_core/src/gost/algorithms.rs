//! GOST digest helpers.
//!
//! Resolves Streebog-256 / Streebog-512 [`MessageDigest`] handles by name
//! (`EVP_get_digestbyname`, via the safe [`MessageDigest::from_name`]),
//! once [`super::engine::ensure_loaded`] has pinned gost-engine as the
//! implementation behind them.
//!
//! `id-GostR3411-2012-256` / `id-GostR3411-2012-512` (Streebog-256/512)
//! **are** genuine static entries in libcrypto's built-in object table
//! (OpenSSL ≥ 1.1.0: `NID_id_GostR3411_2012_256` = 982,
//! `NID_id_GostR3411_2012_512` = 983, per `obj_mac.h`), each with a stable
//! NID/SN (`md_gost12_256`/`md_gost12_512`)/LN baked in at compile time —
//! gost-engine supplies the *implementation* behind these NIDs, it does not
//! register the OID/name itself.
//!
//! Resolution goes by name because an earlier version of this module
//! hardcoded 1177/1178 and those numbers are simply wrong: they belong to
//! `kuznyechik_ctr_acpkm` / `kuznyechik_ctr_acpkm_omac`, a block cipher
//! unrelated to Streebog. Every digest lookup therefore missed, which is a
//! likely cause of the GOST authentication failures observed on the Astra
//! stand. The names are compile-time constants in the same table as the
//! NIDs, so nothing is lost by using them, and a wrong name fails loudly at
//! the lookup instead of silently selecting another algorithm.

use openssl::hash::MessageDigest;

use crate::x509::SignatureAlg;

use super::engine;
use super::errors::GostEngineError;

/// libcrypto's static short name (SN) for `id-GostR3411-2012-256`
/// (Streebog-256), NID 982; the OID is `1.2.643.7.1.1.2.2`.
const GOST_2012_256_NAME: &str = "md_gost12_256";
/// libcrypto's static SN for `id-GostR3411-2012-512` (Streebog-512),
/// NID 983; the OID is `1.2.643.7.1.1.2.3`.
const GOST_2012_512_NAME: &str = "md_gost12_512";

/// Returns the [`MessageDigest`] for Streebog-256.
///
/// # Errors
///
/// * [`GostEngineError::NotAvailable`] if the engine isn't pinned (i.e.
///   [`engine::is_available`] is `false`).  This includes the current
///   stub-mode where the engine is never loaded.
/// * [`GostEngineError::DigestUnavailable`] if the engine claims to be
///   loaded but the name lookup still fails.
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
    // Even if the engine is "available" by our flag, the name lookup can
    // still fail (engine deregistered, build mismatch, etc.). Resolved by
    // name (`EVP_get_digestbyname`) rather than by a NID literal — see the
    // module doc: the literals this module used to carry named a block
    // cipher, not Streebog, and nothing caught it.
    MessageDigest::from_name(name).ok_or_else(|| GostEngineError::digest_unavailable(name))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// Each test here decides what to expect by reading whether an engine is
    /// loaded, so the read and the call it describes must not straddle another
    /// test's load — see [`engine::lock_engine_cell_for_test`].
    use super::engine::lock_engine_cell_for_test;

    #[test]
    fn gost_2012_256_md_returns_not_available_without_engine() {
        // Engine has never been loaded in this test process (or the load
        // failed, which is what the stub guarantees).  Either way, the
        // digest helper must surface NotAvailable.
        let _lock = lock_engine_cell_for_test();
        match gost_2012_256_md() {
            Ok(md) if engine::is_available() => assert_eq!(md.size(), 32),
            Ok(_) => panic!("digest resolved without engine being available"),
            Err(GostEngineError::NotAvailable(_)) => {}
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn gost_2012_512_md_returns_not_available_without_engine() {
        let _lock = lock_engine_cell_for_test();
        match gost_2012_512_md() {
            Ok(md) if engine::is_available() => assert_eq!(md.size(), 64),
            Ok(_) => panic!("digest resolved without engine being available"),
            Err(GostEngineError::NotAvailable(_)) => {}
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    /// libcrypto's static NIDs for Streebog-256/512 — the entries the name
    /// constants above must resolve to. Present in the built-in object
    /// table since OpenSSL 1.1.0, with or without gost-engine.
    const NID_STREEBOG_256: i32 = 982;
    const NID_STREEBOG_512: i32 = 983;

    /// The NID literals an earlier version of this module used for the two
    /// digests.
    const WRONG_LEGACY_NIDS: [i32; 2] = [1177, 1178];

    #[test]
    fn digest_names_match_the_static_streebog_nids() {
        // Ties the two name constants to the object-table entries they are
        // supposed to address. Needs no engine: the names are compiled into
        // libcrypto, only the implementation behind them comes from the
        // engine — so this runs everywhere, unlike the four tests below.
        for (nid, name) in [
            (NID_STREEBOG_256, GOST_2012_256_NAME),
            (NID_STREEBOG_512, GOST_2012_512_NAME),
        ] {
            let sn = openssl::nid::Nid::from_raw(nid)
                .short_name()
                .unwrap_or_else(|e| panic!("nid {nid} has no short name: {e}"));
            assert_eq!(sn, name, "nid {nid} does not name {name}");
        }
    }

    #[test]
    fn the_legacy_nid_literals_do_not_name_streebog() {
        // Guards the regression the module doc describes: 1177/1178 name a
        // Kuznyechik cipher mode, so resolving digests through them yielded
        // nothing usable while looking plausible in review.
        for nid in WRONG_LEGACY_NIDS {
            let nid = openssl::nid::Nid::from_raw(nid);
            if let Ok(sn) = nid.short_name() {
                assert_ne!(sn, GOST_2012_256_NAME);
                assert_ne!(sn, GOST_2012_512_NAME);
            }
            if let Some(md) = MessageDigest::from_nid(nid) {
                assert_ne!(
                    md.size(),
                    32,
                    "nid {} resolves to a 32-byte digest",
                    nid.as_raw()
                );
                assert_ne!(
                    md.size(),
                    64,
                    "nid {} resolves to a 64-byte digest",
                    nid.as_raw()
                );
            }
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
        let _lock = lock_engine_cell_for_test();
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
