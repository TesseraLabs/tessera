//! Process-global gost-engine loader.
//!
//! # Design
//!
//! Tessera may run on hosts that do **or do not** have the
//! `gost-engine` shared library available to libcrypto.  The
//! [`ensure_loaded`] entry point captures both worlds:
//!
//! * On the first call it attempts to locate and pin the engine according
//!   to the supplied [`ValidatedConfig`].  The result (success or first
//!   error) is stored in a [`std::sync::OnceLock`].
//! * Every subsequent call returns the cached result without re-touching
//!   OpenSSL global state — engine load is a once-per-process operation.
//!
//! # Implementation
//!
//! The actual FFI to libcrypto's `ENGINE_*` API lives in the private
//! [`super::sys`] module and is the only place in the core crate where
//! `unsafe` is permitted.  The flow is:
//!
//! 1. If `cfg.gost_engine_path` is set: ensure the file exists, then
//!    load it via the `dynamic` engine (`SO_PATH` + `ID` + `LOAD` commands).
//! 2. Otherwise: ask libcrypto to find `"gost"` via its standard
//!    `OPENSSL_ENGINES` search path.
//! 3. Either way: `ENGINE_set_default(ENGINE_METHOD_ALL)` so GOST OIDs
//!    resolve to the engine's implementations.
//! 4. Sanity-check that at least one of the well-known GOST digests is
//!    registered; if not, the engine load is considered to have failed
//!    silently and we surface [`GostEngineError::DigestUnavailable`].

use std::path::Path;
use std::sync::OnceLock;

use crate::config::ValidatedConfig;
use crate::x509::{Certificate, SignatureAlg};

use super::errors::GostEngineError;
use super::sys::{digest_available, EngineHandle};

/// Cached outcome of the first `ensure_loaded` call in the process.
///
/// The handle is kept alive (never dropped) so the engine stays pinned
/// for the lifetime of the process — exactly what the `gost-engine`
/// design contract requires.
static ENGINE_RESULT: OnceLock<Result<EngineHandle, GostEngineError>> = OnceLock::new();

/// Idempotently load and pin the gost-engine.
///
/// Returns the cached result of the first invocation; subsequent calls
/// neither retry the load nor mutate OpenSSL state.
///
/// # Errors
///
/// * [`GostEngineError::PathMissing`] — `cfg.gost_engine_path` is set but
///   does not point to an existing file.
/// * [`GostEngineError::NotAvailable`] — the engine could not be located
///   on the system (no `gost` engine registered, no SO file installed).
/// * [`GostEngineError::LoadFailed`] — the engine .so was found but
///   failed to load (bad ABI, wrong build, init returned 0).
/// * [`GostEngineError::SetDefaultFailed`] — the engine loaded but could
///   not be pinned as default for GOST methods.
/// * [`GostEngineError::DigestUnavailable`] — the engine claimed to load
///   but failed to register any of the expected GOST digests.
pub fn ensure_loaded(cfg: &ValidatedConfig) -> Result<(), GostEngineError> {
    ensure_loaded_with_path(cfg.gost_engine_path.as_deref())
}

/// Idempotently load and pin the gost-engine using only an optional engine path.
///
/// This is the path-only variant of [`ensure_loaded`].  It is the preferred
/// entry point for components that already keep a reference to
/// [`crate::config::ValidatedConfig::gost_engine_path`] in their state and do
/// not want to thread the whole config through.
///
/// As with [`ensure_loaded`], the underlying load is performed exactly once
/// per process via the same [`OnceLock`].  Subsequent calls — regardless of
/// whether they came through this entry point or [`ensure_loaded`] — return
/// the cached result.
///
/// # Errors
///
/// Same set as [`ensure_loaded`].
pub fn ensure_loaded_with_path(gost_engine_path: Option<&Path>) -> Result<(), GostEngineError> {
    match ENGINE_RESULT.get_or_init(|| try_load_path(gost_engine_path)) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.clone()),
    }
}

/// Loads the gost-engine only when at least one certificate in `certs` carries
/// a GOST signature algorithm.
///
/// Useful for verifiers that handle mixed RSA/ECDSA/GOST inputs and want to
/// avoid touching OpenSSL's engine machinery on hosts where no GOST chains
/// are ever observed.
///
/// On a chain with no GOST certificates this returns `Ok(())` without
/// triggering [`ensure_loaded_with_path`], so the engine `OnceLock` remains
/// uninitialized and [`is_available`] keeps returning `false`.
///
/// # Errors
///
/// Same set as [`ensure_loaded_with_path`].
pub fn ensure_loaded_if_any_gost(
    certs: &[&Certificate],
    gost_engine_path: Option<&Path>,
) -> Result<(), GostEngineError> {
    let needs_gost = certs.iter().any(|c| c.signature_alg().is_gost());
    if needs_gost {
        ensure_loaded_with_path(gost_engine_path)?;
    }
    Ok(())
}

/// Loads the gost-engine only when `sig_alg` is one of the GOST variants.
///
/// Sibling of [`ensure_loaded_if_any_gost`] for callers that already have a
/// classified [`SignatureAlg`] (CRL signature OID, ACL signature OID).
///
/// # Errors
///
/// Same set as [`ensure_loaded_with_path`].
pub fn ensure_loaded_if_signature_alg_gost(
    sig_alg: &SignatureAlg,
    gost_engine_path: Option<&Path>,
) -> Result<(), GostEngineError> {
    if sig_alg.is_gost() {
        ensure_loaded_with_path(gost_engine_path)?;
    }
    Ok(())
}

/// Returns `true` if a previous `ensure_loaded` call established the
/// engine successfully.
///
/// Does **not** trigger a load.  Useful for runtime test gating: callers
/// can skip GOST-dependent tests when the engine wasn't pre-warmed.
#[must_use]
pub fn is_available() -> bool {
    matches!(ENGINE_RESULT.get(), Some(Ok(_)))
}

/// Convenience helper for integration tests: attempt to load the engine
/// (idempotently, via the same [`OnceLock`] every other entry point uses),
/// then report whether it is now available.
///
/// Equivalent to:
/// ```ignore
/// let _ = ensure_loaded_with_path(path);
/// is_available()
/// ```
///
/// Discards any [`GostEngineError`] from the load attempt because the only
/// thing the caller actually cares about — at this gate — is the boolean
/// "can we run GOST tests now?".
#[must_use]
pub fn is_available_after_attempt(path: Option<&Path>) -> bool {
    // Ошибку загрузки намеренно отбрасываем: на этом гейте важен только
    // итоговый булев ответ is_available() (см. док-комментарий выше).
    #[allow(clippy::let_underscore_must_use)]
    let _ = ensure_loaded_with_path(path);
    is_available()
}

fn try_load_path(path: Option<&Path>) -> Result<EngineHandle, GostEngineError> {
    let handle = match path {
        Some(p) => {
            if !p.exists() {
                return Err(GostEngineError::PathMissing(p.to_path_buf()));
            }
            EngineHandle::load_dynamic(p, "gost")?
        }
        None => EngineHandle::by_id("gost")?,
    };

    handle.set_default_all()?;

    // Post-load sanity check.  gost-engine registers Streebog under the
    // canonical name `md_gost12_256`; some forks of the engine spell
    // the same digest as `streebog256`.  Accept either.
    if !digest_available("md_gost12_256") && !digest_available("streebog256") {
        return Err(GostEngineError::digest_unavailable(
            "md_gost12_256 not registered after engine load",
        ));
    }

    Ok(handle)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::raw::RawConfig;

    fn validated_with_optional_path(path: Option<&std::path::Path>) -> ValidatedConfig {
        let original = include_str!("../../tests/fixtures/full_valid.toml");
        let dir = tempfile::tempdir().expect("tempdir");
        let anchor = dir.path().join("anchor.pem");
        std::fs::write(
            &anchor,
            "-----BEGIN CERTIFICATE-----\n\
             MIIBfTCCAS6gAwIBAgIUcheCkYc5VvuuVlZ8KqfA8R6Bvs8wCgYIKoZIzj0EAwIw\n\
             -----END CERTIFICATE-----\n",
        )
        .expect("write anchor");
        let body = original.replace(
            "anchors = [\"/bin/sh\"]",
            &format!("anchors = [{:?}]", anchor.to_string_lossy()),
        );
        let body = if let Some(p) = path {
            format!("gost_engine_path = {:?}\n{}", p.to_string_lossy(), body)
        } else {
            body
        };
        let raw: RawConfig = toml::from_str(&body).expect("parse fixture");
        let v = ValidatedConfig::try_from(&raw).expect("validate");
        // Hold the tempdir alive only as long as the validated config in
        // each test scope needs anchors readable; it's OK to drop here:
        // the metadata read happened during `try_from`.
        drop(dir);
        v
    }

    #[test]
    fn ensure_loaded_is_idempotent() {
        let cfg = validated_with_optional_path(None);
        let first = ensure_loaded(&cfg);
        let second = ensure_loaded(&cfg);
        // Both calls must yield the same Result shape.
        match (&first, &second) {
            (Ok(()), Ok(())) => {}
            (Err(e1), Err(e2)) => assert_eq!(
                std::mem::discriminant(e1),
                std::mem::discriminant(e2),
                "second ensure_loaded returned a different variant",
            ),
            _ => panic!("idempotency violated: {first:?} vs {second:?}"),
        }
    }

    #[test]
    fn is_available_matches_cached_result() {
        // We can't assert false unconditionally because another test may
        // have warmed the OnceLock; we can only assert that the answer is
        // consistent with what `ensure_loaded` would now return.
        let observed = is_available();
        let cfg = validated_with_optional_path(None);
        let res = ensure_loaded(&cfg);
        // The observed value (taken before our ensure_loaded above) must
        // match `is_available()` taken now: both look at the same cell.
        assert_eq!(observed, is_available());
        // And the cached result must be consistent with what we just got.
        match res {
            Ok(()) => assert!(is_available()),
            Err(_) => assert!(!is_available()),
        }
    }

    #[test]
    fn ensure_loaded_returns_not_available_on_macos_dev_host() {
        // On a developer host without gost-engine installed, `ENGINE_by_id("gost")`
        // returns NULL → NotAvailable.  This is the expected steady state
        // for CI on macOS.  On Linux hosts that DO ship gost-engine, this
        // call may instead succeed; we accept either outcome and only
        // assert that the result is one of the documented variants.
        let cfg = validated_with_optional_path(None);
        match ensure_loaded(&cfg) {
            Ok(()) => assert!(is_available()),
            Err(
                GostEngineError::NotAvailable(_)
                | GostEngineError::LoadFailed(_)
                | GostEngineError::SetDefaultFailed(_)
                | GostEngineError::DigestUnavailable { .. },
            ) => {
                assert!(!is_available());
            }
            Err(other) => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn ensure_loaded_with_path_matches_ensure_loaded_when_path_is_none() {
        // Both entry points share the same OnceLock so the second call must
        // return the same Result variant (cached) as the first.
        let cfg = validated_with_optional_path(None);
        let from_cfg = ensure_loaded(&cfg);
        let from_path = ensure_loaded_with_path(None);
        match (&from_cfg, &from_path) {
            (Ok(()), Ok(())) => {}
            (Err(e1), Err(e2)) => assert_eq!(
                std::mem::discriminant(e1),
                std::mem::discriminant(e2),
                "ensure_loaded_with_path diverged from ensure_loaded",
            ),
            _ => panic!(
                "ensure_loaded vs ensure_loaded_with_path mismatch: {from_cfg:?} vs {from_path:?}"
            ),
        }
    }

    #[test]
    fn ensure_loaded_if_signature_alg_gost_is_noop_for_rsa() {
        // RSA classification must never trigger the loader.  The cached
        // `is_available()` reading taken before and after the call is the
        // best non-invasive proxy we have to assert "no engine state was
        // mutated by this call".
        let before = is_available();
        let res = ensure_loaded_if_signature_alg_gost(&SignatureAlg::RsaWithSha256, None);
        assert!(res.is_ok(), "rsa path must be Ok: {res:?}");
        assert_eq!(before, is_available());
    }

    #[test]
    fn ensure_loaded_if_any_gost_is_noop_on_empty_slice() {
        let before = is_available();
        let res = ensure_loaded_if_any_gost(&[], None);
        assert!(res.is_ok(), "empty slice must be Ok: {res:?}");
        assert_eq!(before, is_available());
    }
}
