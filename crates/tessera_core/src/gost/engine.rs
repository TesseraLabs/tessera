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
//! 1. Without a configured `gost_engine_path` there is nothing to load and
//!    the call fails with [`GostEngineError::PathNotConfigured`] — before the
//!    `OnceLock` is touched, so a later call that does carry a path still
//!    gets a real load attempt rather than a cached refusal.
//! 2. With a path: ensure the file exists, then load it via the `dynamic`
//!    engine (`SO_PATH` + `ID` + `LOAD` commands).
//! 3. `ENGINE_set_default(ENGINE_METHOD_ALL)` so GOST OIDs resolve to the
//!    engine's implementations.
//! 4. Sanity-check that at least one of the well-known GOST digests is
//!    registered; if not, the engine load is considered to have failed
//!    silently and we surface [`GostEngineError::DigestUnavailable`].
//!
//! # Why the path is mandatory
//!
//! There is deliberately no id-based lookup here. `ENGINE_by_id("gost")`
//! makes libcrypto search `OPENSSL_ENGINES` and `dlopen` whatever `gost.so`
//! it finds; step 3 would then make that library the default implementation
//! for RSA, DSA, DH, RAND and every digest, process-wide. An unauthenticated
//! caller can reach these entry points simply by presenting a certificate
//! that claims a GOST signature algorithm, so the file that gets loaded must
//! come from the deployment's own configuration and from nowhere else.
//! Config validation refuses a deployment that allows GOST signatures without
//! naming the engine, so on any host where a GOST certificate could be
//! accepted at all the path is set.

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
/// * [`GostEngineError::PathNotConfigured`] — `cfg.gost_engine_path` is unset,
///   so there is no engine this deployment permits loading.
/// * [`GostEngineError::PathMissing`] — `cfg.gost_engine_path` is set but
///   does not point to an existing file.
/// * [`GostEngineError::NotAvailable`] — libcrypto has no `dynamic` loader
///   engine, so no engine can be loaded from a path at all.
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
/// A `None` path is refused outright: see the module docs for why there is no
/// id-based fallback. The refusal happens *before* the `OnceLock`, so it is
/// not remembered — a caller that does know the path still gets a genuine
/// load attempt afterwards.
///
/// # Errors
///
/// Same set as [`ensure_loaded`].
pub fn ensure_loaded_with_path(gost_engine_path: Option<&Path>) -> Result<(), GostEngineError> {
    let Some(path) = gost_engine_path else {
        return Err(GostEngineError::PathNotConfigured);
    };
    match ENGINE_RESULT.get_or_init(|| try_load(path)) {
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
/// The trigger is what the *presented* certificates claim, which anyone able
/// to reach the verifier controls. So on a deployment that named no engine
/// this fails closed with [`GostEngineError::PathNotConfigured`] rather than
/// going looking for one: such a deployment does not allow GOST signatures
/// either, and the chain was going to be rejected a step later regardless.
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
///
/// `path` must name the engine. A `None` path answers `false` on every host,
/// engine or no engine: there is no lookup by id to fall back on, so nothing
/// was attempted. A test gate that passes `None` therefore does not report
/// "this host has no engine" — it skips unconditionally, including on the one
/// host where the GOST coverage matters.
#[must_use]
pub fn is_available_after_attempt(path: Option<&Path>) -> bool {
    // Ошибку загрузки намеренно отбрасываем: на этом гейте важен только
    // итоговый булев ответ is_available() (см. док-комментарий выше).
    #[allow(clippy::let_underscore_must_use)]
    let _ = ensure_loaded_with_path(path);
    is_available()
}

fn try_load(path: &Path) -> Result<EngineHandle, GostEngineError> {
    if !path.exists() {
        return Err(GostEngineError::PathMissing(path.to_path_buf()));
    }
    let handle = EngineHandle::load_dynamic(path, "gost")?;

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
            &format!("anchors = [{}]", crate::test_support::toml_path(&anchor)),
        );
        let body = if let Some(p) = path {
            format!(
                "gost_engine_path = {}\n{}",
                crate::test_support::toml_path(p),
                body
            )
        } else {
            body
        };
        let body = crate::test_support::platform_config_toml(&body);
        let raw: RawConfig = toml::from_str(&body).expect("parse fixture");
        let v = ValidatedConfig::try_from(&raw).expect("validate");
        // Hold the tempdir alive only as long as the validated config in
        // each test scope needs anchors readable; it's OK to drop here:
        // the metadata read happened during `try_from`.
        drop(dir);
        v
    }

    #[test]
    fn an_unconfigured_path_is_refused_without_touching_the_engine_cell() {
        // The load that must never happen: without a configured path the only
        // way to get an engine is to let libcrypto search OPENSSL_ENGINES and
        // then make whatever it finds the default implementation for RSA, DSA,
        // DH, RAND and the digests. Refusing before the OnceLock also keeps
        // the refusal from being cached — reading the cell directly is the
        // only way to see that, and this module owns it.
        let cell_was_initialised = ENGINE_RESULT.get().is_some();
        let res = ensure_loaded_with_path(None);
        assert!(
            matches!(res, Err(GostEngineError::PathNotConfigured)),
            "an unconfigured path must be refused outright, got {res:?}",
        );
        assert_eq!(
            cell_was_initialised,
            ENGINE_RESULT.get().is_some(),
            "the refusal was written into the process-global cell, so a later \
             caller that does know the path would get it back instead of a load",
        );
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
    fn a_config_without_an_engine_path_never_loads_one() {
        // `needs_gost()` is false for this fixture, so validation lets the
        // path stay unset — and then no certificate, however it is signed,
        // can cause an engine to be loaded through this config.
        let cfg = validated_with_optional_path(None);
        let res = ensure_loaded(&cfg);
        assert!(
            matches!(res, Err(GostEngineError::PathNotConfigured)),
            "expected a refusal, got {res:?}",
        );
        assert!(!is_available());
    }

    #[test]
    fn ensure_loaded_with_path_matches_ensure_loaded_when_path_is_none() {
        // Both entry points funnel a missing path into the same refusal.
        let cfg = validated_with_optional_path(None);
        let from_cfg = ensure_loaded(&cfg);
        let from_path = ensure_loaded_with_path(None);
        match (&from_cfg, &from_path) {
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
    fn a_gost_signature_alg_without_a_configured_path_fails_closed() {
        // The reachable shape of the attack: the algorithm classification
        // comes from a presented certificate, so it must not be able to pull
        // an engine into the process on its own.
        let before = is_available();
        let res = ensure_loaded_if_signature_alg_gost(
            &SignatureAlg::IdTc26SignWithDigestGostR341012_256,
            None,
        );
        assert!(
            matches!(res, Err(GostEngineError::PathNotConfigured)),
            "a GOST algorithm with no configured engine must fail closed, got {res:?}",
        );
        assert_eq!(before, is_available());
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
