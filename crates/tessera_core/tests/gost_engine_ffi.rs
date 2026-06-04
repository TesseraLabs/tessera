//! Integration test for the public surface of `gost::engine`.
//!
//! These tests cover only the cross-platform contract: every host
//! either has gost-engine registered (Linux build host with the
//! library installed) or it does not (CI on macOS, dev hosts).  In
//! both cases `ensure_loaded` and `is_available` must return
//! consistent results without panicking.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::Path;

use tessera_core::config::raw::RawConfig;
use tessera_core::gost::engine::{ensure_loaded, is_available};
use tessera_core::gost::GostEngineError;
use tessera_core::ValidatedConfig;

fn validated(path: Option<&Path>) -> ValidatedConfig {
    let original = include_str!("fixtures/full_valid.toml");
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
    let cfg = ValidatedConfig::try_from(&raw).expect("validate");
    drop(dir);
    cfg
}

#[test]
fn ensure_loaded_returns_consistent_result_with_is_available() {
    let cfg = validated(None);
    match ensure_loaded(&cfg) {
        Ok(()) => {
            assert!(is_available(), "Ok must imply is_available");
        }
        Err(
            GostEngineError::NotAvailable(_)
            | GostEngineError::LoadFailed(_)
            | GostEngineError::SetDefaultFailed(_)
            | GostEngineError::DigestUnavailable { .. },
        ) => {
            assert!(!is_available(), "Err must imply !is_available");
        }
        Err(other) => panic!("unexpected variant: {other:?}"),
    }
}

#[test]
fn ensure_loaded_is_idempotent() {
    let cfg = validated(None);
    let a = ensure_loaded(&cfg);
    let b = ensure_loaded(&cfg);
    match (a, b) {
        (Ok(()), Ok(())) => {}
        (Err(e1), Err(e2)) => assert_eq!(
            std::mem::discriminant(&e1),
            std::mem::discriminant(&e2),
            "two consecutive ensure_loaded calls returned different variants",
        ),
        (a, b) => panic!("idempotency violated: {a:?} vs {b:?}"),
    }
}
