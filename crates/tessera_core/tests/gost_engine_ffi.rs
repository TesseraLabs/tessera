//! Integration test for the public surface of `gost::engine`.
//!
//! These tests cover the cross-platform contract of a config that names no
//! engine, which is every config the fixture can produce: `ensure_loaded`
//! must refuse, `is_available` must agree, and neither may panic. The load
//! that a configured path performs is exercised by the `gost-tests` files,
//! which need a real engine and real GOST material to say anything.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

// Shared with the crate's unit tests: config validation demands absolute
// paths, and what is absolute differs between Windows and Unix.
#[allow(dead_code)]
#[path = "../src/test_support.rs"]
mod test_support;

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
        &format!("anchors = [{}]", test_support::toml_path(&anchor)),
    );
    let body = if let Some(p) = path {
        format!(
            "gost_engine_path = {}\n{}",
            test_support::toml_path(p),
            body
        )
    } else {
        body
    };
    let body = test_support::platform_config_toml(&body);
    let raw: RawConfig = toml::from_str(&body).expect("parse fixture");
    let cfg = ValidatedConfig::try_from(&raw).expect("validate");
    drop(dir);
    cfg
}

#[test]
fn a_config_naming_no_engine_never_loads_one() {
    // The fixture leaves `gost_engine_path` unset, which is the only shape a
    // non-GOST deployment can have. There is nothing to load, and looking one
    // up along `OPENSSL_ENGINES` is exactly what must not happen — so the
    // answer is a refusal on every host, whether or not it ships an engine.
    let cfg = validated(None);
    let res = ensure_loaded(&cfg);
    assert!(
        matches!(res, Err(GostEngineError::PathNotConfigured)),
        "expected a refusal, got {res:?}",
    );
    assert!(
        !is_available(),
        "a refused load must leave no engine behind"
    );
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
