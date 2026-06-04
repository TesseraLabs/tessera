//! Verifies that the example config files shipped in the .deb parse cleanly
//! against the live `RawConfig` schema.
//!
//! This pins the contract: never let `dist/config/*.example` drift from the
//! schema enforced by the core crate.
//!
//! Note: full `ValidatedConfig` validation requires PEM anchors / module
//! files to actually exist on disk (paths in the example point at
//! `/etc/tessera/...` which only exist on a deployed system). We
//! therefore parse the raw form here and run an additional
//! "swap-in-real-paths" validate pass to confirm the example exercises every
//! validation branch end-to-end.

#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::doc_markdown)]

use std::path::PathBuf;

use tessera_core::config::{RawConfig, ValidatedConfig};

fn dist_dir() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest).join("../../dist/config")
}

#[test]
fn config_example_parses_as_raw() {
    let path = dist_dir().join("config.toml.example");
    let text = std::fs::read_to_string(&path).expect("read config example");
    let _raw: RawConfig = toml::from_str(&text).expect("parse config example");
}

/// Minimal self-signed PEM cert good enough to satisfy the trust-section PEM
/// sniff (which only checks for the `-----BEGIN CERTIFICATE-----` marker).
const FAKE_PEM_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBfTCCAS6gAwIBAgIUcheCkYc5VvuuVlZ8KqfA8R6Bvs8wCgYIKoZIzj0EAwIw\n\
-----END CERTIFICATE-----\n";

/// Stronger contract: rewrite the example so its file-paths point into a
/// scratch directory, then run full `ValidatedConfig` validation. If the
/// example drifts in a way that breaks validation (typo'd field, removed
/// section, invalid range), this test catches it.
#[test]
fn config_example_validates_with_real_paths() {
    let path = dist_dir().join("config.toml.example");
    let text = std::fs::read_to_string(&path).expect("read config example");

    let dir = tempfile::tempdir().expect("tempdir");
    let anchor = dir.path().join("anchor.pem");
    std::fs::write(&anchor, FAKE_PEM_CERT).expect("write anchor");
    let pkcs11_module = dir.path().join("dummy_pkcs11.so");
    std::fs::write(&pkcs11_module, b"\x7fELF").expect("write pkcs11 module");

    // Substitute the documented placeholder paths with our scratch ones.
    let rewritten = text
        .replace(
            "/etc/tessera/ca/bundle.pem",
            anchor.to_str().expect("utf8 anchor"),
        )
        .replace(
            "/usr/lib/librtpkcs11ecp.so",
            pkcs11_module.to_str().expect("utf8 pkcs11 module"),
        );

    let raw: RawConfig = toml::from_str(&rewritten).expect("parse rewritten example");
    let _validated = ValidatedConfig::try_from(&raw).expect("validate rewritten example");
}
