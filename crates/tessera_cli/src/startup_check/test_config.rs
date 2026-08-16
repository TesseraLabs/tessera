//! Config fixtures shared by the startup-check unit tests.
//!
//! Several states these checks have to describe (a GOST OID with no engine
//! path, an engine path that stops existing after load) are refused by the
//! TOML validator and can only be reached by mutating a validated struct in
//! place — the same pattern `tests/startup_check.rs` uses. Building that
//! struct needs a full, valid TOML fixture, so it lives here instead of
//! being copied into every check module that needs one.

#![allow(clippy::expect_used)]

use tessera_core::config::ValidatedConfig;

/// Minimal but fully valid config, mirroring
/// `tests/startup_check.rs::write_min_config`: `crypto_backend = "openssl"`,
/// `mode` as given, no GOST configured.
///
/// `mode` is a parameter because the pairing check needs `"pkcs11"` while
/// the gost-engine cases use `"pkcs12"` so they exercise the engine branches
/// alone.
pub(crate) fn base_cfg(anchor: &std::path::Path, mode: &str) -> ValidatedConfig {
    let body = format!(
        r#"crypto_backend = "openssl"
mode = "{mode}"
pkcs11_module = "/bin/sh"
usb_wait_seconds = 10
on_usb_removed = "lock"
usb_removed_grace_seconds = 5
suspend_grace_seconds = 5
monitor_fail_mode = "strict"

[trust]
anchors = ["{}"]
intermediates = []
max_chain_depth = 5
clock_skew_seconds = 60
allowed_signature_algorithms = []

[trust.revocation]
mode = "none"
crl_paths = []

[trust.pinning]
enabled = false
allowed_root_spki_sha256 = []

[host_identity]
sources = ["hostname"]
fallback = "warn"
custom_command_timeout_seconds = 5

[logging]
level = "info"
syslog_facility = "auth"
journald_priority = true

[mac]
runtime = "auto"
cert_integrity = "optional"
"#,
        anchor.display(),
    );
    let raw: tessera_core::config::RawConfig = toml::from_str(&body).expect("parse fixture");
    ValidatedConfig::try_from(&raw).expect("validate fixture")
}

/// Write a placeholder PEM trust anchor into `dir` and return its path.
pub(crate) fn write_anchor(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("anchor.pem");
    std::fs::write(
        &p,
        "-----BEGIN CERTIFICATE-----\nXX\n-----END CERTIFICATE-----\n",
    )
    .expect("write anchor");
    p
}
