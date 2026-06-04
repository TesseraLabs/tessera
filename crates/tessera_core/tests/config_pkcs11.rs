//! T16 — PKCS#11-specific config validation.
//!
//! Cover the validation rules added on top of `RawConfig` /
//! `ValidatedConfig`:
//!
//! - `pkcs11_module` is required when `mode = "pkcs11"`.
//! - `pkcs11_token_label` and `pkcs11_object_label` are validated for
//!   length and absence of NUL bytes.
//! - `pkcs11_max_pin_attempts` must be in `1..=5`.
//! - `pkcs11_slot_wait_seconds` must be in `0..=60`.
//! - `pkcs11_locking_mode` is a strict enum (`os` | `mutex`).
//! - `deny_unknown_fields` is honoured for unknown PKCS#11-prefixed
//!   keys.
//! - `mode = "pkcs12"` keeps working without any PKCS#11 fields set.

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic,
    clippy::unwrap_used
)]

use std::path::Path;

use tessera_core::config::{RawConfig, ValidatedConfig};
use tessera_core::token::pkcs11::LockingMode;
use tessera_core::Error;

/// Minimal anchor PEM that satisfies the trust validator's content
/// sniff.  The body bytes don't have to parse — only the begin/end
/// markers are checked.
const FAKE_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBfTCCAS6gAwIBAgIUcheCkYc5VvuuVlZ8KqfA8R6Bvs8wCgYIKoZIzj0EAwIw\n\
-----END CERTIFICATE-----\n";

fn write_anchor(dir: &Path) -> std::path::PathBuf {
    let p = dir.join("anchor.pem");
    std::fs::write(&p, FAKE_PEM).expect("write anchor");
    p
}

/// Render the shipping fixture with the requested overrides applied.
/// `extras` are appended at the very top of the document so they
/// remain attached to the root table (TOML treats top-level keys as
/// belonging to whichever section they appear in).
fn fixture_with_overrides(anchor: &Path, mode: &str, pkcs11_module: &str, extras: &str) -> String {
    let original = include_str!("fixtures/full_valid.toml");
    let body = original
        .replace(
            "anchors = [\"/bin/sh\"]",
            &format!("anchors = [{:?}]", anchor.to_string_lossy()),
        )
        .replace(
            "pkcs11_module = \"/bin/sh\"",
            &format!("pkcs11_module = {pkcs11_module:?}"),
        )
        .replace("mode = \"pkcs11\"", &format!("mode = {mode:?}"));
    if extras.is_empty() {
        body
    } else {
        format!("{extras}\n{body}")
    }
}

#[test]
fn defaults_apply_when_minimal_pkcs11() {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor = write_anchor(dir.path());
    let body = fixture_with_overrides(&anchor, "pkcs11", "/usr/lib/x.so", "");
    let raw: RawConfig = toml::from_str(&body).expect("parse");
    let cfg = ValidatedConfig::try_from(&raw).expect("validate");
    assert_eq!(cfg.pkcs11_max_pin_attempts, 3);
    assert_eq!(cfg.pkcs11_locking_mode, LockingMode::Os);
    assert_eq!(cfg.pkcs11_slot_wait, std::time::Duration::from_secs(10));
    assert!(cfg.pkcs11_object_label.is_none());
}

#[test]
fn rejects_max_pin_attempts_zero_or_too_high() {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor = write_anchor(dir.path());
    for n in [0_u32, 6, 100] {
        let extras = format!("pkcs11_max_pin_attempts = {n}");
        let body = fixture_with_overrides(&anchor, "pkcs11", "/usr/lib/x.so", &extras);
        let raw: RawConfig = toml::from_str(&body).expect("parse");
        let err = ValidatedConfig::try_from(&raw).expect_err(&format!("must reject n={n}"));
        match err {
            Error::ConfigInvalid { reason } => assert!(
                reason.contains("pkcs11_max_pin_attempts"),
                "n={n}: {reason}"
            ),
            other => panic!("n={n}: unexpected error: {other:?}"),
        }
    }
}

#[test]
fn unknown_field_rejected_at_parse() {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor = write_anchor(dir.path());
    let extras = "pkcs11_secret_field = \"boom\"";
    let body = fixture_with_overrides(&anchor, "pkcs11", "/usr/lib/x.so", extras);
    let res: Result<RawConfig, _> = toml::from_str(&body);
    assert!(res.is_err(), "deny_unknown_fields must reject the typo");
}

#[test]
fn parses_locking_mode_mutex() {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor = write_anchor(dir.path());
    let extras = "pkcs11_locking_mode = \"mutex\"";
    let body = fixture_with_overrides(&anchor, "pkcs11", "/usr/lib/x.so", extras);
    let raw: RawConfig = toml::from_str(&body).expect("parse");
    let cfg = ValidatedConfig::try_from(&raw).expect("validate");
    assert_eq!(cfg.pkcs11_locking_mode, LockingMode::Mutex);
}

#[test]
fn rejects_token_label_with_nul() {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor = write_anchor(dir.path());
    // The shipping fixture has no `pkcs11_token_label` — append a
    // literal NUL via the unicode escape inside a basic string.
    let extras = "pkcs11_token_label = \"bad\\u0000label\"";
    let body = fixture_with_overrides(&anchor, "pkcs11", "/usr/lib/x.so", extras);
    let raw: RawConfig = toml::from_str(&body).expect("parse");
    let err = ValidatedConfig::try_from(&raw).expect_err("must reject");
    match err {
        Error::ConfigInvalid { reason } => assert!(
            reason.contains("NUL"),
            "expected NUL substring in error, got: {reason}"
        ),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn rejects_object_label_too_long() {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor = write_anchor(dir.path());
    let too_long = "x".repeat(65);
    let extras = format!("pkcs11_object_label = \"{too_long}\"");
    let body = fixture_with_overrides(&anchor, "pkcs11", "/usr/lib/x.so", &extras);
    let raw: RawConfig = toml::from_str(&body).expect("parse");
    let err = ValidatedConfig::try_from(&raw).expect_err("must reject");
    match err {
        Error::ConfigInvalid { reason } => assert!(
            reason.contains("pkcs11_object_label"),
            "expected pkcs11_object_label substring in error, got: {reason}"
        ),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn slot_wait_out_of_range_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor = write_anchor(dir.path());
    let extras = "pkcs11_slot_wait_seconds = 600";
    let body = fixture_with_overrides(&anchor, "pkcs11", "/usr/lib/x.so", extras);
    let raw: RawConfig = toml::from_str(&body).expect("parse");
    let err = ValidatedConfig::try_from(&raw).expect_err("must reject");
    match err {
        Error::ConfigInvalid { reason } => {
            assert!(reason.contains("pkcs11_slot_wait_seconds"), "got: {reason}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn pkcs12_mode_does_not_require_pkcs11_module() {
    // `mode = "pkcs12"` with no `pkcs11_module` field at all is
    // perfectly valid: the field is `Option<PathBuf>` and PKCS#11
    // validation is skipped entirely.  The shipping fixture defaults
    // to `pkcs11_module = "/bin/sh"` — we drop the line via raw text
    // edit.
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor = write_anchor(dir.path());
    let original = include_str!("fixtures/full_valid.toml");
    let body = original
        .replace(
            "anchors = [\"/bin/sh\"]",
            &format!("anchors = [{:?}]", anchor.to_string_lossy()),
        )
        .replace("mode = \"pkcs11\"", "mode = \"pkcs12\"")
        .replace("pkcs11_module = \"/bin/sh\"\n", "");
    let raw: RawConfig = toml::from_str(&body).expect("parse");
    assert!(raw.pkcs11_module.is_none(), "raw module field absent");
    let cfg = ValidatedConfig::try_from(&raw).expect("validate ok");
    assert!(cfg.pkcs11_module.is_none());
}

#[test]
fn pkcs11_mode_without_module_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor = write_anchor(dir.path());
    let original = include_str!("fixtures/full_valid.toml");
    let body = original
        .replace(
            "anchors = [\"/bin/sh\"]",
            &format!("anchors = [{:?}]", anchor.to_string_lossy()),
        )
        .replace("pkcs11_module = \"/bin/sh\"\n", "");
    // mode is already "pkcs11" in the fixture.
    let raw: RawConfig = toml::from_str(&body).expect("parse");
    let err = ValidatedConfig::try_from(&raw).expect_err("must reject");
    match err {
        Error::ConfigInvalid { reason } => assert!(
            reason.contains("pkcs11_module"),
            "expected pkcs11_module substring, got: {reason}"
        ),
        other => panic!("unexpected error: {other:?}"),
    }
}
