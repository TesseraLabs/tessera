//! Tests for the `[mac]` policy section in config (Task 2.1).
//!
//! Verifies:
//! - Defaults when section absent (`cert_integrity` = Optional, no fallback, warn = true).
//! - Parses required + fallback label with hex categories (u64).
//! - Rejects legacy fields `require_mac` and `cert_mac_level` (per spec §2.4).
//! - Rejects invalid trinary value.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::panic)]
#![allow(clippy::items_after_statements)]

#[cfg(feature = "astra-mac")]
use tessera_core::config::validated::CertIntegrityMode;
use tessera_core::config::validated::MacRuntimeMode;
use tessera_core::config::RawConfig;
use tessera_core::config::ValidatedConfig;
use tessera_core::Error;

/// Base TOML fixture; uses `/bin/sh` as a trivially-existing path so the
/// trust-section PEM sniff is intentionally bypassed for these
/// config-parse tests (we never reach `try_from` for negative cases).
fn base_config() -> &'static str {
    include_str!("fixtures/full_valid.toml")
}

#[test]
fn mac_defaults_to_optional_without_fallback() {
    let raw: RawConfig = toml::from_str(base_config()).expect("parse base");
    // The validated layer applies the defaults; we don't fully validate the
    // trust section here (anchors point at /bin/sh) so just assert on raw.
    assert!(raw.mac.cert_integrity.is_none());
    assert!(raw.mac.fallback_max_integrity.is_none());
    assert!(raw.mac.warn_on_homedir_label_mismatch.is_none());
}

#[test]
fn parses_required_with_fallback() {
    let toml = format!(
        "{base}\n\
         [mac]\n\
         cert_integrity = \"required\"\n\
         warn_on_homedir_label_mismatch = false\n\
         \n\
         [mac.fallback_max_integrity]\n\
         level = 50\n\
         categories = \"00000000000000ff\"\n",
        base = base_config()
    );
    let raw: RawConfig = toml::from_str(&toml).expect("parse with [mac]");
    assert!(raw.mac.cert_integrity.is_some());
    let fallback = raw.mac.fallback_max_integrity.as_ref().expect("fallback");
    assert_eq!(fallback.level, 50);
    assert_eq!(fallback.categories, "00000000000000ff");
    assert_eq!(raw.mac.warn_on_homedir_label_mismatch, Some(false));
}

// `Required` policy is rejected by `validate_mac` under stub builds (Phase 5
// Task 5.4 fail-fast). This integration test exercises the validated layer
// when MAC is actually available.
#[cfg(feature = "astra-mac")]
#[test]
fn parses_required_with_fallback_validates() {
    // Verify the validated layer correctly converts the hex categories to u64
    // and propagates the mode. We need a TOML that survives full validation,
    // so we build one with a real PEM anchor.
    const FAKE_PEM_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
        MIIBfTCCAS6gAwIBAgIUcheCkYc5VvuuVlZ8KqfA8R6Bvs8wCgYIKoZIzj0EAwIw\n\
        -----END CERTIFICATE-----\n";
    let tmp = tempfile::tempdir().expect("tmpdir");
    let anchor = tmp.path().join("anchor.pem");
    std::fs::write(&anchor, FAKE_PEM_CERT).expect("write anchor");
    let base = base_config().replace(
        "anchors = [\"/bin/sh\"]",
        &format!("anchors = [{:?}]", anchor.to_string_lossy()),
    );
    let toml = format!(
        "{base}\n\
         [mac]\n\
         cert_integrity = \"required\"\n\
         warn_on_homedir_label_mismatch = false\n\
         \n\
         [mac.fallback_max_integrity]\n\
         level = 50\n\
         categories = \"00000000000000ff\"\n",
    );
    let raw: RawConfig = toml::from_str(&toml).expect("parse");
    let validated = ValidatedConfig::try_from(&raw).expect("validate");
    assert_eq!(validated.mac.cert_integrity, CertIntegrityMode::Required);
    let lbl = validated.mac.fallback_max_integrity.expect("label");
    assert_eq!(lbl.level, 50);
    assert_eq!(lbl.categories, 0x00ff);
    assert!(!validated.mac.warn_on_homedir_label_mismatch);
}

#[test]
fn rejects_legacy_field_require_mac() {
    let toml = format!(
        "{base}\n\
         [mac]\n\
         require_mac = true\n",
        base = base_config()
    );
    let err = toml::from_str::<RawConfig>(&toml).expect_err("legacy require_mac must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("require_mac") || msg.contains("unknown field"),
        "unexpected error: {msg}"
    );
}

#[test]
fn rejects_legacy_field_cert_mac_level() {
    let toml = format!(
        "{base}\n\
         [mac]\n\
         cert_mac_level = 10\n",
        base = base_config()
    );
    let err =
        toml::from_str::<RawConfig>(&toml).expect_err("legacy cert_mac_level must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("cert_mac_level") || msg.contains("unknown field"),
        "unexpected error: {msg}"
    );
}

#[test]
fn runtime_default_is_auto() {
    let raw: RawConfig = toml::from_str(base_config()).expect("parse base");
    assert!(raw.mac.runtime.is_none(), "default raw is None");
    // Validate via a temp PEM anchor so the full validator runs.
    const FAKE_PEM_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
        MIIBfTCCAS6gAwIBAgIUcheCkYc5VvuuVlZ8KqfA8R6Bvs8wCgYIKoZIzj0EAwIw\n\
        -----END CERTIFICATE-----\n";
    let tmp = tempfile::tempdir().expect("tmpdir");
    let anchor = tmp.path().join("anchor.pem");
    std::fs::write(&anchor, FAKE_PEM_CERT).expect("write anchor");
    let toml = base_config().replace(
        "anchors = [\"/bin/sh\"]",
        &format!("anchors = [{:?}]", anchor.to_string_lossy()),
    );
    let raw: RawConfig = toml::from_str(&toml).expect("parse");
    let validated = ValidatedConfig::try_from(&raw).expect("validate");
    assert_eq!(validated.mac.runtime, MacRuntimeMode::Auto);
}

#[test]
fn runtime_disabled_with_cert_integrity_required_rejected() {
    // Even on `astra-mac` builds, disabled + required is logically inconsistent.
    const FAKE_PEM_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
        MIIBfTCCAS6gAwIBAgIUcheCkYc5VvuuVlZ8KqfA8R6Bvs8wCgYIKoZIzj0EAwIw\n\
        -----END CERTIFICATE-----\n";
    let tmp = tempfile::tempdir().expect("tmpdir");
    let anchor = tmp.path().join("anchor.pem");
    std::fs::write(&anchor, FAKE_PEM_CERT).expect("write anchor");
    let base = base_config().replace(
        "anchors = [\"/bin/sh\"]",
        &format!("anchors = [{:?}]", anchor.to_string_lossy()),
    );
    let toml = format!(
        "{base}\n\
         [mac]\n\
         cert_integrity = \"required\"\n\
         runtime = \"disabled\"\n",
    );
    let raw: RawConfig = toml::from_str(&toml).expect("parse");
    let err = ValidatedConfig::try_from(&raw).expect_err("must reject");
    match err {
        Error::ConfigInvalid { reason } => {
            assert!(
                reason.contains("disabled") && reason.contains("required"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[cfg(not(feature = "astra-mac"))]
#[test]
fn runtime_required_without_astra_mac_feature_rejected() {
    const FAKE_PEM_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
        MIIBfTCCAS6gAwIBAgIUcheCkYc5VvuuVlZ8KqfA8R6Bvs8wCgYIKoZIzj0EAwIw\n\
        -----END CERTIFICATE-----\n";
    let tmp = tempfile::tempdir().expect("tmpdir");
    let anchor = tmp.path().join("anchor.pem");
    std::fs::write(&anchor, FAKE_PEM_CERT).expect("write anchor");
    let base = base_config().replace(
        "anchors = [\"/bin/sh\"]",
        &format!("anchors = [{:?}]", anchor.to_string_lossy()),
    );
    let toml = format!(
        "{base}\n\
         [mac]\n\
         runtime = \"required\"\n",
    );
    let raw: RawConfig = toml::from_str(&toml).expect("parse");
    let err = ValidatedConfig::try_from(&raw).expect_err("must reject");
    match err {
        Error::ConfigInvalid { reason } => {
            assert!(
                reason.contains("runtime") && reason.contains("astra-mac"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn runtime_disabled_parses_with_optional_integrity() {
    const FAKE_PEM_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
        MIIBfTCCAS6gAwIBAgIUcheCkYc5VvuuVlZ8KqfA8R6Bvs8wCgYIKoZIzj0EAwIw\n\
        -----END CERTIFICATE-----\n";
    let tmp = tempfile::tempdir().expect("tmpdir");
    let anchor = tmp.path().join("anchor.pem");
    std::fs::write(&anchor, FAKE_PEM_CERT).expect("write anchor");
    let base = base_config().replace(
        "anchors = [\"/bin/sh\"]",
        &format!("anchors = [{:?}]", anchor.to_string_lossy()),
    );
    let toml = format!(
        "{base}\n\
         [mac]\n\
         runtime = \"disabled\"\n",
    );
    let raw: RawConfig = toml::from_str(&toml).expect("parse");
    let validated = ValidatedConfig::try_from(&raw).expect("validate");
    assert_eq!(validated.mac.runtime, MacRuntimeMode::Disabled);
}

#[test]
fn rejects_invalid_trinary_value() {
    let toml = format!(
        "{base}\n\
         [mac]\n\
         cert_integrity = \"sometimes\"\n",
        base = base_config()
    );
    let err = toml::from_str::<RawConfig>(&toml).expect_err("invalid trinary must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("sometimes") || msg.contains("unknown variant") || msg.contains("expected"),
        "unexpected error: {msg}"
    );
}
