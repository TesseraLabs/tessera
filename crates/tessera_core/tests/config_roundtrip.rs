#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::panic_in_result_fn)]

use tessera_core::config::{RawConfig, ValidatedConfig};
use tessera_core::Error;
use std::path::{Path, PathBuf};

#[test]
fn full_fixture_parses_raw() -> Result<(), Box<dyn std::error::Error>> {
    let raw: RawConfig = toml::from_str(include_str!("fixtures/full_valid.toml"))?;
    assert_eq!(raw.usb_wait_seconds, 10);
    assert_eq!(raw.hooks.len(), 5);
    Ok(())
}

#[test]
fn full_fixture_omits_gost_engine_path_by_default() -> Result<(), Box<dyn std::error::Error>> {
    let raw: RawConfig = toml::from_str(include_str!("fixtures/full_valid.toml"))?;
    assert!(raw.gost_engine_path.is_none());
    Ok(())
}

#[test]
fn raw_config_accepts_gost_engine_path() -> Result<(), Box<dyn std::error::Error>> {
    let original = include_str!("fixtures/full_valid.toml");
    // Inject the field at the top, before any [section] header.
    let injected =
        format!("gost_engine_path = \"/usr/lib/x86_64-linux-gnu/engines-1.1/gost.so\"\n{original}");
    let raw: RawConfig = toml::from_str(&injected)?;
    assert_eq!(
        raw.gost_engine_path.as_deref(),
        Some(Path::new("/usr/lib/x86_64-linux-gnu/engines-1.1/gost.so"))
    );
    Ok(())
}

/// Minimal self-signed PEM cert good enough to satisfy the trust-section PEM
/// sniff (which only checks for the `-----BEGIN CERTIFICATE-----` marker).
const FAKE_PEM_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBfTCCAS6gAwIBAgIUcheCkYc5VvuuVlZ8KqfA8R6Bvs8wCgYIKoZIzj0EAwIw\n\
-----END CERTIFICATE-----\n";

fn write_anchor(dir: &Path) -> PathBuf {
    let p = dir.join("anchor.pem");
    std::fs::write(&p, FAKE_PEM_CERT).expect("write anchor");
    p
}

/// Build a fully-validated-friendly TOML: real PEM anchor + non-existent
/// host_acl_path (since `host_acl_required = false`, only ACL_PATH validity
/// is checked at self_check, not at validation).
fn fixture_with_anchor(anchor: &Path) -> String {
    let original = include_str!("fixtures/full_valid.toml");
    original.replace(
        "anchors = [\"/bin/sh\"]",
        &format!("anchors = [{:?}]", anchor.to_string_lossy()),
    )
}

/// Parse a raw config from the fixture with a custom `gost_engine_path`,
/// using `anchor` as the trust anchor (must be an existing PEM file).
fn parse_raw_with_gost_path(anchor: &Path, gost_path: &str) -> RawConfig {
    let body = fixture_with_anchor(anchor);
    let injected = format!("gost_engine_path = {gost_path:?}\n{body}");
    toml::from_str(&injected).expect("fixture parses")
}

#[test]
fn validated_config_accepts_existing_gost_engine_path() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let engine_path = dir.path().join("gost.so");
    std::fs::write(&engine_path, b"\x7fELF")?;
    let raw = parse_raw_with_gost_path(&anchor, &engine_path.to_string_lossy());
    let validated = ValidatedConfig::try_from(&raw)?;
    assert_eq!(
        validated.gost_engine_path.as_deref(),
        Some(engine_path.as_path())
    );
    Ok(())
}

#[test]
fn validated_config_omits_gost_engine_path_when_absent() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let body = fixture_with_anchor(&anchor);
    let raw: RawConfig = toml::from_str(&body)?;
    let validated = ValidatedConfig::try_from(&raw)?;
    assert!(validated.gost_engine_path.is_none());
    Ok(())
}

#[test]
fn validated_config_rejects_missing_gost_engine_path() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let raw = parse_raw_with_gost_path(&anchor, "/nonexistent/path/to/gost.so");
    let err = ValidatedConfig::try_from(&raw).expect_err("must reject missing path");
    assert!(
        matches!(err, Error::GostEnginePathUnreadable { ref path, .. }
            if path == &PathBuf::from("/nonexistent/path/to/gost.so")),
        "unexpected error: {err:?}"
    );
    Ok(())
}

#[test]
fn validated_config_rejects_gost_engine_path_with_pkcs11_backend(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let engine_path = dir.path().join("gost.so");
    std::fs::write(&engine_path, b"x")?;
    let body = fixture_with_anchor(&anchor);
    // Switch backend.
    let switched = body.replace(
        "crypto_backend = \"openssl\"",
        "crypto_backend = \"pkcs11_native\"",
    );
    let injected = format!(
        "gost_engine_path = {:?}\n{}",
        engine_path.to_string_lossy(),
        switched
    );
    let raw: RawConfig = toml::from_str(&injected)?;
    let err = ValidatedConfig::try_from(&raw).expect_err("must reject");
    assert!(
        matches!(err, Error::GostEnginePathRequiresOpenssl),
        "unexpected error: {err:?}"
    );
    Ok(())
}

fn fixture_with_anchor_and_sig_algs(anchor: &Path, algs: &[&str]) -> String {
    let body = fixture_with_anchor(anchor);
    let formatted = algs
        .iter()
        .map(|s| format!("{s:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    body.replace(
        "allowed_signature_algorithms = []",
        &format!("allowed_signature_algorithms = [{formatted}]"),
    )
}

#[test]
fn empty_sig_alg_list_falls_back_to_safe_defaults() -> Result<(), Box<dyn std::error::Error>> {
    // The fixture sets `allowed_signature_algorithms = []`. An empty list must
    // NOT become an empty whitelist (which pre-validate treats as "accept any
    // algorithm, including SHA-1"); it must be replaced by a safe default set.
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let raw: RawConfig = toml::from_str(&fixture_with_anchor(&anchor))?;
    let v = ValidatedConfig::try_from(&raw)?;
    let algs = &v.trust.allowed_signature_algorithms;
    assert!(
        !algs.is_empty(),
        "empty config must not yield an empty (accept-all) whitelist"
    );
    assert!(algs.contains("sha256WithRSAEncryption"));
    assert!(
        !algs.iter().any(|a| a.contains("sha1") || a.contains("SHA1")),
        "default whitelist must not admit SHA-1: {algs:?}"
    );
    Ok(())
}

#[test]
fn validated_config_needs_gost_false_when_empty() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let raw: RawConfig = toml::from_str(&fixture_with_anchor(&anchor))?;
    let v = ValidatedConfig::try_from(&raw)?;
    assert!(!v.needs_gost());
    Ok(())
}

#[test]
fn validated_config_needs_gost_false_for_rsa_only() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let raw: RawConfig = toml::from_str(&fixture_with_anchor_and_sig_algs(
        &anchor,
        &["rsa-with-sha256", "ecdsa-with-sha384"],
    ))?;
    let v = ValidatedConfig::try_from(&raw)?;
    assert!(!v.needs_gost());
    Ok(())
}

#[test]
fn validated_config_needs_gost_true_when_gost_oid_present() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let raw: RawConfig = toml::from_str(&fixture_with_anchor_and_sig_algs(
        &anchor,
        &["1.2.643.7.1.1.3.2"],
    ))?;
    let v = ValidatedConfig::try_from(&raw)?;
    assert!(v.needs_gost());
    Ok(())
}

#[test]
fn validated_config_needs_gost_true_when_mixed() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let raw: RawConfig = toml::from_str(&fixture_with_anchor_and_sig_algs(
        &anchor,
        &[
            "rsa-with-sha256",
            "id-tc26-signwithdigest-gost3410-2012-512",
        ],
    ))?;
    let v = ValidatedConfig::try_from(&raw)?;
    assert!(v.needs_gost());
    Ok(())
}

#[test]
fn validated_config_rejects_relative_custom_command_path() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let body = fixture_with_anchor(&anchor);
    // Add a relative custom_command line under [host_identity].
    let injected = body.replace(
        "custom_command_timeout_seconds = 5",
        "custom_command = \"relative/cmd.sh\"\ncustom_command_timeout_seconds = 5",
    );
    let raw: RawConfig = toml::from_str(&injected)?;
    let err = ValidatedConfig::try_from(&raw).expect_err("must reject relative path");
    assert!(
        matches!(err, Error::ConfigInvalid { ref reason } if reason.contains("custom_command")),
        "unexpected error: {err:?}"
    );
    Ok(())
}

#[test]
fn validated_config_accepts_absolute_custom_command_path() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let body = fixture_with_anchor(&anchor);
    let injected = body.replace(
        "custom_command_timeout_seconds = 5",
        "custom_command = \"/usr/local/bin/host-id.sh\"\ncustom_command_timeout_seconds = 5",
    );
    let raw: RawConfig = toml::from_str(&injected)?;
    let validated = ValidatedConfig::try_from(&raw)?;
    assert_eq!(
        validated.host_identity.custom_command.as_deref(),
        Some(Path::new("/usr/local/bin/host-id.sh"))
    );
    Ok(())
}

#[test]
fn validated_config_parses_monitor_section_overrides() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let body = fixture_with_anchor(&anchor);
    let injected = format!(
        "{body}\n[monitor]\nsocket_path = \"/run/test/m.sock\"\nstate_file_path = \"/var/lib/test/sessions.json\"\non_usb_removed = \"shutdown\"\nusb_removed_grace_seconds = 7\nsuspend_grace_seconds = 11\n"
    );
    let raw: RawConfig = toml::from_str(&injected)?;
    let validated = ValidatedConfig::try_from(&raw)?;
    assert_eq!(
        validated.monitor.socket_path,
        PathBuf::from("/run/test/m.sock")
    );
    assert_eq!(
        validated.monitor.state_file_path,
        PathBuf::from("/var/lib/test/sessions.json")
    );
    assert!(matches!(
        validated.monitor.on_usb_removed,
        tessera_core::config::validated::OnUsbRemoved::Shutdown
    ));
    assert_eq!(
        validated.monitor.usb_removed_grace,
        std::time::Duration::from_secs(7)
    );
    assert_eq!(
        validated.monitor.suspend_grace,
        std::time::Duration::from_secs(11)
    );
    Ok(())
}

#[test]
fn validated_config_rejects_hook_mode_without_hook_path() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let body = fixture_with_anchor(&anchor);
    let injected = format!("{body}\n[monitor]\non_usb_removed = \"hook\"\n");
    let raw: RawConfig = toml::from_str(&injected)?;
    let err = ValidatedConfig::try_from(&raw).expect_err("must reject hook without path");
    assert!(
        matches!(err, Error::ConfigInvalid { ref reason }
            if reason.contains("on_usb_removed_hook_path")),
        "unexpected error: {err:?}"
    );
    Ok(())
}

#[test]
fn validated_config_needs_gost_false_for_pkcs11_backend_even_with_gost_oid(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let body = fixture_with_anchor_and_sig_algs(&anchor, &["1.2.643.7.1.1.3.2"]);
    let switched = body.replace(
        "crypto_backend = \"openssl\"",
        "crypto_backend = \"pkcs11_native\"",
    );
    let raw: RawConfig = toml::from_str(&switched)?;
    let v = ValidatedConfig::try_from(&raw)?;
    assert!(!v.needs_gost());
    Ok(())
}
