#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::panic_in_result_fn)]

use std::path::{Path, PathBuf};
use tessera_core::config::{RawConfig, ValidatedConfig};
use tessera_core::Error;

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
fn validated_config_accepts_logging_without_deprecated_keys(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let body = fixture_with_anchor(&anchor)
        .replace("syslog_facility = \"auth\"\n", "")
        .replace("journald_priority = true\n", "");
    let raw: RawConfig = toml::from_str(&body)?;
    assert!(raw.logging.syslog_facility.is_none());
    assert!(raw.logging.journald_priority.is_none());
    let validated = ValidatedConfig::try_from(&raw)?;
    assert_eq!(validated.logging.level, tessera_core::LogLevel::Info);
    Ok(())
}

#[test]
fn validated_config_rejects_unsupported_syslog_facility() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    // local0..7 are intentionally unsupported even though the key itself
    // is deprecated-and-ignored: a typo should still surface at load time.
    let body = fixture_with_anchor(&anchor)
        .replace("syslog_facility = \"auth\"", "syslog_facility = \"local0\"");
    let raw: RawConfig = toml::from_str(&body)?;
    let err = ValidatedConfig::try_from(&raw).expect_err("must reject local0");
    assert!(
        matches!(err, Error::ConfigInvalid { ref reason } if reason.contains("syslog facility")),
        "unexpected error: {err:?}"
    );
    Ok(())
}

#[test]
fn validated_config_rejects_empty_trust_anchors() -> Result<(), Box<dyn std::error::Error>> {
    let original = include_str!("fixtures/full_valid.toml");
    let body = original.replace("anchors = [\"/bin/sh\"]", "anchors = []");
    let raw: RawConfig = toml::from_str(&body)?;
    let err = ValidatedConfig::try_from(&raw).expect_err("must reject empty anchors");
    assert!(
        matches!(
            err,
            Error::Trust(tessera_core::error::TrustError::AnchorsEmpty)
        ),
        "unexpected error: {err:?}"
    );
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
        !algs
            .iter()
            .any(|a| a.contains("sha1") || a.contains("SHA1")),
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

/// Replace the `[trust.revocation]` section body of the fixture.
fn fixture_with_revocation(anchor: &Path, revocation_body: &str) -> String {
    fixture_with_anchor(anchor).replace(
        "[trust.revocation]\nmode = \"none\"\ncrl_paths = []",
        &format!("[trust.revocation]\n{revocation_body}"),
    )
}

#[test]
fn validated_config_accepts_ocsp_mode_with_url_and_defaults(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let body = fixture_with_revocation(
        &anchor,
        "mode = \"ocsp\"\ncrl_paths = []\nocsp_responder_url = \"https://ocsp.example.org/\"",
    );
    let raw: RawConfig = toml::from_str(&body)?;
    let v = ValidatedConfig::try_from(&raw)?;
    assert_eq!(
        v.trust.revocation.ocsp_responder_url.as_deref(),
        Some("https://ocsp.example.org/")
    );
    assert_eq!(
        v.trust.revocation.ocsp_timeout,
        std::time::Duration::from_secs(5)
    );
    assert_eq!(
        v.trust.revocation.ocsp_cache_ttl,
        std::time::Duration::from_hours(1)
    );
    Ok(())
}

#[test]
fn validated_config_accepts_crl_then_ocsp_mode_with_url() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let body = fixture_with_revocation(
        &anchor,
        "mode = \"crl_then_ocsp\"\ncrl_paths = []\n\
         ocsp_responder_url = \"http://ocsp.example.org/\"\n\
         ocsp_timeout_seconds = 30\nocsp_cache_ttl_seconds = 86400",
    );
    let raw: RawConfig = toml::from_str(&body)?;
    let v = ValidatedConfig::try_from(&raw)?;
    assert_eq!(
        v.trust.revocation.ocsp_responder_url.as_deref(),
        Some("http://ocsp.example.org/")
    );
    assert_eq!(
        v.trust.revocation.ocsp_timeout,
        std::time::Duration::from_secs(30)
    );
    assert_eq!(
        v.trust.revocation.ocsp_cache_ttl,
        std::time::Duration::from_hours(24)
    );
    Ok(())
}

#[test]
fn validated_config_accepts_ocsp_cache_ttl_zero() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let body = fixture_with_revocation(
        &anchor,
        "mode = \"ocsp\"\ncrl_paths = []\n\
         ocsp_responder_url = \"https://ocsp.example.org/\"\nocsp_cache_ttl_seconds = 0",
    );
    let raw: RawConfig = toml::from_str(&body)?;
    let v = ValidatedConfig::try_from(&raw)?;
    assert_eq!(v.trust.revocation.ocsp_cache_ttl, std::time::Duration::ZERO);
    Ok(())
}

#[test]
fn validated_config_rejects_ocsp_mode_without_url() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    for mode in ["ocsp", "crl_then_ocsp"] {
        let body = fixture_with_revocation(&anchor, &format!("mode = {mode:?}\ncrl_paths = []"));
        let raw: RawConfig = toml::from_str(&body)?;
        let err =
            ValidatedConfig::try_from(&raw).expect_err("OCSP mode without url must be rejected");
        assert!(
            matches!(
                err,
                Error::Trust(tessera_core::error::TrustError::OcspResponderInvalid { .. })
            ),
            "unexpected error for mode {mode}: {err:?}"
        );
    }
    Ok(())
}

#[test]
fn validated_config_rejects_ocsp_url_with_bad_scheme() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    for url in ["ftp://ocsp.example.org/", "ocsp.example.org"] {
        let body = fixture_with_revocation(
            &anchor,
            &format!("mode = \"ocsp\"\ncrl_paths = []\nocsp_responder_url = {url:?}"),
        );
        let raw: RawConfig = toml::from_str(&body)?;
        let err = ValidatedConfig::try_from(&raw).expect_err("non-http(s) url must be rejected");
        assert!(
            matches!(
                err,
                Error::Trust(tessera_core::error::TrustError::OcspResponderInvalid { .. })
            ),
            "unexpected error for url {url}: {err:?}"
        );
    }
    Ok(())
}

#[test]
fn validated_config_rejects_ocsp_timeout_out_of_range() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    for seconds in [0u64, 31] {
        let body = fixture_with_revocation(
            &anchor,
            &format!(
                "mode = \"ocsp\"\ncrl_paths = []\n\
                 ocsp_responder_url = \"https://ocsp.example.org/\"\n\
                 ocsp_timeout_seconds = {seconds}"
            ),
        );
        let raw: RawConfig = toml::from_str(&body)?;
        let err = ValidatedConfig::try_from(&raw).expect_err("out-of-range timeout must fail");
        assert!(
            matches!(err, Error::ConfigInvalid { ref reason }
                if reason.contains("ocsp_timeout_seconds")),
            "unexpected error for {seconds}: {err:?}"
        );
    }
    Ok(())
}

#[test]
fn validated_config_rejects_ocsp_cache_ttl_out_of_range() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let body = fixture_with_revocation(
        &anchor,
        "mode = \"ocsp\"\ncrl_paths = []\n\
         ocsp_responder_url = \"https://ocsp.example.org/\"\nocsp_cache_ttl_seconds = 86401",
    );
    let raw: RawConfig = toml::from_str(&body)?;
    let err = ValidatedConfig::try_from(&raw).expect_err("out-of-range ttl must fail");
    assert!(
        matches!(err, Error::ConfigInvalid { ref reason }
            if reason.contains("ocsp_cache_ttl_seconds")),
        "unexpected error: {err:?}"
    );
    Ok(())
}

#[test]
fn validated_config_rejects_ocsp_keys_outside_ocsp_modes() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    // Each ocsp_* key would be silently ignored at runtime in non-OCSP
    // modes, so validation must reject it (same footgun-guard pattern as
    // monitor.on_usb_removed_hook_path).
    // `crl` mode with empty crl_paths is rejected on its own (a silently
    // disabled revocation check), so give the crl case a real CRL path — any
    // regular file satisfies the existence check — to isolate the ocsp-key
    // guard under test. `none` mode does not consult crl_paths.
    let crl_line = format!("crl_paths = [{:?}]", anchor.display().to_string());
    for (mode, crl_paths_line, key_line) in [
        (
            "crl",
            crl_line.as_str(),
            "ocsp_responder_url = \"https://ocsp.example.org/\"",
        ),
        (
            "none",
            "crl_paths = []",
            "ocsp_responder_url = \"https://ocsp.example.org/\"",
        ),
        ("none", "crl_paths = []", "ocsp_timeout_seconds = 5"),
        ("none", "crl_paths = []", "ocsp_cache_ttl_seconds = 600"),
    ] {
        let body = fixture_with_revocation(
            &anchor,
            &format!("mode = {mode:?}\n{crl_paths_line}\n{key_line}"),
        );
        let raw: RawConfig = toml::from_str(&body)?;
        let err = ValidatedConfig::try_from(&raw)
            .expect_err("ocsp_* keys outside OCSP modes must be rejected");
        assert!(
            matches!(err, Error::ConfigInvalid { ref reason }
                if reason.contains("only valid when")),
            "unexpected error for mode {mode} + {key_line}: {err:?}"
        );
    }
    Ok(())
}

#[test]
fn validated_config_passes_crl_max_age_through() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let body = fixture_with_revocation(
        &anchor,
        "mode = \"none\"\ncrl_paths = []\ncrl_max_age_hours = 24",
    );
    let raw: RawConfig = toml::from_str(&body)?;
    let v = ValidatedConfig::try_from(&raw)?;
    assert_eq!(
        v.trust.revocation.crl_max_age,
        Some(std::time::Duration::from_hours(24))
    );
    Ok(())
}

#[test]
fn validated_config_crl_max_age_defaults_to_none() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let raw: RawConfig = toml::from_str(&fixture_with_anchor(&anchor))?;
    let v = ValidatedConfig::try_from(&raw)?;
    assert_eq!(v.trust.revocation.crl_max_age, None);
    Ok(())
}

#[test]
fn validated_config_rejects_crl_max_age_out_of_range() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    for hours in [0u64, 8761] {
        let body = fixture_with_revocation(
            &anchor,
            &format!("mode = \"none\"\ncrl_paths = []\ncrl_max_age_hours = {hours}"),
        );
        let raw: RawConfig = toml::from_str(&body)?;
        let err = ValidatedConfig::try_from(&raw).expect_err("out-of-range max age must fail");
        assert!(
            matches!(err, Error::ConfigInvalid { ref reason }
                if reason.contains("crl_max_age_hours")),
            "unexpected error for {hours}: {err:?}"
        );
    }
    Ok(())
}

#[test]
fn usb_allowed_devices_roundtrip_to_pairs() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let body = fixture_with_anchor(&anchor);
    let injected = format!("usb_allowed_devices = [\"0951:1666\", \"ABCD:0001\"]\n{body}");
    let raw: RawConfig = toml::from_str(&injected)?;
    assert_eq!(raw.usb_allowed_devices.len(), 2);
    let v = ValidatedConfig::try_from(&raw)?;
    assert_eq!(
        v.usb_allowed_devices,
        vec![(0x0951, 0x1666), (0xABCD, 0x0001)]
    );
    Ok(())
}

#[test]
fn usb_allowed_devices_absent_means_no_filter() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let raw: RawConfig = toml::from_str(&fixture_with_anchor(&anchor))?;
    let v = ValidatedConfig::try_from(&raw)?;
    assert!(v.usb_allowed_devices.is_empty());
    Ok(())
}

#[test]
fn usb_allowed_devices_rejects_malformed_entry() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let body = fixture_with_anchor(&anchor);
    let injected = format!("usb_allowed_devices = [\"951:1666\"]\n{body}");
    let raw: RawConfig = toml::from_str(&injected)?;
    let err = ValidatedConfig::try_from(&raw).expect_err("must reject 3-digit vid");
    assert!(
        matches!(err, Error::ConfigInvalid { ref reason }
            if reason.contains("usb_allowed_devices")),
        "unexpected error: {err:?}"
    );
    Ok(())
}

#[test]
fn usb_wait_seconds_accepts_upper_bound() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let body =
        fixture_with_anchor(&anchor).replace("usb_wait_seconds = 10", "usb_wait_seconds = 300");
    let raw: RawConfig = toml::from_str(&body)?;
    let v = ValidatedConfig::try_from(&raw)?;
    assert_eq!(v.usb_wait, std::time::Duration::from_mins(5));
    Ok(())
}

#[test]
fn usb_wait_seconds_rejects_301() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let body =
        fixture_with_anchor(&anchor).replace("usb_wait_seconds = 10", "usb_wait_seconds = 301");
    let raw: RawConfig = toml::from_str(&body)?;
    let err = ValidatedConfig::try_from(&raw).expect_err("must reject above-range wait");
    assert!(
        matches!(err, Error::ConfigInvalid { ref reason }
            if reason.contains("usb_wait_seconds")),
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

// ---- tags-delegation §5.2: [tags] + max_supported_profile_version ----------

#[test]
fn tags_section_absent_yields_no_applied_tags_default() -> Result<(), Box<dyn std::error::Error>> {
    use tessera_core::config::validated::TagsMode;
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    // The full_valid.toml fixture carries no [tags] section.
    let raw: RawConfig = toml::from_str(&fixture_with_anchor(&anchor))?;
    let v = ValidatedConfig::try_from(&raw)?;
    // Fail-closed default: enforce = false (device has no applied tags),
    // standalone mode, default tags path.
    assert!(!v.tags.enforce);
    assert_eq!(v.tags.mode, TagsMode::Standalone);
    assert_eq!(
        v.tags.source,
        std::path::PathBuf::from(tessera_core::tags::DEFAULT_TAGS_FILE)
    );
    Ok(())
}

#[test]
fn max_supported_profile_version_absent_uses_compiled_default(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let raw: RawConfig = toml::from_str(&fixture_with_anchor(&anchor))?;
    assert!(raw.trust.max_supported_profile_version.is_none());
    let v = ValidatedConfig::try_from(&raw)?;
    assert_eq!(
        v.trust.max_supported_profile_version,
        tessera_core::trust::openssl_verifier::DEFAULT_MAX_SUPPORTED_PROFILE_VERSION
    );
    Ok(())
}

#[test]
fn max_supported_profile_version_explicit_is_carried() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let body = fixture_with_anchor(&anchor)
        .replace("[trust]\n", "[trust]\nmax_supported_profile_version = 3\n");
    let raw: RawConfig = toml::from_str(&body)?;
    let v = ValidatedConfig::try_from(&raw)?;
    assert_eq!(v.trust.max_supported_profile_version, 3);
    Ok(())
}

#[test]
fn tags_section_standalone_parses_and_validates() -> Result<(), Box<dyn std::error::Error>> {
    use tessera_core::config::validated::TagsMode;
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let body = format!(
        "{}\n[tags]\nenforce = true\nmode = \"standalone\"\nsource = \"/var/lib/tessera/tags.toml\"\n",
        fixture_with_anchor(&anchor)
    );
    let raw: RawConfig = toml::from_str(&body)?;
    let v = ValidatedConfig::try_from(&raw)?;
    assert!(v.tags.enforce);
    assert_eq!(v.tags.mode, TagsMode::Standalone);
    assert_eq!(
        v.tags.source,
        std::path::PathBuf::from("/var/lib/tessera/tags.toml")
    );
    Ok(())
}

#[test]
fn tags_section_relative_source_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let body = format!(
        "{}\n[tags]\nenforce = true\nsource = \"relative/tags.toml\"\n",
        fixture_with_anchor(&anchor)
    );
    let raw: RawConfig = toml::from_str(&body)?;
    let err = ValidatedConfig::try_from(&raw).expect_err("relative [tags].source must reject");
    assert!(
        matches!(err, Error::ConfigInvalid { ref reason } if reason.contains("[tags].source must be absolute")),
        "unexpected error: {err:?}"
    );
    Ok(())
}

#[test]
fn tags_section_managed_default_source_is_roles_dir() -> Result<(), Box<dyn std::error::Error>> {
    use tessera_core::config::validated::TagsMode;
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    // Managed mode with no explicit source → role-store directory (shared
    // anti-rollback floor). No [roles] section means the role-store default.
    let body = format!(
        "{}\n[tags]\nenforce = true\nmode = \"managed\"\n",
        fixture_with_anchor(&anchor)
    );
    let raw: RawConfig = toml::from_str(&body)?;
    let v = ValidatedConfig::try_from(&raw)?;
    assert_eq!(v.tags.mode, TagsMode::Managed);
    assert_eq!(
        v.tags.source,
        std::path::PathBuf::from(tessera_core::role::DEFAULT_ROLES_DIR)
    );
    Ok(())
}

#[test]
fn tags_section_rejects_unknown_field() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let anchor = write_anchor(dir.path());
    let body = format!(
        "{}\n[tags]\nenforce = true\nbogus = 1\n",
        fixture_with_anchor(&anchor)
    );
    let parsed: Result<RawConfig, _> = toml::from_str(&body);
    assert!(
        parsed.is_err(),
        "unknown [tags] field must be rejected at parse"
    );
    Ok(())
}
