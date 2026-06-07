//! Integration tests for `tessera_cli::startup_check`.
//!
//! Covers the PAM-stack ordering scanner, the [mac].runtime cross-check,
//! and the trust-anchor existence/empty checks. Production callers compose
//! these into [`run_startup_checks`]; the tests drive each helper
//! independently with deterministic injected inputs.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use tessera_cli::startup_check::{
    self, run_startup_checks, KernelParsecState, StartupCheckOptions, StartupCheckReport,
    StartupCheckSeverity,
};
use tessera_core::config::validated::MacRuntimeMode;
use tessera_core::config::{load_validated_config, ValidatedConfig};

/// Helper: minimal config TOML mirroring `fixtures/full_valid.toml` but
/// parameterised on anchor path, mac runtime, and `host_identity` sources
/// so each test can drive the validator from a controlled state.
fn write_min_config(
    dir: &std::path::Path,
    anchor_path: &str,
    mac_runtime: &str,
    cert_integrity: &str,
) -> PathBuf {
    let path = dir.join("config.toml");
    let body = format!(
        r#"crypto_backend = "openssl"
mode = "pkcs11"
pkcs11_module = "/bin/sh"
usb_wait_seconds = 10
on_usb_removed = "lock"
usb_removed_grace_seconds = 5
suspend_grace_seconds = 5
monitor_fail_mode = "strict"

[trust]
anchors = ["{anchor_path}"]
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

[[user_mapping]]
pam_user = "alice"
cert_subject_cn = "Alice"

[logging]
level = "info"
syslog_facility = "auth"
journald_priority = true

[mac]
runtime = "{mac_runtime}"
cert_integrity = "{cert_integrity}"
"#,
    );
    fs::write(&path, body).expect("write config");
    path
}

/// Tiny anchor file with one valid-looking PEM header so the trust check
/// doesn't bail before the file size invariant.
fn write_anchor(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, body).expect("anchor write");
    p
}

const FAKE_PEM: &str = "-----BEGIN CERTIFICATE-----\nXX\n-----END CERTIFICATE-----\n";

fn load_cfg(toml_path: &std::path::Path) -> ValidatedConfig {
    load_validated_config(toml_path).expect("validate config")
}

// ---------------------------------------------------------------------------
// PAM stack ordering
// ---------------------------------------------------------------------------

#[test]
fn startup_check_pam_misorder_emits_error() {
    let tmp = tempfile::tempdir().expect("tmp");
    let svc = tmp.path().join("login");
    let mut f = fs::File::create(&svc).expect("svc");
    writeln!(
        f,
        "@include certauth-only\nauth required pam_parsec_mac.so\naccount required pam_parsec_mac.so"
    )
    .expect("write");

    let mut report = StartupCheckReport::default();
    startup_check::pam_stack::check(tmp.path(), &mut report);

    let errs: Vec<_> = report
        .records
        .iter()
        .filter(|r| r.severity == StartupCheckSeverity::Error)
        .collect();
    assert_eq!(errs.len(), 1, "expected one ERROR record, got {report:#?}");
    let err = errs[0];
    assert_eq!(err.check, "pam_stack_misorder");
    assert!(err.message.contains("login"), "msg: {}", err.message);
    assert!(
        err.message.contains("integrate-pam.sh"),
        "expected admin fix hint in: {}",
        err.message
    );
}

#[test]
fn startup_check_pam_correct_order_emits_info() {
    let tmp = tempfile::tempdir().expect("tmp");
    let svc = tmp.path().join("login");
    let mut f = fs::File::create(&svc).expect("svc");
    writeln!(
        f,
        "auth required pam_parsec_mac.so\n@include certauth-only\naccount required pam_parsec_mac.so"
    )
    .expect("write");

    let mut report = StartupCheckReport::default();
    startup_check::pam_stack::check(tmp.path(), &mut report);

    assert_eq!(report.count(StartupCheckSeverity::Error), 0);
    let oks: Vec<_> = report
        .records
        .iter()
        .filter(|r| r.check == "pam_stack_ok")
        .collect();
    assert_eq!(oks.len(), 1);
}

#[test]
fn startup_check_pam_no_parsec_mac_is_silent() {
    let tmp = tempfile::tempdir().expect("tmp");
    let svc = tmp.path().join("login");
    let mut f = fs::File::create(&svc).expect("svc");
    writeln!(f, "@include certauth-only\nauth required pam_unix.so").expect("write");

    let mut report = StartupCheckReport::default();
    startup_check::pam_stack::check(tmp.path(), &mut report);
    // No pam_parsec_mac in stack -> no record (host without МКЦ).
    assert!(
        report.records.is_empty(),
        "expected silent, got: {report:#?}"
    );
}

#[test]
fn startup_check_pam_session_misorder_detected() {
    // session pam_tessera.so BEFORE @include common-session →
    // XDG_SESSION_ID не доступен на момент sm_open_session.
    let tmp = tempfile::tempdir().expect("tmp");
    let svc = tmp.path().join("login");
    let mut f = fs::File::create(&svc).expect("svc");
    writeln!(
        f,
        "auth required pam_unix.so\n\
         session required pam_tessera.so\n\
         @include common-session"
    )
    .expect("write");

    let mut report = StartupCheckReport::default();
    startup_check::pam_stack::check(tmp.path(), &mut report);

    let errs: Vec<_> = report
        .records
        .iter()
        .filter(|r| r.severity == StartupCheckSeverity::Error)
        .collect();
    assert_eq!(errs.len(), 1, "expected one ERROR record, got {report:#?}");
    assert_eq!(errs[0].check, "pam_stack_session_misorder");
    assert!(
        errs[0].message.contains("XDG_SESSION_ID"),
        "msg: {}",
        errs[0].message
    );
    assert!(
        errs[0].message.contains("integrate-pam.sh"),
        "expected fix hint in: {}",
        errs[0].message
    );
}

#[test]
fn startup_check_pam_session_correct_order_emits_info() {
    let tmp = tempfile::tempdir().expect("tmp");
    let svc = tmp.path().join("login");
    let mut f = fs::File::create(&svc).expect("svc");
    writeln!(
        f,
        "auth required pam_unix.so\n\
         @include common-session\n\
         session required pam_tessera.so"
    )
    .expect("write");

    let mut report = StartupCheckReport::default();
    startup_check::pam_stack::check(tmp.path(), &mut report);

    assert_eq!(report.count(StartupCheckSeverity::Error), 0);
    let oks: Vec<_> = report
        .records
        .iter()
        .filter(|r| r.check == "pam_stack_session_ok")
        .collect();
    assert_eq!(oks.len(), 1, "{report:#?}");
}

#[test]
fn startup_check_pam_session_no_systemd_is_info() {
    // session pam_tessera present but no pam_systemd / common-session →
    // not an error, but an INFO so the operator knows logind logout is off.
    let tmp = tempfile::tempdir().expect("tmp");
    let svc = tmp.path().join("login");
    let mut f = fs::File::create(&svc).expect("svc");
    writeln!(
        f,
        "auth required pam_unix.so\nsession required pam_tessera.so"
    )
    .expect("write");

    let mut report = StartupCheckReport::default();
    startup_check::pam_stack::check(tmp.path(), &mut report);

    assert_eq!(report.count(StartupCheckSeverity::Error), 0);
    let infos: Vec<_> = report
        .records
        .iter()
        .filter(|r| r.check == "pam_stack_session_no_systemd")
        .collect();
    assert_eq!(infos.len(), 1, "{report:#?}");
}

#[test]
fn startup_check_pam_session_direct_pam_systemd_anchor() {
    // Direct `session ... pam_systemd.so` line (no @include common-session
    // aggregator) should still anchor the ordering check.
    let tmp = tempfile::tempdir().expect("tmp");
    let svc = tmp.path().join("login");
    let mut f = fs::File::create(&svc).expect("svc");
    writeln!(
        f,
        "auth required pam_unix.so\n\
         session optional pam_systemd.so\n\
         session required pam_tessera.so"
    )
    .expect("write");

    let mut report = StartupCheckReport::default();
    startup_check::pam_stack::check(tmp.path(), &mut report);

    assert_eq!(report.count(StartupCheckSeverity::Error), 0);
    assert_eq!(
        report
            .records
            .iter()
            .filter(|r| r.check == "pam_stack_session_ok")
            .count(),
        1,
        "{report:#?}"
    );
}

#[test]
fn startup_check_pam_comments_are_ignored() {
    let tmp = tempfile::tempdir().expect("tmp");
    let svc = tmp.path().join("login");
    let mut f = fs::File::create(&svc).expect("svc");
    // The `@include` is commented out so should not register.
    writeln!(
        f,
        "# @include certauth-only\nauth required pam_parsec_mac.so"
    )
    .expect("write");

    let mut report = StartupCheckReport::default();
    startup_check::pam_stack::check(tmp.path(), &mut report);
    assert!(report.records.is_empty(), "got: {report:#?}");
}

// ---------------------------------------------------------------------------
// MAC runtime cross-check
// ---------------------------------------------------------------------------

#[test]
fn startup_check_runtime_required_without_kernel_errors() {
    // The TOML validator rejects [mac].runtime = "required" when the binary
    // is built without `astra-mac`, so we mutate the field directly after a
    // valid load. The startup check itself doesn't care how the field was
    // populated — production builds with the feature ship `required` from
    // TOML, dev/test builds reach the same branch via this shortcut.
    let tmp = tempfile::tempdir().expect("tmp");
    let anchor = write_anchor(tmp.path(), "anchor.pem", FAKE_PEM);
    let cfg_path = write_min_config(tmp.path(), anchor.to_str().unwrap(), "auto", "optional");
    let mut cfg = load_cfg(&cfg_path);
    cfg.mac.runtime = MacRuntimeMode::Required;

    let mut report = StartupCheckReport::default();
    startup_check::mac_runtime::check(&cfg, KernelParsecState::Unavailable, &mut report);

    let errs: Vec<_> = report
        .records
        .iter()
        .filter(|r| r.severity == StartupCheckSeverity::Error)
        .collect();
    assert_eq!(errs.len(), 1, "{report:#?}");
    assert_eq!(errs[0].check, "mac_runtime_required_missing_kernel");
}

#[test]
fn startup_check_runtime_disabled_with_kernel_present_is_info() {
    let tmp = tempfile::tempdir().expect("tmp");
    let anchor = write_anchor(tmp.path(), "anchor.pem", FAKE_PEM);
    let cfg_path = write_min_config(tmp.path(), anchor.to_str().unwrap(), "disabled", "optional");
    let cfg = load_cfg(&cfg_path);

    let mut report = StartupCheckReport::default();
    startup_check::mac_runtime::check(&cfg, KernelParsecState::Active, &mut report);

    assert_eq!(report.count(StartupCheckSeverity::Error), 0);
    assert_eq!(report.count(StartupCheckSeverity::Warn), 0);
    assert_eq!(report.count(StartupCheckSeverity::Info), 1);
    assert_eq!(report.records[0].check, "mac_runtime_disabled_with_kernel");
}

#[test]
fn startup_check_runtime_auto_without_kernel_warns() {
    let tmp = tempfile::tempdir().expect("tmp");
    let anchor = write_anchor(tmp.path(), "anchor.pem", FAKE_PEM);
    let cfg_path = write_min_config(tmp.path(), anchor.to_str().unwrap(), "auto", "optional");
    let cfg = load_cfg(&cfg_path);

    let mut report = StartupCheckReport::default();
    startup_check::mac_runtime::check(&cfg, KernelParsecState::Disabled, &mut report);
    assert_eq!(report.count(StartupCheckSeverity::Warn), 1);
    assert_eq!(report.records[0].check, "mac_runtime_auto_fallback");
}

// ---------------------------------------------------------------------------
// Trust anchor checks
// ---------------------------------------------------------------------------

#[test]
fn startup_check_missing_anchor_errors() {
    // The TOML validator already rejects missing-anchor paths, so we mutate
    // the field after load to exercise the startup-time defense-in-depth
    // path (e.g. anchor deleted between provisioning and a daemon restart).
    let tmp = tempfile::tempdir().expect("tmp");
    let anchor = write_anchor(tmp.path(), "anchor.pem", FAKE_PEM);
    let cfg_path = write_min_config(tmp.path(), anchor.to_str().unwrap(), "auto", "optional");
    let mut cfg = load_cfg(&cfg_path);
    cfg.trust.anchors = vec![PathBuf::from("/nonexistent/path/to/anchor.pem")];

    let mut report = StartupCheckReport::default();
    startup_check::trust::check_anchors(&cfg, &mut report);

    let errs: Vec<_> = report
        .records
        .iter()
        .filter(|r| r.severity == StartupCheckSeverity::Error)
        .collect();
    assert_eq!(errs.len(), 1, "{report:#?}");
    assert_eq!(errs[0].check, "trust_anchor_missing");
}

#[test]
fn startup_check_empty_anchor_errors() {
    // Same shape as the missing-anchor test: validator rejects empty/non-PEM
    // anchors at load time, but the startup check still needs to catch the
    // scenario where the anchor file has been truncated after validation.
    let tmp = tempfile::tempdir().expect("tmp");
    let anchor = write_anchor(tmp.path(), "anchor.pem", FAKE_PEM);
    let cfg_path = write_min_config(tmp.path(), anchor.to_str().unwrap(), "auto", "optional");
    let mut cfg = load_cfg(&cfg_path);
    let empty = write_anchor(tmp.path(), "empty.pem", "");
    cfg.trust.anchors = vec![empty];

    let mut report = StartupCheckReport::default();
    startup_check::trust::check_anchors(&cfg, &mut report);

    let errs: Vec<_> = report
        .records
        .iter()
        .filter(|r| r.severity == StartupCheckSeverity::Error)
        .collect();
    assert_eq!(errs.len(), 1, "{report:#?}");
    assert_eq!(errs[0].check, "trust_anchor_empty");
}

#[test]
fn startup_check_anchor_with_pem_emits_ok() {
    let tmp = tempfile::tempdir().expect("tmp");
    let anchor = write_anchor(tmp.path(), "good.pem", FAKE_PEM);
    let cfg_path = write_min_config(tmp.path(), anchor.to_str().unwrap(), "auto", "optional");
    let cfg = load_cfg(&cfg_path);

    let mut report = StartupCheckReport::default();
    startup_check::trust::check_anchors(&cfg, &mut report);

    assert_eq!(report.count(StartupCheckSeverity::Error), 0);
    let oks: Vec<_> = report
        .records
        .iter()
        .filter(|r| r.check == "trust_anchor_ok")
        .collect();
    assert_eq!(oks.len(), 1);
    assert!(oks[0].message.contains("1 PEM block"));
}

#[test]
fn startup_check_anchor_no_pem_markers_warns() {
    let tmp = tempfile::tempdir().expect("tmp");
    let anchor = write_anchor(tmp.path(), "anchor.pem", FAKE_PEM);
    let cfg_path = write_min_config(tmp.path(), anchor.to_str().unwrap(), "auto", "optional");
    let mut cfg = load_cfg(&cfg_path);
    let junk = write_anchor(tmp.path(), "junk.pem", "not really pem data\n");
    cfg.trust.anchors = vec![junk];

    let mut report = StartupCheckReport::default();
    startup_check::trust::check_anchors(&cfg, &mut report);
    assert_eq!(report.count(StartupCheckSeverity::Warn), 1);
    assert_eq!(report.records[0].check, "trust_anchor_no_pem");
}

// ---------------------------------------------------------------------------
// Full pipeline smoke
// ---------------------------------------------------------------------------

#[test]
fn run_startup_checks_full_smoke_no_errors_for_healthy_config() {
    let tmp = tempfile::tempdir().expect("tmp");
    let anchor = write_anchor(tmp.path(), "anchor.pem", FAKE_PEM);
    let cfg_path = write_min_config(tmp.path(), anchor.to_str().unwrap(), "auto", "optional");
    let cfg = load_cfg(&cfg_path);

    // pam_d empty -> no pam_stack records; fs_root tmpdir -> no /etc dir.
    let pam_d = tmp.path().join("pam.d");
    fs::create_dir_all(&pam_d).expect("mkdir");
    let opts = StartupCheckOptions {
        pam_d_root: pam_d,
        fs_root: Some(tmp.path().to_path_buf()),
        kernel_parsec_probe: Some(probe_unavailable),
    };

    let report = run_startup_checks(&cfg, &opts);
    assert!(!report.has_errors(), "expected clean sweep: {report:#?}");
}

fn probe_unavailable() -> KernelParsecState {
    KernelParsecState::Unavailable
}
