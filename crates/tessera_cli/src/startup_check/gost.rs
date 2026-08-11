//! GOST-engine configuration diagnostics.
//!
//! Beyond `tessera_core::self_check::self_check()` — which does a fail-closed
//! engine probe on every authentication — operators benefit from seeing
//! GOST misconfiguration up front, at `tessera check` time, in plain
//! language rather than as a PAM denial during the first real login.
//!
//! Four cases are distinguished:
//!
//! 1. `mode = "pkcs11"` with GOST allowed: the PKCS#11 token signing path
//!    can never satisfy this — WARN.
//! 2. `gost_engine_path` set but no GOST OID whitelisted: the engine will
//!    never be reached — WARN (dead configuration).
//! 3. Both set (the fully correct configuration): actually attempt to load
//!    the engine, via the same [`tessera_core::gost::engine::ensure_loaded`]
//!    call `self_check()` makes, and report INFO/ERROR accordingly.
//! 4. Neither set: GOST is simply not in use — no record at all.

use tessera_core::config::validated::{CryptoBackend, Mode};
use tessera_core::config::ValidatedConfig;

use super::{StartupCheckRecord, StartupCheckReport};

/// Cross-check the GOST-related configuration for internally inconsistent
/// or unreachable combinations.
///
/// See the module docs for the four cases distinguished here.
pub fn check(cfg: &ValidatedConfig, report: &mut StartupCheckReport) {
    let engine_path_set = cfg.gost_engine_path.is_some();
    let needs_gost = cfg.needs_gost();

    // Case 4 first, cheaply: neither the engine path nor a GOST OID is
    // configured — this host simply doesn't use GOST. No record: this
    // mirrors how the other check modules stay silent on inapplicable
    // branches (e.g. `mac_runtime::check` on a host with no kernel parsec
    // and `mac.runtime = disabled`).
    if !engine_path_set && !needs_gost {
        return;
    }

    // Case 1: PKCS#11-token signing can never do GOST, regardless of
    // whether the engine machinery below is also configured — the token
    // path never touches it. See the module doc-comment on
    // `crate::token::pkcs11::mechanism` (`OPEN QUESTION (cryptoki <= 0.7)`):
    // cryptoki 0.7's `Mechanism` enum has no GOST signing variant — neither
    // `CKM_GOSTR3410` nor any 2012-prefixed extension. PKCS#11 v2.40 only
    // carries them as numeric constants in the vendor-extension range, and
    // the crate exposes no `Custom`/`Raw` escape hatch to reach them.
    if matches!(cfg.mode, Mode::Pkcs11) && needs_gost {
        report.push(StartupCheckRecord::warn(
            "gost_pkcs11_unsupported",
            "mode = \"pkcs11\" with a GOST signature algorithm allowed: GOST via a \
             PKCS#11 token is not supported. The upstream `cryptoki` crate (<= 0.7) has no \
             mechanism variant for CKM_GOSTR3410 or any 2012-prefixed GOST mechanism — \
             PKCS#11 v2.40 only exposes them as numeric vendor-extension constants, and \
             `cryptoki` provides no Custom/Raw escape hatch to reach them. Any GOST \
             certificate presented through this token will fail to sign at auth time. \
             Remove the GOST OID(s) from allowed_signature_algorithms, or switch to \
             mode = \"pkcs12\" (crypto_backend = \"openssl\" with gost_engine_path set).",
        ));
        return;
    }

    // Everything past this point only concerns the OpenSSL/gost-engine
    // path; `needs_gost()` is `false` for `CryptoBackend::Pkcs11Native` by
    // construction (see its doc comment), so there is nothing further to
    // check for that backend once case 1 above didn't apply.
    if !matches!(cfg.crypto_backend, CryptoBackend::Openssl) {
        return;
    }

    if engine_path_set && !needs_gost {
        // Case 2: dead configuration. The validator does not reject this
        // combination — an engine path with no GOST OID whitelisted is not
        // unsafe, just pointless — so surface it as a WARN rather than
        // silence, since it's most likely a config left behind after
        // trimming allowed_signature_algorithms.
        report.push(StartupCheckRecord::warn(
            "gost_engine_configured_unused",
            "gost_engine_path is set, but no GOST signature algorithm is present in \
             trust.allowed_signature_algorithms: the gost-engine will never be loaded. \
             Add a GOST OID to the whitelist if GOST certificates are expected, or remove \
             gost_engine_path if GOST is not needed on this host.",
        ));
        return;
    }

    if engine_path_set && needs_gost {
        // Case 3: the fully correct configuration. Reuse the same
        // `ensure_loaded` call `self_check()` makes on every authentication
        // — this surfaces the same failure mode at preflight time instead
        // of at the first real login.
        match tessera_core::gost::engine::ensure_loaded(cfg) {
            Ok(()) => {
                report.push(StartupCheckRecord::info(
                    "gost_engine_ok",
                    "GOST is configured (gost_engine_path set, a GOST signature algorithm is \
                     whitelisted) and the gost-engine loaded successfully.",
                ));
            }
            Err(err) => {
                report.push(StartupCheckRecord::error(
                    "gost_engine_load_failed",
                    format!(
                        "GOST is configured (gost_engine_path set, a GOST signature \
                         algorithm is whitelisted) but the gost-engine failed to load: \
                         {err}. Authentication against GOST certificates will fail closed \
                         until this is fixed."
                    ),
                ));
            }
        }
    }

    // The remaining combination — `needs_gost() && !engine_path_set` — is
    // rejected by `ValidatedConfig::try_from` before a `ValidatedConfig`
    // ever exists (see `crates/tessera_core/src/config/validated.rs`), so
    // it is unreachable through normal construction and deliberately left
    // as a silent no-op here rather than duplicating that validation.
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::startup_check::StartupCheckSeverity;

    /// Minimal but fully valid config TOML, mirroring
    /// `tests/startup_check.rs::write_min_config`: `crypto_backend =
    /// "openssl"`, `mode` as given, no GOST configured. Each test mutates
    /// the loaded [`ValidatedConfig`] in place to reach the scenario it
    /// wants to exercise — the same pattern the trust-anchor tests in
    /// `tests/startup_check.rs` use (e.g. `startup_check_missing_anchor_errors`),
    /// since several of the states here (a GOST OID with no engine path
    /// configured, an engine path that stops existing after load) are
    /// refused by the TOML validator and can only be reached by mutating
    /// the struct directly. `mode` is parameterised because case A needs
    /// `"pkcs11"` specifically while the OpenSSL-engine cases (C/D/E) use
    /// `"pkcs12"` so they don't also trip the `mode == Pkcs11` branch.
    fn base_cfg(anchor: &std::path::Path, mode: &str) -> ValidatedConfig {
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

    fn write_anchor(dir: &std::path::Path) -> std::path::PathBuf {
        let p = dir.join("anchor.pem");
        std::fs::write(
            &p,
            "-----BEGIN CERTIFICATE-----\nXX\n-----END CERTIFICATE-----\n",
        )
        .expect("write anchor");
        p
    }

    const GOST_OID: &str = "1.2.643.7.1.1.3.2";

    #[test]
    fn case_a_pkcs11_mode_with_gost_warns_and_stops() {
        let tmp = tempfile::tempdir().expect("tmp");
        let anchor = write_anchor(tmp.path());
        let mut cfg = base_cfg(&anchor, "pkcs11");
        // mode is "pkcs11"; make needs_gost() true.
        cfg.trust
            .allowed_signature_algorithms
            .insert(GOST_OID.to_owned());
        assert!(matches!(cfg.mode, Mode::Pkcs11));
        assert!(cfg.needs_gost());

        let mut report = StartupCheckReport::default();
        check(&cfg, &mut report);

        assert_eq!(report.records.len(), 1, "{report:#?}");
        assert_eq!(report.records[0].severity, StartupCheckSeverity::Warn);
        assert_eq!(report.records[0].check, "gost_pkcs11_unsupported");
    }

    #[test]
    fn case_c_engine_path_without_gost_oid_warns() {
        let tmp = tempfile::tempdir().expect("tmp");
        let anchor = write_anchor(tmp.path());
        let mut cfg = base_cfg(&anchor, "pkcs12");
        let engine = tmp.path().join("gost.so");
        std::fs::write(&engine, "not a real engine").expect("write fake engine");
        cfg.gost_engine_path = Some(engine);
        // No GOST OID whitelisted -> needs_gost() stays false.
        assert!(!cfg.needs_gost());

        let mut report = StartupCheckReport::default();
        check(&cfg, &mut report);

        assert_eq!(report.records.len(), 1, "{report:#?}");
        assert_eq!(report.records[0].severity, StartupCheckSeverity::Warn);
        assert_eq!(report.records[0].check, "gost_engine_configured_unused");
    }

    #[test]
    fn case_d_correct_config_but_missing_engine_file_errors() {
        let tmp = tempfile::tempdir().expect("tmp");
        let anchor = write_anchor(tmp.path());
        let mut cfg = base_cfg(&anchor, "pkcs12");
        cfg.trust
            .allowed_signature_algorithms
            .insert(GOST_OID.to_owned());
        // Point at a path that does not exist on disk: `ensure_loaded`
        // checks existence at call time (not at config-load time), so this
        // reaches a genuine `GostEngineError::PathMissing` without needing
        // a real gost-engine .so on the test host.
        cfg.gost_engine_path = Some(tmp.path().join("nonexistent-gost.so"));
        assert!(cfg.needs_gost());

        let mut report = StartupCheckReport::default();
        check(&cfg, &mut report);

        assert_eq!(report.records.len(), 1, "{report:#?}");
        assert_eq!(report.records[0].severity, StartupCheckSeverity::Error);
        assert_eq!(report.records[0].check, "gost_engine_load_failed");
        assert!(
            report.records[0].message.contains("nonexistent-gost.so"),
            "expected the missing path in the error message: {}",
            report.records[0].message
        );
    }

    #[test]
    fn case_e_nothing_configured_is_silent() {
        let tmp = tempfile::tempdir().expect("tmp");
        let anchor = write_anchor(tmp.path());
        let cfg = base_cfg(&anchor, "pkcs12");
        assert!(cfg.gost_engine_path.is_none());
        assert!(!cfg.needs_gost());

        let mut report = StartupCheckReport::default();
        check(&cfg, &mut report);

        assert!(report.records.is_empty(), "{report:#?}");
    }
}
