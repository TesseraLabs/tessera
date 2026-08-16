//! GOST-engine configuration diagnostics.
//!
//! Beyond `tessera_core::self_check::self_check()` — which does a fail-closed
//! engine probe on every authentication — operators benefit from seeing
//! GOST misconfiguration up front, at `tessera check` time, in plain
//! language rather than as a PAM denial during the first real login.
//!
//! Three cases are distinguished:
//!
//! 1. `gost_engine_path` set but no GOST OID whitelisted: the engine is
//!    still loaded at auth time, so it is probed here too; a working engine
//!    only earns a WARN about the apparently forgotten setting, while a
//!    broken one denies every authentication on the host regardless of the
//!    whitelist.
//! 2. Both set (the fully correct configuration): probe the engine and
//!    report INFO/ERROR accordingly.
//! 3. Neither set: GOST is simply not in use — no record at all.
//!
//! Every case with an engine path configured runs the same
//! [`tessera_core::gost::engine::ensure_ready`] probe that
//! `tessera_core::self_check::self_check()` runs on every authentication, so
//! preflight and PAM cannot disagree about whether GOST works on this host.
//! The probe therefore does not depend on the rest of the configuration
//! being usable: on a host where the `mode`/`crypto_backend` pairing already
//! dooms every login (see [`super::crypto_backend`]), authentication still
//! hits the engine first, and preflight has to report it in the same order.

use std::path::Path;

use tessera_core::config::validated::CryptoBackend;
use tessera_core::config::ValidatedConfig;
use tessera_core::gost::GostEngineError;

use super::{StartupCheckRecord, StartupCheckReport};

/// Signature of the engine probe.
///
/// Injecting it is what lets the tests reach both outcomes of every branch:
/// a working engine cannot be conjured from a fixture, and a process-global
/// loader that caches its first result cannot be made to answer differently
/// twice.
pub type EngineProbe = fn(&ValidatedConfig) -> Result<(), GostEngineError>;

/// Engine readiness, carried from the point where the probe has to run to
/// the point where its record belongs in the report.
///
/// The probe must happen before anything else in the pipeline touches
/// libcrypto (see [`super::run_startup_checks_with_backend`]), while the
/// record reads best next to the `mode`/`crypto_backend` pairing. This type
/// is what keeps those two places apart.
#[derive(Debug)]
#[must_use]
pub struct EngineReadiness {
    /// `None` when this host has no GOST configuration worth probing — see
    /// the module docs, case 3.
    outcome: Option<Result<(), GostEngineError>>,
}

/// Signature of the path-only engine probe.
///
/// The engine is decided by one field, and a caller that has to probe before
/// the rest of the configuration is loadable has nothing else to offer. See
/// [`probe_path`].
pub type EnginePathProbe = fn(Option<&Path>) -> Result<(), GostEngineError>;

/// Probe the configured gost-engine, if this host configures one at all.
///
/// Nothing is loaded when neither `gost_engine_path` nor a GOST OID is
/// configured, so a host without GOST pays no cost and gets no record.
pub fn probe(cfg: &ValidatedConfig) -> EngineReadiness {
    probe_with(cfg, tessera_core::gost::engine::ensure_ready)
}

/// Probe an engine path that has already been established as trusted, with no
/// [`ValidatedConfig`] in hand.
///
/// For callers that must settle the engine before the whole configuration can
/// be loaded — `tessera enroll` installs the very artefacts a first-enrollment
/// config already names, so the full load only succeeds after the import, and
/// the import verifies the manifest through libcrypto. `None` means the config
/// loads no engine at all, which is the same silence [`probe_with`] keeps for
/// such a host.
///
/// The path must come from a source that applied the root-control policy
/// (`tessera_core::config::load_privileged_gost_engine_path`), not from raw
/// TOML: what is loaded here runs inside the authentication process.
pub fn probe_path(engine_path: Option<&Path>) -> EngineReadiness {
    probe_path_with(
        engine_path,
        tessera_core::gost::engine::ensure_ready_with_path,
    )
}

/// [`probe_path`] with the engine probe supplied by the caller.
pub fn probe_path_with<P>(engine_path: Option<&Path>, probe: P) -> EngineReadiness
where
    P: FnOnce(Option<&Path>) -> Result<(), GostEngineError>,
{
    match engine_path {
        None => EngineReadiness { outcome: None },
        Some(path) => EngineReadiness {
            outcome: Some(probe(Some(path))),
        },
    }
}

/// Readiness for a host whose engine was never probed, and whose report
/// therefore carries no engine record.
pub fn not_probed() -> EngineReadiness {
    EngineReadiness { outcome: None }
}

/// [`probe`] with the engine probe supplied by the caller.
pub fn probe_with<P>(cfg: &ValidatedConfig, probe: P) -> EngineReadiness
where
    P: FnOnce(&ValidatedConfig) -> Result<(), GostEngineError>,
{
    let engine_path_set = cfg.gost_engine_path.is_some();

    // Case 3 first, cheaply: neither the engine path nor a GOST OID is
    // configured — this host simply doesn't use GOST. No record: this
    // mirrors how the other check modules stay silent on inapplicable
    // branches (e.g. `mac_runtime::check` on a host with no kernel parsec
    // and `mac.runtime = disabled`).
    if !engine_path_set && !cfg.needs_gost() {
        return EngineReadiness { outcome: None };
    }

    // Everything past this point only concerns the OpenSSL/gost-engine
    // path; `needs_gost()` is `false` for `CryptoBackend::Pkcs11Native` by
    // construction (see its doc comment), and `gost_engine_path` is rejected
    // outright for that backend by `ValidatedConfig::try_from`, so this
    // guard is belt-and-braces rather than a reachable branch.
    if !matches!(cfg.crypto_backend, CryptoBackend::Openssl) {
        return EngineReadiness { outcome: None };
    }

    if !engine_path_set {
        // The remaining combination — `needs_gost() && !engine_path_set` —
        // is rejected by `ValidatedConfig::try_from` before a
        // `ValidatedConfig` ever exists (see
        // `crates/tessera_core/src/config/validated.rs`), so it is
        // unreachable through normal construction and deliberately left as
        // a silent no-op here rather than duplicating that validation.
        return EngineReadiness { outcome: None };
    }

    // Cases 1 and 2 both probe: whenever a path is configured, `self_check`
    // loads the engine on every authentication regardless of the whitelist,
    // and refuses the call before it has looked at the certificate or the
    // mode. A broken engine therefore breaks *every* login on this host, not
    // only the GOST ones — which is exactly what preflight has to say out
    // loud.
    EngineReadiness {
        outcome: Some(probe(cfg)),
    }
}

/// Cross-check the GOST-related configuration for internally inconsistent
/// or unreachable combinations.
///
/// See the module docs for the three cases distinguished here. Probes the
/// engine on the spot; pipelines that must control *when* the engine is
/// loaded probe with [`probe`] and report with [`record`] instead.
pub fn check(cfg: &ValidatedConfig, report: &mut StartupCheckReport) {
    record(cfg, probe(cfg), report);
}

/// Turn an already obtained [`EngineReadiness`] into a report record.
pub fn record(cfg: &ValidatedConfig, readiness: EngineReadiness, report: &mut StartupCheckReport) {
    let Some(readiness) = readiness.outcome else {
        return;
    };
    let needs_gost = cfg.needs_gost();

    match (readiness, needs_gost) {
        (Err(err), _) => {
            report.push(StartupCheckRecord::error(
                "gost_engine_load_failed",
                format!(
                    "gost_engine_path is set but the gost-engine is not usable: {err}. \
                     No authentication succeeds on this host at all: the engine is probed \
                     before the certificate or the mode is looked at, so RSA and ECDSA \
                     logins are refused too, with PAM_AUTHINFO_UNAVAIL. Remove \
                     gost_engine_path if GOST is not needed on this host, or fix the \
                     engine installation."
                ),
            ));
        }
        (Ok(()), false) => {
            // Dead-looking configuration. The validator does not reject it
            // — an engine path with no GOST OID whitelisted is not unsafe,
            // just probably left behind after trimming
            // allowed_signature_algorithms — and the engine does load, so
            // this is a WARN about the setting, not about the host.
            report.push(StartupCheckRecord::warn(
                "gost_engine_configured_unused",
                "gost_engine_path is set and the gost-engine loads, but no GOST signature \
                 algorithm is present in trust.allowed_signature_algorithms: no GOST \
                 certificate chain will be accepted. Add a GOST OID to the whitelist if \
                 GOST certificates are expected, or remove gost_engine_path if GOST is not \
                 needed on this host.",
            ));
        }
        (Ok(()), true) => {
            report.push(StartupCheckRecord::info(
                "gost_engine_ok",
                "GOST is configured (gost_engine_path set, a GOST signature algorithm is \
                 whitelisted); the gost-engine loaded and both Streebog digests resolved.",
            ));
        }
    }
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
    use crate::startup_check::test_config::{base_cfg, write_anchor};
    use crate::startup_check::StartupCheckSeverity;

    const GOST_OID: &str = "1.2.643.7.1.1.3.2";

    /// Probe and report in one step, the way [`check`] does, but with the
    /// probe supplied by the test.
    fn check_with_probe<P>(cfg: &ValidatedConfig, report: &mut StartupCheckReport, probe: P)
    where
        P: FnOnce(&ValidatedConfig) -> Result<(), GostEngineError>,
    {
        record(cfg, probe_with(cfg, probe), report);
    }

    /// Probe stub standing in for a host where the engine loads and both
    /// Streebog digests resolve.
    const ENGINE_READY: fn(&ValidatedConfig) -> Result<(), GostEngineError> = |_| Ok(());

    /// Probe stub standing in for a host where the engine is configured but
    /// unusable — the failure operators actually hit (wrong build, missing
    /// file, an engine that registers no Streebog).
    const ENGINE_BROKEN: fn(&ValidatedConfig) -> Result<(), GostEngineError> = |_| {
        Err(GostEngineError::digest_unavailable(
            "md_gost12_512 not registered after engine load",
        ))
    };

    /// A doomed `mode`/`crypto_backend` pairing must not swallow the engine
    /// probe: `self_check` loads the engine before it ever reaches PKCS#11,
    /// so a broken engine is what an operator hits first, and preflight has
    /// to list it first too.
    #[test]
    fn broken_engine_is_reported_before_the_unusable_mode_pairing() {
        let tmp = tempfile::tempdir().expect("tmp");
        let anchor = write_anchor(tmp.path());
        let mut cfg = base_cfg(&anchor, "pkcs11");
        let engine = tmp.path().join("gost.so");
        std::fs::write(&engine, "not a real engine").expect("write fake engine");
        cfg.gost_engine_path = Some(engine);
        cfg.trust
            .allowed_signature_algorithms
            .insert(GOST_OID.to_owned());
        assert!(cfg.needs_gost());

        let mut report = StartupCheckReport::default();
        check_with_probe(&cfg, &mut report, ENGINE_BROKEN);
        crate::startup_check::crypto_backend::check(&cfg, &mut report);

        assert_eq!(report.records.len(), 2, "{report:#?}");
        assert_eq!(report.records[0].check, "gost_engine_load_failed");
        assert_eq!(report.records[0].severity, StartupCheckSeverity::Error);
        assert_eq!(report.records[1].check, "pkcs11_openssl_unsupported");
        assert_eq!(report.records[1].severity, StartupCheckSeverity::Error);
    }

    #[test]
    fn case_1_engine_path_without_gost_oid_warns_when_engine_is_usable() {
        let tmp = tempfile::tempdir().expect("tmp");
        let anchor = write_anchor(tmp.path());
        let mut cfg = base_cfg(&anchor, "pkcs12");
        let engine = tmp.path().join("gost.so");
        std::fs::write(&engine, "not a real engine").expect("write fake engine");
        cfg.gost_engine_path = Some(engine);
        // No GOST OID whitelisted -> needs_gost() stays false.
        assert!(!cfg.needs_gost());

        let mut report = StartupCheckReport::default();
        check_with_probe(&cfg, &mut report, ENGINE_READY);

        assert_eq!(report.records.len(), 1, "{report:#?}");
        assert_eq!(report.records[0].severity, StartupCheckSeverity::Warn);
        assert_eq!(report.records[0].check, "gost_engine_configured_unused");
    }

    #[test]
    fn case_1_engine_path_without_gost_oid_errors_when_engine_is_broken() {
        // The combination the WARN used to hide: no GOST OID is whitelisted,
        // so the old check returned early and reported nothing worse than a
        // warning — while `self_check` loads the engine on every
        // authentication whenever a path is configured, and fails closed.
        let tmp = tempfile::tempdir().expect("tmp");
        let anchor = write_anchor(tmp.path());
        let mut cfg = base_cfg(&anchor, "pkcs12");
        let engine = tmp.path().join("gost.so");
        std::fs::write(&engine, "not a real engine").expect("write fake engine");
        cfg.gost_engine_path = Some(engine);
        assert!(!cfg.needs_gost());

        let mut report = StartupCheckReport::default();
        check_with_probe(&cfg, &mut report, ENGINE_BROKEN);

        assert_eq!(report.records.len(), 1, "{report:#?}");
        assert_eq!(report.records[0].severity, StartupCheckSeverity::Error);
        assert_eq!(report.records[0].check, "gost_engine_load_failed");
        assert!(
            report.records[0].message.contains("md_gost12_512"),
            "expected the probe failure in the message: {}",
            report.records[0].message
        );
    }

    #[test]
    fn case_2_correct_config_with_usable_engine_is_info() {
        let tmp = tempfile::tempdir().expect("tmp");
        let anchor = write_anchor(tmp.path());
        let mut cfg = base_cfg(&anchor, "pkcs12");
        cfg.trust
            .allowed_signature_algorithms
            .insert(GOST_OID.to_owned());
        cfg.gost_engine_path = Some(tmp.path().join("gost.so"));
        assert!(cfg.needs_gost());

        let mut report = StartupCheckReport::default();
        check_with_probe(&cfg, &mut report, ENGINE_READY);

        assert_eq!(report.records.len(), 1, "{report:#?}");
        assert_eq!(report.records[0].severity, StartupCheckSeverity::Info);
        assert_eq!(report.records[0].check, "gost_engine_ok");
    }

    #[test]
    fn case_2_correct_config_but_missing_engine_file_errors() {
        let tmp = tempfile::tempdir().expect("tmp");
        let anchor = write_anchor(tmp.path());
        let mut cfg = base_cfg(&anchor, "pkcs12");
        cfg.trust
            .allowed_signature_algorithms
            .insert(GOST_OID.to_owned());
        // Goes through the real probe, not a stub, so the wiring from
        // `check` to `ensure_ready` is covered too. Point at a path that
        // does not exist on disk: the loader checks existence at call time
        // (not at config-load time), so this reaches a genuine
        // `GostEngineError::PathMissing` without needing a real
        // gost-engine .so on the test host.
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
    fn case_3_nothing_configured_is_silent() {
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
