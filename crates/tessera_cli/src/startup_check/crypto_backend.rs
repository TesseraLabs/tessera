//! `mode` × `crypto_backend` pairing diagnostics.
//!
//! One pairing — `mode = "pkcs11"` with `crypto_backend = "openssl"` — is
//! accepted by the config validator but refused by the authentication flow
//! for *every* credential, GOST or not: `pam_tessera::flow` returns
//! `Pkcs11OpensslEngineNotImplemented` (PAM_AUTHINFO_UNAVAIL) before the
//! token is touched, because driving a token through OpenSSL would need the
//! `pkcs11` engine (libp11), which Tessera does not use. Nobody logs in on
//! such a host, so preflight has to say so out loud even when the
//! configuration mentions no GOST at all.
//!
//! Kept apart from [`super::gost`] deliberately: this pairing is fatal
//! independently of GOST, so it must not sit behind any GOST-shaped
//! condition. It runs *after* the GOST checks so the report lists failures
//! in the order authentication hits them — `tessera_core::self_check`
//! probes the gost-engine before it touches PKCS#11.

use tessera_core::config::validated::{CryptoBackend, Mode};
use tessera_core::config::ValidatedConfig;

use super::{StartupCheckRecord, StartupCheckReport};

/// Report configuration pairings under which no authentication can succeed.
pub fn check(cfg: &ValidatedConfig, report: &mut StartupCheckReport) {
    if !matches!(cfg.mode, Mode::Pkcs11) || !matches!(cfg.crypto_backend, CryptoBackend::Openssl) {
        return;
    }

    report.push(StartupCheckRecord::error(
        "pkcs11_openssl_unsupported",
        "mode = \"pkcs11\" with crypto_backend = \"openssl\": no authentication of any kind \
         succeeds in this combination — driving a token through OpenSSL requires the `pkcs11` \
         engine (libp11), which Tessera does not use, so every attempt fails with \
         PAM_AUTHINFO_UNAVAIL before the token is touched. GOST is no exception and has no \
         token-side path either: `cryptoki` 0.12 exposes no GOST signing mechanism \
         (CKM_GOSTR3410 = 0x1201 and CKM_GOSTR3411 = 0x1210 are standard, not vendor-defined, \
         so `MechanismType::new_vendor_defined` rejects them — it only accepts values at or \
         above CKM_VENDOR_DEFINED = 0x80000000). Switch to crypto_backend = \"pkcs11_native\" \
         for token authentication, or to mode = \"pkcs12\" (crypto_backend = \"openssl\" with \
         gost_engine_path set) for GOST.",
    ));
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

    #[test]
    fn pkcs11_mode_with_openssl_backend_errors_without_any_gost_configured() {
        let tmp = tempfile::tempdir().expect("tmp");
        let anchor = write_anchor(tmp.path());
        let cfg = base_cfg(&anchor, "pkcs11");
        // Neither a GOST OID nor an engine path: the pairing alone is fatal.
        assert!(!cfg.needs_gost());
        assert!(cfg.gost_engine_path.is_none());

        let mut report = StartupCheckReport::default();
        check(&cfg, &mut report);

        assert_eq!(report.records.len(), 1, "{report:#?}");
        assert_eq!(report.records[0].severity, StartupCheckSeverity::Error);
        assert_eq!(report.records[0].check, "pkcs11_openssl_unsupported");
    }

    #[test]
    fn pkcs11_mode_with_openssl_backend_errors_with_gost_configured_too() {
        let tmp = tempfile::tempdir().expect("tmp");
        let anchor = write_anchor(tmp.path());
        let mut cfg = base_cfg(&anchor, "pkcs11");
        cfg.trust
            .allowed_signature_algorithms
            .insert("1.2.643.7.1.1.3.2".to_owned());
        assert!(cfg.needs_gost());

        let mut report = StartupCheckReport::default();
        check(&cfg, &mut report);

        assert_eq!(report.records.len(), 1, "{report:#?}");
        assert_eq!(report.records[0].check, "pkcs11_openssl_unsupported");
    }

    #[test]
    fn pkcs12_mode_is_silent() {
        let tmp = tempfile::tempdir().expect("tmp");
        let anchor = write_anchor(tmp.path());
        let cfg = base_cfg(&anchor, "pkcs12");

        let mut report = StartupCheckReport::default();
        check(&cfg, &mut report);

        assert!(report.records.is_empty(), "{report:#?}");
    }
}
