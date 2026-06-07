//! Structural self-checks.

use crate::config::validated::{Mode, RevocationMode, ValidatedConfig};
use crate::error::SelfCheckError;
use crate::gost;
use crate::token::pkcs11::Pkcs11Backend;
use tracing::warn;

/// Run structural and crypto-readiness self-checks.
///
/// In addition to the Stage-1 PEM/CRL/hook/ACL checks, this also performs
/// a fail-closed gost-engine probe when the active configuration whitelists
/// GOST signature OIDs.  The engine is loaded once per process and the
/// required digest NIDs are resolved; any failure surfaces as
/// [`SelfCheckError::GostEngineUnavailable`] so that the caller can refuse
/// authentication outright rather than silently downgrade to a non-GOST
/// path.
///
/// # Errors
///
/// Any of the [`SelfCheckError`] variants — see the enum docs.
pub fn self_check(cfg: &ValidatedConfig) -> Result<(), SelfCheckError> {
    for path in &cfg.trust.anchors {
        let text = std::fs::read_to_string(path)
            .map_err(|_| SelfCheckError::AnchorUnreadable { path: path.clone() })?;
        if !text.contains("-----BEGIN CERTIFICATE-----") {
            return Err(SelfCheckError::AnchorNotPem { path: path.clone() });
        }
    }
    if cfg.trust.revocation.mode == RevocationMode::Crl {
        for path in &cfg.trust.revocation.crl_paths {
            let text = std::fs::read_to_string(path)
                .map_err(|_| SelfCheckError::CrlUnreadable { path: path.clone() })?;
            if !text.contains("-----BEGIN X509 CRL-----") {
                return Err(SelfCheckError::CrlNotPem { path: path.clone() });
            }
        }
    }
    for hook in &cfg.hooks {
        // `validate_hook` отвергает пустой command (EmptyCommand), поэтому
        // в валидированном HookConfig первый элемент всегда присутствует.
        #[allow(clippy::indexing_slicing)]
        let path = std::path::PathBuf::from(&hook.command[0]);
        if !path.exists() {
            return Err(SelfCheckError::HookCommandMissing {
                stage: hook.stage,
                path,
            });
        }
    }
    if matches!(cfg.mode, Mode::Pkcs11) {
        self_check_pkcs11(cfg)?;
    }
    if cfg.needs_gost() {
        gost::engine::ensure_loaded(cfg)?;
        // Probe the digest NIDs as well; a misconfigured engine that
        // claims to load but doesn't register Streebog should fail
        // self_check, not the first auth attempt.
        let _ = gost::algorithms::gost_2012_256_md()?;
        let _ = gost::algorithms::gost_2012_512_md()?;
    }
    Ok(())
}

/// PKCS#11-mode self-check (T15).
///
/// Verifies that:
/// 1. `pkcs11_module` is set in the validated config (validation should
///    already have caught a missing path; this is belt-and-braces).
/// 2. The configured `.so` actually exists on disk and is readable.
/// 3. `Pkcs11Backend::load` succeeds (`dlopen` + `C_Initialize`).
/// 4. At least one slot reports a present token — but a missing token
///    is **not** fatal here (see [`SelfCheckError::Pkcs11NoToken`]):
///    operators commonly run Tessera self-test before plugging
///    the token, so we only WARN.
fn self_check_pkcs11(cfg: &ValidatedConfig) -> Result<(), SelfCheckError> {
    let module_path = cfg.pkcs11_module.as_ref().ok_or_else(|| {
        SelfCheckError::Pkcs11ModuleMissing("pkcs11_module not set in config".to_owned())
    })?;
    if !module_path.exists() {
        return Err(SelfCheckError::Pkcs11ModuleMissing(format!(
            "pkcs11_module path does not exist: {}",
            module_path.display()
        )));
    }
    let metadata = std::fs::metadata(module_path).map_err(|source| {
        SelfCheckError::Pkcs11ModuleMissing(format!(
            "pkcs11_module unreadable {}: {source}",
            module_path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(SelfCheckError::Pkcs11ModuleMissing(format!(
            "pkcs11_module is not a regular file: {}",
            module_path.display()
        )));
    }

    // `cryptoki::Pkcs11::new` has been observed to panic when handed a
    // .so that lacks `C_GetFunctionList` (e.g. an arbitrary executable
    // pointed to by a misconfigured `pkcs11_module`).  Self-check is
    // expected to be fail-closed but **never** to abort the host
    // process: catch the unwind and convert it into a normal error.
    let module_path_owned = module_path.clone();
    let locking_mode = cfg.pkcs11_locking_mode;
    let load_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        Pkcs11Backend::load(&module_path_owned, locking_mode)
    }));
    let backend = match load_result {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            return Err(SelfCheckError::Pkcs11ModuleMissing(format!(
                "pkcs11 backend load failed for {}: {e}",
                module_path.display()
            )));
        }
        Err(panic) => {
            let panic_msg = panic
                .downcast_ref::<&str>()
                .map(|s| (*s).to_owned())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "(non-string panic payload)".to_owned());
            return Err(SelfCheckError::Pkcs11ModuleMissing(format!(
                "pkcs11 backend panicked while loading {}: {panic_msg}",
                module_path.display()
            )));
        }
    };

    match backend.list_slots_with_token() {
        Ok(slots) if slots.is_empty() => {
            warn!(
                target: "tessera.self_check",
                module = %module_path.display(),
                "pkcs11_self_check_no_token: backend loaded but no slot reports a present \
                 token; continuing — this is informational, the auth flow will block on \
                 wait_for_token at run time"
            );
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(e) => {
            warn!(
                target: "tessera.self_check",
                error = %e,
                "pkcs11_self_check_slot_query_failed: backend loaded but C_GetSlotList \
                 failed; continuing — most providers recover at auth time"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::raw::RawConfig;
    use crate::gost::engine;

    fn fixture(extra_top: &str, anchor_path: &std::path::Path) -> ValidatedConfig {
        let original = include_str!("../tests/fixtures/full_valid.toml");
        // The fixture defaults to `mode = "pkcs11"` with a fake module
        // path (`/bin/sh`).  Pre-T15 the self-check ignored that field
        // entirely; T15 now actually `dlopen`s it which fails (or, on
        // some platforms, panics from inside cryptoki).  Switch the
        // fixture to `mode = "pkcs12"` for the GOST self-check tests so
        // they keep targeting the same code path they always did.
        let body = original
            .replace(
                "anchors = [\"/bin/sh\"]",
                &format!("anchors = [{:?}]", anchor_path.to_string_lossy()),
            )
            .replace("mode = \"pkcs11\"", "mode = \"pkcs12\"");
        let body = if extra_top.is_empty() {
            body
        } else {
            format!("{extra_top}\n{body}")
        };
        let raw: RawConfig = toml::from_str(&body).expect("parse fixture");
        ValidatedConfig::try_from(&raw).expect("validate")
    }

    fn write_pem_anchor(dir: &std::path::Path) -> std::path::PathBuf {
        let p = dir.join("anchor.pem");
        std::fs::write(
            &p,
            "-----BEGIN CERTIFICATE-----\n\
             MIIBfTCCAS6gAwIBAgIUcheCkYc5VvuuVlZ8KqfA8R6Bvs8wCgYIKoZIzj0EAwIw\n\
             -----END CERTIFICATE-----\n",
        )
        .expect("write anchor");
        p
    }

    #[test]
    fn self_check_passes_when_no_gost_required() {
        let dir = tempfile::tempdir().expect("tempdir");
        let anchor = write_pem_anchor(dir.path());
        let cfg = fixture("", &anchor);
        // Sanity: this fixture must not require GOST.
        assert!(!cfg.needs_gost());
        match self_check(&cfg) {
            Ok(()) => {}
            Err(e) => panic!("self_check unexpectedly failed: {e:?}"),
        }
    }

    #[test]
    fn self_check_fails_with_gost_unavailable_when_gost_oids_required() {
        let dir = tempfile::tempdir().expect("tempdir");
        let anchor = write_pem_anchor(dir.path());
        // Inject a GOST OID into the trust whitelist via raw mutation:
        // we cannot simply prepend at top level (it would be parsed under
        // the last [section]), so we splice in the trust block.
        let original = include_str!("../tests/fixtures/full_valid.toml");
        let body = original
            .replace(
                "anchors = [\"/bin/sh\"]",
                &format!("anchors = [{:?}]", anchor.to_string_lossy()),
            )
            .replace("mode = \"pkcs11\"", "mode = \"pkcs12\"");
        let body = body.replace(
            "allowed_signature_algorithms = []",
            "allowed_signature_algorithms = [\"1.2.643.7.1.1.3.2\"]",
        );
        let raw: RawConfig = toml::from_str(&body).expect("parse");
        let cfg = ValidatedConfig::try_from(&raw).expect("validate");
        assert!(cfg.needs_gost());

        let res = self_check(&cfg);
        if engine::is_available() {
            // CARGO_GOST_TESTS / real engine present.
            match res {
                Ok(()) => {}
                Err(e) => panic!("expected ok with engine loaded: {e:?}"),
            }
        } else {
            match res {
                Err(SelfCheckError::GostEngineUnavailable(_)) => {}
                Ok(()) => panic!("self_check passed without engine"),
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
    }
}
