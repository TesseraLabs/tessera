//! T15 — `self_check` PKCS#11 branch.
//!
//! These tests cover the PKCS#11-specific code path that was added to
//! [`tessera_core::self_check::self_check`] in stage 4: when
//! `mode = "pkcs11"` we now actively probe the configured module path,
//! catching `dlopen`/`C_Initialize` failures (and any panics inside
//! `cryptoki`) and reporting them as
//! [`SelfCheckError::Pkcs11ModuleMissing`].
//!
//! These run on every host — they don't require a real PKCS#11
//! provider.  The "module load fails" case uses paths that are
//! guaranteed to fail loading (`/nonexistent/...`, `/bin/sh`).

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic,
    clippy::unwrap_used
)]

use std::path::Path;

use tessera_core::config::{RawConfig, ValidatedConfig};
use tessera_core::self_check::self_check;
use tessera_core::SelfCheckError;

/// Minimal self-signed-looking PEM blob that satisfies the PEM sniff
/// in the trust validator.
const FAKE_PEM_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBfTCCAS6gAwIBAgIUcheCkYc5VvuuVlZ8KqfA8R6Bvs8wCgYIKoZIzj0EAwIw\n\
-----END CERTIFICATE-----\n";

fn write_anchor(dir: &Path) -> std::path::PathBuf {
    let p = dir.join("anchor.pem");
    std::fs::write(&p, FAKE_PEM_CERT).expect("write anchor");
    p
}

/// Build a fully-validated config from the shipping fixture, with
/// configurable module path and mode.  The fixture defaults to
/// `mode = "pkcs11"` and `pkcs11_module = "/bin/sh"`; we override both
/// here.
fn cfg_with(mode: &str, pkcs11_module_path: &str, anchor: &Path) -> ValidatedConfig {
    let original = include_str!("fixtures/full_valid.toml");
    let body = original
        .replace(
            "anchors = [\"/bin/sh\"]",
            &format!("anchors = [{:?}]", anchor.to_string_lossy()),
        )
        .replace(
            "pkcs11_module = \"/bin/sh\"",
            &format!("pkcs11_module = {pkcs11_module_path:?}"),
        )
        .replace("mode = \"pkcs11\"", &format!("mode = {mode:?}"));
    let raw: RawConfig = toml::from_str(&body).expect("parse fixture");
    ValidatedConfig::try_from(&raw).expect("validate")
}

#[test]
fn pkcs11_mode_with_missing_module_path_returns_module_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor = write_anchor(dir.path());
    let cfg = cfg_with(
        "pkcs11",
        "/nonexistent/__tessera_no_such_module__.so",
        &anchor,
    );
    let err = self_check(&cfg).err().expect("must fail");
    match err {
        SelfCheckError::Pkcs11ModuleMissing(msg) => {
            assert!(
                msg.contains("does not exist"),
                "expected 'does not exist' substring, got {msg}"
            );
        }
        other => panic!("expected Pkcs11ModuleMissing, got {other:?}"),
    }
}

#[test]
fn pkcs11_mode_with_non_pkcs11_so_returns_module_missing() {
    // `/bin/sh` exists and is loadable as a Mach-O / ELF object, but it
    // does not export `C_GetFunctionList`.  cryptoki 0.7 is known to
    // panic from inside `Pkcs11::new` in this case; T15's catch_unwind
    // converts that into a normal `Pkcs11ModuleMissing` error.
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor = write_anchor(dir.path());
    let cfg = cfg_with("pkcs11", "/bin/sh", &anchor);
    let err = self_check(&cfg).err().expect("must fail");
    match err {
        SelfCheckError::Pkcs11ModuleMissing(msg) => {
            assert!(
                msg.contains("/bin/sh"),
                "error must mention the module path, got {msg}"
            );
        }
        other => panic!("expected Pkcs11ModuleMissing, got {other:?}"),
    }
}

#[test]
fn pkcs12_mode_does_not_touch_pkcs11_module_path() {
    // PKCS#12 mode must skip the PKCS#11 self-check entirely, even
    // when `pkcs11_module` happens to point at a bogus path.
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor = write_anchor(dir.path());
    let cfg = cfg_with(
        "pkcs12",
        "/nonexistent/__tessera_no_such_module__.so",
        &anchor,
    );
    self_check(&cfg).expect("pkcs12 mode must skip pkcs11 self-check");
}

#[test]
fn pkcs11_no_token_branch_compiles() {
    // The `Pkcs11NoToken` variant currently isn't returned (we WARN +
    // Ok) but we still want to make sure the variant remains
    // constructible by external code so the public API is stable.
    let e: SelfCheckError = SelfCheckError::Pkcs11NoToken;
    assert!(format!("{e}").contains("pkcs11"));
}
