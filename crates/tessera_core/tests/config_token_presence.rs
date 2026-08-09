//! Config surface of the token-presence monitor.
//!
//! Two things are read off a whole config document rather than off a single
//! validator function: the poll interval that bounds detection latency, and
//! the pairing of strict monitoring with the token carrier — which used to be
//! refused here, because nothing observed a token's presence.

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic,
    clippy::unwrap_used
)]

#[allow(dead_code)]
#[path = "../src/test_support.rs"]
mod test_support;

use std::path::Path;
use std::time::Duration;

use tessera_core::config::validated::{MonitorFailMode, Pkcs12Source};
use tessera_core::config::{RawConfig, ValidatedConfig};
use tessera_core::Error;

const FAKE_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBfTCCAS6gAwIBAgIUcheCkYc5VvuuVlZ8KqfA8R6Bvs8wCgYIKoZIzj0EAwIw\n\
-----END CERTIFICATE-----\n";

fn write_anchor(dir: &Path) -> std::path::PathBuf {
    let p = dir.join("anchor.pem");
    std::fs::write(&p, FAKE_PEM).expect("write anchor");
    p
}

/// The shipping fixture, switched to the token carrier, with `monitor_extra`
/// appended to the trailing `[monitor]` table that
/// [`test_support::platform_config_toml`] adds.
///
/// The fixture already carries `monitor_fail_mode = "strict"`, which is the
/// combination under test.
fn token_carrier_config(anchor: &Path, monitor_extra: &str) -> String {
    let module = test_support::absolute("/usr/lib/x.so");
    let body = include_str!("fixtures/full_valid.toml")
        .replace(
            "anchors = [\"/bin/sh\"]",
            &format!("anchors = [{}]", test_support::toml_path(anchor)),
        )
        .replace(
            "pkcs11_module = \"/bin/sh\"",
            &format!("pkcs11_module = {}", test_support::toml_path(&module)),
        )
        .replace("mode = \"pkcs11\"", "mode = \"pkcs12\"");
    let body = format!(
        "pkcs12_source = \"token_object\"\n\
         pkcs12_token_object_label = \"tessera-credential\"\n\
         {body}"
    );
    format!(
        "{}\n{monitor_extra}\n",
        test_support::platform_config_toml(&body)
    )
}

fn validate(body: &str) -> Result<ValidatedConfig, Error> {
    let raw: RawConfig = toml::from_str(body).expect("parse");
    ValidatedConfig::try_from(&raw)
}

/// Strict monitoring promises the session ends with its carrier. The daemon
/// now polls the provider for the carrier's serial, so the promise is
/// keepable and the configuration is accepted.
#[test]
fn strict_monitoring_is_accepted_for_the_token_carrier() {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor = write_anchor(dir.path());
    let cfg = validate(&token_carrier_config(&anchor, ""))
        .expect("strict monitoring of a token carrier is enforceable");

    assert_eq!(
        cfg.monitor.fail_mode,
        MonitorFailMode::Strict,
        "the fixture's strict mode must survive validation, or this proves nothing"
    );
    assert_eq!(
        cfg.pkcs12_source,
        Pkcs12Source::TokenObject {
            object_label: "tessera-credential".to_owned()
        }
    );
}

/// The interval is the floor on detection latency, so an operator who never
/// sets it still gets a bounded one.
#[test]
fn the_poll_interval_has_a_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor = write_anchor(dir.path());
    let cfg = validate(&token_carrier_config(&anchor, "")).expect("validate");
    assert_eq!(cfg.monitor.token_poll_interval, Duration::from_secs(2));
}

#[test]
fn the_poll_interval_is_configurable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor = write_anchor(dir.path());
    let body = token_carrier_config(&anchor, "token_poll_interval_seconds = 5");
    let cfg = validate(&body).expect("validate");
    assert_eq!(cfg.monitor.token_poll_interval, Duration::from_secs(5));
}

/// Zero is not "poll as fast as possible" but a busy loop against the
/// provider, and the value has an upper bound for the same reason the removal
/// grace does.
#[test]
fn an_out_of_range_poll_interval_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor = write_anchor(dir.path());
    for n in [0_u64, 601, 100_000] {
        let body = token_carrier_config(&anchor, &format!("token_poll_interval_seconds = {n}"));
        let err = validate(&body).expect_err(&format!("must reject n={n}"));
        match err {
            Error::ConfigInvalid { reason } => assert!(
                reason.contains("token_poll_interval_seconds"),
                "n={n}: {reason}"
            ),
            other => panic!("n={n}: unexpected error: {other:?}"),
        }
    }
}
