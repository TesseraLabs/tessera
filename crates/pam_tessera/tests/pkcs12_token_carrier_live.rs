//! Live check of the token carrier on the authentication path.
//!
//! The unit tests around [`pam_tessera::flow::authenticate_pkcs12`] serve the
//! envelope from a stub, which proves the branching but says nothing about a
//! real provider. These tests drive the same function the login drives,
//! against whatever token `PKCS11_MODULE_PATH` points at.
//!
//! Two properties a stub cannot establish: the container comes back byte for
//! byte, and it comes off **the token the configuration names**. The second
//! only fails on a bench with more than one token connected, which is exactly
//! the bench where a first-slot read looks like a byte mismatch.
//!
//! Preconditions, because the reading side does not write:
//!
//! - `PKCS11_MODULE_PATH` — the provider (unset: the tests skip).
//! - `SOFTHSM_USER_PIN` — the token PIN (default `1234`), the same variable
//!   the other live PKCS#11 tests use.
//! - `TESSERA_CARRIER_TOKEN` — `CK_TOKEN_INFO.label` of the token holding the
//!   envelope. Unset means "whatever token is connected", which is only
//!   meaningful with exactly one; with two the reading path refuses to choose.
//! - `TESSERA_CARRIER_OBJECT` — label the envelope was written under
//!   (default `tessera-credential`), placed there by
//!   `issuer prepare-carrier --module … --object-label …`.
//! - `TESSERA_CARRIER_TOKEN_SERIAL` — optional; the serial the envelope is
//!   expected to have come from, so a read off the wrong device is named as
//!   such instead of surfacing as a byte mismatch.
//! - `TESSERA_CARRIER_P12` — optional; the container that was written, for a
//!   byte-for-byte comparison against what came back.
//!
//! Nothing here writes to the token or logs in more than once per test.

#![cfg(feature = "pkcs11-tests")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use secrecy::SecretString;
use tessera_core::config::validated::Pkcs12Source;
use tessera_core::config::ValidatedConfig;
use tessera_core::token::pkcs11::test_helpers::{pkcs11_test_module_path, PKCS11_MODULE_ENV};

mod common;

const DEFAULT_OBJECT_LABEL: &str = "tessera-credential";

fn object_label() -> String {
    std::env::var("TESSERA_CARRIER_OBJECT").unwrap_or_else(|_| DEFAULT_OBJECT_LABEL.to_owned())
}

fn user_pin() -> SecretString {
    SecretString::from(std::env::var("SOFTHSM_USER_PIN").unwrap_or_else(|_| "1234".to_owned()))
}

/// The config a login would carry for this carrier.
///
/// `token_label` is threaded through rather than always read from the
/// environment so the ambiguity test can ask for the unnamed case explicitly.
fn token_carrier_cfg(
    module: std::path::PathBuf,
    object_label: String,
    token_label: Option<String>,
) -> ValidatedConfig {
    let mut cfg = common::minimal_cfg();
    cfg.pkcs11_module = Some(module);
    cfg.pkcs11_token_label = token_label;
    cfg.pkcs12_source = Pkcs12Source::TokenObject { object_label };
    cfg
}

#[test]
fn live_the_carrier_object_reaches_the_authentication_path() {
    let Some(module) = pkcs11_test_module_path() else {
        eprintln!("skipped: {PKCS11_MODULE_ENV} is not set to an existing module");
        return;
    };
    let label = object_label();
    let cfg = token_carrier_cfg(
        module,
        label.clone(),
        std::env::var("TESSERA_CARRIER_TOKEN").ok(),
    );
    let io = pam_tessera::flow::real_pkcs11_io(&cfg).expect("load the provider");

    let carrier =
        pam_tessera::flow::read_token_carrier_with(&io, &cfg, &label, &mut |_| Ok(user_pin()))
            .expect("the carrier object is readable behind the PIN");

    // Checked before the bytes: a read off the wrong device shows up as a byte
    // mismatch, and "the container came back truncated" sends whoever reads
    // the failure to the hardware instead of to the configuration.
    if let Ok(want) = std::env::var("TESSERA_CARRIER_TOKEN_SERIAL") {
        assert_eq!(
            carrier.token_serial, want,
            "the envelope came off a different token than the one the config names"
        );
    }
    assert!(
        !carrier.token_serial.trim().is_empty(),
        "an empty serial leaves the session with nothing to match a removal event against"
    );

    if let Ok(expected_path) = std::env::var("TESSERA_CARRIER_P12") {
        let expected = std::fs::read(&expected_path).expect("read the expected container");
        assert_eq!(
            carrier.p12_bytes, expected,
            "the container must come back byte for byte; a length-only check would pass a \
             truncation the device did not report"
        );
    } else {
        eprintln!("note: TESSERA_CARRIER_P12 unset, byte comparison skipped");
        assert!(
            !carrier.p12_bytes.is_empty(),
            "an empty object is not a container"
        );
    }

    eprintln!(
        "carrier read: {} bytes under {label:?} from token serial {}",
        carrier.p12_bytes.len(),
        carrier.token_serial
    );
}

/// With more than one token connected and none named, the reading path must
/// refuse rather than take whichever the provider enumerated first.
///
/// Self-detecting: on a bench with one token there is nothing to be ambiguous
/// about and the test skips.
#[test]
fn live_an_unnamed_carrier_is_refused_when_several_tokens_are_connected() {
    use pam_tessera::flow::Pkcs11Io as _;

    let Some(module) = pkcs11_test_module_path() else {
        eprintln!("skipped: {PKCS11_MODULE_ENV} is not set to an existing module");
        return;
    };
    let label = object_label();
    let cfg = token_carrier_cfg(module, label.clone(), None);
    let io = pam_tessera::flow::real_pkcs11_io(&cfg).expect("load the provider");

    let connected = io.matching_tokens().expect("enumerate tokens").len();
    if connected < 2 {
        eprintln!("skipped: {connected} token(s) connected, nothing to be ambiguous about");
        return;
    }

    let prompts = std::cell::Cell::new(0_usize);
    let err = pam_tessera::flow::read_token_carrier_with(&io, &cfg, &label, &mut |_| {
        prompts.set(prompts.get() + 1);
        Ok(user_pin())
    })
    .expect_err("with several tokens connected the carrier is not determined");

    assert!(
        matches!(
            err,
            pam_tessera::flow::FlowError::TokenCarrierAmbiguous { .. }
        ),
        "got {err:?}"
    );
    assert_eq!(
        prompts.get(),
        0,
        "no PIN may be presented to a token that was not named as the carrier"
    );
    eprintln!("refused as ambiguous with {connected} tokens connected: {err}");
}
