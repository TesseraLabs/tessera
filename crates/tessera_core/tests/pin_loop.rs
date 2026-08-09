#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use std::cell::Cell;

use secrecy::SecretString;
use tessera_core::pam_conv::PamConvError;
use tessera_core::pkcs12::{acquire_p12_material_with_prompter, AcquireError};

const RSA: &[u8] = include_bytes!("fixtures/leaf_rsa.p12");

/// DER of the `id-sha256` OID, as it appears in the container's `macData`.
const SHA256_OID_DER: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];

/// A path no host has an engine at.
///
/// Naming a file is what unlocks the engine retry; whether the file exists
/// only decides how far the retry gets. Tests that want the retry attempted
/// but not completed use this.
const ABSENT_ENGINE: &str = "/nonexistent/engines/gost.so";

/// The RSA fixture with the digest its MAC names replaced by an unassigned
/// OID, so this libcrypto cannot resolve it.
///
/// This reproduces, on a host with no GOST anything, the failure a real GOST
/// container produces before `gost-engine` is registered: the MAC names a
/// digest the process does not have, so `PKCS12_verify_mac` cannot compute a
/// MAC at all and OpenSSL reports the outcome as a MAC verify failure sitting
/// on top of the real cause —
///
/// ```text
/// digital envelope routines:inner_evp_generic_fetch:unsupported ... Algorithm (2.16.840.1.101.3.4.2.127 : 0)
/// PKCS12 routines:pkcs12_gen_mac:unknown digest algorithm
/// PKCS12 routines:PKCS12_verify_mac:mac generation error
/// PKCS12 routines:PKCS12_parse:mac verify failure
/// ```
///
/// Only the MAC's algorithm identifier is touched, and that sits outside the
/// authenticated content, so the container stays a well-formed PKCS#12 and
/// `Pkcs12::from_der` still accepts it. That matters: truncating or corrupting
/// the container instead fails in `from_der`, before the code under test is
/// ever reached.
///
/// The PIN is irrelevant to the outcome, exactly as it is on a real GOST
/// container: the MAC is unreachable before the digest exists, so the password
/// has not yet entered into it.
fn container_with_an_unresolvable_mac_digest() -> Vec<u8> {
    let occurrences: Vec<usize> = RSA
        .windows(SHA256_OID_DER.len())
        .enumerate()
        .filter_map(|(at, window)| (window == SHA256_OID_DER).then_some(at))
        .collect();
    assert_eq!(
        occurrences.len(),
        1,
        "the fixture must name id-sha256 exactly once (its macData); found {occurrences:?}",
    );
    let start = *occurrences.first().expect("exactly one, just asserted");

    let mut bytes = RSA.to_vec();
    // Bump the OID's last arc from 1 (id-sha256) to 127, which is unassigned:
    // `2.16.840.1.101.3.4.2.127`.
    let last_arc = bytes
        .get_mut(start + SHA256_OID_DER.len() - 1)
        .expect("the match was found inside these very bytes");
    *last_arc = 0x7F;
    bytes
}

#[test]
fn succeeds_on_first_try() {
    let calls = Cell::new(0_u8);
    let prompter = |_p: &str| {
        calls.set(calls.get() + 1);
        Ok(SecretString::from("correct-pin".to_string()))
    };
    let m = acquire_p12_material_with_prompter(RSA, 3, None, prompter, None).unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(m.end_entity.subject_cn().unwrap(), "alice");
}

#[test]
fn succeeds_on_third_try() {
    let calls = Cell::new(0_u8);
    let prompter = |_p: &str| {
        calls.set(calls.get() + 1);
        let pin = if calls.get() < 3 {
            "nope"
        } else {
            "correct-pin"
        };
        Ok(SecretString::from(pin.to_string()))
    };
    let m = acquire_p12_material_with_prompter(RSA, 3, None, prompter, None).unwrap();
    assert_eq!(calls.get(), 3);
    assert_eq!(m.end_entity.subject_cn().unwrap(), "alice");
}

#[test]
fn fails_after_three_wrong_pins() {
    let calls = Cell::new(0_u8);
    let prompter = |_p: &str| {
        calls.set(calls.get() + 1);
        Ok(SecretString::from("nope".to_string()))
    };
    let err = acquire_p12_material_with_prompter(RSA, 3, None, prompter, None).unwrap_err();
    assert!(matches!(err, AcquireError::MaxTries), "got {err:?}");
    assert_eq!(calls.get(), 3);
}

#[test]
fn conv_error_short_circuits() {
    let calls = Cell::new(0_u8);
    let prompter = |_p: &str| -> Result<SecretString, PamConvError> {
        calls.set(calls.get() + 1);
        Err(PamConvError::ConvFailed)
    };
    let err = acquire_p12_material_with_prompter(RSA, 3, None, prompter, None).unwrap_err();
    assert!(
        matches!(err, AcquireError::Conv(PamConvError::ConvFailed)),
        "got {err:?}"
    );
    assert_eq!(calls.get(), 1, "should bail on first conv error");
}

#[test]
fn a_container_that_opens_never_reaches_the_engine_at_all() {
    // An RSA container opens on libcrypto's own implementations. The engine
    // is a consequence of a *failure*, never of the configuration, so naming
    // one — here a file that does not exist, which would fail loudly if it
    // were ever loaded — must change nothing about this login.
    let engine = std::path::Path::new(ABSENT_ENGINE);
    let prompter = |_p: &str| Ok(SecretString::from("correct-pin".to_string()));
    let m = acquire_p12_material_with_prompter(RSA, 3, None, prompter, Some(engine)).unwrap();
    assert_eq!(m.end_entity.subject_cn().unwrap(), "alice");
    assert!(
        !tessera_core::gost::engine::is_available(),
        "a container that opened on its own pulled in an engine",
    );
}

#[test]
fn a_container_naming_a_digest_this_host_lacks_is_not_a_wrong_pin() {
    // The Astra defect, reproduced without Astra. OpenSSL puts `mac verify
    // failure` on top of the stack when it cannot compute the MAC at all, and
    // reading only that line turns "this host has no implementation for the
    // algorithm this container uses" into "the engineer mistyped the PIN":
    // the loop then re-prompts to exhaustion and the engine is never loaded.
    //
    // Before the classification looked past that line this returned MaxTries
    // after three prompts.
    let calls = Cell::new(0_u8);
    let prompter = |_p: &str| {
        calls.set(calls.get() + 1);
        Ok(SecretString::from("correct-pin".to_string()))
    };
    let bytes = container_with_an_unresolvable_mac_digest();
    let err = acquire_p12_material_with_prompter(&bytes, 3, None, prompter, None).unwrap_err();
    assert!(
        matches!(err, AcquireError::Corrupt(_)),
        "a missing algorithm must not be reported as a wrong PIN: {err:?}",
    );
    assert_eq!(
        calls.get(),
        1,
        "re-prompting cannot conjure up an algorithm; the loop must stop at once",
    );
}

#[test]
fn the_pin_loop_never_makes_an_engine_the_default_implementation() {
    // The container now reaches the retry decision — that is what the test
    // above establishes — so the decision is genuinely exercised here rather
    // than skipped over. A deployment that named no engine must come out of
    // it with the process-global engine slot still empty: on a host that has
    // a `gost` engine to find, an implementation that fell back to an
    // `OPENSSL_ENGINES` lookup would have made it the default for RSA, DSA,
    // DH, RAND and every digest by now.
    let prompter = |_p: &str| Ok(SecretString::from("correct-pin".to_string()));
    let bytes = container_with_an_unresolvable_mac_digest();
    let err = acquire_p12_material_with_prompter(&bytes, 2, None, prompter, None).unwrap_err();
    assert!(matches!(err, AcquireError::Corrupt(_)), "got {err:?}");
    assert!(
        !tessera_core::gost::engine::is_available(),
        "the PIN loop loaded an engine on a deployment that configured none",
    );
}

#[test]
fn a_failed_engine_load_reports_the_container_error_not_the_engine_one() {
    // With a path configured the retry is attempted, and here it cannot
    // succeed. What the engineer is told must still describe the container —
    // the digest it names — rather than the engine file, which is the
    // administrator's problem and not visible from the login prompt.
    let calls = Cell::new(0_u8);
    let prompter = |_p: &str| {
        calls.set(calls.get() + 1);
        Ok(SecretString::from("correct-pin".to_string()))
    };
    let bytes = container_with_an_unresolvable_mac_digest();
    let engine = std::path::Path::new(ABSENT_ENGINE);
    let err =
        acquire_p12_material_with_prompter(&bytes, 3, None, prompter, Some(engine)).unwrap_err();
    let AcquireError::Corrupt(message) = err else {
        panic!("expected the container's own error, got {err:?}");
    };
    assert!(
        message.contains("unknown digest algorithm"),
        "expected the digest failure the container caused, got {message}",
    );
    assert!(
        !message.contains(ABSENT_ENGINE),
        "the engine path leaked into what the engineer is shown: {message}",
    );
    assert_eq!(calls.get(), 1, "a failed engine load must not re-prompt");
}

#[test]
fn corrupt_bundle_short_circuits() {
    let calls = Cell::new(0_u8);
    let prompter = |_p: &str| {
        calls.set(calls.get() + 1);
        Ok(SecretString::from("correct-pin".to_string()))
    };
    let err =
        acquire_p12_material_with_prompter(b"not-a-p12", 3, None, prompter, None).unwrap_err();
    assert!(matches!(err, AcquireError::Corrupt(_)), "got {err:?}");
    assert_eq!(calls.get(), 1, "should bail on first corrupt-bundle error");
}

#[test]
fn default_prompt_used_when_none_configured() {
    let seen = std::cell::RefCell::new(Vec::new());
    let prompter = |p: &str| {
        seen.borrow_mut().push(p.to_string());
        Ok(SecretString::from("correct-pin".to_string()))
    };
    acquire_p12_material_with_prompter(RSA, 3, None, prompter, None).unwrap();
    assert_eq!(
        seen.borrow().as_slice(),
        [tessera_core::pkcs12::DEFAULT_PKCS12_PIN_PROMPT]
    );
}

#[test]
fn custom_prompt_reaches_prompter_on_every_attempt() {
    let seen = std::cell::RefCell::new(Vec::new());
    let prompter = |p: &str| {
        seen.borrow_mut().push(p.to_string());
        Ok(SecretString::from("nope".to_string()))
    };
    let err = acquire_p12_material_with_prompter(RSA, 2, Some("Введите ПИН: "), prompter, None)
        .unwrap_err();
    assert!(matches!(err, AcquireError::MaxTries), "got {err:?}");
    assert_eq!(seen.borrow().as_slice(), ["Введите ПИН: ", "Введите ПИН: "]);
}

#[test]
fn zero_max_tries_is_max_tries_immediately() {
    let calls = Cell::new(0_u8);
    let prompter = |_p: &str| {
        calls.set(calls.get() + 1);
        Ok(SecretString::from("correct-pin".to_string()))
    };
    let err = acquire_p12_material_with_prompter(RSA, 0, None, prompter, None).unwrap_err();
    assert!(matches!(err, AcquireError::MaxTries), "got {err:?}");
    assert_eq!(calls.get(), 0);
}
