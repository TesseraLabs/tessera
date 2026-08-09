#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::cell::Cell;

use secrecy::SecretString;
use tessera_core::pam_conv::PamConvError;
use tessera_core::pkcs12::{acquire_p12_material_with_prompter, AcquireError};

const RSA: &[u8] = include_bytes!("fixtures/leaf_rsa.p12");

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
fn a_configured_engine_path_does_not_disturb_a_container_that_opens() {
    // An RSA container opens on libcrypto's own implementations, so the
    // engine-retry branch must stay out of the way even where an operator
    // configured an engine — including one whose file does not exist.
    let engine = std::path::Path::new("/nonexistent/engines/gost.so");
    let prompter = |_p: &str| Ok(SecretString::from("correct-pin".to_string()));
    let m = acquire_p12_material_with_prompter(RSA, 3, None, prompter, Some(engine)).unwrap();
    assert_eq!(m.end_entity.subject_cn().unwrap(), "alice");
}

#[test]
fn the_pin_loop_never_makes_an_engine_the_default_implementation() {
    // The retry may only load the engine an operator named. A host that
    // configured none must come out of a full PIN loop with the process-global
    // engine slot still empty — on a host that has a `gost` engine to find,
    // this is what catches a retry that fell back to an OPENSSL_ENGINES
    // lookup and made it the default for RSA, DSA, DH, RAND and the digests.
    let prompter = |_p: &str| Ok(SecretString::from("nope".to_string()));
    let err = acquire_p12_material_with_prompter(RSA, 2, None, prompter, None).unwrap_err();
    assert!(matches!(err, AcquireError::MaxTries), "got {err:?}");
    assert!(
        !tessera_core::gost::engine::is_available(),
        "the PIN loop loaded an engine on a deployment that configured none",
    );
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
