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
    let m = acquire_p12_material_with_prompter(RSA, 3, None, prompter).unwrap();
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
    let m = acquire_p12_material_with_prompter(RSA, 3, None, prompter).unwrap();
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
    let err = acquire_p12_material_with_prompter(RSA, 3, None, prompter).unwrap_err();
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
    let err = acquire_p12_material_with_prompter(RSA, 3, None, prompter).unwrap_err();
    assert!(
        matches!(err, AcquireError::Conv(PamConvError::ConvFailed)),
        "got {err:?}"
    );
    assert_eq!(calls.get(), 1, "should bail on first conv error");
}

#[test]
fn corrupt_bundle_short_circuits() {
    let calls = Cell::new(0_u8);
    let prompter = |_p: &str| {
        calls.set(calls.get() + 1);
        Ok(SecretString::from("correct-pin".to_string()))
    };
    let err = acquire_p12_material_with_prompter(b"not-a-p12", 3, None, prompter).unwrap_err();
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
    acquire_p12_material_with_prompter(RSA, 3, None, prompter).unwrap();
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
    let err =
        acquire_p12_material_with_prompter(RSA, 2, Some("Введите ПИН: "), prompter).unwrap_err();
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
    let err = acquire_p12_material_with_prompter(RSA, 0, None, prompter).unwrap_err();
    assert!(matches!(err, AcquireError::MaxTries), "got {err:?}");
    assert_eq!(calls.get(), 0);
}
