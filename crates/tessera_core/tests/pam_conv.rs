#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::unnecessary_wraps)] // mocks must match the trait signature

use tessera_core::pam_conv::{prompt_pin_via_callback, PamConvError};
use secrecy::ExposeSecret;

fn mock_ok(prompt: &str) -> Result<String, PamConvError> {
    assert_eq!(prompt, "Smart-card PIN: ");
    Ok("1234".into())
}

fn mock_conv_failed(_prompt: &str) -> Result<String, PamConvError> {
    Err(PamConvError::ConvFailed)
}

fn mock_no_conv(_prompt: &str) -> Result<String, PamConvError> {
    Err(PamConvError::NoConv)
}

fn mock_non_utf8(_prompt: &str) -> Result<String, PamConvError> {
    Err(PamConvError::NonUtf8)
}

#[test]
fn returns_secret_pin() {
    let pin = prompt_pin_via_callback("Smart-card PIN: ", mock_ok).unwrap();
    assert_eq!(pin.expose_secret(), "1234");
}

#[test]
fn propagates_conv_failed() {
    let err = prompt_pin_via_callback("Smart-card PIN: ", mock_conv_failed).unwrap_err();
    assert!(matches!(err, PamConvError::ConvFailed));
}

#[test]
fn propagates_no_conv() {
    let err = prompt_pin_via_callback("Smart-card PIN: ", mock_no_conv).unwrap_err();
    assert!(matches!(err, PamConvError::NoConv));
}

#[test]
fn propagates_non_utf8() {
    let err = prompt_pin_via_callback("Smart-card PIN: ", mock_non_utf8).unwrap_err();
    assert!(matches!(err, PamConvError::NonUtf8));
}

#[test]
fn debug_repr_does_not_leak_pin() {
    // Sanity: the wrapped Secret must redact in Debug; Display is not
    // implemented on `secrecy::Secret` precisely so accidental `{pin}`
    // formatting will not compile.
    let pin = prompt_pin_via_callback("Smart-card PIN: ", mock_ok).unwrap();
    let dbg = format!("{pin:?}");
    assert!(!dbg.contains("1234"), "Debug leaked PIN: {dbg}");
}
