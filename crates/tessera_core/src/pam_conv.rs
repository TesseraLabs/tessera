//! PAM conversation helpers used to prompt the user for a PIN.
//!
//! The production driver that talks to the live `pam_conv` callback lives in
//! the `pam_tessera` cdylib (where `unsafe_code` is permitted and the
//! `pam-sys` crate is linked).  This module exposes the safe parts:
//!
//! * [`PamConvError`] — the error variants both halves agree on.
//! * [`prompt_pin_via_callback`] — a closure-based entry point used in tests
//!   and any callers that already have an arbitrary PIN-source closure.
//!
//! Wrapping the response in a [`secrecy::SecretString`] makes accidental
//! logging / debug-printing of the PIN impossible: the `Secret` redacts itself
//! in `Display`/`Debug` and zeroizes its backing buffer on drop.

use secrecy::SecretString;
use thiserror::Error;

/// Errors raised by the PAM conv layer.
///
/// `NoConv` and the OS-specific failure paths are emitted by the production
/// driver in `pam_tessera::pam_conv`; tests typically only ever observe
/// `ConvFailed` and `NonUtf8`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PamConvError {
    /// PAM did not provide a `pam_conv` item — the application embedding PAM
    /// is misconfigured.
    #[error("PAM conversation function unavailable")]
    NoConv,
    /// The conv callback returned a non-success code, returned a NULL response,
    /// or otherwise failed to deliver a PIN.
    #[error("PAM conversation failed")]
    ConvFailed,
    /// The PIN bytes returned by the conv callback are not valid UTF-8.
    #[error("PAM conversation produced non-utf8 PIN")]
    NonUtf8,
}

/// Test-friendly entry point that wraps an arbitrary PIN-source closure into a
/// `SecretString`.
///
/// The closure receives the localized prompt and returns either the raw PIN
/// string (which is then immediately wrapped in `Secret`) or a propagated
/// [`PamConvError`].  No I/O or FFI is performed — production callers should
/// reach for `pam_tessera::pam_conv::prompt_pin` instead, which talks to the
/// live PAM handle.
///
/// # Errors
///
/// Propagates whatever error the closure returns.
pub fn prompt_pin_via_callback<F>(prompt: &str, conv: F) -> Result<SecretString, PamConvError>
where
    F: FnOnce(&str) -> Result<String, PamConvError>,
{
    let raw = conv(prompt)?;
    Ok(SecretString::from(raw))
}

/// Semantic wrapper for [`prompt_pin_via_callback`] used by the Stage 4
/// PKCS#11 mode.
///
/// The function is a thin convenience — it exists so that PKCS#11 call
/// sites read `prompt_pkcs11_pin(...)` rather than the generic name and
/// so that future stage-4 changes (e.g. localization of the prompt
/// label) have a single chokepoint to modify.  It does not allocate
/// extra state and never logs the PIN.
///
/// # Errors
///
/// Propagates whatever error the closure returns.
pub fn prompt_pkcs11_pin<F>(prompt: &str, conv: F) -> Result<SecretString, PamConvError>
where
    F: FnOnce(&str) -> Result<String, PamConvError>,
{
    prompt_pin_via_callback(prompt, conv)
}
