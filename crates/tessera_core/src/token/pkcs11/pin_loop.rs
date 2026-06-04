//! Bounded PIN-retry loop for PKCS#11 sessions (Task T07).
//!
//! The PAM layer never instantiates `Pkcs11Session::open` directly when
//! it is willing to retry: instead it goes through
//! [`acquire_pkcs11_session`], which:
//!
//! - prompts the user via the supplied `pin_prompter` closure,
//! - tries to open a session,
//! - on [`Pkcs11Error::PinIncorrect`] logs a sanitised DEBUG line and
//!   loops up to `max_attempts` times,
//! - on [`Pkcs11Error::PinLocked`] emits an ALERT and short-circuits
//!   immediately,
//! - on any other [`Pkcs11Error`] returns the error verbatim.
//!
//! The loop is generic over an [`PinSessionOpener`] trait so unit tests
//! can drive it without a real PKCS#11 provider — `cryptoki::Session`
//! is a concrete type with no `Mock`-able trait surface.

use cryptoki::slot::Slot;
use secrecy::SecretString;
use thiserror::Error;
use tracing::{debug, error};

use super::backend::Pkcs11Backend;
use super::error::Pkcs11Error;
use super::session::Pkcs11Session;
use crate::pam_conv::PamConvError;

/// Trait for opening a PKCS#11 session given a slot and PIN.
///
/// Production code uses the impl on [`Pkcs11Backend`] below;
/// integration tests inject a closure-backed mock.
pub trait PinSessionOpener {
    /// Open a session against `slot` using `pin`.
    ///
    /// # Errors
    ///
    /// Forwards every [`Pkcs11Error`] returned by the underlying
    /// `Pkcs11Session::open` (or test mock).
    fn open_with_pin(&self, slot: Slot, pin: &SecretString) -> Result<Pkcs11Session, Pkcs11Error>;
}

impl PinSessionOpener for Pkcs11Backend {
    fn open_with_pin(&self, slot: Slot, pin: &SecretString) -> Result<Pkcs11Session, Pkcs11Error> {
        Pkcs11Session::open(self, slot, pin)
    }
}

/// Errors raised by [`acquire_pkcs11_session`].
///
/// PAM mapping (used by the dispatcher in T20):
/// - [`AcquireError::PinLocked`] → `PAM_MAXTRIES`
/// - [`AcquireError::MaxAttemptsExceeded`] → `PAM_MAXTRIES`
/// - [`AcquireError::Conv`] → `PAM_AUTH_ERR`
/// - [`AcquireError::Pkcs11`] → `PAM_AUTH_ERR`
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AcquireError {
    /// The token reported `CKR_PIN_LOCKED`.  Caller must abort
    /// immediately and emit a syslog ALERT (this enum already drives a
    /// matching `tracing::error!` in the loop).
    #[error("token PIN locked")]
    PinLocked,
    /// All `max_attempts` attempts returned `PinIncorrect`.
    #[error("max PIN attempts exceeded")]
    MaxAttemptsExceeded,
    /// The PAM conversation function failed before we could collect a
    /// PIN.  Forwarded verbatim from the prompter closure.
    #[error("PAM conversation error: {0}")]
    Conv(#[from] PamConvError),
    /// Any non-PIN PKCS#11 error from the opener.
    #[error("pkcs#11 error: {0}")]
    Pkcs11(#[from] Pkcs11Error),
}

/// Default prompt string passed to the PAM conv layer.  Russian text
/// matches Astra Linux conventions (and the existing PKCS#12 prompt).
pub const DEFAULT_PROMPT: &str = "Введите PIN токена: ";

/// Run the bounded PIN-retry loop.
///
/// `pin_prompter` is invoked at most `max_attempts` times.  Each PIN is
/// passed to `opener.open_with_pin(slot, &pin)`.  The PIN itself is
/// never logged; only the attempt counter and the typed error category.
///
/// # Errors
///
/// See [`AcquireError`] — every variant has documented PAM mapping.
pub fn acquire_pkcs11_session<O, F>(
    opener: &O,
    slot: Slot,
    max_attempts: u32,
    mut pin_prompter: F,
) -> Result<Pkcs11Session, AcquireError>
where
    O: PinSessionOpener,
    F: FnMut(&str) -> Result<SecretString, PamConvError>,
{
    if max_attempts == 0 {
        return Err(AcquireError::MaxAttemptsExceeded);
    }
    for attempt in 1..=max_attempts {
        let pin = pin_prompter(DEFAULT_PROMPT)?;
        match opener.open_with_pin(slot, &pin) {
            Ok(session) => return Ok(session),
            Err(Pkcs11Error::PinIncorrect) => {
                debug!(
                    target: "tessera.pkcs11",
                    attempt,
                    max_attempts,
                    "pkcs11_pin_invalid"
                );
            }
            Err(Pkcs11Error::PinLocked) => {
                error!(
                    target: "tessera.pkcs11",
                    "pkcs11_pin_locked: token has locked itself out, refusing further attempts"
                );
                return Err(AcquireError::PinLocked);
            }
            Err(other) => return Err(AcquireError::Pkcs11(other)),
        }
    }
    Err(AcquireError::MaxAttemptsExceeded)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::err_expect,
        clippy::panic,
        clippy::unwrap_used
    )]

    use super::*;
    use std::cell::{Cell, RefCell};

    /// Closure-backed mock that hands out scripted `Pkcs11Error` /
    /// `Pkcs11Session` values.  Because we can't construct a real
    /// `Pkcs11Session` without a real provider, every test here forces
    /// an `Err` outcome — the success path is exercised by the
    /// integration tests under `tests/pkcs11_session.rs` (gated on
    /// `pkcs11-tests`).
    struct ScriptedOpener {
        results: RefCell<Vec<Pkcs11Error>>,
        calls: Cell<usize>,
    }

    impl ScriptedOpener {
        fn new(results: Vec<Pkcs11Error>) -> Self {
            Self {
                results: RefCell::new(results),
                calls: Cell::new(0),
            }
        }
    }

    impl PinSessionOpener for ScriptedOpener {
        fn open_with_pin(
            &self,
            _slot: Slot,
            _pin: &SecretString,
        ) -> Result<Pkcs11Session, Pkcs11Error> {
            self.calls.set(self.calls.get() + 1);
            let mut results = self.results.borrow_mut();
            let next = if results.len() > 1 {
                results.remove(0)
            } else if let Some(only) = results.first() {
                clone_err(only)
            } else {
                Pkcs11Error::PinIncorrect
            };
            Err(next)
        }
    }

    fn clone_err(e: &Pkcs11Error) -> Pkcs11Error {
        match e {
            Pkcs11Error::PinIncorrect => Pkcs11Error::PinIncorrect,
            Pkcs11Error::PinLocked => Pkcs11Error::PinLocked,
            Pkcs11Error::NoTokenAvailable => Pkcs11Error::NoTokenAvailable,
            Pkcs11Error::TokenNotFound { label } => Pkcs11Error::TokenNotFound {
                label: label.clone(),
            },
            other => panic!("clone_err does not support {other:?}"),
        }
    }

    fn slot() -> Slot {
        Slot::try_from(0_u64).expect("slot 0 fits")
    }

    fn fixed_prompter<'a>(
        pin: &'static str,
        counter: &'a Cell<usize>,
    ) -> impl FnMut(&str) -> Result<SecretString, PamConvError> + 'a {
        move |_p: &str| {
            counter.set(counter.get() + 1);
            Ok(SecretString::from(pin.to_owned()))
        }
    }

    #[test]
    fn fail_then_pin_locked_short_circuits() {
        // First wrong PIN, then PinLocked — must return PinLocked
        // *without* attempting a third call.
        let opener = ScriptedOpener::new(vec![Pkcs11Error::PinIncorrect, Pkcs11Error::PinLocked]);
        let prompts = Cell::new(0);
        let prompter = fixed_prompter("any", &prompts);
        let err = acquire_pkcs11_session(&opener, slot(), 5, prompter)
            .err()
            .expect("must fail");
        assert!(matches!(err, AcquireError::PinLocked), "got {err:?}");
        assert_eq!(opener.calls.get(), 2);
        assert_eq!(prompts.get(), 2);
    }

    #[test]
    fn pin_locked_on_first_attempt_is_immediate() {
        let opener = ScriptedOpener::new(vec![Pkcs11Error::PinLocked]);
        let prompts = Cell::new(0);
        let prompter = fixed_prompter("any", &prompts);
        let err = acquire_pkcs11_session(&opener, slot(), 3, prompter)
            .err()
            .expect("must fail");
        assert!(matches!(err, AcquireError::PinLocked));
        assert_eq!(opener.calls.get(), 1);
    }

    #[test]
    fn returns_max_attempts_after_n_wrong_pins() {
        let opener = ScriptedOpener::new(vec![Pkcs11Error::PinIncorrect]);
        let prompts = Cell::new(0);
        let prompter = fixed_prompter("any", &prompts);
        let err = acquire_pkcs11_session(&opener, slot(), 3, prompter)
            .err()
            .expect("must fail");
        assert!(matches!(err, AcquireError::MaxAttemptsExceeded));
        assert_eq!(opener.calls.get(), 3);
        assert_eq!(prompts.get(), 3);
    }

    #[test]
    fn conv_error_short_circuits_without_calling_opener() {
        let opener = ScriptedOpener::new(vec![Pkcs11Error::PinIncorrect]);
        let prompts = Cell::new(0_usize);
        let prompter = |_p: &str| -> Result<SecretString, PamConvError> {
            prompts.set(prompts.get() + 1);
            Err(PamConvError::ConvFailed)
        };
        let err = acquire_pkcs11_session(&opener, slot(), 3, prompter)
            .err()
            .expect("must fail");
        assert!(
            matches!(err, AcquireError::Conv(PamConvError::ConvFailed)),
            "got {err:?}"
        );
        assert_eq!(prompts.get(), 1);
        assert_eq!(opener.calls.get(), 0);
    }

    #[test]
    fn other_pkcs11_error_short_circuits() {
        let opener = ScriptedOpener::new(vec![Pkcs11Error::NoTokenAvailable]);
        let prompts = Cell::new(0);
        let prompter = fixed_prompter("any", &prompts);
        let err = acquire_pkcs11_session(&opener, slot(), 3, prompter)
            .err()
            .expect("must fail");
        assert!(
            matches!(err, AcquireError::Pkcs11(Pkcs11Error::NoTokenAvailable)),
            "got {err:?}"
        );
        assert_eq!(opener.calls.get(), 1);
    }

    #[test]
    fn zero_max_attempts_is_max_attempts_exceeded() {
        let opener = ScriptedOpener::new(vec![Pkcs11Error::PinIncorrect]);
        let prompts = Cell::new(0);
        let prompter = fixed_prompter("any", &prompts);
        let err = acquire_pkcs11_session(&opener, slot(), 0, prompter)
            .err()
            .expect("must fail");
        assert!(matches!(err, AcquireError::MaxAttemptsExceeded));
        assert_eq!(opener.calls.get(), 0);
        assert_eq!(prompts.get(), 0);
    }
}
