//! `Pkcs11Session` — RAII wrapper around `cryptoki::session::Session`.
//!
//! The wrapper exists to ensure `C_Logout` runs before the upstream
//! `Session::Drop` calls `C_CloseSession`.  `cryptoki` 0.7 already takes
//! care of `C_CloseSession` on its own; we deliberately do **not** call
//! it ourselves to avoid double-closing the handle.
//!
//! `Drop` never panics:
//! - If `logout` fails we log a WARN through `tracing` and continue.
//! - If `logout` is not appropriate (we never logged in) we skip it.
//!
//! No PIN bytes are ever stored — the supplied `SecretString` is
//! dropped (and zeroized) as soon as `C_Login` returns.

use cryptoki::error::{Error as CkError, RvError};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use secrecy::SecretString;
use tracing::warn;

use super::backend::{LockingMode, Pkcs11Backend};
use super::error::Pkcs11Error;
use super::locking::with_global_lock;

/// RAII wrapper around an authenticated PKCS#11 session.
///
/// Construct via [`Pkcs11Session::open`].  The session can be queried
/// through the crate-private `raw()` accessor; subsequent stage-4 tasks
/// (T08, T09, T12) will add typed methods on top of it.
#[derive(Debug)]
pub struct Pkcs11Session {
    /// `Option` so that `Drop` can `take()` the inner session and
    /// transfer ownership before the underlying `cryptoki` `Drop` runs.
    inner: Option<Session>,
    /// Tracks whether `C_Login` succeeded so `Drop` knows whether
    /// `C_Logout` is appropriate.
    logged_in: bool,
    /// Locking mode propagated from the owning [`Pkcs11Backend`] so
    /// `Drop` (which has no other reference to the backend) can still
    /// honour the user-space serialization layer when calling
    /// `C_Logout`.
    locking_mode: LockingMode,
}

impl Pkcs11Session {
    /// Open a R/W session against `slot` and log in as `CKU_USER` with
    /// `pin`.
    ///
    /// We use `open_rw_session` rather than `open_ro_session` because
    /// some PKCS#11 providers (notably JaCarta-2 GOST) require RW for
    /// `C_Sign` operations even though the operation itself is logically
    /// read-only.  The challenge-response flow (T12) needs `C_Sign`, so
    /// we standardise on RW from T05 onward.
    ///
    /// # Errors
    ///
    /// - [`Pkcs11Error::SessionOpenFailed`] when `C_OpenSession` fails.
    /// - [`Pkcs11Error::PinIncorrect`] on `CKR_PIN_INCORRECT`.
    /// - [`Pkcs11Error::PinLocked`] on `CKR_PIN_LOCKED`.
    /// - [`Pkcs11Error::Cryptoki`] for any other login failure.
    pub fn open(
        backend: &Pkcs11Backend,
        slot: Slot,
        pin: &SecretString,
    ) -> Result<Self, Pkcs11Error> {
        let mode = backend.locking_mode();
        let session = with_global_lock(mode, || backend.ctx().open_rw_session(slot))
            .map_err(|source| Pkcs11Error::SessionOpenFailed { source })?;
        // cryptoki 0.12: `AuthPin` is a type alias for `secrecy::SecretString`,
        // so we can pass the caller's pin reference directly.
        match with_global_lock(mode, || session.login(UserType::User, Some(pin))) {
            Ok(()) => Ok(Self {
                inner: Some(session),
                logged_in: true,
                locking_mode: mode,
            }),
            Err(CkError::Pkcs11(RvError::PinIncorrect, _)) => Err(Pkcs11Error::PinIncorrect),
            Err(CkError::Pkcs11(RvError::PinLocked, _)) => Err(Pkcs11Error::PinLocked),
            Err(other) => Err(Pkcs11Error::Cryptoki(other)),
        }
    }

    /// Return the locking mode this session was opened under.
    ///
    /// Sibling modules (`cert_lookup`, `key_lookup`, `sign`) read this
    /// to wrap their own cryptoki calls with [`with_global_lock`].
    #[must_use]
    pub(crate) fn locking_mode(&self) -> LockingMode {
        self.locking_mode
    }

    /// Borrow the underlying `cryptoki` session.  Crate-private — the
    /// public surface for object lookup / signing is added in later
    /// stage-4 tasks (T08, T09, T12).  Marked `dead_code`-allow because
    /// no caller exists yet in block 1 of stage 4.
    #[allow(dead_code)]
    pub(crate) fn raw(&self) -> Option<&Session> {
        self.inner.as_ref()
    }
}

impl Drop for Pkcs11Session {
    fn drop(&mut self) {
        if let Some(session) = self.inner.take() {
            let mode = self.locking_mode;
            if self.logged_in {
                if let Err(e) = with_global_lock(mode, || session.logout()) {
                    warn!(
                        target: "tessera.pkcs11",
                        "C_Logout failed during session drop: {e}"
                    );
                }
            }
            // `Session::Drop` (cryptoki 0.7) calls `C_CloseSession`.
            // We wrap the explicit drop in `with_global_lock` so the
            // `C_CloseSession` issued by `Session::Drop` runs while we
            // still hold the user-space serialisation lock.
            with_global_lock(mode, || drop(session));
        }
    }
}
