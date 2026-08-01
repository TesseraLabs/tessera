//! `Pkcs11Session` — RAII wrapper around `cryptoki::session::Session`.
//!
//! The wrapper exists to ensure `C_Logout` runs before the upstream
//! `Session::Drop` calls `C_CloseSession`.  `cryptoki` 0.12 already takes
//! care of `C_CloseSession` on its own; we deliberately do **not** call
//! it ourselves to avoid double-closing the handle.
//!
//! `Drop` never panics:
//! - If `logout` is not appropriate (we never logged in) we skip it.
//! - If `logout` fails it is retried once, and a second failure is logged
//!   at ERROR.  The login is scoped to the PKCS#11 *application* — the
//!   `C_Initialize` — which this process shares for its whole life, so a
//!   logout that never happened leaves the token authenticated for
//!   whoever comes next.  See [`Pkcs11Session::logout_before_close`].
//!
//! No PIN bytes are ever stored — the supplied `SecretString` is
//! dropped (and zeroized) as soon as `C_Login` returns.

use cryptoki::error::{Error as CkError, RvError};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use secrecy::SecretString;
use tracing::{error, warn};

use super::backend::{LockingMode, Pkcs11Backend, SharedLockingMode};
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
    /// Live view of the owning context's locking mode, so `Drop` (which
    /// has no other reference to the backend) can still honour the
    /// user-space serialization layer when calling `C_Logout`.  A view
    /// rather than a copy because the mode can be raised while this
    /// session is open, and a session left on the old value would run
    /// concurrently with calls the raiser believes are serialized.
    locking_mode: SharedLockingMode,
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
        let shared_mode = backend.shared_locking_mode();
        let mode = shared_mode.get();
        let session = with_global_lock(mode, || backend.ctx().open_rw_session(slot))
            .map_err(|source| Pkcs11Error::SessionOpenFailed { source })?;
        // cryptoki 0.12: `AuthPin` is a type alias for `secrecy::SecretString`,
        // so we can pass the caller's pin reference directly.
        match with_global_lock(shared_mode.get(), || {
            session.login(UserType::User, Some(pin))
        }) {
            Ok(()) => Ok(Self {
                inner: Some(session),
                logged_in: true,
                locking_mode: shared_mode,
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
        self.locking_mode.get()
    }

    /// Borrow the underlying `cryptoki` session.  Crate-private — the
    /// public surface for object lookup / signing is added in later
    /// stage-4 tasks (T08, T09, T12).  Marked `dead_code`-allow because
    /// no caller exists yet in block 1 of stage 4.
    #[allow(dead_code)]
    pub(crate) fn raw(&self) -> Option<&Session> {
        self.inner.as_ref()
    }

    /// Log out, retrying once, before the session is closed.
    ///
    /// A single retry rather than a loop: the failures worth retrying are
    /// transient contention inside the provider, and anything durable
    /// will not resolve while a `Drop` blocks the authentication path.
    ///
    /// The second failure is an ERROR, not a WARN, because of what it
    /// leaves behind.  PKCS#11 scopes the login to the application, and
    /// the application is the `C_Initialize` this process shares for its
    /// whole life; the `fly-dm` display slave serves every login attempt
    /// of the machine's uptime from one process.  A logout that did not
    /// happen therefore hands the next person at the console a token
    /// that is already authenticated.  The message says that, rather than
    /// naming the call that failed, because the operator reading it has
    /// to decide whether someone got in without a PIN.
    ///
    /// A second attempt answering `CKR_USER_NOT_LOGGED_IN` means the
    /// first one took effect after all, and is treated as success.
    fn logout_before_close(session: &Session, mode: LockingMode) {
        let Err(first) = with_global_lock(mode, || session.logout()) else {
            return;
        };
        match with_global_lock(mode, || session.logout()) {
            Ok(()) | Err(CkError::Pkcs11(RvError::UserNotLoggedIn, _)) => {
                warn!(
                    target: "tessera.pkcs11",
                    error = %first,
                    "pkcs11_logout_succeeded_on_retry"
                );
            }
            Err(second) => {
                error!(
                    target: "tessera.pkcs11",
                    first_error = %first,
                    error = %second,
                    "C_Logout failed twice: the token may stay logged in until this process \
                     exits, so a later authentication attempt in the same process could reach \
                     private objects without presenting a PIN"
                );
            }
        }
    }
}

impl Drop for Pkcs11Session {
    fn drop(&mut self) {
        if let Some(session) = self.inner.take() {
            let mode = self.locking_mode.get();
            if self.logged_in {
                Self::logout_before_close(&session, mode);
            }
            // `Session::Drop` (cryptoki 0.12) calls `C_CloseSession`.
            // We wrap the explicit drop in `with_global_lock` so the
            // `C_CloseSession` issued by `Session::Drop` runs while we
            // still hold the user-space serialisation lock.
            with_global_lock(mode, || drop(session));
        }
    }
}
