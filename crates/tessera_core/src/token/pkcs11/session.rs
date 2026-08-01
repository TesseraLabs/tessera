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
//! The same application-wide scope means the token may already be
//! logged in when a session opens.  That is not an authentication:
//! [`Pkcs11Session::open`] logs the residual login out and presents the
//! PIN for real, so `CKR_USER_ALREADY_LOGGED_IN` never becomes a way in
//! without one.
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
    /// A token that is already logged in does not shortcut the PIN: see
    /// [`Self::login_displacing_residual`].
    ///
    /// # Errors
    ///
    /// - [`Pkcs11Error::SessionOpenFailed`] when `C_OpenSession` fails.
    /// - [`Pkcs11Error::PinIncorrect`] on `CKR_PIN_INCORRECT`.
    /// - [`Pkcs11Error::PinLocked`] on `CKR_PIN_LOCKED`.
    /// - [`Pkcs11Error::LogoutFailed`] when a residual login could not be
    ///   cleared, so the PIN could not be checked.
    /// - [`Pkcs11Error::Cryptoki`] for any other login failure.
    pub fn open(
        backend: &Pkcs11Backend,
        slot: Slot,
        pin: &SecretString,
    ) -> Result<Self, Pkcs11Error> {
        let shared_mode = backend.shared_locking_mode();
        let session = with_global_lock(shared_mode.get(), || backend.ctx().open_rw_session(slot))
            .map_err(|source| Pkcs11Error::SessionOpenFailed { source })?;
        match Self::login_displacing_residual(&session, &shared_mode, pin) {
            Ok(()) => Ok(Self {
                inner: Some(session),
                logged_in: true,
                locking_mode: shared_mode,
            }),
            Err(error) => {
                // Dropping `session` here would send `C_CloseSession`
                // outside the serialization layer — the same call `Drop`
                // takes trouble to keep inside it.  A failed
                // authentication is not a reason to make an unserialized
                // call into a provider that may not survive one.
                with_global_lock(shared_mode.get(), || drop(session));
                Err(error)
            }
        }
    }

    /// `C_Login` as `CKU_USER`, clearing a login left behind by someone
    /// else first.
    ///
    /// PKCS#11 scopes the login to the *application* — the
    /// `C_Initialize` — and this process shares one for its whole life,
    /// so the token can already be authenticated when we arrive: a
    /// `C_Logout` that failed at the end of the previous authentication
    /// left it that way, or a neighbour sharing the adopted context
    /// (`sshd` built with `PKCS11Provider` holds its login for the length
    /// of a connection) logged in before us.  `C_Login` then answers
    /// `CKR_USER_ALREADY_LOGGED_IN`.
    ///
    /// That answer is neither success nor a refusal.  Taking it for
    /// success would authenticate the person at the console on the
    /// strength of somebody else's PIN — no PIN of theirs was ever
    /// presented to the provider.  Returning it as an error would deny
    /// every login for the rest of the process's life, which in the
    /// `fly-dm` display slave means until the machine is rebooted.  So
    /// the residual login is dropped and the PIN presented for real; a
    /// wrong one fails exactly as it would have on a logged-out token.
    ///
    /// The cost is that a neighbour loses its login.  That is the same
    /// direction of influence already accepted for the `C_Logout` in
    /// `Drop`, and the choice here is between "the neighbour
    /// re-authenticates" and "the engineer cannot log in".
    ///
    /// Only one displacement is attempted: if the second `C_Login` also
    /// reports a login in place, something is putting one back, and
    /// looping would spin inside an authentication.
    fn login_displacing_residual(
        session: &Session,
        mode: &SharedLockingMode,
        pin: &SecretString,
    ) -> Result<(), Pkcs11Error> {
        // cryptoki 0.12: `AuthPin` is a type alias for `secrecy::SecretString`,
        // so we can pass the caller's pin reference directly.
        let login = || with_global_lock(mode.get(), || session.login(UserType::User, Some(pin)));

        match login() {
            Ok(()) => return Ok(()),
            Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
            Err(other) => return Err(Self::login_error(other)),
        }

        warn!(
            target: "tessera.pkcs11",
            "the token was already logged in when this authentication started; logging it out \
             so the PIN can be checked — a neighbouring PKCS#11 consumer in this process will \
             have to authenticate again"
        );
        if let Err(source) = with_global_lock(mode.get(), || session.logout()) {
            return Err(Pkcs11Error::LogoutFailed { source });
        }
        login().map_err(Self::login_error)
    }

    /// Map a `C_Login` failure onto our typed error.
    ///
    /// `CKR_USER_ALREADY_LOGGED_IN` deliberately has no variant: by the
    /// time this runs it can only come from the second attempt, where it
    /// means the logout did not stick, and the honest report of that is
    /// the raw provider status rather than a claim about the PIN.
    fn login_error(error: CkError) -> Pkcs11Error {
        match error {
            CkError::Pkcs11(RvError::PinIncorrect, _) => Pkcs11Error::PinIncorrect,
            CkError::Pkcs11(RvError::PinLocked, _) => Pkcs11Error::PinLocked,
            other => Pkcs11Error::Cryptoki(other),
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
    /// The retry is immediate and taken under the same global mutex, so
    /// nothing about the provider's state can have changed in between —
    /// it buys nothing against contention.  What it does buy is the one
    /// case where the first call failed but moved the state anyway: the
    /// second then answers `CKR_USER_NOT_LOGGED_IN`, which *is* the
    /// postcondition, and the operator gets a WARN instead of an ERROR
    /// telling them the token may still be authenticated.  A durable
    /// refusal fails identically the second time, at the cost of one FFI
    /// call on a path that is already logging an ERROR.
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
    /// `CKR_USER_NOT_LOGGED_IN` is success on either attempt: the
    /// postcondition — this application is not logged in — already holds.
    /// On the first attempt it means somebody else's `C_Logout` (or a
    /// `C_CloseSession` that dropped the last session of the
    /// application) got there first, which is not worth a retry and not
    /// worth a WARN; on the second, that the first call took effect
    /// despite reporting failure.
    fn logout_before_close(session: &Session, mode: LockingMode) {
        let first = match with_global_lock(mode, || session.logout()) {
            Ok(()) | Err(CkError::Pkcs11(RvError::UserNotLoggedIn, _)) => return,
            Err(first) => first,
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
