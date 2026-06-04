//! `Pkcs11Backend` — owning wrapper around `cryptoki::context::Pkcs11`.
//!
//! The backend is responsible for:
//!
//! 1. Loading the configured PKCS#11 dynamic library (`Pkcs11::new`) — T02.
//! 2. Calling `C_Initialize` with the requested locking mode — T02.
//! 3. Enumerating slots that have a present token — T03.
//! 4. Polling for a token to arrive (used by the cdylib's wait UX) — T04.
//!
//! `cryptoki`'s own `Pkcs11Impl` already calls `C_Finalize` from its `Drop`,
//! so we don't need to drive finalization ourselves; we only own the
//! initialization side and surface typed errors.

use std::path::{Path, PathBuf};
use std::time::Duration;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::slot::Slot;
use tracing::warn;

use super::error::Pkcs11Error;
use super::locking::with_global_lock;
use super::waiter::{wait_for_token_with_clock, RealClock, TokenLocator};

/// Locking mode passed to `C_Initialize`.
///
/// `cryptoki` 0.7 only exposes `CInitializeArgs::OsThreads`, which sets
/// `CKF_OS_LOCKING_OK` on the underlying call.  PKCS#11 implementations
/// that don't accept that flag (e.g. JaCarta-2 GOST) need user-space
/// serialization; that wrapper layer is added in T14 and consults this
/// field.  For T01-T07 we record the desired mode but the actual
/// `C_Initialize` argument is identical for both variants — see the OPEN
/// QUESTION block in the PKCS#11 module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockingMode {
    /// Native OS thread locking (`CKF_OS_LOCKING_OK`).  Default for
    /// Rutoken/ESMART.
    Os,
    /// Caller serializes all PKCS#11 calls through a process-global mutex.
    /// Used for legacy providers that mishandle `CKF_OS_LOCKING_OK`.
    Mutex,
}

/// Owned PKCS#11 context plus the locking mode it was initialized with.
///
/// Hold one per process.  Cloning the underlying `Pkcs11` is cheap (it's
/// `Arc`-backed inside `cryptoki`) but creating a second `Pkcs11Backend`
/// for the same `.so` is **not supported** — `C_Initialize` can only be
/// called once per library instance.
#[derive(Debug)]
pub struct Pkcs11Backend {
    ctx: Pkcs11,
    module_path: PathBuf,
    locking_mode: LockingMode,
}

impl Pkcs11Backend {
    /// Load `module_path` and call `C_Initialize`.
    ///
    /// # Errors
    ///
    /// - [`Pkcs11Error::ModulePathMissing`] when `module_path` does not
    ///   exist on disk.  Distinguishing this from a `dlopen` failure helps
    ///   produce a better config-validation message; both
    ///   `cryptoki`/`libloading` would otherwise surface a generic
    ///   `cannot open shared object file: No such file or directory`.
    /// - [`Pkcs11Error::ModuleLoadFailed`] when `cryptoki::Pkcs11::new`
    ///   fails for any other reason (ABI mismatch, missing transitive
    ///   dep, permission denied).
    /// - [`Pkcs11Error::InitFailed`] when `C_Initialize` itself returns a
    ///   non-zero status.
    pub fn load(module_path: &Path, locking_mode: LockingMode) -> Result<Self, Pkcs11Error> {
        if !module_path.exists() {
            return Err(Pkcs11Error::ModulePathMissing(module_path.to_path_buf()));
        }
        let ctx = Pkcs11::new(module_path).map_err(|source| Pkcs11Error::ModuleLoadFailed {
            path: module_path.to_path_buf(),
            source,
        })?;
        // cryptoki 0.7 only models `CInitializeArgs::OsThreads`, which
        // sets `CKF_OS_LOCKING_OK`.  In `Mutex` mode we still pass that
        // flag — providers that ignore it (legacy JaCarta-2 GOST) get
        // the user-space serialization layer below; modern providers
        // get both, which is harmless duplication (≈ 20 ns / call).
        let init_args = CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK);
        if matches!(locking_mode, LockingMode::Mutex) {
            warn!(
                target: "tessera.pkcs11",
                "pkcs11_user_space_lock_active: Mutex mode serialises every cryptoki \
                 call through a process-global parking_lot::Mutex; this is required \
                 for legacy providers that ignore CKF_OS_LOCKING_OK"
            );
        }
        with_global_lock(locking_mode, || ctx.initialize(init_args))
            .map_err(|source| Pkcs11Error::InitFailed { source })?;
        Ok(Self {
            ctx,
            module_path: module_path.to_path_buf(),
            locking_mode,
        })
    }

    /// Return the path the backend was loaded from (useful for logging).
    #[must_use]
    pub fn module_path(&self) -> &Path {
        &self.module_path
    }

    /// Return the locking mode this backend was initialized with.
    #[must_use]
    pub fn locking_mode(&self) -> LockingMode {
        self.locking_mode
    }

    /// Borrow the underlying `cryptoki::Pkcs11` context.  Used by sibling
    /// modules in this crate; not part of the stable public surface.
    pub(crate) fn ctx(&self) -> &Pkcs11 {
        &self.ctx
    }

    /// Enumerate every slot that currently has a present token.
    ///
    /// # Errors
    ///
    /// Forwards any `cryptoki` error from `C_GetSlotList` as
    /// [`Pkcs11Error::Cryptoki`].
    pub fn list_slots_with_token(&self) -> Result<Vec<Slot>, Pkcs11Error> {
        let mode = self.locking_mode;
        Ok(with_global_lock(mode, || self.ctx.get_slots_with_token())?)
    }

    /// Find a single slot with a present token.
    ///
    /// When `token_label` is `None` the first slot returned by
    /// `C_GetSlotList` is used.  When it is `Some(label)` the slots are
    /// scanned for one whose `CK_TOKEN_INFO.label` (trailing-space
    /// trimmed) equals `label`.
    ///
    /// # Errors
    ///
    /// - [`Pkcs11Error::NoTokenAvailable`] when no slot reports a token.
    /// - [`Pkcs11Error::TokenNotFound`] when at least one slot has a
    ///   token but none match the supplied label.
    /// - [`Pkcs11Error::Cryptoki`] for any FFI error from
    ///   `C_GetSlotList` / `C_GetTokenInfo`.
    pub fn find_slot(&self, token_label: Option<&str>) -> Result<Slot, Pkcs11Error> {
        let slots = self.list_slots_with_token()?;
        if slots.is_empty() {
            return Err(Pkcs11Error::NoTokenAvailable);
        }
        let Some(want) = token_label else {
            // Safe: we just verified slots is non-empty.
            return slots
                .into_iter()
                .next()
                .ok_or(Pkcs11Error::NoTokenAvailable);
        };
        let mode = self.locking_mode;
        for slot in slots {
            let info = with_global_lock(mode, || self.ctx.get_token_info(slot))?;
            if info.label().trim_end() == want {
                return Ok(slot);
            }
        }
        Err(Pkcs11Error::TokenNotFound {
            label: want.to_owned(),
        })
    }

    /// Block until a matching token is present, polling every 200 ms.
    ///
    /// # Errors
    ///
    /// - [`Pkcs11Error::TokenWaitTimeout`] when `timeout` elapses without
    ///   a matching token appearing.
    /// - Forwards any [`Pkcs11Error`] returned by [`Self::find_slot`]
    ///   that is not [`Pkcs11Error::NoTokenAvailable`] or
    ///   [`Pkcs11Error::TokenNotFound`] (those two are the "keep
    ///   polling" signal).
    pub fn wait_for_token(
        &self,
        timeout: Duration,
        token_label: Option<&str>,
    ) -> Result<Slot, Pkcs11Error> {
        wait_for_token_with_clock(self, token_label, timeout, &RealClock)
    }
}

/// Trait impl so [`super::waiter::wait_for_token_with_clock`] can be unit-
/// tested without a real PKCS#11 module.  Production code only ever sees
/// the concrete `Pkcs11Backend`.
impl TokenLocator for Pkcs11Backend {
    fn try_find(&self, token_label: Option<&str>) -> Result<Slot, Pkcs11Error> {
        self.find_slot(token_label)
    }
}

/// Test helpers for the in-process backend.  Kept here (rather than under
/// `tests/`) so that the test module can re-use the production type.
#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::err_expect,
        clippy::panic,
        clippy::unwrap_used
    )]

    use super::*;
    use std::path::PathBuf;

    #[test]
    fn missing_path_returns_module_path_missing() {
        // We use a path that is guaranteed not to exist on either Linux
        // or macOS dev hosts.
        let path = PathBuf::from("/nonexistent/__tessera_test_no_such_lib__.so");
        let err = Pkcs11Backend::load(&path, LockingMode::Os)
            .err()
            .expect("loading a non-existent module must fail");
        match err {
            Pkcs11Error::ModulePathMissing(p) => assert_eq!(p, path),
            other => panic!("expected ModulePathMissing, got {other:?}"),
        }
    }
}
