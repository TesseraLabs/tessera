//! `Pkcs11Backend` — owning wrapper around `cryptoki::context::Pkcs11`.
//!
//! The backend is responsible for:
//!
//! 1. Loading the configured PKCS#11 dynamic library (`Pkcs11::new`) — T02.
//! 2. Calling `C_Initialize` with the requested locking mode — T02.
//! 3. Enumerating slots that have a present token — T03.
//! 4. Polling for a token to arrive (used by the cdylib's wait UX) — T04.
//!
//! ## One `C_Initialize` per module path per process
//!
//! `cryptoki` 0.12 does **not** finalize on `Drop` — `Pkcs11::finalize` is an
//! explicit consuming call — and `C_Initialize` is process-global state in
//! every provider.  A second `C_Initialize` on a live library is at best
//! `CKR_CRYPTOKI_ALREADY_INITIALIZED`; on `rtpkcs11ecp` 2.14.1 a *concurrent*
//! one aborts the process from an uncaught C++ exception, which for a PAM
//! cdylib means killing `sshd` / `login` / `fly-dm`.
//!
//! So the context lives in a process-global registry keyed by the canonical
//! module path.  [`Pkcs11Backend::load`] hands out a shared handle,
//! initializing the library only when no live handle exists, and the last
//! backend to go away calls `C_Finalize`.  Both transitions happen while
//! holding the registry lock, so no two threads can be inside
//! `C_Initialize`/`C_Finalize` for the same library at once — regardless of
//! the per-backend [`LockingMode`], which the vendor defect does not respect.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Weak};
use std::time::Duration;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::slot::Slot;
use parking_lot::Mutex;
use tracing::warn;

use super::error::Pkcs11Error;
use super::locking::with_global_lock;
use super::waiter::{wait_for_token_with_clock, RealClock, TokenLocator};

/// Number of successful `C_Initialize` calls made by this process, across
/// every module path.  Monotonic; only ever read as a delta by the
/// integration tests that prove the context is shared.
static INIT_COUNT: AtomicU64 = AtomicU64::new(0);

/// Read the process-wide count of successful `C_Initialize` calls.
///
/// Diagnostic surface for the PKCS#11 integration tests: the singleton
/// invariant is stated in terms of "how many times did the library get
/// initialized", and there is no other way to observe that from outside
/// the crate.  Feature-gated so production builds cannot depend on it.
#[cfg(feature = "pkcs11-tests")]
#[must_use]
pub fn context_init_count() -> u64 {
    INIT_COUNT.load(Ordering::SeqCst)
}

/// Registry of live PKCS#11 contexts, keyed by canonical module path.
///
/// Only `Weak` handles are stored: the registry keeps a context findable,
/// it does not keep it alive.  Every state transition — upgrade, insert,
/// `C_Initialize`, `C_Finalize`, removal — happens while this mutex is
/// held, which is what makes the "one live initialization per path"
/// invariant race-free.
///
/// A process-global singleton is the point rather than an accident: the
/// state it guards (`C_Initialize`) is itself process-global inside the
/// provider, so passing it around explicitly could not enforce anything.
static CONTEXTS: LazyLock<Mutex<HashMap<PathBuf, Weak<SharedContext>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// An initialized PKCS#11 library shared by every backend loaded from the
/// same module path.
///
/// Deliberately has no `Drop`: finalization must be serialized against
/// [`Pkcs11Backend::load`], and `Drop` would run after the last strong
/// count already hit zero — a window in which a concurrent `load` could
/// have created a replacement context that our `C_Finalize` would then
/// tear down.  [`Pkcs11Backend::drop`] does it under the registry lock
/// instead.
#[derive(Debug)]
struct SharedContext {
    ctx: Pkcs11,
    module_path: PathBuf,
}

impl SharedContext {
    /// Call `C_Finalize` on the shared library, reporting failures without
    /// propagating them — the caller is a `Drop` and has nowhere to put an
    /// error.
    fn finalize(&self) {
        // `Pkcs11::finalize` consumes the handle; cloning is a refcount
        // bump on cryptoki's inner `Arc`, not a second `dlopen`.
        if let Err(source) = self.ctx.clone().finalize() {
            warn!(
                target: "tessera.pkcs11",
                module = %self.module_path.display(),
                error = %source,
                "pkcs11_finalize_failed"
            );
        }
    }
}

/// Locking mode passed to every cryptoki call.
///
/// `CInitializeArgs::new(OS_LOCKING_OK)` is used for both variants — the
/// flag is what the provider is *asked* for.  This mode decides whether we
/// additionally serialize on our side, see
/// [`crate::token::pkcs11::locking`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockingMode {
    /// Concurrent cryptoki calls are allowed to reach the provider.  Only
    /// correct on providers that genuinely honour `CKF_OS_LOCKING_OK`;
    /// selected explicitly by the operator.
    Os,
    /// Every cryptoki call goes through a process-global mutex.  The
    /// default: providers that advertise `CKF_OS_LOCKING_OK` and still
    /// mishandle concurrency exist in the field.
    Mutex,
}

/// Handle to the process-global PKCS#11 context for one module path, plus
/// the locking mode this handle was created with.
///
/// Several backends may exist for the same module — they share one
/// `C_Initialize`.  Backends for *different* modules are independent.  The
/// library is finalized when the last backend for its path is dropped.
#[derive(Debug)]
pub struct Pkcs11Backend {
    ctx: Arc<SharedContext>,
    module_path: PathBuf,
    locking_mode: LockingMode,
}

impl Pkcs11Backend {
    /// Obtain a handle to the PKCS#11 library at `module_path`.
    ///
    /// The library is loaded and `C_Initialize`d only if no other backend
    /// for the same canonical path is alive; otherwise the existing
    /// context is shared.  The call is serialized process-wide, so
    /// concurrent callers never enter `C_Initialize` together.
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
        // Two configs may name the same library through different paths
        // (symlink, `..`, relative dir).  Sharing must follow the file,
        // not the spelling; if the path cannot be canonicalized we fall
        // back to it verbatim rather than failing the load.
        let key = std::fs::canonicalize(module_path).unwrap_or_else(|_| module_path.to_path_buf());

        // The whole lookup-or-create sequence runs under this guard.
        // Holding it across `C_Initialize` (tens of ms on a real device,
        // once per process per module) is the price of never letting two
        // threads into the provider's initialization at the same time —
        // `rtpkcs11ecp` 2.14.1 aborts the process when they do, and the
        // per-backend `locking_mode` cannot prevent that because two
        // backends may disagree about it.
        let mut registry = CONTEXTS.lock();
        // Defensive sweep: with finalization done under this same lock a
        // dead entry should be impossible, but a leaked one would pin a
        // `PathBuf` forever across repeated load/drop cycles.
        registry.retain(|_, weak| weak.strong_count() > 0);

        if let Some(ctx) = registry.get(&key).and_then(Weak::upgrade) {
            return Ok(Self {
                ctx,
                module_path: module_path.to_path_buf(),
                locking_mode,
            });
        }

        let ctx = Pkcs11::new(module_path).map_err(|source| Pkcs11Error::ModuleLoadFailed {
            path: module_path.to_path_buf(),
            source,
        })?;
        // `CKF_OS_LOCKING_OK` is requested in both modes: it is what a
        // conforming provider needs to hear, and `Mutex` mode's user-space
        // serialization is additive.
        let init_args = CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK);
        ctx.initialize(init_args)
            .map_err(|source| Pkcs11Error::InitFailed { source })?;
        INIT_COUNT.fetch_add(1, Ordering::SeqCst);

        let shared = Arc::new(SharedContext {
            ctx,
            module_path: key.clone(),
        });
        registry.insert(key, Arc::downgrade(&shared));
        Ok(Self {
            ctx: shared,
            module_path: module_path.to_path_buf(),
            locking_mode,
        })
    }

    /// Return the path the backend was loaded from (useful for logging).
    ///
    /// This is the path as the caller spelled it, not the canonical form
    /// used to key the shared context — diagnostics should echo what the
    /// config says.
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
        &self.ctx.ctx
    }

    /// Enumerate every slot that currently has a present token.
    ///
    /// # Errors
    ///
    /// Forwards any `cryptoki` error from `C_GetSlotList` as
    /// [`Pkcs11Error::Cryptoki`].
    pub fn list_slots_with_token(&self) -> Result<Vec<Slot>, Pkcs11Error> {
        let mode = self.locking_mode;
        Ok(with_global_lock(mode, || {
            self.ctx().get_slots_with_token()
        })?)
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
            let info = with_global_lock(mode, || self.ctx().get_token_info(slot))?;
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

impl Drop for Pkcs11Backend {
    /// Finalize the library once the last backend for this module path
    /// goes away.
    ///
    /// The strong-count check is taken while holding the registry lock, and
    /// every other path that can create a strong reference
    /// ([`Pkcs11Backend::load`]) needs the same lock.  So "count is 1 here"
    /// means "no other owner exists and none can appear", and removing the
    /// entry before `C_Finalize` guarantees a `load` that arrives next will
    /// build a fresh context instead of resurrecting a finalized one.
    ///
    /// `C_Finalize` runs without the per-call lock from
    /// [`super::locking`], and must: a thread inside a cryptoki call holds
    /// that lock and may drop a backend, so taking it here would invert the
    /// lock order.  There is nothing to serialize against anyway — reaching
    /// this point means no backend, and therefore no session, is left to
    /// issue calls through this context.
    fn drop(&mut self) {
        let mut registry = CONTEXTS.lock();
        if Arc::strong_count(&self.ctx) > 1 {
            return;
        }
        registry.remove(&self.ctx.module_path);
        self.ctx.finalize();
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

    /// The registry must not grow across load/drop cycles: a leaked entry
    /// would pin a `PathBuf` (and a dangling `Weak`) for the lifetime of a
    /// long-running daemon.
    #[cfg(feature = "pkcs11-tests")]
    #[test]
    fn registry_is_empty_after_every_backend_is_dropped() {
        let Some(path) = super::super::test_helpers::pkcs11_test_module_path() else {
            eprintln!("skipped: PKCS11_MODULE_PATH not set or path missing");
            return;
        };
        for _ in 0..3 {
            let backend = Pkcs11Backend::load(&path, LockingMode::Mutex).expect("load");
            drop(backend);
        }
        assert!(
            CONTEXTS.lock().is_empty(),
            "dead registry entries must not accumulate"
        );
    }
}
