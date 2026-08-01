//! `Pkcs11Backend` — owning wrapper around `cryptoki::context::Pkcs11`.
//!
//! The backend is responsible for:
//!
//! 1. Loading the configured PKCS#11 dynamic library (`Pkcs11::new`) — T02.
//! 2. Calling `C_Initialize` with the requested locking mode — T02.
//! 3. Enumerating slots that have a present token — T03.
//! 4. Polling for a token to arrive (used by the cdylib's wait UX) — T04.
//!
//! ## One `C_Initialize` per module path per process, and no `C_Finalize`
//!
//! `cryptoki` 0.12 does **not** finalize on `Drop` — `Pkcs11::finalize` is an
//! explicit consuming call — and `C_Initialize` is process-global state in
//! every provider.  A second `C_Initialize` on a live library is at best
//! `CKR_CRYPTOKI_ALREADY_INITIALIZED`; on `rtpkcs11ecp` 2.14.1 a *concurrent*
//! one aborts the process from an uncaught C++ exception, which for a PAM
//! cdylib means killing `sshd` / `login` / `fly-dm`.
//!
//! So the context lives in a process-global registry keyed by the canonical
//! module path.  [`Pkcs11Backend::load`] hands out a shared handle and
//! initializes the library only the first time a path is asked for, while
//! holding the registry lock — so no two threads can be inside
//! `C_Initialize` for the same library at once, regardless of the
//! per-backend [`LockingMode`], which the vendor defect does not respect.
//!
//! The registry owns the context and never gives it up: `C_Finalize` is
//! never called and the module stays loaded until the process exits.  That
//! is deliberate.  Finalization is a process-global operation on a `dlopen`
//! we share with anyone else in the same process — `pam_pkcs11`, `sshd`
//! built with `PKCS11Provider`, p11-kit — and none of them can detect that
//! their provider was pulled out from under them.  On our own side the
//! bookkeeping was worse than the leak it saved: `cryptoki`'s `Session`
//! holds its own clone of `Pkcs11`, invisible to any refcount we could
//! check, so "last owner" never implied "no live session".  The cost of
//! keeping the module resident is nil where the process serves one
//! authentication (`sshd`, `login`) and is the whole point where it does
//! not (the `fly-dm` display slave lives for the machine's uptime).
//!
//! Sharing one `C_Initialize` also shares the PKCS#11 login state, which is
//! scoped to the *application* rather than to a session.  Logging out is
//! therefore [`super::session::Pkcs11Session`]'s job on every exit path,
//! not a side effect of tearing the context down.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
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

/// Registry of PKCS#11 contexts, keyed by canonical module path.
///
/// Strong handles: the registry owns every context it has ever created
/// and outlives all backends, because the library is never finalized.
/// Both the lookup and the `C_Initialize` that may follow it happen while
/// this mutex is held, which is what makes the "one initialization per
/// path" invariant race-free.  The map grows by one entry per distinct
/// module path in the process — a bound set by the config, not by call
/// volume.
///
/// A process-global singleton is the point rather than an accident: the
/// state it guards (`C_Initialize`) is itself process-global inside the
/// provider, so passing it around explicitly could not enforce anything.
static CONTEXTS: LazyLock<Mutex<HashMap<PathBuf, Arc<SharedContext>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// An initialized PKCS#11 library shared by every backend loaded from the
/// same module path.
///
/// Deliberately has no `Drop`: there is nothing to undo.
#[derive(Debug)]
struct SharedContext {
    ctx: Pkcs11,
    /// Locking mode of whoever created the context.  Every backend on
    /// this path obeys it, because the mode governs a shared library
    /// rather than a handle: one backend skipping the mutex would let
    /// its calls run concurrently with the calls another backend
    /// believes are serialized.
    locking_mode: LockingMode,
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

/// Handle to the process-global PKCS#11 context for one module path.
///
/// Several backends may exist for the same module — they share one
/// `C_Initialize` and one locking mode.  Backends for *different* modules
/// are independent.  Dropping a backend releases nothing beyond the
/// handle: the library stays initialized for the life of the process.
#[derive(Debug)]
pub struct Pkcs11Backend {
    ctx: Arc<SharedContext>,
    module_path: PathBuf,
}

impl Pkcs11Backend {
    /// Obtain a handle to the PKCS#11 library at `module_path`.
    ///
    /// The library is loaded and `C_Initialize`d only the first time the
    /// process asks for a given canonical path; every later call shares
    /// the existing context, including after all previous handles were
    /// dropped.  The call is serialized process-wide, so concurrent
    /// callers never enter `C_Initialize` together.
    ///
    /// `locking_mode` applies only when this call is the one that creates
    /// the context.  A later caller asking for a different mode on the
    /// same path gets the established one and a WARN — see
    /// [`Self::locking_mode`].
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
        // back to it verbatim rather than failing the load — but that
        // fallback is exactly the failure mode this registry exists to
        // prevent, since two spellings would then key two contexts and
        // the second `C_Initialize` is what kills the process.
        let key = match std::fs::canonicalize(module_path) {
            Ok(key) => key,
            Err(source) => {
                warn!(
                    target: "tessera.pkcs11",
                    module = %module_path.display(),
                    error = %source,
                    "pkcs11_module_path_not_canonical"
                );
                module_path.to_path_buf()
            }
        };

        // The whole lookup-or-create sequence runs under this guard.
        // Holding it across `C_Initialize` (tens of ms on a real device,
        // once per process per module) is the price of never letting two
        // threads into the provider's initialization at the same time —
        // `rtpkcs11ecp` 2.14.1 aborts the process when they do, and the
        // per-backend `locking_mode` cannot prevent that because two
        // backends may disagree about it.
        let mut registry = CONTEXTS.lock();

        if let Some(shared) = registry.get(&key) {
            if shared.locking_mode != locking_mode {
                warn!(
                    target: "tessera.pkcs11",
                    module = %key.display(),
                    requested = ?locking_mode,
                    effective = ?shared.locking_mode,
                    "pkcs11_locking_mode_conflict"
                );
            }
            return Ok(Self {
                ctx: Arc::clone(shared),
                module_path: module_path.to_path_buf(),
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

        let shared = Arc::new(SharedContext { ctx, locking_mode });
        registry.insert(key, Arc::clone(&shared));
        Ok(Self {
            ctx: shared,
            module_path: module_path.to_path_buf(),
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

    /// Return the locking mode in force for this module path.
    ///
    /// This is the mode the *context* was created with, which is not
    /// necessarily the one this backend asked for: the mode decides
    /// whether calls into a shared library are serialized, so it has to
    /// be a property of the library rather than of the handle.  Letting
    /// one backend skip the mutex while another relies on it would put
    /// concurrent calls into a provider that was declared unable to
    /// take them.  A mismatch is logged at WARN by [`Self::load`].
    #[must_use]
    pub fn locking_mode(&self) -> LockingMode {
        self.ctx.locking_mode
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
        let mode = self.locking_mode();
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
        let mode = self.locking_mode();
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

    /// The registry keeps exactly one entry per module path, and keeps it
    /// on purpose: the context is never finalized, so its entry must
    /// survive every backend being dropped.  What must *not* happen is
    /// growth — a second entry for the same library would mean a second
    /// `C_Initialize`, the very thing that kills the process.
    ///
    /// The assertion is scoped to this path rather than to the whole map:
    /// the registry is process-global, so a test that checked global
    /// emptiness (or a global length) would start failing the day any
    /// other test in this binary holds a backend.
    #[cfg(feature = "pkcs11-tests")]
    #[test]
    fn registry_keeps_exactly_one_entry_per_module_path() {
        let Some(path) = super::super::test_helpers::pkcs11_test_module_path() else {
            eprintln!("skipped: PKCS11_MODULE_PATH not set or path missing");
            return;
        };
        let key = std::fs::canonicalize(&path).unwrap_or(path.clone());
        let entries_before = CONTEXTS.lock().len();
        for _ in 0..3 {
            let backend = Pkcs11Backend::load(&path, LockingMode::Mutex).expect("load");
            drop(backend);
        }
        let registry = CONTEXTS.lock();
        assert!(
            registry.contains_key(&key),
            "the context must outlive its backends: no C_Finalize is ever issued"
        );
        assert!(
            registry.len() <= entries_before + 1,
            "three load/drop cycles on one path must add at most one entry: {} -> {}",
            entries_before,
            registry.len()
        );
    }
}
