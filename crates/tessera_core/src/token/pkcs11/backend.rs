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
//! The registry is a cache, not the holder of that invariant, so
//! `CKR_CRYPTOKI_ALREADY_INITIALIZED` counts as success: the provider can
//! be up without the registry knowing.  Someone else in the process may
//! have initialized it — `pam_pkcs11`, `sshd` built with
//! `PKCS11Provider`, p11-kit — or a previous incarnation of this very
//! module may have: libpam unloads modules on `pam_end`, and `dlclose`
//! erases these statics without running any destructor while the
//! provider image stays mapped and initialized, because the `Library`
//! holding it leaks along with them.  Refusing to adopt would deny every
//! login after the first in a process that outlives one authentication.
//! Adopting is safe for the same reason the registry can be a mere
//! cache: we never finalize, so there is nothing to take away from
//! whoever owns the initialization.
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::slot::Slot;
use parking_lot::Mutex;
use tracing::{info, warn};

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
    /// The locking mode in force for this module path.
    mode: SharedLockingMode,
}

/// Live view of the locking mode of one PKCS#11 context.
///
/// The mode governs a shared library rather than a handle — one backend
/// skipping the mutex would let its calls run concurrently with the calls
/// another backend believes are serialized — so it cannot be copied into
/// a handle at creation time and left there.  A later `load` asking for
/// [`LockingMode::Mutex`] raises it, and the raise has to reach handles
/// that already exist or it protects nothing.  Everything that has to
/// know the mode ([`Pkcs11Backend`], [`super::session::Pkcs11Session`],
/// whose `Drop` has no backend to ask) holds a clone of this and reads it
/// per call.
#[derive(Debug, Clone)]
pub(crate) struct SharedLockingMode {
    /// `true` means [`LockingMode::Mutex`].  Only ever set, never
    /// cleared — see [`LockingMode::stricter`].
    serialized: Arc<AtomicBool>,
}

impl SharedLockingMode {
    fn new(mode: LockingMode) -> Self {
        Self {
            serialized: Arc::new(AtomicBool::new(matches!(mode, LockingMode::Mutex))),
        }
    }

    /// The mode currently in force.
    pub(crate) fn get(&self) -> LockingMode {
        // `Relaxed` is enough: the flag orders no other memory, and a
        // reader that misses a raise by a few nanoseconds starts
        // serializing from its next call, which is all the raise
        // promises.  Every write happens under the registry lock.
        if self.serialized.load(Ordering::Relaxed) {
            LockingMode::Mutex
        } else {
            LockingMode::Os
        }
    }

    /// Fold `requested` in and return the mode in force afterwards.
    /// Never relaxes.
    fn raise_to(&self, requested: LockingMode) -> LockingMode {
        let effective = self.get().stricter(requested);
        if matches!(effective, LockingMode::Mutex) {
            self.serialized.store(true, Ordering::Relaxed);
        }
        effective
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

impl LockingMode {
    /// The safer of two modes requested for the same module path.
    ///
    /// Backends sharing a module share one mode, so a disagreement has
    /// to be resolved somehow, and the direction is not symmetric.
    /// Resolving towards `Os` — which "whoever loaded first wins" does
    /// half the time — withdraws serialization from a caller that asked
    /// for it, silently and while `Mutex` is the default: a
    /// configuration that said nothing at all would lose its protection
    /// to whoever happened to load first. Resolving towards `Mutex` only
    /// ever costs an uncontended lock (≈ 20 ns) on calls that expected
    /// to run concurrently.
    #[must_use]
    const fn stricter(self, other: Self) -> Self {
        match (self, other) {
            (Self::Os, Self::Os) => Self::Os,
            _ => Self::Mutex,
        }
    }
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
    /// `locking_mode` is folded into the mode of the shared context
    /// rather than applied to this handle: the stricter of the two wins
    /// and the conflict is logged at WARN — see [`Self::locking_mode`].
    ///
    /// A `CKR_CRYPTOKI_ALREADY_INITIALIZED` from `C_Initialize` is not
    /// an error: the provider is up, which is what the caller needs, and
    /// it may well have been brought up by a party this registry cannot
    /// see (see the module docs).
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
    /// - [`Pkcs11Error::InitFailed`] when `C_Initialize` returns any
    ///   status other than `CKR_OK` or `CKR_CRYPTOKI_ALREADY_INITIALIZED`.
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
            let previous = shared.mode.get();
            let effective = shared.mode.raise_to(locking_mode);
            if previous != effective {
                warn!(
                    target: "tessera.pkcs11",
                    module = %key.display(),
                    requested = ?locking_mode,
                    previous = ?previous,
                    effective = ?effective,
                    "pkcs11_locking_mode_upgraded"
                );
            } else if effective != locking_mode {
                warn!(
                    target: "tessera.pkcs11",
                    module = %key.display(),
                    requested = ?locking_mode,
                    effective = ?effective,
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
        match ctx.initialize(init_args) {
            Ok(()) => {
                INIT_COUNT.fetch_add(1, Ordering::SeqCst);
            }
            // Someone got here first — a neighbour in this process, or a
            // previous incarnation of this module whose registry went
            // away with `dlclose` while the provider stayed up.  Adopt
            // the initialization instead of refusing the login: we never
            // finalize, so adopting takes nothing from its owner.  Not a
            // warning — in a login process that outlives one
            // authentication this is the steady state after the first
            // attempt, and a per-login WARN for an expected condition
            // teaches operators to skip warnings.
            Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {
                info!(
                    target: "tessera.pkcs11",
                    module = %key.display(),
                    "pkcs11_context_adopted"
                );
            }
            Err(source) => return Err(Pkcs11Error::InitFailed { source }),
        }

        let shared = Arc::new(SharedContext {
            ctx,
            mode: SharedLockingMode::new(locking_mode),
        });
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
    /// This is the mode of the *context*, which is not necessarily the
    /// one this backend asked for: the mode decides whether calls into a
    /// shared library are serialized, so it has to be a property of the
    /// library rather than of the handle.  Letting one backend skip the
    /// mutex while another relies on it would put concurrent calls into
    /// a provider that was declared unable to take them.
    ///
    /// The value can change under a live handle — a later `load` asking
    /// for [`LockingMode::Mutex`] upgrades the context, and the upgrade
    /// has to reach handles already given out or it protects nothing.
    /// It never moves the other way; see [`LockingMode::stricter`].
    /// Every call site therefore reads it afresh rather than caching it.
    #[must_use]
    pub fn locking_mode(&self) -> LockingMode {
        self.ctx.mode.get()
    }

    /// Hand out the live mode view so a [`super::session::Pkcs11Session`]
    /// can keep honouring the serialization layer in `Drop`, where it has
    /// no backend left to ask.
    pub(crate) fn shared_locking_mode(&self) -> SharedLockingMode {
        self.ctx.mode.clone()
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

    /// A conflict over the mode of a shared context resolves towards
    /// `Mutex` in every combination, and only leaves `Os` when nobody
    /// asked for anything else.
    ///
    /// The live counterpart (`tests/pkcs11_singleton.rs`) needs a second
    /// module path and skips wherever a provider copy will not load,
    /// which includes the host that motivated the whole rule.  This one
    /// runs everywhere: a table of four cases is what stops the
    /// resolution silently flipping back to "first load wins".
    #[test]
    fn mode_conflicts_resolve_towards_mutex() {
        use LockingMode::{Mutex as M, Os};

        assert_eq!(Os.stricter(Os), Os);
        assert_eq!(Os.stricter(M), M, "a request for serialization must win");
        assert_eq!(
            M.stricter(Os),
            M,
            "os must never relax an established mutex"
        );
        assert_eq!(M.stricter(M), M);
    }

    /// Raising is retroactive and one-way: every clone of the view sees
    /// the upgrade, and a later `Os` request cannot undo it.
    #[test]
    fn raising_the_shared_mode_reaches_existing_holders() {
        let held_earlier = SharedLockingMode::new(LockingMode::Os);
        let same_context = held_earlier.clone();
        assert_eq!(held_earlier.get(), LockingMode::Os);

        assert_eq!(
            same_context.raise_to(LockingMode::Mutex),
            LockingMode::Mutex
        );
        assert_eq!(
            held_earlier.get(),
            LockingMode::Mutex,
            "a handle taken out before the upgrade must serialize too, or the calls it \
             makes run concurrently with calls the upgrader believes are protected"
        );

        assert_eq!(same_context.raise_to(LockingMode::Os), LockingMode::Mutex);
        assert_eq!(held_earlier.get(), LockingMode::Mutex);
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
