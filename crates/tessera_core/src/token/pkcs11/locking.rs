//! Process-global serialization for PKCS#11 calls.
//!
//! Some PKCS#11 providers do **not** survive concurrent `C_*` calls and
//! require the host application to serialize them.  When
//! [`crate::token::pkcs11::LockingMode::Mutex`] is selected this
//! module's [`with_global_lock`] helper takes a process-global
//! `parking_lot::Mutex<()>` for the duration of every cryptoki FFI call
//! made by [`crate::token::pkcs11::Pkcs11Backend`] and
//! [`crate::token::pkcs11::Pkcs11Session`].
//!
//! Advertising `CKF_OS_LOCKING_OK` support is not evidence of it, and
//! this is not confined to legacy hardware.  On `rtpkcs11ecp` 2.14.1
//! (Rutoken, current at the time of writing) a `C_Initialize` entered
//! from two threads at once escapes as an uncaught C++ exception in
//! `CApplication::InitializeCryptoki` and takes the process down through
//! `std::terminate`, despite the flag having been passed.  Measured
//! there: sequential re-initialization returns the correct
//! `CKR_CRYPTOKI_ALREADY_INITIALIZED`; two unserialized threads produced
//! zero clean runs out of three; under a user-space mutex, five out of
//! five.  Nothing here claims that every provider is defective — one was
//! examined — only that the defect is not restricted to old ones, which
//! is why `Mutex` is the default.
//!
//! `Mutex` mode is additive: the `C_Initialize` call still asks for
//! `CKF_OS_LOCKING_OK`, because a conforming provider needs to hear it.
//! The cost is one uncontended `parking_lot::Mutex` lock per call
//! (≈ 20 ns on x86-64), negligible next to a real `C_Sign`.
//!
//! `Os` mode skips the lock entirely, allowing concurrent calls from
//! independent threads.  It remains available for operators who know
//! their provider handles that, and buys real parallelism there.
//!
//! Neither mode governs *context creation*: `C_Initialize` is serialized
//! process-wide by the context registry in
//! [`crate::token::pkcs11::Pkcs11Backend`], because two backends may
//! disagree about the locking mode while the provider defect is
//! process-global.  For the same reason the mode itself is a property of
//! the shared context rather than of a backend handle — the first load of
//! a module path fixes it, and a later load asking for the other mode is
//! told what it got at WARN.  Serialization that half the callers opt out
//! of serializes nothing.
//!
//! ## Test instrumentation
//!
//! [`mutex_currently_held`] returns `true` while a `Mutex`-mode guard is
//! alive on any thread.  This is used by the unit tests in
//! `tests/pkcs11_locking.rs` to prove that `Mutex` mode actually
//! serializes contention.  The flag is updated *before* `f` runs and
//! cleared *after* it returns; tests that rely on it must therefore
//! observe it from a different thread (the closure on the holding
//! thread still sees `true`).

use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::Mutex;

use crate::token::pkcs11::backend::LockingMode;

/// Process-global serialization mutex.
///
/// `parking_lot::Mutex::new` is `const`, so we use a plain `static`
/// without `Lazy` / `OnceLock` boilerplate.  The mutex is intentionally
/// `Mutex<()>` — we hold it just for the duration of an FFI call and
/// never store data inside it.
static GLOBAL_LOCK: Mutex<()> = Mutex::new(());

/// Counter of currently-held `Mutex`-mode guards.  Incremented before
/// the closure runs and decremented after, so a peer thread that calls
/// [`mutex_currently_held`] sees `true` for the entire critical
/// section.
///
/// Using an `AtomicUsize` (not `AtomicBool`) lets reentrancy be
/// accurately reported even though `parking_lot::Mutex` itself is not
/// reentrant — in practice the loop inside a single
/// [`with_global_lock`] call cannot enter again, but the counter
/// remains correct under future refactoring.
static HELD_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Run `f` while serializing against any other call wrapped in
/// `with_global_lock(LockingMode::Mutex, …)`.
///
/// In [`LockingMode::Os`] mode the global mutex is **not** taken and
/// `f` runs directly — concurrent calls from independent threads are
/// allowed.
///
/// In [`LockingMode::Mutex`] mode the global mutex is acquired,
/// [`mutex_currently_held`] starts returning `true`, `f` runs, and the
/// guard plus counter are dropped together.
///
/// This wrapper does **not** add any error-handling — `f` is expected
/// to return its own `Result`.  Panics from `f` are still safe: the
/// `parking_lot::Mutex` guard will be dropped on unwind and
/// [`HELD_COUNT`] is decremented inside a small `Drop` shim so the
/// counter cannot leak past a panic.  See [`HeldGuard`] below.
pub fn with_global_lock<R>(mode: LockingMode, f: impl FnOnce() -> R) -> R {
    match mode {
        LockingMode::Os => f(),
        LockingMode::Mutex => {
            let _g = GLOBAL_LOCK.lock();
            let _held = HeldGuard::new();
            f()
        }
    }
}

/// Returns `true` while at least one [`with_global_lock`] call is
/// running in [`LockingMode::Mutex`] mode anywhere in the process.
///
/// Test-only diagnostic; production callers have no reason to check
/// this.  Made `pub` (not `pub(crate)`) so unit tests in the
/// `tests/pkcs11_locking.rs` file can link against it without going
/// through any private surface.
#[must_use]
pub fn mutex_currently_held() -> bool {
    HELD_COUNT.load(Ordering::SeqCst) > 0
}

/// RAII helper that increments [`HELD_COUNT`] on construction and
/// decrements on drop.  Survives panics inside the closure.
struct HeldGuard;

impl HeldGuard {
    fn new() -> Self {
        HELD_COUNT.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for HeldGuard {
    fn drop(&mut self) {
        HELD_COUNT.fetch_sub(1, Ordering::SeqCst);
    }
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
    use std::sync::Mutex as StdMutex;

    /// Test-only serializer: the two tests below both observe
    /// [`HELD_COUNT`] (a process-global atomic). When cargo runs them in
    /// parallel, one test's `Mutex`-mode critical section can race with
    /// the other's `Os`-mode probe and falsely flip `held = true`. We
    /// take a tiny per-test-binary mutex around both tests so they run
    /// sequentially — without affecting production behaviour.
    static TEST_SERIALIZER: StdMutex<()> = StdMutex::new(());

    #[test]
    fn os_mode_does_not_set_held_flag() {
        let _g = TEST_SERIALIZER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let observed = with_global_lock(LockingMode::Os, mutex_currently_held);
        assert!(
            !observed,
            "Os mode must not set the held flag: held = {observed}"
        );
    }

    #[test]
    fn mutex_mode_sets_held_flag_inside_closure() {
        let _g = TEST_SERIALIZER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let observed = with_global_lock(LockingMode::Mutex, mutex_currently_held);
        assert!(observed, "Mutex mode must set the held flag inside closure");
        // After the call returns, the flag clears again.
        assert!(!mutex_currently_held());
    }
}
