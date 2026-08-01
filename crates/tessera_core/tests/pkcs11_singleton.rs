//! Process-global PKCS#11 context: one `C_Initialize` per module path.
//!
//! `rtpkcs11ecp` 2.14.1 aborts the whole process when `C_Initialize` is
//! entered concurrently from two threads, even though the call passes
//! `CKF_OS_LOCKING_OK`.  `pam_tessera` is a cdylib inside `sshd` /
//! `login` / `fly-dm`, so that abort is a denial of authentication.  The
//! tests below pin the invariant that protects against it: however many
//! times `Pkcs11Backend::load` runs, the library is initialized exactly
//! once per module path — and stays initialized, because the context is
//! never finalized.
//!
//! Every test needs a real provider and is therefore gated twice:
//!
//! 1. the `pkcs11-tests` Cargo feature (compile-time); and
//! 2. `PKCS11_MODULE_PATH` pointing at a loadable module (runtime).
//!
//! Without a provider each test prints `skipped: …` and returns `Ok`,
//! matching the convention in `pkcs11_integration.rs`.

#![cfg(feature = "pkcs11-tests")]
#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic,
    clippy::unwrap_used
)]

use std::path::PathBuf;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use secrecy::SecretString;
use tessera_core::token::pkcs11::{
    context_init_count, test_helpers, LockingMode, Pkcs11Backend, Pkcs11Error, Pkcs11Session,
};

/// The init counter is process-global, so two tests from this binary
/// running in parallel would see each other's `C_Initialize` calls and
/// read the wrong delta.  Every test in this file takes this lock for
/// its whole body; `cargo test` still parallelises across binaries.
static SERIALIZE: Mutex<()> = Mutex::new(());

fn lock_tests() -> std::sync::MutexGuard<'static, ()> {
    SERIALIZE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Print a uniform skip line and return `true` when no provider is
/// configured on this host.
fn skip_unless_module() -> bool {
    if test_helpers::pkcs11_test_module_path().is_none() {
        eprintln!("skipped: PKCS11_MODULE_PATH not set or path missing");
        return true;
    }
    false
}

fn module_path() -> PathBuf {
    test_helpers::pkcs11_test_module_path().expect("checked by skip_unless_module")
}

fn token_label() -> Option<String> {
    std::env::var("SOFTHSM_TEST_LABEL").ok()
}

fn user_pin() -> SecretString {
    SecretString::from(std::env::var("SOFTHSM_USER_PIN").unwrap_or_else(|_| "1234".to_owned()))
}

/// Copy the configured module to a fresh path so the process holds two
/// *different* module paths.  Returns `None` when the copy cannot be
/// loaded (a provider whose transitive dependencies resolve relative to
/// its original location) — the caller then skips.
fn second_module(dir: &std::path::Path) -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("PKCS11_MODULE_PATH_2") {
        let p = PathBuf::from(explicit);
        return p.exists().then_some(p);
    }
    let src = module_path();
    let name = src.file_name()?;
    let dst = dir.join(name);
    std::fs::copy(&src, &dst).ok()?;
    Some(dst)
}

/// The counter is process-global and the context is never torn down, so
/// a test cannot demand a fresh initialization: whether the delta of a
/// first load is 0 or 1 depends on which test in this binary ran first.
/// Every assertion below is therefore phrased as "at most once, and the
/// repeat adds nothing", which is the invariant itself rather than an
/// artefact of test ordering.
#[test]
fn repeated_load_of_same_module_initializes_once() {
    let _serial = lock_tests();
    if skip_unless_module() {
        return;
    }
    let path = module_path();
    let before = context_init_count();
    let first = Pkcs11Backend::load(&path, LockingMode::Mutex).expect("first load");
    let after_first = context_init_count();
    let second = Pkcs11Backend::load(&path, LockingMode::Mutex).expect("second load");
    assert!(
        after_first - before <= 1,
        "a load may initialize at most once (delta = {})",
        after_first - before
    );
    assert_eq!(
        context_init_count(),
        after_first,
        "the second load of a live module must reuse the initialized context"
    );
    // Both handles must be usable — sharing the context is not allowed
    // to break slot enumeration.
    first.list_slots_with_token().expect("slots via first");
    second.list_slots_with_token().expect("slots via second");
}

/// The locking mode belongs to the shared context, not to the handle.
///
/// Two backends on one module path share one library, so they cannot
/// disagree about whether calls into it are serialized: a backend that
/// skipped the mutex would run concurrently with calls another backend
/// believes are protected — which is the state that aborts the process
/// on a provider that mishandles concurrency.  The mode of the first
/// load therefore wins, and the loser is told at WARN
/// (`pkcs11_locking_mode_conflict`).
///
/// Every other test in this binary loads in `Mutex`, so `Mutex` is the
/// established mode regardless of which test runs first.
#[test]
fn locking_mode_is_fixed_by_the_first_load() {
    let _serial = lock_tests();
    if skip_unless_module() {
        return;
    }
    let path = module_path();
    let established =
        Pkcs11Backend::load(&path, LockingMode::Mutex).expect("load in the established mode");
    assert_eq!(established.locking_mode(), LockingMode::Mutex);

    let dissenter = Pkcs11Backend::load(&path, LockingMode::Os).expect("load asking for Os");
    assert_eq!(
        dissenter.locking_mode(),
        LockingMode::Mutex,
        "a later load must not switch a shared context out of Mutex mode"
    );
    dissenter
        .list_slots_with_token()
        .expect("the dissenting backend must still work");
}

/// Dropping every backend must **not** tear the context down: the
/// registry keeps a strong reference and `C_Finalize` is never called.
///
/// `C_Finalize` is process-global inside the provider's single `dlopen`,
/// so calling it would deinitialize PKCS#11 for unrelated consumers in
/// the same process (`pam_pkcs11`, `sshd` with `PKCS11Provider`) that
/// have no way of noticing.  The observable consequence, and what this
/// test pins, is that a `load` arriving after the last backend died
/// reuses the existing context instead of initializing a second time.
#[test]
fn load_after_last_backend_dropped_reuses_the_context() {
    let _serial = lock_tests();
    if skip_unless_module() {
        return;
    }
    let path = module_path();
    let before = context_init_count();
    {
        let backend = Pkcs11Backend::load(&path, LockingMode::Mutex).expect("first load");
        backend.list_slots_with_token().expect("slots");
    }
    let after_first = context_init_count();
    assert!(
        after_first - before <= 1,
        "the first load may initialize at most once (delta = {})",
        after_first - before
    );

    let reborn = Pkcs11Backend::load(&path, LockingMode::Mutex).expect("second load");
    assert_eq!(
        context_init_count(),
        after_first,
        "no backend is alive, but the context must survive: a re-initialization here \
         would mean C_Finalize ran and took the provider down for the whole process"
    );
    // The surviving context must still be usable — "not finalized" is
    // only worth anything if calls through it still work.
    reborn.list_slots_with_token().expect("slots after reload");
}

#[test]
fn two_distinct_module_paths_get_independent_contexts() {
    let _serial = lock_tests();
    if skip_unless_module() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(other) = second_module(dir.path()) else {
        eprintln!("skipped: could not provide a second module path");
        return;
    };
    let first = Pkcs11Backend::load(&module_path(), LockingMode::Mutex).expect("load first module");
    // The copy is a path this process has never seen, so it must draw
    // its own `C_Initialize` — measured from here, the count is exact
    // whatever earlier tests left behind.
    let before_second_module = context_init_count();
    let second = match Pkcs11Backend::load(&other, LockingMode::Mutex) {
        Ok(b) => b,
        Err(Pkcs11Error::ModuleLoadFailed { .. }) => {
            eprintln!("skipped: the copied module is not loadable from a new location");
            return;
        }
        Err(other_err) => panic!("unexpected load error: {other_err:?}"),
    };
    assert_eq!(
        context_init_count() - before_second_module,
        1,
        "distinct module paths must not share a context"
    );
    // Both handles stay usable: an independent context per path is only
    // meaningful if each one actually talks to its own library.
    first
        .list_slots_with_token()
        .expect("slots via first module");
    second
        .list_slots_with_token()
        .expect("slots via second module");
}

/// The regression test for the vendor defect: many threads race into
/// `load` for one module path.  At most one `C_Initialize` may happen,
/// every thread must get a usable backend, and the process must survive.
///
/// The race is run against a private copy of the module when the host
/// allows one, because a path this process has never touched makes the
/// expected count exactly one instead of "one or zero, depending on
/// which test ran first".  Where the copy will not load — providers
/// that resolve their own dependencies relative to the install
/// directory — the run falls back to the configured module and the
/// weaker bound, which is still the assertion that matters: two
/// `C_Initialize` calls are what kills the process.
#[test]
fn concurrent_load_initializes_once_and_survives() {
    const THREADS: usize = 8;

    let _serial = lock_tests();
    if skip_unless_module() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let (path, unseen_path) = match second_module(dir.path()) {
        Some(copy) => (copy, true),
        None => (module_path(), false),
    };
    let before = context_init_count();
    let barrier = Arc::new(Barrier::new(THREADS));

    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let backend = Pkcs11Backend::load(&path, LockingMode::Mutex)?;
                // A real cryptoki call, not a sleep: the point is to hit
                // the provider concurrently, not to time a mutex.
                backend.list_slots_with_token()?;
                Ok::<_, Pkcs11Error>(backend)
            })
        })
        .collect();

    let results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("worker join"))
        .collect();

    if unseen_path
        && results
            .iter()
            .all(|r| matches!(r, Err(Pkcs11Error::ModuleLoadFailed { .. })))
    {
        eprintln!("skipped: the copied module is not loadable from a new location");
        return;
    }
    let backends: Vec<_> = results
        .into_iter()
        .map(|r| r.expect("every racing thread must get a usable backend"))
        .collect();

    assert_eq!(backends.len(), THREADS);
    let delta = context_init_count() - before;
    if unseen_path {
        assert_eq!(
            delta, 1,
            "concurrent loads of an unseen path must collapse to a single C_Initialize"
        );
    } else {
        assert!(
            delta <= 1,
            "concurrent loads must never produce a second C_Initialize (delta = {delta})"
        );
    }
}

/// Load and drop backends from several threads at full churn.
///
/// This is the shape that broke the earlier refcounted-finalization
/// design: the last owner's `Drop` decremented the `Arc` *after*
/// returning, so the count it had checked under the registry lock was
/// already stale, and two threads could either both skip finalization or
/// both perform it.  Nothing is refcounted any more — the registry owns
/// the context outright — so the invariant this test pins is the
/// absolute one: whatever the interleaving, the library is initialized
/// exactly once and every handle handed out stays usable.
#[test]
fn concurrent_load_and_drop_never_reinitializes() {
    const THREADS: usize = 8;
    const CYCLES: usize = 25;

    let _serial = lock_tests();
    if skip_unless_module() {
        return;
    }
    let path = module_path();
    // Prime the context so the churn below measures drops, not the
    // single legitimate initialization.
    let primer = Pkcs11Backend::load(&path, LockingMode::Mutex).expect("primer load");
    let before = context_init_count();
    let barrier = Arc::new(Barrier::new(THREADS));

    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for _ in 0..CYCLES {
                    let backend = Pkcs11Backend::load(&path, LockingMode::Mutex).expect("load");
                    backend.list_slots_with_token().expect("slots");
                    drop(backend);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("worker join");
    }

    assert_eq!(
        context_init_count(),
        before,
        "load/drop churn must not re-initialize the library"
    );
    // The primer predates the churn: if any thread had torn the context
    // down, this call would fail with CKR_CRYPTOKI_NOT_INITIALIZED.
    primer
        .list_slots_with_token()
        .expect("the pre-existing handle must survive the churn");
}

/// Two authentications in one process: the second must start on a
/// logged-out token.
///
/// Sharing one `C_Initialize` means sharing the login state — PKCS#11
/// scopes `C_Login` to the application, not to the session.  Before this
/// change every `load` created its own application and the isolation was
/// accidental; now it rests entirely on `C_Logout` running when the
/// session is dropped.  The `fly-dm` display slave serves every login
/// attempt of the machine's whole uptime from one process, so a residual
/// login would let the next person at the console reach private objects
/// without ever presenting a PIN.
///
/// The un-logged-in probe is the observation: it must read zero private
/// objects between authentications and non-zero during one — the latter
/// is what proves the probe can see anything at all.
///
/// Whether the *second* `C_Login` then succeeds is a property of the
/// provider, not of this code, and it is not universal: SoftHSM2 2.7
/// fails every `C_Login` after the first one in a process with
/// `CKR_GENERAL_ERROR`, with or without an intervening `C_Logout`
/// (reproduced against bare `cryptoki`, no tessera code involved).  So a
/// failure there is reported and skipped rather than asserted — the
/// security half of the invariant, "the login did not survive", is
/// asserted unconditionally.
#[test]
fn login_state_does_not_outlive_the_session() {
    let _serial = lock_tests();
    if skip_unless_module() {
        return;
    }
    let backend = Pkcs11Backend::load(&module_path(), LockingMode::Mutex).expect("load");
    let slot = match backend.find_slot(token_label().as_deref()) {
        Ok(slot) => slot,
        Err(Pkcs11Error::NoTokenAvailable | Pkcs11Error::TokenNotFound { .. }) => {
            eprintln!("skipped: no matching token present");
            return;
        }
        Err(other) => panic!("unexpected find_slot error: {other:?}"),
    };
    let probe = |stage: &str| {
        test_helpers::private_objects_visible_without_login(&backend, slot)
            .unwrap_or_else(|e| panic!("private-object probe failed ({stage}): {e:?}"))
    };

    assert_eq!(
        probe("before"),
        0,
        "the token must be logged out before the first authentication"
    );

    // First authentication.
    let visible_while_logged_in = {
        let session = match Pkcs11Session::open(&backend, slot, &user_pin()) {
            Ok(s) => s,
            Err(Pkcs11Error::PinIncorrect | Pkcs11Error::PinLocked) => {
                eprintln!("skipped: token PIN does not match SOFTHSM_USER_PIN");
                return;
            }
            Err(other) => panic!("unexpected open error: {other:?}"),
        };
        let seen = probe("during first login");
        drop(session);
        seen
    };
    if visible_while_logged_in == 0 {
        eprintln!("skipped: token holds no private objects, the probe proves nothing");
        return;
    }

    assert_eq!(
        probe("after first session dropped"),
        0,
        "dropping the session must C_Logout: with a shared context the login would \
         otherwise stay valid for the rest of the process's life"
    );

    // Second authentication in the same process.  It is *required* —
    // the probe read zero above — and on a conforming provider it also
    // works; see the note on SoftHSM2 in the doc comment.
    let Ok(session) = Pkcs11Session::open(&backend, slot, &user_pin()) else {
        eprintln!(
            "note: this provider refuses a second C_Login in one process; \
             the logout invariant above still held"
        );
        return;
    };
    assert!(
        probe("during second login") > 0,
        "the second login must actually take effect"
    );
    drop(session);
    assert_eq!(
        probe("after second session dropped"),
        0,
        "the second session must log out too"
    );
}
