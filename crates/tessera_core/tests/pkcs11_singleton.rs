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
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11 as RawPkcs11};
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

/// Serial number for private module copies, so no two of them ever share
/// a file name even inside one directory.
static COPY_SERIAL: AtomicUsize = AtomicUsize::new(0);

/// Which module the private copies are cut from: `PKCS11_MODULE_PATH_2`
/// when set, the configured module otherwise.
///
/// The variable exists because the configured provider may refuse to load
/// from anywhere but its install directory — `rtpkcs11ecp` resolves its
/// dependencies relatively and does — which leaves the host unable to
/// produce a second module path at all.  Point it at something that
/// relocates cleanly (`SoftHSM2`) to get these tests running there.
fn copy_source() -> PathBuf {
    std::env::var("PKCS11_MODULE_PATH_2").map_or_else(|_| module_path(), PathBuf::from)
}

/// Can this process `dlopen` `path`?
///
/// `Pkcs11::new` stops at `C_GetFunctionList`, so probing costs no
/// `C_Initialize` and does not spend the path's freshness.  Dropping the
/// handle unloads the library again — `cryptoki` 0.12 has no `Drop`
/// beyond releasing the `Library`, and nothing was initialized.
fn module_is_loadable(path: &std::path::Path) -> bool {
    RawPkcs11::new(path).is_ok()
}

/// A module path **this process has never loaded**, or `None` when the
/// host cannot produce one.
///
/// # Every test that asserts on `context_init_count` deltas or on a
/// context's starting locking mode must take its path from here
///
/// Contexts are immortal by design: the registry keeps them for the life
/// of the process and `C_Finalize` is never called.  So the *first* test
/// to touch a given path decides what every later test sees on it — an
/// exact `+1` on the init counter becomes `0`, and a context asked for in
/// `Os` mode reports `Mutex` because someone already raised it.  Sharing
/// one "second module path" across tests made the outcome depend on
/// alphabetical test order, and hid that dependency completely on hosts
/// where no second path existed and every such test skipped.  A unique
/// file per call removes the coupling instead of documenting it: the
/// registry keys on the canonical path, and no two copies share one.
///
/// # A copy that loads is a second live instance of the provider
///
/// `dlopen` keys on the file, so a copy is a separate image with its own
/// `C_Initialize` state — that is exactly what makes it usable as a fresh
/// path.  The flip side is that the process then holds two initialized
/// instances of the *same vendor library* driving the same device.  That
/// is a condition production never creates and one that `rtpkcs11ecp`
/// 2.14.1 has already been seen to answer with `abort` rather than an
/// error code, so a host where such a copy loads can lose the whole test
/// binary instead of failing a test.  Setting `PKCS11_MODULE_PATH_2` to a
/// *different* provider avoids that: the copies are then cut from
/// something that has no second instance of the vendor library to clash
/// with.
fn fresh_module_path(dir: &std::path::Path) -> Option<PathBuf> {
    let src = copy_source();
    let stem = src.file_stem()?.to_str()?;
    let serial = COPY_SERIAL.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let name = match src.extension().and_then(std::ffi::OsStr::to_str) {
        Some(ext) => format!("{stem}-{serial}.{ext}"),
        None => format!("{stem}-{serial}"),
    };
    let dst = dir.join(name);
    std::fs::copy(&src, &dst).ok()?;
    module_is_loadable(&dst).then_some(dst)
}

/// Uniform skip line for a host that cannot provide a fresh module path.
fn skip_no_fresh_path() {
    eprintln!(
        "skipped: no loadable copy of the module could be made \
         (set PKCS11_MODULE_PATH_2 to a relocatable provider)"
    );
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

/// The locking mode belongs to the shared context, not to the handle,
/// and a conflict is resolved towards the stricter mode.
///
/// Two backends on one module path share one library, so they cannot
/// disagree about whether calls into it are serialized: a backend that
/// skipped the mutex would run concurrently with calls another backend
/// believes are protected — which is the state that aborts the process
/// on a provider that mishandles concurrency.  "First load wins" would
/// resolve that in the unsafe direction, and silently: `mutex` is the
/// default, so a configuration that asked for nothing at all would lose
/// its serialization to whoever happened to load first with `os`.
///
/// The upgrade is therefore mandatory and retroactive — the mode is read
/// per call, so backends handed out earlier pick it up too.  The reverse
/// never happens: `os` cannot take a context out of `mutex`.
///
/// Needs a path no other test has established a mode on, or the starting
/// `Os` is not observable — see [`fresh_module_path`].
#[test]
fn locking_mode_upgrades_to_mutex_and_never_relaxes() {
    let _serial = lock_tests();
    if skip_unless_module() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(path) = fresh_module_path(dir.path()) else {
        skip_no_fresh_path();
        return;
    };
    let relaxed = Pkcs11Backend::load(&path, LockingMode::Os).expect("load asking for Os");
    assert_eq!(
        relaxed.locking_mode(),
        LockingMode::Os,
        "an unseen path loaded in Os mode must start in Os mode"
    );

    let strict = Pkcs11Backend::load(&path, LockingMode::Mutex).expect("load asking for Mutex");
    assert_eq!(
        strict.locking_mode(),
        LockingMode::Mutex,
        "a load that asked for serialization must get it"
    );
    assert_eq!(
        relaxed.locking_mode(),
        LockingMode::Mutex,
        "the upgrade governs the shared library, so the earlier handle must observe it too: \
         one backend skipping the mutex would run concurrently with calls the other believes \
         are serialized"
    );

    let late = Pkcs11Backend::load(&path, LockingMode::Os).expect("load asking for Os again");
    assert_eq!(
        late.locking_mode(),
        LockingMode::Mutex,
        "os must never take an established context out of mutex mode"
    );
    late.list_slots_with_token()
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

/// Needs a second path that nobody has initialized yet, or the exact
/// `+1` below is not the assertion it claims to be — see
/// [`fresh_module_path`].
#[test]
fn two_distinct_module_paths_get_independent_contexts() {
    let _serial = lock_tests();
    if skip_unless_module() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(other) = fresh_module_path(dir.path()) else {
        skip_no_fresh_path();
        return;
    };
    let first = Pkcs11Backend::load(&module_path(), LockingMode::Mutex).expect("load first module");
    // The copy is a path this process has never seen, so it must draw
    // its own `C_Initialize` — measured from here, the count is exact
    // whatever earlier tests left behind.
    let before_second_module = context_init_count();
    let second = Pkcs11Backend::load(&other, LockingMode::Mutex).expect("load second module");
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

/// A provider that someone else already initialized must be adopted, not
/// rejected.
///
/// The registry only knows about initializations it performed itself,
/// and there are two ways for the provider to be up without it knowing.
/// A neighbour in the PAM stack (`pam_pkcs11`, `sshd` built with
/// `PKCS11Provider`, p11-kit) may have called `C_Initialize` first.  And
/// libpam unloads modules on `pam_end`: `dlclose` erases our statics —
/// registry included — without running destructors, while the provider
/// image stays mapped and initialized because the `Library` that held it
/// leaked along with them.  In a process that serves one authentication
/// that is invisible; in the `fly-dm` display slave, which lives for the
/// machine's uptime, it happens after *every* login attempt, so treating
/// `CKR_CRYPTOKI_ALREADY_INITIALIZED` as a failure would deny every
/// login from the second one onwards until the machine is rebooted.
///
/// Adoption is safe for exactly one reason: we never call `C_Finalize`,
/// so there is no way to take the initialization away from whoever owns
/// it.  The registry is a cache, not the holder of the invariant.
///
/// The outsider is raised on a path this process's registry has never
/// seen — otherwise `load` would return the cached context and the
/// adoption path would go untested.  See [`fresh_module_path`].
#[test]
fn load_adopts_a_context_initialized_outside_the_registry() {
    let _serial = lock_tests();
    if skip_unless_module() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(path) = fresh_module_path(dir.path()) else {
        skip_no_fresh_path();
        return;
    };

    // Initialize behind the registry's back, the way an unrelated
    // PKCS#11 consumer in the same process would.  Kept alive to the end
    // of the test: dropping it changes nothing (cryptoki 0.12 does not
    // finalize on `Drop`), but a live outsider is the situation being
    // modelled.
    let outsider = RawPkcs11::new(&path).expect("fresh_module_path returns loadable paths only");
    if let Err(e) = outsider.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        eprintln!("skipped: the copied module could not be initialized directly: {e}");
        return;
    }

    let before = context_init_count();
    let backend = Pkcs11Backend::load(&path, LockingMode::Mutex).expect(
        "a provider already initialized outside the registry must be adopted: rejecting it \
         denies authentication for the rest of the process's life",
    );
    assert_eq!(
        context_init_count(),
        before,
        "adoption is not an initialization: CKR_CRYPTOKI_ALREADY_INITIALIZED means the \
         library was up before we asked"
    );
    backend
        .list_slots_with_token()
        .expect("the adopted context must be usable");

    // A later load must reuse the adopted context rather than re-enter
    // `C_Initialize`: adoption has to put the context in the registry,
    // not merely survive once.
    let again = Pkcs11Backend::load(&path, LockingMode::Mutex).expect("second load");
    assert_eq!(
        context_init_count(),
        before,
        "the adopted context must be cached like any other"
    );
    again
        .list_slots_with_token()
        .expect("slots via second load");
    drop(outsider);
}

/// The regression test for the vendor defect: many threads race into
/// `load` for one module path.  At most one `C_Initialize` may happen,
/// every thread must get a usable backend, and the process must survive.
///
/// The race is run against a fresh path when the host can produce one,
/// because a path this process has never touched makes the expected
/// count exactly one instead of "one or zero, depending on which test
/// ran first".  Where no copy will load — providers that resolve their
/// own dependencies relative to the install directory, which is the very
/// hardware the defect was found on — the run falls back to the
/// configured module and the weaker bound rather than skipping: two
/// `C_Initialize` calls are what kills the process, and that assertion
/// still holds without an exact count.
///
/// See [`fresh_module_path`] for what a host on which the copy *does*
/// load is being asked to tolerate.
#[test]
fn concurrent_load_initializes_once_and_survives() {
    const THREADS: usize = 8;

    let _serial = lock_tests();
    if skip_unless_module() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let (path, unseen_path) = if let Some(copy) = fresh_module_path(dir.path()) {
        (copy, true)
    } else {
        skip_no_fresh_path();
        eprintln!("note: racing on the configured module instead, with the weaker bound");
        (module_path(), false)
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

    let backends: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("worker join"))
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
/// provider, not of this code, and it is not universal: `SoftHSM2` 2.7
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
