//! Process-global PKCS#11 context: one `C_Initialize` per module path.
//!
//! `rtpkcs11ecp` 2.14.1 aborts the whole process when `C_Initialize` is
//! entered concurrently from two threads, even though the call passes
//! `CKF_OS_LOCKING_OK`.  `pam_tessera` is a cdylib inside `sshd` /
//! `login` / `fly-dm`, so that abort is a denial of authentication.  The
//! tests below pin the invariant that protects against it: however many
//! times `Pkcs11Backend::load` runs, the library is initialized exactly
//! once per module path while at least one backend is alive.
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

use tessera_core::token::pkcs11::{
    context_init_count, test_helpers, LockingMode, Pkcs11Backend, Pkcs11Error,
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

#[test]
fn repeated_load_of_same_module_initializes_once() {
    let _serial = lock_tests();
    if skip_unless_module() {
        return;
    }
    let path = module_path();
    let before = context_init_count();
    let first = Pkcs11Backend::load(&path, LockingMode::Mutex).expect("first load");
    let second = Pkcs11Backend::load(&path, LockingMode::Mutex).expect("second load");
    assert_eq!(
        context_init_count() - before,
        1,
        "the second load of a live module must reuse the initialized context"
    );
    // Both handles must be usable — sharing the context is not allowed
    // to break slot enumeration.
    first.list_slots_with_token().expect("slots via first");
    second.list_slots_with_token().expect("slots via second");
}

#[test]
fn load_after_last_backend_dropped_initializes_again() {
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
    let reborn = Pkcs11Backend::load(&path, LockingMode::Mutex).expect("second load");
    assert_eq!(
        context_init_count() - before,
        2,
        "dropping the last owner must finalize, so the next load initializes anew"
    );
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
    let before = context_init_count();
    let first = Pkcs11Backend::load(&module_path(), LockingMode::Mutex).expect("load first module");
    let second = match Pkcs11Backend::load(&other, LockingMode::Mutex) {
        Ok(b) => b,
        Err(Pkcs11Error::ModuleLoadFailed { .. }) => {
            eprintln!("skipped: the copied module is not loadable from a new location");
            return;
        }
        Err(other_err) => panic!("unexpected load error: {other_err:?}"),
    };
    assert_eq!(
        context_init_count() - before,
        2,
        "distinct module paths must not share a context"
    );
    assert_ne!(first.module_path(), second.module_path());
}

/// The regression test for the vendor defect: many threads race into
/// `load` for one module path.  Exactly one `C_Initialize` must happen,
/// every thread must get a usable backend, and the process must survive.
///
/// Each thread returns its backend so that no handle is dropped while
/// another thread is still loading — otherwise a legitimate finalize +
/// re-initialize would show up as a second `C_Initialize`.
#[test]
fn concurrent_load_initializes_once_and_survives() {
    const THREADS: usize = 8;

    let _serial = lock_tests();
    if skip_unless_module() {
        return;
    }
    let path = module_path();
    let before = context_init_count();
    let barrier = Arc::new(Barrier::new(THREADS));

    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let backend = Pkcs11Backend::load(&path, LockingMode::Mutex).expect("load");
                // A real cryptoki call, not a sleep: the point is to hit
                // the provider concurrently, not to time a mutex.
                backend.list_slots_with_token().expect("slots");
                backend
            })
        })
        .collect();

    let backends: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("worker join"))
        .collect();

    assert_eq!(backends.len(), THREADS);
    assert_eq!(
        context_init_count() - before,
        1,
        "concurrent loads must collapse to a single C_Initialize"
    );
}
