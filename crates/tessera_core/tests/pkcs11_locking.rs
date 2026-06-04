//! Unit tests for the process-global PKCS#11 serialization layer (T14).
//!
//! These tests do not require any real PKCS#11 provider — they only
//! exercise the in-process `parking_lot::Mutex` wrapper.  They run on
//! every host (Linux dev, macOS dev, CI without softhsm2).

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic,
    clippy::unwrap_used
)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tessera_core::token::pkcs11::locking::{mutex_currently_held, with_global_lock};
use tessera_core::token::pkcs11::LockingMode;

/// In-test mutex used to serialize tests that observe the global
/// `mutex_currently_held` flag — `cargo test` runs integration tests in
/// parallel by default, and the held flag is process-wide, so two
/// `Mutex`-mode tests can race.  Using `parking_lot` here would create
/// a transitive dep alignment headache; `std::sync::Mutex` is plenty.
static TEST_SERIALIZE: Mutex<()> = Mutex::new(());

/// In `Mutex` mode a peer thread observes the lock as held while the
/// closure on the holding thread is sleeping.
///
/// The strategy is to spawn a thread that holds the lock for ~80 ms,
/// then poll from the main thread (after a small delay) and check that
/// `mutex_currently_held` returns `true` *before* the holder releases
/// it.
#[test]
fn mutex_mode_makes_lock_visible_to_peer_thread() {
    let _serial = TEST_SERIALIZE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let started = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicBool::new(false));
    let started_c = Arc::clone(&started);
    let finished_c = Arc::clone(&finished);

    let h = thread::spawn(move || {
        with_global_lock(LockingMode::Mutex, || {
            started_c.store(true, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(80));
            finished_c.store(true, Ordering::SeqCst);
        });
    });

    // Wait until the worker is inside the critical section.
    let deadline = Instant::now() + Duration::from_millis(500);
    while !started.load(Ordering::SeqCst) {
        assert!(
            Instant::now() <= deadline,
            "worker thread never entered critical section"
        );
        thread::sleep(Duration::from_millis(2));
    }

    // The worker is sleeping for ~80 ms — assert that the held flag is
    // visible from this thread *before* the worker finishes.
    assert!(
        mutex_currently_held(),
        "peer thread must observe the held flag while the worker holds it"
    );
    assert!(
        !finished.load(Ordering::SeqCst),
        "worker should still be inside the critical section"
    );

    h.join().expect("worker join");
    assert!(
        !mutex_currently_held(),
        "held flag must be cleared once all guards are dropped"
    );
}

/// In `Mutex` mode two threads that both call `with_global_lock` must
/// **not** observe each other inside the critical section — total
/// wall-clock time is at least the sum of their sleeps.
#[test]
fn mutex_mode_serialises_two_threads() {
    const SLEEP_MS: u64 = 60;
    let _serial = TEST_SERIALIZE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let start = Instant::now();
    let h1 = thread::spawn(|| {
        with_global_lock(LockingMode::Mutex, || {
            thread::sleep(Duration::from_millis(SLEEP_MS));
        });
    });
    let h2 = thread::spawn(|| {
        with_global_lock(LockingMode::Mutex, || {
            thread::sleep(Duration::from_millis(SLEEP_MS));
        });
    });
    h1.join().expect("h1 join");
    h2.join().expect("h2 join");
    let elapsed = start.elapsed();
    // Each closure sleeps 60 ms.  If the lock serialises them, total
    // wall-clock is ≥ 120 ms.  We allow a small fuzz factor (-10 ms) to
    // account for timer granularity but require visibly more than a
    // single sleep — a non-serialised run would finish in ≈ 60 ms.
    assert!(
        elapsed >= Duration::from_millis(SLEEP_MS * 2 - 10),
        "Mutex mode must serialise: elapsed={elapsed:?}"
    );
}

/// In `Os` mode two threads run concurrently — total wall-clock time
/// is approximately the per-thread sleep, not the sum.
#[test]
fn os_mode_allows_concurrent_calls() {
    const SLEEP_MS: u64 = 60;
    let _serial = TEST_SERIALIZE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let start = Instant::now();
    let h1 = thread::spawn(|| {
        with_global_lock(LockingMode::Os, || {
            thread::sleep(Duration::from_millis(SLEEP_MS));
        });
    });
    let h2 = thread::spawn(|| {
        with_global_lock(LockingMode::Os, || {
            thread::sleep(Duration::from_millis(SLEEP_MS));
        });
    });
    h1.join().expect("h1 join");
    h2.join().expect("h2 join");
    let elapsed = start.elapsed();
    // Concurrent execution: total ≈ 60 ms.  Allow up to 110 ms to
    // accommodate slow CI runners; anything ≥ 120 ms (= 2× sleep)
    // would indicate accidental serialisation.
    assert!(
        elapsed < Duration::from_millis(SLEEP_MS * 2),
        "Os mode must allow concurrency: elapsed={elapsed:?}"
    );
}
