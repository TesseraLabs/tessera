//! Bounded token-arrival polling helper (Task T04).
//!
//! [`Pkcs11Backend::wait_for_token`](super::Pkcs11Backend::wait_for_token)
//! re-uses [`wait_for_token_with_clock`] under the hood, passing in the
//! real [`RealClock`].  Test code in this file injects a mock clock and a
//! [`TokenLocator`] implementation that returns scripted results, which
//! lets us verify the timing semantics without loading a `.so`.

use std::thread::sleep;
use std::time::{Duration, Instant};

use cryptoki::slot::Slot;

use super::error::Pkcs11Error;

/// Abstraction over `Pkcs11Backend::find_slot` so the polling loop can be
/// driven from tests without a real PKCS#11 provider.
pub trait TokenLocator {
    /// Return a slot for the given label, or one of the `keep polling`
    /// errors ([`Pkcs11Error::NoTokenAvailable`] /
    /// [`Pkcs11Error::TokenNotFound`]).
    ///
    /// # Errors
    ///
    /// Implementations may return any [`Pkcs11Error`]; the polling loop
    /// only retries on `NoTokenAvailable` and `TokenNotFound` and bails
    /// on every other variant.
    fn try_find(&self, token_label: Option<&str>) -> Result<Slot, Pkcs11Error>;
}

/// Abstraction over `Instant::now` and `thread::sleep` so the polling
/// loop is deterministic in unit tests.
pub(crate) trait Clock {
    /// Current monotonic instant.
    fn now(&self) -> Instant;
    /// Sleep for the given duration (or simulated equivalent).
    fn sleep(&self, dur: Duration);
}

/// Production clock that uses [`Instant::now`] and [`std::thread::sleep`].
pub(crate) struct RealClock;

impl Clock for RealClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&self, dur: Duration) {
        sleep(dur);
    }
}

const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Drive the polling loop using the supplied locator and clock.
///
/// # Errors
///
/// - [`Pkcs11Error::TokenWaitTimeout`] when `timeout` elapses without a
///   matching token appearing.
/// - Forwards any non-"keep polling" [`Pkcs11Error`] from `locator`.
pub(crate) fn wait_for_token_with_clock<L, C>(
    locator: &L,
    token_label: Option<&str>,
    timeout: Duration,
    clock: &C,
) -> Result<Slot, Pkcs11Error>
where
    L: TokenLocator,
    C: Clock,
{
    let started = clock.now();
    loop {
        match locator.try_find(token_label) {
            Ok(slot) => return Ok(slot),
            Err(Pkcs11Error::NoTokenAvailable | Pkcs11Error::TokenNotFound { .. }) => {
                // keep polling
            }
            Err(other) => return Err(other),
        }
        if clock.now().duration_since(started) >= timeout {
            return Err(Pkcs11Error::TokenWaitTimeout {
                seconds: timeout.as_secs(),
            });
        }
        clock.sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::err_expect,
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::unwrap_used
    )]

    use super::*;
    use std::cell::{Cell, RefCell};

    struct ScriptedLocator {
        results: RefCell<Vec<Result<Slot, Pkcs11Error>>>,
        calls: Cell<usize>,
    }

    impl ScriptedLocator {
        fn new(results: Vec<Result<Slot, Pkcs11Error>>) -> Self {
            Self {
                results: RefCell::new(results),
                calls: Cell::new(0),
            }
        }
    }

    impl TokenLocator for ScriptedLocator {
        fn try_find(&self, _token_label: Option<&str>) -> Result<Slot, Pkcs11Error> {
            self.calls.set(self.calls.get() + 1);
            // Pop from the front; the last entry is repeated indefinitely.
            let mut results = self.results.borrow_mut();
            if results.len() > 1 {
                results.remove(0)
            } else if let Some(only) = results.first() {
                clone_result(only)
            } else {
                Err(Pkcs11Error::NoTokenAvailable)
            }
        }
    }

    fn clone_result(r: &Result<Slot, Pkcs11Error>) -> Result<Slot, Pkcs11Error> {
        // `Slot` is Copy; the error variants we use in tests are
        // reconstructed by hand because `cryptoki::error::Error` doesn't
        // implement `Clone`.
        match r {
            Ok(s) => Ok(*s),
            Err(Pkcs11Error::NoTokenAvailable) => Err(Pkcs11Error::NoTokenAvailable),
            Err(Pkcs11Error::TokenNotFound { label }) => Err(Pkcs11Error::TokenNotFound {
                label: label.clone(),
            }),
            Err(Pkcs11Error::PinIncorrect) => Err(Pkcs11Error::PinIncorrect),
            Err(Pkcs11Error::PinLocked) => Err(Pkcs11Error::PinLocked),
            Err(other) => panic!("clone_result does not support {other:?}"),
        }
    }

    /// Mock clock that advances by an explicit step on every `sleep` and
    /// records the wall-clock equivalent of every `now` call.
    struct MockClock {
        ticks: RefCell<u64>,
        step_ms: u64,
        base: Instant,
    }

    impl MockClock {
        fn new(step_ms: u64) -> Self {
            Self {
                ticks: RefCell::new(0),
                step_ms,
                base: Instant::now(),
            }
        }
        fn elapsed_ms(&self) -> u64 {
            *self.ticks.borrow()
        }
    }

    impl Clock for MockClock {
        fn now(&self) -> Instant {
            // The waiter only ever calls `duration_since` against the
            // first observed value; we synthesise a monotonic Instant by
            // adding the accumulated tick count to `base`.
            self.base + Duration::from_millis(*self.ticks.borrow())
        }
        fn sleep(&self, _dur: Duration) {
            *self.ticks.borrow_mut() += self.step_ms;
        }
    }

    fn slot(id: u64) -> Slot {
        // `cryptoki::slot::Slot` exposes `try_from(u64)`.
        Slot::try_from(id).expect("test slot id fits in CK_SLOT_ID")
    }

    #[test]
    fn returns_immediately_when_token_present() {
        let locator = ScriptedLocator::new(vec![Ok(slot(7))]);
        let clock = MockClock::new(200);
        let got = wait_for_token_with_clock(&locator, None, Duration::from_secs(5), &clock)
            .expect("first poll succeeds");
        assert_eq!(got, slot(7));
        assert_eq!(locator.calls.get(), 1);
        assert_eq!(clock.elapsed_ms(), 0, "no sleeps before success");
    }

    #[test]
    fn waits_until_token_appears() {
        let locator = ScriptedLocator::new(vec![
            Err(Pkcs11Error::NoTokenAvailable),
            Err(Pkcs11Error::NoTokenAvailable),
            Ok(slot(3)),
        ]);
        let clock = MockClock::new(200);
        let got = wait_for_token_with_clock(&locator, None, Duration::from_secs(5), &clock)
            .expect("third poll succeeds");
        assert_eq!(got, slot(3));
        assert_eq!(locator.calls.get(), 3);
        // Two sleeps of 200 ms before the third successful poll.
        assert_eq!(clock.elapsed_ms(), 400);
    }

    #[test]
    fn times_out_when_token_never_appears() {
        let locator = ScriptedLocator::new(vec![Err(Pkcs11Error::NoTokenAvailable)]);
        let clock = MockClock::new(200);
        let err = wait_for_token_with_clock(&locator, None, Duration::from_secs(1), &clock)
            .err()
            .expect("must time out");
        assert!(
            matches!(err, Pkcs11Error::TokenWaitTimeout { seconds: 1 }),
            "got {err:?}"
        );
        // The mock clock advances by 200 ms per sleep; we time out as
        // soon as the cumulative sleep reaches 1 s.  The locator is
        // called once per loop iteration, so the call count is 1 +
        // floor(1000 / 200) = 6.
        assert!(locator.calls.get() >= 5);
    }

    #[test]
    fn forwards_unexpected_errors_immediately() {
        let locator = ScriptedLocator::new(vec![Err(Pkcs11Error::PinLocked)]);
        let clock = MockClock::new(200);
        let err = wait_for_token_with_clock(&locator, None, Duration::from_secs(5), &clock)
            .err()
            .expect("must propagate PinLocked");
        assert!(matches!(err, Pkcs11Error::PinLocked));
        assert_eq!(
            locator.calls.get(),
            1,
            "no further polling after fatal error"
        );
    }

    #[test]
    fn token_not_found_is_keep_polling() {
        let locator = ScriptedLocator::new(vec![
            Err(Pkcs11Error::TokenNotFound { label: "x".into() }),
            Ok(slot(1)),
        ]);
        let clock = MockClock::new(200);
        let got = wait_for_token_with_clock(&locator, Some("x"), Duration::from_secs(5), &clock)
            .expect("eventually finds token");
        assert_eq!(got, slot(1));
        assert_eq!(locator.calls.get(), 2);
    }
}
