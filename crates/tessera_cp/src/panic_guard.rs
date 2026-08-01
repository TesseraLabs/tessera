//! Containment of panics at the COM boundary.
//!
//! This code runs inside `LogonUI`. An unwind that reaches an `extern "system"`
//! function aborts the process, and aborting that process is the logon screen
//! of the device going away — the failure mode the tile exists to avoid. So
//! every COM entry point runs its body through [`guard`], which turns a panic
//! into a defined return value and a raised flag instead of a dead `LogonUI`.
//!
//! The flag is what makes the degradation honest. A caught panic means the
//! tile's state was interrupted somewhere unknown, so the tile does not pretend
//! to work afterwards: it goes to a permanent error status and refuses to
//! serialise anything. Only the Tessera tile is affected; the standard
//! providers never see any of this.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};

/// Sticky record of a panic having crossed a COM entry point.
///
/// Once raised it never clears: the process it lives in is `LogonUI`, and there
/// is no state in this crate worth trusting after an interrupted mutation.
#[derive(Debug, Default)]
pub struct PanicFlag(AtomicBool);

impl PanicFlag {
    /// Creates a flag in the not-yet-raised state.
    #[must_use]
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    /// Marks that a panic was contained.
    pub fn raise(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Reports whether a panic has ever been contained.
    #[must_use]
    pub fn is_raised(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Runs the body of a COM entry point with unwinding contained.
///
/// On a panic the flag is raised, the event is logged, and `fallback` is
/// returned to the caller — for an `HRESULT`-returning entry point that means
/// a failure code, for a value-returning one an empty or refusing value.
///
/// # Unwind safety
///
/// The body is wrapped in [`AssertUnwindSafe`] deliberately. Entry points
/// borrow tile state mutably, so the body is not unwind-safe in the type
/// system's sense, and it genuinely can leave that state half-updated. The
/// assertion is sound here because the alternative is not "no torn state" but
/// "no logon screen", and because [`PanicFlag`] makes the torn state
/// unreachable: a tile that has raised the flag serialises nothing.
pub fn guard<T, F>(entry: &'static str, flag: &PanicFlag, fallback: T, body: F) -> T
where
    F: FnOnce() -> T,
{
    // Every guarded entry point announces itself. The order in which `LogonUI`
    // calls a provider is not something one can look up with confidence — the
    // documentation describes the interfaces, not the sequence — so the log has
    // to be able to answer "was this even called, and when".
    tracing::debug!(target: "tessera.cp", entry_point = entry, "com entry");

    let Ok(value) = catch_unwind(AssertUnwindSafe(body)) else {
        flag.raise();
        tracing::error!(
            target: "tessera.panic",
            entry_point = entry,
            "panic contained at the credential provider boundary"
        );
        return fallback;
    };
    value
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn passes_the_body_value_through() {
        let flag = PanicFlag::new();
        let value = guard("Nop", &flag, -1, || 42);
        assert_eq!(value, 42);
        assert!(!flag.is_raised());
    }

    #[test]
    fn contains_a_panic_and_returns_the_fallback() {
        let flag = PanicFlag::new();
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let value = guard("Boom", &flag, -1, || panic!("boom"));
        std::panic::set_hook(previous);

        assert_eq!(value, -1);
        assert!(flag.is_raised());
    }

    #[test]
    fn stays_usable_after_a_contained_panic() {
        let flag = PanicFlag::new();
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let _ = guard("Boom", &flag, -1, || panic!("boom"));
        let second = guard("Nop", &flag, -1, || 7);
        std::panic::set_hook(previous);

        assert_eq!(second, 7);
        assert!(
            flag.is_raised(),
            "the flag stays raised for the tile's life"
        );
    }
}
