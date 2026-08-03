#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]

use std::time::{Duration, Instant};
use tessera_cli::state::SuspendState;

#[test]
fn awake_is_not_in_grace() {
    let s = SuspendState::Awake;
    assert!(!s.is_in_grace_window(5));
}

#[test]
fn suspending_is_in_grace() {
    let s = SuspendState::SuspendingAt(Instant::now());
    assert!(s.is_in_grace_window(5));
}

/// A `PrepareForSleep(true)` whose matching `false` never arrives must not
/// suppress removals for the rest of the daemon's life. Under strict
/// monitoring that would be a promise of continuous presence with no
/// enforcement behind it, and nothing in the daemon would say so.
///
/// Safe to bound because the monotonic clock does not run while the machine
/// is suspended: reaching this state means the daemon has been awake that
/// long since the announcement.
#[test]
fn a_suspend_announcement_without_a_resume_stops_suppressing() {
    let s = SuspendState::SuspendingAt(Instant::now() - Duration::from_secs(10));
    assert!(!s.is_in_grace_window(5));
}

#[test]
fn resumed_within_window_is_in_grace() {
    let s = SuspendState::ResumedAt(Instant::now());
    assert!(s.is_in_grace_window(5));
}

#[test]
fn resumed_outside_window_is_awake() {
    let s = SuspendState::ResumedAt(Instant::now() - Duration::from_secs(10));
    assert!(!s.is_in_grace_window(5));
}
