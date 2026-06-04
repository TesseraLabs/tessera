#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]

use tessera_cli::state::SuspendState;
use std::time::{Duration, Instant};

#[test]
fn awake_is_not_in_grace() {
    let s = SuspendState::Awake;
    assert!(!s.is_in_grace_window(5));
}

#[test]
fn suspending_is_always_in_grace() {
    let s = SuspendState::SuspendingAt(Instant::now());
    assert!(s.is_in_grace_window(5));
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
