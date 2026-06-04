#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]

use tessera_cli::notify::{notify_ready, NotifyHandle};

#[test]
fn notify_ready_is_idempotent_in_test_recorder() {
    let mut h = NotifyHandle::test_recorder();
    notify_ready(&mut h);
    notify_ready(&mut h);
    assert_eq!(
        h.calls(),
        1,
        "must be recorded once due to internal `sent` flag"
    );
}

#[test]
fn notify_ready_fallback_does_not_panic_outside_systemd() {
    let mut h = NotifyHandle::system_default();
    notify_ready(&mut h); // must not panic even without NOTIFY_SOCKET
}
