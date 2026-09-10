//! Writing to an overlay that has gone must return an error, not kill us.
//!
//! # Why this is a binary of its own
//!
//! The test has to put `SIGPIPE` back to its default disposition, and a
//! disposition is a property of the whole process. In the library's own test
//! binary that would change the ground under every other test — and they run in
//! threads of one process — so this lives alone and does nothing else.
//!
//! # Why the default disposition is the honest setting
//!
//! Every Rust program starts with `SIGPIPE` ignored, because the runtime sets
//! it aside before `main`. `pam_tessera` is a cdylib loaded with `dlopen` into
//! `sshd`, `login` or a display manager: that start-up never runs, and the
//! module inherits whatever the host left. `sshd` ignores the signal; a display
//! manager is under no obligation to, and a display manager is the only thing
//! that raises the overlay. A test that kept the Rust default would be a test
//! of the harness rather than of the module — it would pass with the guard
//! removed, which is the whole failure being guarded against.
//!
//! # What it does not cover
//!
//! Only platforms whose `send(2)` carries `MSG_NOSIGNAL` are exercised, which
//! is every platform the product ships to and not a developer's macOS. The live
//! path — a display manager whose disposition is default, an overlay that exits
//! on a missing display — is a stand case; see `tests/e2e/BASELINE.md`.

#![cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "solaris"
))]
#![allow(clippy::expect_used)]

use std::os::unix::net::UnixStream;

use pam_tessera::overlay::send_frame;

/// Puts `SIGPIPE` back to what a process that never ran Rust's start-up has.
fn restore_default_sigpipe() {
    // SAFETY: changing a signal disposition is unsafe because it affects the
    // whole process; this binary holds one test and does nothing else, so there
    // is no other code here whose assumptions could be broken.
    unsafe {
        nix::sys::signal::signal(
            nix::sys::signal::Signal::SIGPIPE,
            nix::sys::signal::SigHandler::SigDfl,
        )
    }
    .expect("SIGPIPE could not be put back to its default");
}

#[test]
fn a_frame_written_to_an_overlay_that_left_is_an_error_and_not_a_dead_process() {
    restore_default_sigpipe();

    let (module_side, overlay_side) = UnixStream::pair().expect("a pair of sockets");
    // The overlay exits between the module's accept and the module's first
    // byte: it connects to the socket before it opens the display, so a wrong
    // cookie or a dead X server ends it exactly here.
    drop(overlay_side);

    // Reaching the assertion at all is most of the result. Without the guard
    // the process dies on this line and the harness reports a signal, which is
    // what the module dying inside a display manager looks like.
    let refused = send_frame(&module_side, b"a frame the peer will never read")
        .expect_err("a write to a socket with no peer must not succeed");

    assert_eq!(
        refused.kind(),
        std::io::ErrorKind::BrokenPipe,
        "the write failed for some other reason: {refused}"
    );
}
