//! Smoke test that confirms `nix` is available as a runtime dependency
//! with all features required by the Stage 5 hook executor.

use nix::sys::signal::Signal;
use nix::sys::wait::WaitPidFlag;
use nix::unistd::Pid;

#[test]
fn nix_unistd_pid_compiles() {
    // Just checking that we can name a Pid value.
    let pid = Pid::from_raw(0);
    assert_eq!(pid.as_raw(), 0);
}

#[test]
fn nix_signal_enum_compiles() {
    // SIGTERM/SIGKILL must be available for hook timeout escalation.
    assert_eq!(Signal::SIGTERM as i32, libc::SIGTERM);
    assert_eq!(Signal::SIGKILL as i32, libc::SIGKILL);
}

#[test]
fn nix_wait_flags_compile() {
    // The executor uses WNOHANG for the deadline-polling waitpid loop.
    let flag = WaitPidFlag::WNOHANG;
    assert!(flag.contains(WaitPidFlag::WNOHANG));
}
