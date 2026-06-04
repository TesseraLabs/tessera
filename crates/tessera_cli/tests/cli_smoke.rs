//! Smoke test for the clap subcommand skeleton.
//!
//! Locks in the public CLI shape used by the systemd unit and operator
//! tooling: `tessera daemon --help` must succeed and advertise the
//! daemon subcommand. Future subcommands (`execute`, `policy`, …) will
//! extend this test.

#![allow(clippy::expect_used)]

use std::process::Command;

#[test]
fn binary_has_daemon_subcommand_help() {
    let out = Command::new(env!("CARGO_BIN_EXE_tessera"))
        .args(["daemon", "--help"])
        .output()
        .expect("run tessera daemon --help");
    assert!(out.status.success(), "daemon --help failed: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Run the monitor daemon"),
        "help text mismatch:\n{stdout}"
    );
}

#[test]
fn binary_has_check_subcommand_help() {
    let out = Command::new(env!("CARGO_BIN_EXE_tessera"))
        .args(["check", "--help"])
        .output()
        .expect("run tessera check --help");
    assert!(out.status.success(), "check --help failed: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("startup validation checks"),
        "help text mismatch:\n{stdout}"
    );
}
