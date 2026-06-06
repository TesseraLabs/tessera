//! T13: integration tests for `ForkExecExecutor` — echo/exit/sleep/timeout/missing.
//!
//! These tests perform a real `fork`+`execve` from the test runner. macOS's
//! cargo-test sandbox can interact unpredictably with `fork()` (in particular
//! `setrlimit` of NPROC and `prctl(PR_SET_NO_NEW_PRIVS)` are unsupported),
//! so the whole file is gated to Linux builds.

#![cfg(target_os = "linux")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::items_after_statements,
    clippy::manual_let_else
)]

use std::collections::BTreeMap;
use std::time::Duration;

use tessera_core::hooks::{
    apply_on_failure, ForkExecExecutor, HookConfig, HookError, HookExecutor, HookStage, HookVars,
    OnFailure, RunAs,
};

fn make_hook(
    stage: HookStage,
    command: Vec<&str>,
    timeout_secs: u64,
    on_failure: OnFailure,
) -> HookConfig {
    HookConfig {
        stage,
        command: command.into_iter().map(String::from).collect(),
        timeout: Duration::from_secs(timeout_secs),
        on_failure,
        run_as: RunAs::Root,
        env: BTreeMap::new(),
    }
}

#[test]
fn echo_returns_zero_exit() {
    let executor = ForkExecExecutor::new();
    let hook = make_hook(
        HookStage::PreAuth,
        vec!["/bin/echo", "hello"],
        5,
        OnFailure::Abort,
    );
    let outcome = executor
        .execute(
            &hook,
            &HookVars::empty().with_pam_user("u").with_pam_service("s"),
        )
        .expect("execute echo");
    assert_eq!(outcome.exit_code, 0);
    assert!(!outcome.killed_by_timeout);
    assert!(
        outcome.stdout_lines >= 1,
        "stdout_lines = {}",
        outcome.stdout_lines
    );
}

#[test]
fn exit_code_propagates() {
    let executor = ForkExecExecutor::new();
    let hook = make_hook(
        HookStage::PreAuth,
        vec!["/bin/sh", "-c", "exit 7"],
        5,
        OnFailure::Abort,
    );
    let outcome = executor
        .execute(
            &hook,
            &HookVars::empty().with_pam_user("u").with_pam_service("s"),
        )
        .expect("execute sh");
    assert_eq!(outcome.exit_code, 7);
    assert!(!outcome.killed_by_timeout);
}

#[test]
fn timeout_kills_long_running_hook() {
    let executor = ForkExecExecutor::new();
    let hook = make_hook(
        HookStage::PreAuth,
        vec!["/bin/sleep", "30"],
        1,
        OnFailure::Abort,
    );
    let outcome = executor
        .execute(
            &hook,
            &HookVars::empty().with_pam_user("u").with_pam_service("s"),
        )
        .expect("execute sleep");
    assert!(outcome.killed_by_timeout);
    // 1s timeout + 2s grace + epsilon
    assert!(
        outcome.duration >= Duration::from_secs(1) && outcome.duration < Duration::from_secs(5),
        "duration = {:?}",
        outcome.duration
    );
}

#[test]
fn nonexistent_command_is_rejected_before_exec() {
    // The pre-exec security walk canonicalizes argv[0] before fork. A command
    // whose path (or any ancestor) does not exist cannot be canonicalized, so
    // the executor fails closed with CommandUnusable rather than forking and
    // letting execve surface a 127 exit. Rejecting an unresolvable hook path up
    // front is the intended fail-closed behavior.
    let executor = ForkExecExecutor::new();
    let hook = make_hook(
        HookStage::PreAuth,
        vec!["/no/such/binary/anywhere"],
        5,
        OnFailure::Abort,
    );
    let res = executor.execute(
        &hook,
        &HookVars::empty().with_pam_user("u").with_pam_service("s"),
    );
    assert!(
        matches!(res, Err(HookError::CommandUnusable { .. })),
        "unresolvable hook path must be rejected before exec, got {res:?}"
    );
}

#[test]
fn echo_with_no_args_returns_zero() {
    let executor = ForkExecExecutor::new();
    let hook = make_hook(HookStage::PreAuth, vec!["/bin/echo"], 5, OnFailure::Abort);
    let outcome = executor
        .execute(
            &hook,
            &HookVars::empty().with_pam_user("u").with_pam_service("s"),
        )
        .expect("execute echo");
    assert_eq!(outcome.exit_code, 0);
}

#[test]
fn on_failure_abort_maps_nonzero_to_err() {
    let executor = ForkExecExecutor::new();
    let hook = make_hook(
        HookStage::PreAuth,
        vec!["/bin/sh", "-c", "exit 2"],
        5,
        OnFailure::Abort,
    );
    let outcome = executor
        .execute(
            &hook,
            &HookVars::empty().with_pam_user("u").with_pam_service("s"),
        )
        .expect("execute sh");
    let r = apply_on_failure(Ok(outcome), OnFailure::Abort);
    assert!(matches!(r, Err(HookError::NonZeroExit { exit_code: 2 })));
}

#[test]
fn on_failure_warn_maps_nonzero_to_ok() {
    let executor = ForkExecExecutor::new();
    let hook = make_hook(
        HookStage::PreAuth,
        vec!["/bin/sh", "-c", "exit 2"],
        5,
        OnFailure::Warn,
    );
    let outcome = executor
        .execute(
            &hook,
            &HookVars::empty().with_pam_user("u").with_pam_service("s"),
        )
        .expect("execute sh");
    let r = apply_on_failure(Ok(outcome), OnFailure::Warn);
    assert!(r.is_ok());
}

#[test]
fn on_failure_ignore_maps_nonzero_to_ok() {
    let executor = ForkExecExecutor::new();
    let hook = make_hook(
        HookStage::PreAuth,
        vec!["/bin/sh", "-c", "exit 2"],
        5,
        OnFailure::Ignore,
    );
    let outcome = executor
        .execute(
            &hook,
            &HookVars::empty().with_pam_user("u").with_pam_service("s"),
        )
        .expect("execute sh");
    let r = apply_on_failure(Ok(outcome), OnFailure::Ignore);
    assert!(r.is_ok());
}
