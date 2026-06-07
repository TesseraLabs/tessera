//! Hook executor abstraction.
//!
//! [`HookExecutor`] is the trait that abstracts how a validated [`HookConfig`]
//! actually runs. Stage 5 ships two implementations:
//!
//! * [`NoopExecutor`] — used by unit tests and as a stub on early flow paths;
//!   never spawns a subprocess and always returns canned outcomes.
//! * `ForkExecExecutor` (in a later task) — the real `fork`+`execve`
//!   implementation.
//!
//! [`apply_on_failure`] wraps a `Result<HookOutcome, HookError>` and the
//! hook's [`OnFailure`] policy and returns `Ok(())` / `Err(HookError)` for
//! the calling flow.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use crate::hooks::result::{HookError, HookOutcome};
use crate::hooks::stage::HookStage;
use crate::hooks::validator::{HookConfig, OnFailure};
use crate::hooks::vars::HookVars;

/// Abstraction over hook execution. The cdylib auth thread holds a
/// `&dyn HookExecutor` so production code can swap in `ForkExecExecutor` and
/// tests can swap in [`NoopExecutor`].
pub trait HookExecutor: Send + Sync {
    /// Run a hook to completion (or timeout).
    ///
    /// # Errors
    ///
    /// Returns [`HookError`] for any failure that prevented the hook from
    /// running or being reaped; see the variant-level docs there for the
    /// complete list. A non-zero exit code or a timeout are returned **as
    /// part of the `Ok(HookOutcome)`** — apply [`apply_on_failure`] to map
    /// those to errors per the configured policy.
    fn execute(&self, hook: &HookConfig, vars: &HookVars) -> Result<HookOutcome, HookError>;
}

/// Executor that records every call but never spawns. Returns canned
/// outcomes from a `VecDeque`; once empty, falls back to a default success
/// outcome.
pub struct NoopExecutor {
    state: Mutex<NoopState>,
}

struct NoopState {
    outcomes: VecDeque<Result<HookOutcome, HookError>>,
    calls: Vec<(HookStage, Vec<String>)>,
}

impl NoopExecutor {
    /// Construct an executor that always returns success outcomes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(NoopState {
                outcomes: VecDeque::new(),
                calls: Vec::new(),
            }),
        }
    }

    /// Construct an executor that returns `outcome` for the next `execute()`
    /// call.
    #[must_use]
    pub fn with_outcome(outcome: HookOutcome) -> Self {
        let mut q = VecDeque::with_capacity(1);
        q.push_back(Ok(outcome));
        Self {
            state: Mutex::new(NoopState {
                outcomes: q,
                calls: Vec::new(),
            }),
        }
    }

    /// Construct an executor with a sequence of outcomes/errors. The k-th
    /// call returns the k-th element; when the queue is empty, a default
    /// success outcome is returned.
    #[must_use]
    pub fn with_outcomes(outcomes: Vec<Result<HookOutcome, HookError>>) -> Self {
        Self {
            state: Mutex::new(NoopState {
                outcomes: outcomes.into(),
                calls: Vec::new(),
            }),
        }
    }

    /// Snapshot of the calls recorded so far, in order.
    pub fn calls(&self) -> Vec<(HookStage, Vec<String>)> {
        self.state
            .lock()
            .map(|g| g.calls.clone())
            .unwrap_or_default()
    }
}

impl Default for NoopExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl HookExecutor for NoopExecutor {
    fn execute(&self, hook: &HookConfig, _vars: &HookVars) -> Result<HookOutcome, HookError> {
        let mut guard = self.state.lock().map_err(|_| HookError::ChildSetup {
            message: "noop executor mutex poisoned".into(),
        })?;
        guard.calls.push((hook.stage, hook.command.clone()));
        match guard.outcomes.pop_front() {
            Some(r) => r,
            None => Ok(HookOutcome {
                stage: hook.stage,
                command: hook.command.clone(),
                exit_code: 0,
                killed_by_timeout: false,
                duration: Duration::ZERO,
                stdout_lines: 0,
                stderr_lines: 0,
            }),
        }
    }
}

/// Apply an [`OnFailure`] policy to the result of a hook execution.
///
/// | state                              | Abort           | Warn         | Ignore     |
/// |------------------------------------|-----------------|--------------|------------|
/// | `Ok` with `exit_code == 0`         | Ok              | Ok           | Ok         |
/// | `Ok` with `exit_code != 0`         | `NonZeroExit`   | Ok (logged)  | Ok         |
/// | `Ok` with `killed_by_timeout`      | `Timeout`       | `Timeout`    | Ok (logged)|
/// | `Err(HookError)`                   | `Err(passthrough)` | Ok (logged) | Ok (logged) |
///
/// Note: a timeout under `Warn` still errors, because parent-side `SIGKILL`
/// is *structural* — the hook didn't get to choose its exit.
///
/// # Errors
///
/// See the matrix above; this never adds new failure modes beyond what the
/// inputs describe.
pub fn apply_on_failure(
    outcome: Result<HookOutcome, HookError>,
    on_failure: OnFailure,
) -> Result<(), HookError> {
    match (outcome, on_failure) {
        // Success path: always Ok.
        (Ok(o), _) if o.exit_code == 0 && !o.killed_by_timeout => Ok(()),

        // Timeout: always errors, except Ignore.
        (Ok(o), OnFailure::Ignore) if o.killed_by_timeout => {
            tracing::debug!(
                target: "tessera.hook.timeout",
                stage = %o.stage,
                duration_ms = o.duration.as_millis(),
                "hook timeout suppressed by on_failure=ignore",
            );
            Ok(())
        }
        (Ok(o), _) if o.killed_by_timeout => Err(HookError::Timeout {
            timeout_ms: u64::try_from(o.duration.as_millis()).unwrap_or(u64::MAX),
        }),

        // Non-zero exit, not timed out.
        (Ok(o), OnFailure::Abort) => Err(HookError::NonZeroExit {
            exit_code: o.exit_code,
        }),
        (Ok(o), OnFailure::Warn) => {
            tracing::warn!(
                target: "tessera.hook.failed",
                stage = %o.stage,
                exit_code = o.exit_code,
                "hook exited non-zero (on_failure=warn)",
            );
            Ok(())
        }
        (Ok(o), OnFailure::Ignore) => {
            tracing::debug!(
                target: "tessera.hook.failed",
                stage = %o.stage,
                exit_code = o.exit_code,
                "hook exited non-zero (on_failure=ignore)",
            );
            Ok(())
        }

        // Executor-level errors.
        (Err(e), OnFailure::Abort) => Err(e),
        (Err(e), OnFailure::Warn) => {
            tracing::warn!(
                target: "tessera.hook.failed",
                error = %e,
                "hook executor error (on_failure=warn)",
            );
            Ok(())
        }
        (Err(e), OnFailure::Ignore) => {
            tracing::debug!(
                target: "tessera.hook.failed",
                error = %e,
                "hook executor error (on_failure=ignore)",
            );
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::hooks::placeholder::Template;
    use std::collections::BTreeMap;

    fn dummy_hook(stage: HookStage) -> HookConfig {
        HookConfig {
            stage,
            command: vec!["/bin/true".into()],
            timeout: Duration::from_secs(5),
            on_failure: OnFailure::Abort,
            run_as: crate::hooks::validator::RunAs::Root,
            env: BTreeMap::<String, Template>::new(),
        }
    }

    fn ok_outcome(stage: HookStage, code: i32, killed: bool) -> HookOutcome {
        HookOutcome {
            stage,
            command: vec!["/bin/true".into()],
            exit_code: code,
            killed_by_timeout: killed,
            duration: Duration::from_millis(123),
            stdout_lines: 0,
            stderr_lines: 0,
        }
    }

    #[test]
    fn noop_default_returns_zero_exit() {
        let exec = NoopExecutor::new();
        let hook = dummy_hook(HookStage::PreAuth);
        let out = exec
            .execute(&hook, &HookVars::empty())
            .expect("noop never errors by default");
        assert_eq!(out.exit_code, 0);
        assert!(!out.killed_by_timeout);
        assert_eq!(out.command, vec!["/bin/true".to_string()]);
    }

    #[test]
    fn noop_records_calls() {
        let exec = NoopExecutor::new();
        let h1 = dummy_hook(HookStage::PreAuth);
        let h2 = dummy_hook(HookStage::SessionOpen);
        let _ = exec.execute(&h1, &HookVars::empty()).unwrap();
        let _ = exec.execute(&h2, &HookVars::empty()).unwrap();
        let calls = exec.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, HookStage::PreAuth);
        assert_eq!(calls[1].0, HookStage::SessionOpen);
    }

    #[test]
    fn noop_with_outcome_returns_canned() {
        let canned = ok_outcome(HookStage::PreAuth, 7, false);
        let exec = NoopExecutor::with_outcome(canned.clone());
        let hook = dummy_hook(HookStage::PreAuth);
        let out = exec.execute(&hook, &HookVars::empty()).unwrap();
        assert_eq!(out.exit_code, 7);
    }

    #[test]
    fn noop_with_outcomes_drains_in_order_then_default() {
        let exec = NoopExecutor::with_outcomes(vec![
            Ok(ok_outcome(HookStage::PreAuth, 1, false)),
            Err(HookError::CommandUnusable { path: "/x".into() }),
        ]);
        let hook = dummy_hook(HookStage::PreAuth);
        let r1 = exec.execute(&hook, &HookVars::empty()).unwrap();
        assert_eq!(r1.exit_code, 1);
        let r2 = exec.execute(&hook, &HookVars::empty());
        assert!(matches!(r2, Err(HookError::CommandUnusable { .. })));
        // After draining: default success.
        let r3 = exec.execute(&hook, &HookVars::empty()).unwrap();
        assert_eq!(r3.exit_code, 0);
    }

    // apply_on_failure: 9-cell matrix coverage.
    #[test]
    fn afp_ok0_abort_ok() {
        assert!(apply_on_failure(
            Ok(ok_outcome(HookStage::PreAuth, 0, false)),
            OnFailure::Abort
        )
        .is_ok());
    }

    #[test]
    fn afp_ok0_warn_ok() {
        assert!(apply_on_failure(
            Ok(ok_outcome(HookStage::PreAuth, 0, false)),
            OnFailure::Warn
        )
        .is_ok());
    }

    #[test]
    fn afp_ok0_ignore_ok() {
        assert!(apply_on_failure(
            Ok(ok_outcome(HookStage::PreAuth, 0, false)),
            OnFailure::Ignore
        )
        .is_ok());
    }

    #[test]
    fn afp_oknonzero_abort_err() {
        let r = apply_on_failure(
            Ok(ok_outcome(HookStage::PreAuth, 7, false)),
            OnFailure::Abort,
        );
        assert!(matches!(r, Err(HookError::NonZeroExit { exit_code: 7 })));
    }

    #[test]
    fn afp_oknonzero_warn_ok() {
        assert!(apply_on_failure(
            Ok(ok_outcome(HookStage::PreAuth, 7, false)),
            OnFailure::Warn
        )
        .is_ok());
    }

    #[test]
    fn afp_oknonzero_ignore_ok() {
        assert!(apply_on_failure(
            Ok(ok_outcome(HookStage::PreAuth, 7, false)),
            OnFailure::Ignore
        )
        .is_ok());
    }

    #[test]
    fn afp_timeout_abort_err() {
        let r = apply_on_failure(
            Ok(ok_outcome(HookStage::PreAuth, 137, true)),
            OnFailure::Abort,
        );
        assert!(matches!(r, Err(HookError::Timeout { .. })));
    }

    #[test]
    fn afp_timeout_warn_err() {
        // Timeout is structural — warn still errors.
        let r = apply_on_failure(
            Ok(ok_outcome(HookStage::PreAuth, 137, true)),
            OnFailure::Warn,
        );
        assert!(matches!(r, Err(HookError::Timeout { .. })));
    }

    #[test]
    fn afp_timeout_ignore_ok() {
        assert!(apply_on_failure(
            Ok(ok_outcome(HookStage::PreAuth, 137, true)),
            OnFailure::Ignore
        )
        .is_ok());
    }

    #[test]
    fn afp_err_abort_passes_through() {
        let r = apply_on_failure(
            Err(HookError::CommandUnusable { path: "/x".into() }),
            OnFailure::Abort,
        );
        assert!(matches!(r, Err(HookError::CommandUnusable { .. })));
    }

    #[test]
    fn afp_err_warn_ok() {
        let r = apply_on_failure(
            Err(HookError::CommandUnusable { path: "/x".into() }),
            OnFailure::Warn,
        );
        assert!(r.is_ok());
    }

    #[test]
    fn afp_err_ignore_ok() {
        let r = apply_on_failure(
            Err(HookError::CommandUnusable { path: "/x".into() }),
            OnFailure::Ignore,
        );
        assert!(r.is_ok());
    }
}
