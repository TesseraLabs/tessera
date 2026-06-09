//! Hook runner — bridges a [`crate::config::ValidatedConfig`], a
//! [`HookStage`], and a [`HookExecutor`] into a single sequenced run.
//!
//! Invoked by the cdylib at the four PAM stages where Stage 5 hooks fire:
//!
//! * `pre_auth` — before USB-wait / token-wait
//! * `post_auth_success` — after cert verification, before `set_pam_data`
//! * `session_open` — at `pam_sm_open_session`
//! * `session_close` — at `pam_sm_close_session`
//!
//! The runner walks the config's hook list in declaration order, executes
//! every hook whose `stage` matches, and applies the per-hook
//! [`crate::hooks::OnFailure`] policy via [`crate::hooks::apply_on_failure`].
//! On the first error returned by `apply_on_failure`, the runner returns
//! immediately and skips any remaining hooks at the same stage.

use crate::config::ValidatedConfig;
use crate::hooks::executor::{apply_on_failure, HookExecutor};
use crate::hooks::result::HookError;
use crate::hooks::stage::HookStage;
use crate::hooks::vars::HookVars;

/// Run every hook configured for `stage` in declaration order.
///
/// Each hook is dispatched through `executor`. After it returns, the hook's
/// own `on_failure` policy (`Abort`/`Warn`/`Ignore`) decides whether to
/// short-circuit the loop. See [`apply_on_failure`] for the policy table.
///
/// # Errors
///
/// Returns the first [`HookError`] the policy mapper produces. If every hook
/// returns success or a tolerated failure, this returns `Ok(())`.
pub fn run_hooks_for_stage(
    cfg: &ValidatedConfig,
    stage: HookStage,
    executor: &dyn HookExecutor,
    vars: &HookVars,
) -> Result<(), HookError> {
    for hook in cfg.hooks.iter().filter(|h| h.stage == stage) {
        let outcome = executor.execute(hook, vars);
        apply_on_failure(outcome, hook.on_failure)?;
    }
    Ok(())
}

/// Number of hooks configured for `stage`.
#[must_use]
pub fn count_for_stage(cfg: &ValidatedConfig, stage: HookStage) -> usize {
    cfg.hooks.iter().filter(|h| h.stage == stage).count()
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
    use crate::hooks::result::HookOutcome;
    use crate::hooks::validator::{HookConfig, OnFailure, RunAs};
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::time::Duration;

    /// Test executor that returns scripted results in order and records
    /// every call.
    struct MockExecutor {
        results: Mutex<std::collections::VecDeque<Result<HookOutcome, HookError>>>,
        calls: Mutex<Vec<(HookStage, Vec<String>)>>,
    }

    impl MockExecutor {
        fn new(results: Vec<Result<HookOutcome, HookError>>) -> Self {
            Self {
                results: Mutex::new(results.into()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(HookStage, Vec<String>)> {
            self.calls.lock().map(|g| g.clone()).unwrap_or_default()
        }
    }

    impl HookExecutor for MockExecutor {
        fn execute(&self, hook: &HookConfig, _vars: &HookVars) -> Result<HookOutcome, HookError> {
            let mut calls = self.calls.lock().unwrap();
            calls.push((hook.stage, hook.command.clone()));
            drop(calls);
            let mut results = self.results.lock().unwrap();
            match results.pop_front() {
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

    fn ok_outcome(stage: HookStage) -> HookOutcome {
        HookOutcome {
            stage,
            command: vec!["/bin/true".into()],
            exit_code: 0,
            killed_by_timeout: false,
            duration: Duration::from_millis(1),
            stdout_lines: 0,
            stderr_lines: 0,
        }
    }

    fn nonzero_outcome(stage: HookStage, code: i32) -> HookOutcome {
        HookOutcome {
            stage,
            command: vec!["/bin/false".into()],
            exit_code: code,
            killed_by_timeout: false,
            duration: Duration::from_millis(1),
            stdout_lines: 0,
            stderr_lines: 0,
        }
    }

    fn dummy_hook(stage: HookStage, on_failure: OnFailure, command: &str) -> HookConfig {
        HookConfig {
            stage,
            command: vec![command.into()],
            timeout: Duration::from_secs(5),
            on_failure,
            run_as: RunAs::Root,
            env: BTreeMap::<String, Template>::new(),
        }
    }

    /// Build a minimal `ValidatedConfig` with the given hook list.  We
    /// reuse the toml fast path used by `flow.rs` tests and overwrite the
    /// `hooks` field after parsing.
    fn cfg_with_hooks(hooks: Vec<HookConfig>) -> ValidatedConfig {
        // Config validation rejects empty `[trust].anchors`, so point at a
        // real PEM fixture.
        let anchor = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ca.pem");
        let raw_toml = r#"
crypto_backend = "openssl"
mode = "pkcs12"
pkcs12_path_pattern = "certs/user.p12"
pkcs12_pin_prompt = "PIN: "
usb_wait_seconds = 5
on_usb_removed = "lock"
usb_removed_grace_seconds = 5
suspend_grace_seconds = 30
monitor_fail_mode = "permissive"

[trust]
anchors = [@ANCHOR@]
intermediates = []
allowed_signature_algorithms = []
max_chain_depth = 4
clock_skew_seconds = 60

[trust.revocation]
mode = "none"
crl_paths = []

[trust.pinning]
enabled = false
allowed_root_spki_sha256 = []

[host_identity]
sources = ["override"]
fallback = "deny"
override = "host-T"
custom_command_timeout_seconds = 5

[logging]
level = "info"
syslog_facility = "auth"
journald_priority = false
"#;
        let raw_toml =
            raw_toml.replace("@ANCHOR@", &format!("{:?}", anchor.to_string_lossy()));
        let raw: crate::config::raw::RawConfig = toml::from_str(&raw_toml).unwrap();
        let mut cfg = ValidatedConfig::try_from(&raw).unwrap();
        cfg.hooks = hooks;
        cfg
    }

    #[test]
    fn empty_hooks_list_returns_ok_without_executing() {
        let cfg = cfg_with_hooks(Vec::new());
        let exec = MockExecutor::new(Vec::new());
        let vars = HookVars::empty();

        let r = run_hooks_for_stage(&cfg, HookStage::PreAuth, &exec, &vars);

        assert!(r.is_ok());
        assert!(exec.calls().is_empty());
    }

    #[test]
    fn count_for_stage_returns_correct_number() {
        let cfg = cfg_with_hooks(vec![
            dummy_hook(HookStage::PreAuth, OnFailure::Abort, "/h1"),
            dummy_hook(HookStage::PreAuth, OnFailure::Warn, "/h2"),
            dummy_hook(HookStage::SessionOpen, OnFailure::Warn, "/h3"),
        ]);

        assert_eq!(count_for_stage(&cfg, HookStage::PreAuth), 2);
        assert_eq!(count_for_stage(&cfg, HookStage::SessionOpen), 1);
        assert_eq!(count_for_stage(&cfg, HookStage::PostAuthSuccess), 0);
    }

    #[test]
    fn multiple_hooks_for_one_stage_all_run_in_order() {
        let cfg = cfg_with_hooks(vec![
            dummy_hook(HookStage::PreAuth, OnFailure::Abort, "/first"),
            dummy_hook(HookStage::PreAuth, OnFailure::Abort, "/second"),
            dummy_hook(HookStage::PreAuth, OnFailure::Abort, "/third"),
        ]);
        let exec = MockExecutor::new(vec![
            Ok(ok_outcome(HookStage::PreAuth)),
            Ok(ok_outcome(HookStage::PreAuth)),
            Ok(ok_outcome(HookStage::PreAuth)),
        ]);

        run_hooks_for_stage(&cfg, HookStage::PreAuth, &exec, &HookVars::empty()).unwrap();

        let calls = exec.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].1, vec!["/first".to_string()]);
        assert_eq!(calls[1].1, vec!["/second".to_string()]);
        assert_eq!(calls[2].1, vec!["/third".to_string()]);
    }

    #[test]
    fn abort_on_first_nonzero_exit_skips_subsequent_hooks() {
        let cfg = cfg_with_hooks(vec![
            dummy_hook(HookStage::PreAuth, OnFailure::Abort, "/first"),
            dummy_hook(HookStage::PreAuth, OnFailure::Abort, "/second"),
        ]);
        let exec = MockExecutor::new(vec![Ok(nonzero_outcome(HookStage::PreAuth, 5))]);

        let r = run_hooks_for_stage(&cfg, HookStage::PreAuth, &exec, &HookVars::empty());

        assert!(matches!(r, Err(HookError::NonZeroExit { exit_code: 5 })));
        // Only the first hook ran — second was skipped after Abort.
        let calls = exec.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, vec!["/first".to_string()]);
    }

    #[test]
    fn warn_continues_after_nonzero_exit() {
        let cfg = cfg_with_hooks(vec![
            dummy_hook(HookStage::PreAuth, OnFailure::Warn, "/first"),
            dummy_hook(HookStage::PreAuth, OnFailure::Abort, "/second"),
        ]);
        let exec = MockExecutor::new(vec![
            Ok(nonzero_outcome(HookStage::PreAuth, 5)),
            Ok(ok_outcome(HookStage::PreAuth)),
        ]);

        let r = run_hooks_for_stage(&cfg, HookStage::PreAuth, &exec, &HookVars::empty());

        assert!(r.is_ok());
        assert_eq!(exec.calls().len(), 2);
    }

    #[test]
    fn ignore_continues_after_executor_error() {
        let cfg = cfg_with_hooks(vec![
            dummy_hook(HookStage::PreAuth, OnFailure::Ignore, "/first"),
            dummy_hook(HookStage::PreAuth, OnFailure::Abort, "/second"),
        ]);
        let exec = MockExecutor::new(vec![
            Err(HookError::CommandUnusable { path: "/x".into() }),
            Ok(ok_outcome(HookStage::PreAuth)),
        ]);

        let r = run_hooks_for_stage(&cfg, HookStage::PreAuth, &exec, &HookVars::empty());

        assert!(r.is_ok());
        assert_eq!(exec.calls().len(), 2);
    }

    #[test]
    fn only_hooks_for_requested_stage_are_executed() {
        let cfg = cfg_with_hooks(vec![
            dummy_hook(HookStage::PreAuth, OnFailure::Abort, "/pre1"),
            dummy_hook(HookStage::SessionOpen, OnFailure::Abort, "/open1"),
            dummy_hook(HookStage::SessionClose, OnFailure::Abort, "/close1"),
            dummy_hook(HookStage::PreAuth, OnFailure::Abort, "/pre2"),
        ]);
        let exec = MockExecutor::new(Vec::new());

        run_hooks_for_stage(&cfg, HookStage::PreAuth, &exec, &HookVars::empty()).unwrap();

        let calls = exec.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].1, vec!["/pre1".to_string()]);
        assert_eq!(calls[1].1, vec!["/pre2".to_string()]);
    }

    #[test]
    fn session_open_iter_uses_session_open_stage_only() {
        let cfg = cfg_with_hooks(vec![
            dummy_hook(HookStage::SessionOpen, OnFailure::Abort, "/open"),
            dummy_hook(HookStage::SessionClose, OnFailure::Abort, "/close"),
        ]);
        let exec = MockExecutor::new(Vec::new());

        run_hooks_for_stage(&cfg, HookStage::SessionOpen, &exec, &HookVars::empty()).unwrap();

        let calls = exec.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, HookStage::SessionOpen);
        assert_eq!(calls[0].1, vec!["/open".to_string()]);
    }
}
