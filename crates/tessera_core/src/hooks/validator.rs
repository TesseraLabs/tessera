//! Hook validation.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use crate::config::raw::RawHook;
use crate::error::HookValidationError;
use crate::hooks::{HookStage, PlaceholderVar, Template, TemplatePart};

/// Validated hook.
#[derive(Debug, Clone)]
pub struct HookConfig {
    /// Stage.
    pub stage: HookStage,
    /// Command argv.
    pub command: Vec<String>,
    /// Timeout.
    pub timeout: Duration,
    /// Failure behavior.
    pub on_failure: OnFailure,
    /// Run-as behavior.
    pub run_as: RunAs,
    /// Environment templates.
    pub env: BTreeMap<String, Template>,
}

/// Failure behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnFailure {
    /// Abort.
    Abort,
    /// Warn.
    Warn,
    /// Ignore.
    Ignore,
}

/// Run-as behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunAs {
    /// Root.
    Root,
    /// User.
    User,
}

/// Return whether a placeholder is valid at a stage.
pub const fn is_var_allowed(stage: HookStage, var: PlaceholderVar) -> bool {
    match stage {
        HookStage::PreAuth => matches!(
            var,
            PlaceholderVar::PamUser
                | PlaceholderVar::PamService
                | PlaceholderVar::HostId
                | PlaceholderVar::HostIdHash
                | PlaceholderVar::HostIdSource
        ),
        HookStage::PostAuthSuccess
        | HookStage::SessionOpen
        | HookStage::SessionClose
        | HookStage::UsbRemoved => true,
    }
}

/// Validate a raw hook.
pub fn validate_hook(raw: &RawHook) -> Result<HookConfig, HookValidationError> {
    let Some(first) = raw.command.first() else {
        return Err(HookValidationError::EmptyCommand);
    };
    if !Path::new(first).is_absolute() {
        return Err(HookValidationError::InvalidCommandPath {
            path: first.clone(),
        });
    }
    if raw.timeout_seconds == 0 || raw.timeout_seconds > 120 {
        return Err(HookValidationError::InvalidTimeout);
    }
    let mut env = BTreeMap::new();
    for (key, value) in &raw.env {
        let template = Template::parse(value).map_err(|e| HookValidationError::Template {
            reason: e.to_string(),
        })?;
        for part in template.parts() {
            if let TemplatePart::Var(var) = part {
                if !is_var_allowed(raw.stage, *var) {
                    return Err(HookValidationError::PlaceholderNotAllowedAtStage {
                        stage: raw.stage,
                        var: *var,
                    });
                }
            }
        }
        env.insert(key.clone(), template);
    }
    Ok(HookConfig {
        stage: raw.stage,
        command: raw.command.clone(),
        timeout: Duration::from_secs(raw.timeout_seconds),
        on_failure: parse_failure(raw.on_failure.as_deref(), raw.stage),
        run_as: parse_run_as(raw.run_as.as_deref())?,
        env,
    })
}

/// Map the configured `run_as` string to a concrete [`RunAs`], rejecting any
/// value the module cannot map to a known privilege.
///
/// `run_as` sits on a root execution boundary: an unrecognized value must never
/// default to root, or a typo (or an account name the module does not resolve)
/// would silently amplify a hook to root. Only two values are accepted —
/// `root` (also the default when unset) and `user`/`pam_user` (the
/// authenticating PAM user). Everything else is a configuration error.
fn parse_run_as(value: Option<&str>) -> Result<RunAs, HookValidationError> {
    match value {
        None | Some("root") => Ok(RunAs::Root),
        Some("user" | "pam_user") => Ok(RunAs::User),
        Some(other) => Err(HookValidationError::InvalidRunAs {
            value: other.to_string(),
        }),
    }
}

fn parse_failure(value: Option<&str>, stage: HookStage) -> OnFailure {
    match value {
        Some("warn") | None if !matches!(stage, HookStage::PreAuth) => OnFailure::Warn,
        Some("ignore") => OnFailure::Ignore,
        _ => OnFailure::Abort,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::raw::RawHook;

    fn raw_hook_with_run_as(run_as: Option<&str>) -> RawHook {
        RawHook {
            stage: HookStage::PostAuthSuccess,
            command: vec!["/usr/local/sbin/hook".to_string()],
            timeout_seconds: 5,
            on_failure: None,
            run_as: run_as.map(str::to_string),
            env: BTreeMap::new(),
        }
    }

    #[test]
    fn run_as_defaults_to_root_when_unset() {
        let cfg = validate_hook(&raw_hook_with_run_as(None)).expect("valid");
        assert_eq!(cfg.run_as, RunAs::Root);
    }

    #[test]
    fn run_as_root_and_user_are_accepted() {
        assert_eq!(
            validate_hook(&raw_hook_with_run_as(Some("root")))
                .expect("root")
                .run_as,
            RunAs::Root
        );
        assert_eq!(
            validate_hook(&raw_hook_with_run_as(Some("user")))
                .expect("user")
                .run_as,
            RunAs::User
        );
        assert_eq!(
            validate_hook(&raw_hook_with_run_as(Some("pam_user")))
                .expect("pam_user")
                .run_as,
            RunAs::User
        );
    }

    /// A documented-but-unsupported account name (or a typo) must be a hard
    /// config error, never a silent fall-through to root.
    #[test]
    fn unknown_run_as_is_rejected_not_silently_root() {
        for value in ["audit", "nobody", "roo", "User", ""] {
            let err = validate_hook(&raw_hook_with_run_as(Some(value)))
                .expect_err("unknown run_as must be rejected");
            assert!(
                matches!(err, HookValidationError::InvalidRunAs { value: ref v } if v == value),
                "expected InvalidRunAs for {value:?}, got {err:?}"
            );
        }
    }
}
