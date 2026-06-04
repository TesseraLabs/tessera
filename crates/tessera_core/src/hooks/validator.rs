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
        run_as: match raw.run_as.as_deref() {
            Some("user") => RunAs::User,
            _ => RunAs::Root,
        },
        env,
    })
}

fn parse_failure(value: Option<&str>, stage: HookStage) -> OnFailure {
    match value {
        Some("warn") | None if !matches!(stage, HookStage::PreAuth) => OnFailure::Warn,
        Some("ignore") => OnFailure::Ignore,
        _ => OnFailure::Abort,
    }
}
