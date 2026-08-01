//! Hook support.
//!
//! Configuration parsing, the executor trait, and the no-op executor are
//! portable. The executing half is built on `fork(2)`/`execve(2)`, POSIX user
//! lookup, `waitpid(2)` and resource limits, so it is compiled on Unix only;
//! on other platforms only [`NoopExecutor`] is available and hooks never run.

pub mod executor;
pub mod placeholder;
pub mod result;
pub mod runner;
pub mod stage;
pub mod validator;
pub mod vars;

#[cfg(unix)]
pub mod child_setup;
#[cfg(unix)]
pub mod env;
#[cfg(unix)]
pub mod fork_exec;
#[cfg(unix)]
pub mod pipe_reader;
#[cfg(unix)]
pub mod rlimit;
#[cfg(unix)]
pub mod user;
#[cfg(unix)]
pub mod wait;

pub use executor::{apply_on_failure, HookExecutor, NoopExecutor};
pub use placeholder::{PlaceholderVar, Template, TemplatePart};
pub use result::{HookError, HookOutcome};
pub use runner::{count_for_stage, run_hooks_for_stage};
pub use stage::HookStage;
pub use validator::{is_var_allowed, validate_hook, HookConfig, OnFailure, RunAs};
pub use vars::HookVars;

#[cfg(unix)]
pub use env::build_env_vector;
#[cfg(unix)]
pub use fork_exec::ForkExecExecutor;
#[cfg(unix)]
pub use pipe_reader::{PipeReader, PipeStream};
#[cfg(unix)]
pub use rlimit::{apply_caps, default_caps_for_timeout, RlimitCaps};
#[cfg(unix)]
pub use user::{lookup_user, UserInfo};
#[cfg(unix)]
pub use wait::{wait_with_timeout, ExitStatus, WaitOutcome};
