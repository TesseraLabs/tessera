//! Hook support.

pub mod child_setup;
pub mod env;
pub mod executor;
pub mod fork_exec;
pub mod pipe_reader;
pub mod placeholder;
pub mod result;
pub mod rlimit;
pub mod runner;
pub mod stage;
pub mod user;
pub mod validator;
pub mod vars;
pub mod wait;

pub use env::build_env_vector;
pub use executor::{apply_on_failure, HookExecutor, NoopExecutor};
pub use fork_exec::ForkExecExecutor;
pub use pipe_reader::{PipeReader, PipeStream};
pub use placeholder::{PlaceholderVar, Template, TemplatePart};
pub use result::{HookError, HookOutcome};
pub use rlimit::{apply_caps, default_caps_for_timeout, RlimitCaps};
pub use runner::{count_for_stage, run_hooks_for_stage};
pub use stage::HookStage;
pub use user::{lookup_user, UserInfo};
pub use validator::{is_var_allowed, validate_hook, HookConfig, OnFailure, RunAs};
pub use vars::HookVars;
pub use wait::{wait_with_timeout, ExitStatus, WaitOutcome};
