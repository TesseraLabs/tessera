//! `tessera check` subcommand.
//!
//! Loads + validates the config file, runs the same
//! [`crate::startup_check::run_startup_checks`] pipeline as the daemon, and
//! prints a coloured/prefixed summary to stdout. Returns exit code 0 iff
//! no record reached `Error` severity — wrapping it in a systemd
//! `ExecStartPre=` slot turns the preflight into a hard gate.
//!
//! Does NOT open any socket, contact monitord, or start the IPC server.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;

use crate::startup_check::{run_startup_checks, StartupCheckOptions, StartupCheckSeverity};

/// CLI arguments for `tessera check`.
#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Path to `config.toml`. Defaults to `/etc/tessera/config.toml`,
    /// matching the daemon's default so a bare `tessera check` covers
    /// the production layout.
    #[arg(long, default_value = "/etc/tessera/config.toml")]
    pub config: PathBuf,
}

/// Run the subcommand and turn the report into an exit code.
///
/// Takes `CheckArgs` by value to mirror [`crate::daemon::run`]'s signature
/// and keep `main.rs` dispatch symmetric across subcommands.
#[allow(clippy::needless_pass_by_value)]
pub fn run(args: CheckArgs) -> ExitCode {
    let validated = match tessera_core::config::load_validated_config(&args.config) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "ERROR: failed to load config {path}: {e}",
                path = args.config.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let opts = StartupCheckOptions::default();
    let report = run_startup_checks(&validated, &opts);

    let info = report.count(StartupCheckSeverity::Info);
    let warn = report.count(StartupCheckSeverity::Warn);
    let err = report.count(StartupCheckSeverity::Error);

    for r in &report.records {
        let prefix = match r.severity {
            StartupCheckSeverity::Info => "INFO ",
            StartupCheckSeverity::Warn => "WARN ",
            StartupCheckSeverity::Error => "ERROR",
        };
        println!(
            "[{prefix}] {check}: {msg}",
            check = r.check,
            msg = r.message
        );
    }
    println!("---");
    println!("summary: {info} info, {warn} warn, {err} error");
    if err == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
