//! `tessera` entry point.
//!
//! Thin clap dispatcher: every subcommand's lifecycle lives in its own
//! library module (see `tessera_cli::daemon` for the monitor daemon).

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use tessera_cli::check::{self, CheckArgs};
use tessera_cli::daemon::{self, DaemonArgs};
use tessera_cli::dump_host_id::{self, DumpHostIdArgs};

#[derive(Debug, Parser)]
#[command(name = "tessera", version, about = "Tessera control plane")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Run the monitor daemon (USB / logind enforcement, IPC server).
    Daemon(DaemonArgs),
    /// Run the startup validation checks against `config.toml` without
    /// starting the daemon. Exits 0 when every check is INFO/WARN, exits
    /// 1 when at least one check reports ERROR. Intended as a preflight
    /// before `systemctl restart tessera`.
    Check(CheckArgs),
    /// Probe every `[host_identity]` source and emit a TSV report of the
    /// resulting `host_id_hash` values. Use on freshly cloned ATM images
    /// to learn which host_id the daemon will resolve so the CA admin can
    /// issue a per-host service cert. Output destinations: `--output PATH`,
    /// `--usb` (writes to first viable USB partition), or stdout.
    DumpHostId(DumpHostIdArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Daemon(args) => daemon::run(args),
        Cmd::Check(args) => check::run(args),
        Cmd::DumpHostId(args) => dump_host_id::run_cli(args),
    }
}
