//! Bench tool: print the privileged-path verdict for the paths given to it.
//!
//! The trust walk decides whether a component of a path can be substituted by
//! someone the service does not trust. That verdict depends on descriptors that
//! only a real installation has — a stock volume root is owned by
//! `TrustedInstaller` and carries inherit-only templates that no hand-written
//! test fixture would think to include. This tool exists so the verdict can be
//! *observed* on such a machine instead of argued about.
//!
//! It is read-only: it opens nothing for writing, changes no permissions, and
//! creates no files. The worst it can do is read a security descriptor.
//!
//! Usage:
//!
//! ```text
//! tessera_path_check <path>...
//! ```
//!
//! Pass a whole chain to see exactly where trust breaks, since the walk reports
//! the first component it refuses:
//!
//! ```text
//! tessera_path_check C:\ C:\ProgramData C:\ProgramData\Tessera C:\ProgramData\Tessera\config.toml
//! ```
//!
//! Exit status is 0 only when every path given was accepted.

#![allow(clippy::print_stderr, clippy::print_stdout)]

use std::path::Path;
use std::process::ExitCode;

use tessera_core::privileged_path::{validate_directory, validate_file, ExecTrust, ValidatedPath};

fn main() -> ExitCode {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: tessera_path_check <path>...");
        eprintln!();
        eprintln!("Prints the privileged-path trust verdict for each path.");
        eprintln!("Reads security descriptors only; changes nothing.");
        return ExitCode::FAILURE;
    }

    let mut all_trusted = true;
    for arg in &paths {
        if !report(Path::new(arg)) {
            all_trusted = false;
        }
    }

    if all_trusted {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Print one path's verdict; return whether it was accepted.
fn report(path: &Path) -> bool {
    // The entry point is chosen the way real call sites choose it: the config
    // and the tags source are files, the role-store base is a directory. This
    // probe does not influence the verdict — it only picks which of the two
    // leaf-type requirements is asserted, and a path that vanishes between here
    // and the walk is refused by the walk itself.
    let as_directory = path.is_dir();
    let (entry_point, outcome): (&str, _) = if as_directory {
        (
            "validate_directory",
            validate_directory(path, ExecTrust::Root),
        )
    } else {
        ("validate_file", validate_file(path, ExecTrust::Root))
    };

    match outcome {
        Ok(validated) => {
            println!("TRUSTED  {}", path.display());
            print_detail(&validated, entry_point);
            true
        }
        Err(error) => {
            println!("REFUSED  {}", path.display());
            println!("         via {entry_point}");
            println!("         {error}");
            let mut source = std::error::Error::source(&error);
            while let Some(cause) = source {
                println!("         caused by: {cause}");
                source = std::error::Error::source(cause);
            }
            false
        }
    }
}

/// Print what a successful walk established, so a passing run is informative
/// rather than a bare "ok".
fn print_detail(validated: &ValidatedPath, entry_point: &str) {
    println!("         via {entry_point}");
    println!("         canonical: {}", validated.canonical().display());
}
