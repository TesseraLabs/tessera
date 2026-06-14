//! `tessera role` subcommand: `lint` and `list` over a role base.
//!
//! `lint` validates every `*.toml` slice in the directory strictly and
//! reports per-slice OK/FAIL, exiting non-zero if *any* slice is invalid or
//! the base exceeds the role cap — it does NOT use the lenient store loader
//! (which skips bad slices), because lint's job is to surface every problem.
//!
//! `list` uses the lenient [`RoleStore`] loader and prints the roles that
//! would actually load (sorted), exiting 0.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Subcommand};

use tessera_core::role::store::{RoleStore, TrustMode, DEFAULT_ROLES_DIR, MAX_ROLES};
use tessera_core::role::{parse_slice, RoleOs};

/// CLI arguments for `tessera role`.
#[derive(Debug, Args)]
pub struct RoleArgs {
    /// The role operation to run.
    #[command(subcommand)]
    pub cmd: RoleCmd,
}

/// `tessera role` operations.
#[derive(Debug, Subcommand)]
pub enum RoleCmd {
    /// Strictly validate every slice in the directory; exit non-zero on any
    /// invalid slice or if the base exceeds the role cap.
    Lint(RoleLintArgs),
    /// List the roles that would load (lenient: bad slices are skipped).
    List(RoleListArgs),
}

/// Arguments for `role lint`.
#[derive(Debug, Args)]
pub struct RoleLintArgs {
    /// Role directory. Defaults to the production layout.
    #[arg(long, default_value = DEFAULT_ROLES_DIR)]
    pub dir: PathBuf,
    /// Device OS (`astra`, `linux`, `windows`).
    #[arg(long, default_value = "linux")]
    pub os: String,
}

/// Arguments for `role list`.
#[derive(Debug, Args)]
pub struct RoleListArgs {
    /// Role directory. Defaults to the production layout.
    #[arg(long, default_value = DEFAULT_ROLES_DIR)]
    pub dir: PathBuf,
    /// Device OS (`astra`, `linux`, `windows`).
    #[arg(long, default_value = "linux")]
    pub os: String,
}

/// Parse an OS string (`astra`/`linux`/`windows`) into a [`RoleOs`].
fn parse_os(s: &str) -> Result<RoleOs, String> {
    match s {
        "astra" => Ok(RoleOs::Astra),
        "linux" => Ok(RoleOs::Linux),
        "windows" => Ok(RoleOs::Windows),
        other => Err(format!(
            "unknown os {other:?}: expected astra, linux, or windows"
        )),
    }
}

/// One slice's lint outcome.
#[derive(Debug)]
pub struct LintEntry {
    /// Slice file path.
    pub path: PathBuf,
    /// Role id (file stem).
    pub role: String,
    /// `Ok(version)` if it validated, else the error message.
    pub result: Result<u32, String>,
}

/// Aggregate lint report over a directory.
#[derive(Debug, Default)]
pub struct LintReport {
    /// Per-slice outcomes, sorted by role id.
    pub entries: Vec<LintEntry>,
    /// True if the number of `*.toml` slices exceeds [`MAX_ROLES`].
    pub over_cap: bool,
}

impl LintReport {
    /// Whether every slice validated and the base is within the cap.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        !self.over_cap && self.entries.iter().all(|e| e.result.is_ok())
    }
}

/// Lint every `*.toml` slice in `dir` strictly. The directory read itself
/// failing is reported as a single error entry. `manifest.toml` is ignored.
#[must_use]
pub fn lint_dir(dir: &Path, os: RoleOs) -> LintReport {
    let mut report = LintReport::default();
    let read = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            report.entries.push(LintEntry {
                path: dir.to_path_buf(),
                role: String::new(),
                result: Err(format!("cannot read directory: {e}")),
            });
            return report;
        }
    };
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in read.flatten() {
        let path = entry.path();
        if path.extension() != Some(OsStr::new("toml")) {
            continue;
        }
        if path.file_name() == Some(OsStr::new("manifest.toml")) {
            continue;
        }
        if !path.is_file() {
            continue;
        }
        paths.push(path);
    }
    paths.sort();
    report.over_cap = paths.len() > MAX_ROLES;

    for path in paths {
        let stem = path
            .file_stem()
            .and_then(OsStr::to_str)
            .unwrap_or("")
            .to_owned();
        let result = match fs::read(&path) {
            Ok(bytes) => match parse_slice(&bytes, &stem, os) {
                Ok(slice) => Ok(slice.version),
                Err(e) => Err(e.to_string()),
            },
            Err(e) => Err(format!("read error: {e}")),
        };
        report.entries.push(LintEntry {
            path,
            role: stem,
            result,
        });
    }
    report
}

/// Run `role lint` and turn the report into an exit code.
fn run_lint(args: &RoleLintArgs) -> ExitCode {
    let os = match parse_os(&args.os) {
        Ok(os) => os,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return ExitCode::FAILURE;
        }
    };
    let report = lint_dir(&args.dir, os);
    let mut fail = 0usize;
    for entry in &report.entries {
        match &entry.result {
            Ok(version) => println!("[OK]   {} v{version}", entry.role),
            Err(msg) => {
                fail += 1;
                println!("[FAIL] {}: {msg}", entry.path.display());
            }
        }
    }
    println!("---");
    let total = report.entries.len();
    println!("summary: {total} slices, {fail} invalid");
    if report.over_cap {
        println!(
            "ERROR: base has more than {MAX_ROLES} slices (the role cap)"
        );
    }
    if report.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Roles that would load, sorted by role id, as `(role, version, name)`.
pub fn list_roles(dir: &Path, os: RoleOs) -> Result<Vec<(String, u32, String)>, String> {
    let store = RoleStore::load(dir, os, TrustMode::Standalone)
        .map_err(|e| format!("failed to load role base: {e}"))?;
    let mut rows: Vec<(String, u32, String)> = store
        .list()
        .map(|s| (s.role.to_string(), s.version, s.name.clone()))
        .collect();
    rows.sort();
    Ok(rows)
}

/// Run `role list` and turn the result into an exit code.
fn run_list(args: &RoleListArgs) -> ExitCode {
    let os = match parse_os(&args.os) {
        Ok(os) => os,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return ExitCode::FAILURE;
        }
    };
    match list_roles(&args.dir, os) {
        Ok(rows) => {
            for (role, version, name) in &rows {
                println!("{role}\t{version}\t{name}");
            }
            println!("---");
            println!("summary: {} roles", rows.len());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ERROR: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Dispatch `tessera role`.
#[allow(clippy::needless_pass_by_value)]
pub fn run(args: RoleArgs) -> ExitCode {
    match args.cmd {
        RoleCmd::Lint(a) => run_lint(&a),
        RoleCmd::List(a) => run_list(&a),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::missing_panics_doc,
        clippy::missing_docs_in_private_items,
        clippy::let_underscore_must_use
    )]

    use super::*;
    use tempfile::TempDir;

    fn slice_doc(role: &str, version: u32) -> String {
        format!(
            "role = \"{role}\"\nversion = {version}\nos = \"linux\"\nname = \"{role} role\"\nlevel = 1\n"
        )
    }

    fn write_slice(dir: &TempDir, role: &str, version: u32) {
        fs::write(
            dir.path().join(format!("{role}.toml")),
            slice_doc(role, version).as_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn lint_clean_dir_ok() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "oper", 1);
        write_slice(&dir, "serv", 2);
        let report = lint_dir(dir.path(), RoleOs::Linux);
        assert!(report.is_clean());
        assert_eq!(report.entries.len(), 2);
        // Sorted by role id.
        assert_eq!(report.entries[0].role, "oper");
        assert_eq!(report.entries[1].role, "serv");
    }

    #[test]
    fn lint_dir_with_bad_slice_fails() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "oper", 1);
        // Unknown field → strict parse failure.
        fs::write(
            dir.path().join("serv.toml"),
            b"role = \"serv\"\nversion = 1\nos = \"linux\"\nname = \"s\"\nlevel = 1\nbogus = 1\n",
        )
        .unwrap();
        let report = lint_dir(dir.path(), RoleOs::Linux);
        assert!(!report.is_clean());
        let fails = report.entries.iter().filter(|e| e.result.is_err()).count();
        assert_eq!(fails, 1);
    }

    #[test]
    fn lint_ignores_manifest() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "oper", 1);
        fs::write(dir.path().join("manifest.toml"), b"bundle_version = 1\n").unwrap();
        let report = lint_dir(dir.path(), RoleOs::Linux);
        assert!(report.is_clean());
        assert_eq!(report.entries.len(), 1);
    }

    #[test]
    fn list_returns_sorted_roles() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "serv", 7);
        write_slice(&dir, "oper", 3);
        write_slice(&dir, "admin", 1);
        let rows = list_roles(dir.path(), RoleOs::Linux).unwrap();
        let ids: Vec<&str> = rows.iter().map(|(r, _, _)| r.as_str()).collect();
        assert_eq!(ids, vec!["admin", "oper", "serv"]);
        assert_eq!(rows[1], ("oper".to_string(), 3, "oper role".to_string()));
    }

    #[test]
    fn list_skips_bad_slice() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "oper", 1);
        fs::write(dir.path().join("serv.toml"), b"not valid toml {{{").unwrap();
        let rows = list_roles(dir.path(), RoleOs::Linux).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "oper");
    }

    #[test]
    fn parse_os_rejects_unknown() {
        assert!(parse_os("bsd").is_err());
        assert_eq!(parse_os("astra").unwrap(), RoleOs::Astra);
    }
}
