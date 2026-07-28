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
use tessera_core::role::{parse_slice, RoleOs, SystemAccounts, DEFAULT_ACCOUNT_LOOKUP_TIMEOUT};

/// Where the device keeps its configuration, matching the daemon's default so
/// an on-device run reads the same file the login path does.
const DEFAULT_CONFIG_PATH: &str = "/etc/tessera/config.toml";

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
    /// This run is on the device the base belongs to: check slice names
    /// against the local account database.
    #[arg(long)]
    pub on_device: bool,
    /// Path to `config.toml`, read with `--on-device` for the bound the login
    /// path puts on name resolution.
    #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
    pub config: PathBuf,
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
    /// This run is on the device the base belongs to: check slice names
    /// against the local account database.
    #[arg(long)]
    pub on_device: bool,
    /// Path to `config.toml`, read with `--on-device` for the bound the login
    /// path puts on name resolution.
    #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
    pub config: PathBuf,
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
///
/// `accounts` is the account view a slice name is checked against: a slice
/// named after an account the system already owns can never be a role, and
/// lint is where that provisioning mistake should surface.
#[must_use]
pub fn lint_dir(dir: &Path, os: RoleOs, accounts: SystemAccounts) -> LintReport {
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

    let stems: Vec<String> = paths
        .iter()
        .map(|path| {
            path.file_stem()
                .and_then(OsStr::to_str)
                .unwrap_or("")
                .to_owned()
        })
        .collect();
    // Both account sources answer once for the whole base, as they do in the
    // loader on the device: the question is the same one, and asking it per
    // slice would read the account database — and run name resolution — as many
    // times as there are slices.
    let device_accounts = {
        let names: Vec<&str> = stems.iter().map(String::as_str).collect();
        accounts.snapshot(&names)
    };

    for (path, stem) in paths.into_iter().zip(stems) {
        let result = match device_accounts.check(&stem) {
            Ok(()) => match fs::read(&path) {
                Ok(bytes) => match parse_slice(&bytes, &stem, os) {
                    Ok(slice) => Ok(slice.version),
                    Err(e) => Err(e.to_string()),
                },
                Err(e) => Err(format!("read error: {e}")),
            },
            Err(e) => Err(e.to_string()),
        };
        report.entries.push(LintEntry {
            path,
            role: stem,
            result,
        });
    }
    report
}

/// The account view this run may honestly check slice names against.
///
/// The question a slice name is checked against is "does the DEVICE this base
/// belongs to already own an account by that name" — and only a run on that
/// device can answer it. Sharing an OS family with the device does not grant
/// that right: `tessera-cli` mostly runs on workstations, whose accounts are
/// somebody else's entirely. A base staged for a device would then be judged by
/// the operator's own machine — the legitimate slice `mail` rejected because
/// the workstation ships that account, and a system account unique to the
/// device passing lint untouched.
///
/// So the local database is consulted only when the caller states outright that
/// this run happens on the device (`--on-device`). Otherwise the check is
/// skipped with a note in the output, rather than answered by the wrong
/// machine. Skipping is not a hole: the on-device load path checks again with
/// the device's own accounts, and it is the one that decides whether a role
/// exists.
///
/// The bound on name resolution comes from the device's own configuration.
/// The limit does not only shorten a wait: only an answer that arrives inside
/// it can add a refusal, so a run with a different limit answers a different
/// question than the login path does. With a longer limit configured, a slice
/// the login refuses would be reported as sound; with a shorter one, a sound
/// slice would be reported as refused.
///
/// A configuration that cannot be read leaves the built-in default in force —
/// the check is worth more than nothing — but the run says so, because the
/// answer it gives may then differ from the login path's.
///
/// Returns the view plus the notes to print with the report.
fn accounts_for(on_device: bool, config: &Path) -> (SystemAccounts, Vec<String>) {
    if !on_device {
        return (
            SystemAccounts::empty(),
            vec![
                "note: slice names were not checked against system accounts \u{2014} \
                 pass --on-device when running on the device this base belongs to"
                    .to_owned(),
            ],
        );
    }
    match tessera_core::config::load_validated_config(config) {
        Ok(validated) => (
            SystemAccounts::device(validated.roles.account_lookup_timeout),
            Vec::new(),
        ),
        Err(error) => (
            SystemAccounts::device(DEFAULT_ACCOUNT_LOOKUP_TIMEOUT),
            vec![format!(
                "note: device configuration {path} could not be read ({error}) \u{2014} \
                 name resolution is bounded by the built-in default of {default} s, which may \
                 not be the bound the login path applies",
                path = config.display(),
                default = DEFAULT_ACCOUNT_LOOKUP_TIMEOUT.as_secs(),
            )],
        ),
    }
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
    let (accounts, notes) = accounts_for(args.on_device, &args.config);
    let report = lint_dir(&args.dir, os, accounts);
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
    for note in &notes {
        println!("{note}");
    }
    let total = report.entries.len();
    println!("summary: {total} slices, {fail} invalid");
    if report.over_cap {
        println!("ERROR: base has more than {MAX_ROLES} slices (the role cap)");
    }
    if report.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Roles that would load, sorted by role id, as `(role, version, name)`.
///
/// `accounts` is the account view slice names are checked against; slices named
/// after a system account of the device never load and therefore never appear.
pub fn list_roles(
    dir: &Path,
    os: RoleOs,
    accounts: SystemAccounts,
) -> Result<Vec<(String, u32, String)>, String> {
    let store = RoleStore::load(dir, os, TrustMode::Standalone, accounts)
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
    let (accounts, notes) = accounts_for(args.on_device, &args.config);
    match list_roles(&args.dir, os, accounts) {
        Ok(rows) => {
            for (role, version, name) in &rows {
                println!("{role}\t{version}\t{name}");
            }
            println!("---");
            for note in &notes {
                println!("{note}");
            }
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
    use tessera_core::role::PasswdLookup;

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
        let report = lint_dir(dir.path(), RoleOs::Linux, SystemAccounts::empty());
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
        let report = lint_dir(dir.path(), RoleOs::Linux, SystemAccounts::empty());
        assert!(!report.is_clean());
        let fails = report.entries.iter().filter(|e| e.result.is_err()).count();
        assert_eq!(fails, 1);
    }

    #[test]
    fn lint_flags_a_slice_named_after_a_system_account() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "oper", 1);
        write_slice(&dir, "root", 1);
        // The device's account view, not the one of the machine running tests.
        let accounts = SystemAccounts::with_lookup(|account| match account {
            "root" => PasswdLookup::Uid(0),
            _ => PasswdLookup::NoEntry,
        });

        let report = lint_dir(dir.path(), RoleOs::Linux, accounts);

        assert!(!report.is_clean());
        let root = report
            .entries
            .iter()
            .find(|e| e.role == "root")
            .expect("root slice is reported");
        let message = root.result.as_ref().unwrap_err();
        assert!(message.contains("system account"), "{message}");
    }

    /// A device configuration that validates, carrying an explicit bound on
    /// name resolution.
    fn config_with_timeout(dir: &TempDir, seconds: u64) -> PathBuf {
        let anchor = dir.path().join("ca.pem");
        fs::write(&anchor, b"-----BEGIN CERTIFICATE-----\n").unwrap();
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            format!(
                "crypto_backend = \"openssl\"\n\
                 mode = \"pkcs12\"\n\
                 pkcs12_path_pattern = \"user.p12\"\n\
                 \n\
                 [trust]\n\
                 anchors = [\"{anchor}\"]\n\
                 \n\
                 [trust.revocation]\n\
                 mode = \"none\"\n\
                 \n\
                 [host_identity]\n\
                 sources = [\"dmi_board_serial\"]\n\
                 \n\
                 [logging]\n\
                 level = \"info\"\n\
                 \n\
                 [roles]\n\
                 account_lookup_timeout_seconds = {seconds}\n",
                anchor = anchor.display(),
            )
            .as_bytes(),
        )
        .unwrap();
        path
    }

    #[test]
    fn a_run_that_is_not_on_the_device_does_not_judge_by_this_machine() {
        // The default: the accounts of the machine running lint describe
        // somebody else, so the check is skipped and the run says so instead of
        // answering with the wrong device's rules.
        let dir = tempfile::tempdir().unwrap();
        let (accounts, notes) = accounts_for(false, &config_with_timeout(&dir, 3));
        let note = notes
            .first()
            .expect("skipping the check must be stated in the output");
        assert!(
            note.contains("not checked against system accounts"),
            "{note}"
        );
        assert!(note.contains("--on-device"), "{note}");
        // `root` exists on every machine this suite runs on, through the file
        // and through name resolution alike — clearing it is what proves no
        // local database was consulted.
        accounts
            .check("root")
            .expect("no local account database may be consulted without --on-device");
    }

    #[test]
    fn a_run_declared_on_device_takes_the_bound_from_the_device_configuration() {
        // The bound decides which answers can still add a refusal, so a run
        // that answers with a different one answers a different question than
        // the login path does.
        let dir = tempfile::tempdir().unwrap();
        let (accounts, notes) = accounts_for(true, &config_with_timeout(&dir, 3));

        assert_eq!(
            accounts.name_lookup_bound(),
            std::time::Duration::from_secs(3),
            "the device's own limit, not the built-in default"
        );
        assert!(
            notes.is_empty(),
            "an on-device run with a readable configuration has nothing to warn about: {notes:?}"
        );
    }

    #[test]
    fn an_unreadable_configuration_falls_back_to_the_default_and_says_so() {
        // The check is worth more than nothing, so it still runs — but under a
        // bound that may not be the device's, which the operator has to be told
        // rather than left to assume.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-config.toml");

        let (accounts, notes) = accounts_for(true, &missing);

        assert_eq!(accounts.name_lookup_bound(), DEFAULT_ACCOUNT_LOOKUP_TIMEOUT);
        let note = notes
            .first()
            .expect("a fallback bound must be stated in the output");
        assert!(note.contains("could not be read"), "{note}");
        assert!(note.contains("default"), "{note}");
    }

    #[test]
    fn lint_without_the_on_device_flag_accepts_a_slice_named_after_a_local_account() {
        // A base staged on a workstation for a device: `root` here is the
        // workstation's account, and judging the base by it would report a
        // failure about the wrong machine. The device's own load path is where
        // that slice gets refused.
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "root", 1);
        let (accounts, _notes) = accounts_for(false, Path::new(DEFAULT_CONFIG_PATH));

        let report = lint_dir(dir.path(), RoleOs::Linux, accounts);

        assert!(report.is_clean(), "{:?}", report.entries);
    }

    #[test]
    fn lint_ignores_manifest() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "oper", 1);
        fs::write(dir.path().join("manifest.toml"), b"bundle_version = 1\n").unwrap();
        let report = lint_dir(dir.path(), RoleOs::Linux, SystemAccounts::empty());
        assert!(report.is_clean());
        assert_eq!(report.entries.len(), 1);
    }

    #[test]
    fn list_returns_sorted_roles() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "serv", 7);
        write_slice(&dir, "oper", 3);
        write_slice(&dir, "admin", 1);
        let rows = list_roles(dir.path(), RoleOs::Linux, SystemAccounts::empty()).unwrap();
        let ids: Vec<&str> = rows.iter().map(|(r, _, _)| r.as_str()).collect();
        assert_eq!(ids, vec!["admin", "oper", "serv"]);
        assert_eq!(rows[1], ("oper".to_string(), 3, "oper role".to_string()));
    }

    #[test]
    fn list_skips_bad_slice() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "oper", 1);
        fs::write(dir.path().join("serv.toml"), b"not valid toml {{{").unwrap();
        let rows = list_roles(dir.path(), RoleOs::Linux, SystemAccounts::empty()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "oper");
    }

    #[test]
    fn parse_os_rejects_unknown() {
        assert!(parse_os("bsd").is_err());
        assert_eq!(parse_os("astra").unwrap(), RoleOs::Astra);
    }
}
