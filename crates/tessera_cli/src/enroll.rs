//! `tessera enroll` subcommand: import an enrollment package after
//! `finish-bootstrap` (`device-enrollment` sections 2 + 4).
//!
//! After `clone-image-bootstrap` flips a clone to its per-host identity, the
//! operator imports the *enrollment package* (per-host `.p12` + the first
//! tags/roles/CRL bundle). Two trust modes mirror the import core:
//!
//! - **managed** (`--import <path>` + `--manifest-pubkey <pem>`): the bundle is
//!   a signed `manifest.toml`; signature + anti-rollback `bundle_version` are
//!   verified by [`tessera_core::enrollment`].
//! - **standalone** (`--import <path> --standalone`): no signature; the tags
//!   file + role slices are trusted by filesystem permissions, for server-less
//!   rollout.
//!
//! On success the command prints a report (`host_id` prefix8, per-host cert
//! serial, applied `bundle_version`, mode) and runs the existing
//! [`crate::check`] preflight against the device config — a failed post-import
//! check is surfaced as a non-zero exit (fail-closed). On any import error the
//! command exits non-zero; the import core guarantees the device is left in its
//! prior consistent state (atomic rollback).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;

use tessera_core::enrollment::audit::EnrollAuditIds;
use tessera_core::enrollment::{
    EnrollmentPackage, ImportError, ImportMode, ImportOutcome, InstallPaths,
};
use tessera_core::host_identity::HostIdentityResolver;
use tessera_core::pkcs12;
use tessera_core::role::RoleOs;

/// CLI arguments for `tessera enroll`.
#[derive(Debug, Args)]
pub struct EnrollArgs {
    /// Enrollment-package path: a directory (or a mounted USB path) holding the
    /// per-host `.p12` plus the bundle (`manifest.toml` for managed,
    /// `tags.toml` + role slices for standalone).
    #[arg(long)]
    pub import: PathBuf,

    /// Standalone mode: trust the package by filesystem permissions, no
    /// signature (server-less rollout). Mutually exclusive with
    /// `--manifest-pubkey`.
    #[arg(long, default_value_t = false, conflicts_with = "manifest_pubkey")]
    pub standalone: bool,

    /// Managed mode: PEM file holding the trusted manifest-verification public
    /// key. Its presence selects managed mode; required unless `--standalone`.
    #[arg(long)]
    pub manifest_pubkey: Option<PathBuf>,

    /// Device OS (`astra`, `linux`, `windows`). Selects the role payload
    /// schema the import validates against.
    #[arg(long, default_value = "linux")]
    pub os: String,

    /// Path to `config.toml`. Defaults to `/etc/tessera/config.toml`, matching
    /// the daemon, `tessera check`, and `tessera dump-host-id`. Used to resolve
    /// the device `host_id` for the audit/report and to run the post-import
    /// preflight check.
    #[arg(long, default_value = "/etc/tessera/config.toml")]
    pub config: PathBuf,

    /// Skip the post-import `tessera check` preflight. NOT recommended: the
    /// check is the fail-closed gate that a half-broken config never reaches a
    /// reboot. Provided for environments where the config is validated out of
    /// band.
    #[arg(long, default_value_t = false)]
    pub skip_check: bool,
}

/// Test-friendly options surface mirroring [`EnrollArgs`], plus an
/// [`InstallPaths`] override so unit tests pin the install to a tempdir and a
/// resolved `host_id` prefix injected directly (tests do not have a real
/// `config.toml` / host-identity tree).
#[derive(Debug, Clone)]
pub struct EnrollOptions {
    /// Package path.
    pub import: PathBuf,
    /// Trust mode.
    pub mode: ImportMode,
    /// Trusted manifest public key (PEM), required for managed mode.
    pub manifest_pubkey: Option<PathBuf>,
    /// Device OS.
    pub os: RoleOs,
    /// Where artefacts install. Production defaults match the role-store /
    /// tags / revocation paths; tests override onto a tempdir.
    pub paths: InstallPaths,
    /// Resolved `host_id` prefix8 for the report/audit (`""` when unknown).
    pub host_id_prefix8: String,
    /// Whether to run the post-import `tessera check`.
    pub run_check: bool,
    /// Config path for the post-import check.
    pub config: PathBuf,
}

/// What `enroll` produced on success: the import outcome plus the identifiers
/// surfaced in the report and the audit event.
#[derive(Debug, Clone)]
pub struct EnrollReport {
    /// The underlying import outcome (mode, applied `bundle_version`, no-op).
    pub outcome: ImportOutcome,
    /// `host_id` prefix8 (`""` when it could not be resolved).
    pub host_id_prefix8: String,
    /// Per-host leaf certificate serial, uppercase hex (`""` when the `.p12`
    /// leaf could not be read without the PIN — best-effort).
    pub serial: String,
}

/// Errors returned by [`run`].
#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    /// A `--manifest-pubkey` PEM file could not be read.
    #[error("cannot read manifest public key {path}: {reason}")]
    PubkeyRead {
        /// PEM path.
        path: String,
        /// Underlying I/O error.
        reason: String,
    },
    /// Managed mode was selected without a `--manifest-pubkey`.
    #[error("managed enrollment requires --manifest-pubkey <pem> (or use --standalone)")]
    MissingPubkey,
    /// The import core rejected the package (fail-closed; device unchanged).
    #[error(transparent)]
    Import(#[from] ImportError),
    /// The post-import `tessera check` preflight reported an ERROR.
    #[error("post-import check failed: the device config did not pass `tessera check`")]
    PostCheckFailed,
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

/// Resolve the device `host_id` prefix8 from the validated config, best-effort.
/// A resolution failure is not fatal to enrollment (the package install does
/// not depend on it) — it only blanks the `host_id` field in the report/audit.
fn resolve_host_id_prefix8(config: &Path) -> String {
    let Ok(validated) = tessera_core::config::load_validated_config(config) else {
        return String::new();
    };
    let resolver =
        HostIdentityResolver::from_validated(&validated.host_identity, PathBuf::from("/"));
    match resolver.resolve() {
        Ok(r) => r.hash_prefix().to_owned(),
        Err(_) => String::new(),
    }
}

/// Read the per-host leaf certificate serial from the package `.p12` WITHOUT a
/// PIN (best-effort; modern bundles place the leaf in an unencrypted SafeBag).
/// Returns `""` when the leaf is encrypted/absent — the serial is a reporting
/// nicety, never a gate.
fn read_p12_serial(pkg: &EnrollmentPackage, import_root: &Path) -> String {
    // `EnrollmentPackage::p12_file()` is a bare name validated by the core's
    // parser; join it under the package root we were given.
    let p12_path = import_root.join(pkg.p12_file());
    let Ok(bytes) = std::fs::read(&p12_path) else {
        return String::new();
    };
    match pkcs12::try_extract_cert_without_pin(&bytes) {
        Some(cert) => cert.serial_hex(),
        None => String::new(),
    }
}

/// Run the post-import `tessera check` preflight against `config`. Returns
/// `true` when the config passed (no ERROR records), `false` otherwise. Reuses
/// the exact [`crate::check`] machinery (no duplicate validation).
fn post_import_check(config: &Path) -> bool {
    let Ok(validated) = tessera_core::config::load_validated_config(config) else {
        return false;
    };
    let opts = crate::startup_check::StartupCheckOptions::default();
    let report = crate::startup_check::run_startup_checks(&validated, &opts);
    report.count(crate::startup_check::StartupCheckSeverity::Error) == 0
}

/// Execute the enrollment. Imports the package (emitting the enriched
/// `device_enrolled` / `enrollment_rejected` audit event via the core, with the
/// resolved `host_id` prefix8 + per-host serial), then runs the post-import
/// `tessera check` when `run_check` is set. A failed check is fail-closed:
/// [`EnrollError::PostCheckFailed`].
pub fn run(opts: EnrollOptions) -> Result<EnrollReport, EnrollError> {
    // Resolve the trusted pubkey bytes up front (managed only).
    let pubkey_bytes = match (opts.mode, &opts.manifest_pubkey) {
        (ImportMode::Managed, Some(path)) => {
            let bytes = std::fs::read(path).map_err(|e| EnrollError::PubkeyRead {
                path: path.display().to_string(),
                reason: e.to_string(),
            })?;
            Some(bytes)
        }
        (ImportMode::Managed, None) => return Err(EnrollError::MissingPubkey),
        (ImportMode::Standalone, _) => None,
    };

    let pkg = EnrollmentPackage::parse(&opts.import, opts.mode)?;
    // The per-host serial is read from the package `.p12` (best-effort, no PIN)
    // BEFORE the install consumes anything; it enriches both the audit event
    // and the printed report.
    let serial = read_p12_serial(&pkg, &opts.import);

    let ids = EnrollAuditIds {
        host_id_prefix8: &opts.host_id_prefix8,
        serial: &serial,
    };
    // The core is the single audit-emission point: it emits the enriched
    // `device_enrolled` on success (non-no-op) or `enrollment_rejected` on
    // failure, fail-closed.
    let outcome = pkg.install_with_ids(&opts.paths, opts.os, pubkey_bytes.as_deref(), ids)?;

    // Post-import preflight: reuse `tessera check`. A failing config is
    // fail-closed — the operator must fix it before the device is trusted.
    if opts.run_check && !post_import_check(&opts.config) {
        return Err(EnrollError::PostCheckFailed);
    }

    Ok(EnrollReport {
        outcome,
        host_id_prefix8: opts.host_id_prefix8,
        serial,
    })
}

/// Print the success report (one `key\tvalue` line per field, then a summary),
/// mirroring the TSV-ish shape of the other subcommands.
fn print_report(report: &EnrollReport) {
    let mode = match report.outcome.mode {
        ImportMode::Managed => "managed",
        ImportMode::Standalone => "standalone",
    };
    let host_id = if report.host_id_prefix8.is_empty() {
        "-"
    } else {
        &report.host_id_prefix8
    };
    let serial = if report.serial.is_empty() {
        "-"
    } else {
        &report.serial
    };
    println!("host_id\t{host_id}");
    println!("serial\t{serial}");
    println!("bundle_version\t{}", report.outcome.bundle_version);
    println!("mode\t{mode}");
    println!("---");
    if report.outcome.no_op {
        println!("summary: enrollment no-op (bundle already applied)");
    } else if report.outcome.baseline_established {
        println!("summary: enrolled (baseline established)");
    } else {
        println!("summary: enrolled");
    }
}

/// CLI entry point. Translates [`EnrollArgs`] into [`EnrollOptions`], runs the
/// import, and maps the result onto an exit code + a stderr line on failure,
/// mirroring the shape of the other subcommands.
#[allow(clippy::needless_pass_by_value)]
pub fn run_cli(args: EnrollArgs) -> ExitCode {
    // Bring up tracing so the enrollment audit event (`device_enrolled` /
    // `enrollment_rejected`) the core emits actually reaches stderr, mirroring
    // the daemon. Best-effort: a logging-init failure must not block the import.
    if let Err(e) = crate::logging::init() {
        eprintln!("WARN: failed to initialize logging: {e}");
    }
    let os = match parse_os(&args.os) {
        Ok(os) => os,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Managed unless `--standalone`. A managed run requires `--manifest-pubkey`;
    // `run` enforces this (fail-closed) so the error message stays in one place.
    let mode = if args.standalone {
        ImportMode::Standalone
    } else {
        ImportMode::Managed
    };
    let host_id_prefix8 = resolve_host_id_prefix8(&args.config);
    let opts = EnrollOptions {
        import: args.import,
        mode,
        manifest_pubkey: args.manifest_pubkey,
        os,
        paths: InstallPaths::default(),
        host_id_prefix8,
        run_check: !args.skip_check,
        config: args.config,
    };
    match run(opts) {
        Ok(report) => {
            print_report(&report);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ERROR: {e}");
            ExitCode::FAILURE
        }
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
    use openssl::pkey::PKey;
    use openssl::sign::Signer;
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    use std::fs;
    use tempfile::TempDir;

    /// Opaque per-host `.p12` bytes the test packages ship (never decrypted).
    const P12_OPAQUE: &[u8] = b"\x30\x82PKCS12-OPAQUE";

    struct TestKey {
        pkey: PKey<openssl::pkey::Private>,
        pub_pem: Vec<u8>,
    }

    fn gen_key() -> TestKey {
        let pkey = PKey::generate_ed25519().unwrap();
        let pub_pem = pkey.public_key_to_pem().unwrap();
        TestKey { pkey, pub_pem }
    }

    fn sign(key: &TestKey, payload: &[u8]) -> String {
        let mut signer = Signer::new_without_digest(&key.pkey).unwrap();
        let sig = signer.sign_oneshot_to_vec(payload).unwrap();
        hex::encode(sig)
    }

    fn slice_doc(role: &str, version: u32) -> String {
        format!("role = \"{role}\"\nversion = {version}\nos = \"linux\"\nname = \"{role}\"\nlevel = 1\n")
    }

    /// Install paths rooted at a fresh tempdir (never touch real device paths).
    fn install_paths(base: &Path) -> InstallPaths {
        InstallPaths {
            roles_dir: base.join("roles"),
            tags_file: base.join("tags.toml"),
            crl_path: base.join("device.crl"),
            p12_path: base.join("host.p12"),
            persist_dir: base.join("persist"),
        }
    }

    /// Build a MANAGED enrollment package directory (signed manifest).
    fn build_managed_pkg(key: &TestKey, bundle_version: u64) -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        let mut roles_toml = String::new();
        let body = slice_doc("oper", 1);
        fs::write(dir.path().join("oper.toml"), body.as_bytes()).unwrap();
        let sha = hex::encode(Sha256::digest(body.as_bytes()));
        let _ = write!(
            roles_toml,
            "[roles.oper]\nversion = 1\nsha256 = \"{sha}\"\n"
        );
        let tags_toml = "[tags]\nregion = \"north\"\n";
        let unsigned =
            format!("bundle_version = {bundle_version}\nos = \"linux\"\n{tags_toml}{roles_toml}");
        let sig = sign(key, unsigned.as_bytes());
        let full = format!(
            "bundle_version = {bundle_version}\nos = \"linux\"\nsignature = \"{sig}\"\n{tags_toml}{roles_toml}"
        );
        fs::write(dir.path().join("manifest.toml"), full.as_bytes()).unwrap();
        fs::write(dir.path().join("host-abc123.p12"), P12_OPAQUE).unwrap();
        dir
    }

    /// Build a STANDALONE enrollment package directory (no signature).
    fn build_standalone_pkg() -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("oper.toml"),
            slice_doc("oper", 1).as_bytes(),
        )
        .unwrap();
        fs::write(
            dir.path().join("tags.toml"),
            b"[tags]\nregion = \"north\"\n",
        )
        .unwrap();
        fs::write(dir.path().join("host-xyz.p12"), P12_OPAQUE).unwrap();
        dir
    }

    fn write_pubkey(dir: &Path, pem: &[u8]) -> PathBuf {
        let path = dir.join("manifest.pub.pem");
        fs::write(&path, pem).unwrap();
        path
    }

    #[test]
    fn managed_import_succeeds_and_reports() {
        let key = gen_key();
        let pkg = build_managed_pkg(&key, 7);
        let root = tempfile::tempdir().unwrap();
        let pubkey = write_pubkey(root.path(), &key.pub_pem);
        let opts = EnrollOptions {
            import: pkg.path().to_path_buf(),
            mode: ImportMode::Managed,
            manifest_pubkey: Some(pubkey),
            os: RoleOs::Linux,
            paths: install_paths(root.path()),
            host_id_prefix8: "deadbeef".to_string(),
            run_check: false,
            config: PathBuf::from("/nonexistent/config.toml"),
        };
        let report = run(opts).expect("managed import ok");
        assert_eq!(report.outcome.mode, ImportMode::Managed);
        assert_eq!(report.outcome.bundle_version, 7);
        assert!(report.outcome.baseline_established);
        assert!(!report.outcome.no_op);
        assert_eq!(report.host_id_prefix8, "deadbeef");
    }

    #[test]
    fn managed_import_without_pubkey_fails() {
        let key = gen_key();
        let pkg = build_managed_pkg(&key, 1);
        let root = tempfile::tempdir().unwrap();
        let opts = EnrollOptions {
            import: pkg.path().to_path_buf(),
            mode: ImportMode::Managed,
            manifest_pubkey: None,
            os: RoleOs::Linux,
            paths: install_paths(root.path()),
            host_id_prefix8: String::new(),
            run_check: false,
            config: PathBuf::from("/nonexistent/config.toml"),
        };
        let err = run(opts).expect_err("missing pubkey must fail");
        assert!(matches!(err, EnrollError::MissingPubkey));
    }

    #[test]
    fn standalone_import_succeeds() {
        let pkg = build_standalone_pkg();
        let root = tempfile::tempdir().unwrap();
        let opts = EnrollOptions {
            import: pkg.path().to_path_buf(),
            mode: ImportMode::Standalone,
            manifest_pubkey: None,
            os: RoleOs::Linux,
            paths: install_paths(root.path()),
            host_id_prefix8: "abc12345".to_string(),
            run_check: false,
            config: PathBuf::from("/nonexistent/config.toml"),
        };
        let report = run(opts).expect("standalone import ok");
        assert_eq!(report.outcome.mode, ImportMode::Standalone);
        assert_eq!(report.outcome.bundle_version, 0);
        assert!(!report.outcome.no_op);
        // Standalone laid the tags + role slice down under the install paths.
        let paths = install_paths(root.path());
        assert!(paths.roles_dir.join("oper.toml").exists());
        assert!(paths.tags_file.exists());
    }

    #[test]
    fn malformed_package_exits_nonzero() {
        // A directory with no `.p12` is not a valid package → ImportError.
        let pkg = tempfile::tempdir().unwrap();
        fs::write(pkg.path().join("tags.toml"), b"[tags]\n").unwrap();
        let root = tempfile::tempdir().unwrap();
        let opts = EnrollOptions {
            import: pkg.path().to_path_buf(),
            mode: ImportMode::Standalone,
            manifest_pubkey: None,
            os: RoleOs::Linux,
            paths: install_paths(root.path()),
            host_id_prefix8: String::new(),
            run_check: false,
            config: PathBuf::from("/nonexistent/config.toml"),
        };
        let err = run(opts).expect_err("malformed package must fail");
        assert!(matches!(err, EnrollError::Import(ImportError::NoP12)));
    }

    #[test]
    fn missing_package_path_exits_nonzero() {
        let root = tempfile::tempdir().unwrap();
        let opts = EnrollOptions {
            import: root.path().join("does-not-exist"),
            mode: ImportMode::Standalone,
            manifest_pubkey: None,
            os: RoleOs::Linux,
            paths: install_paths(root.path()),
            host_id_prefix8: String::new(),
            run_check: false,
            config: PathBuf::from("/nonexistent/config.toml"),
        };
        let err = run(opts).expect_err("missing path must fail");
        assert!(matches!(
            err,
            EnrollError::Import(ImportError::PackageMissing { .. })
        ));
    }

    #[test]
    fn post_import_check_failure_is_fail_closed() {
        // run_check = true with a config path that cannot load → post-import
        // check returns false → PostCheckFailed (fail-closed). The package
        // itself imports fine first.
        let pkg = build_standalone_pkg();
        let root = tempfile::tempdir().unwrap();
        let opts = EnrollOptions {
            import: pkg.path().to_path_buf(),
            mode: ImportMode::Standalone,
            manifest_pubkey: None,
            os: RoleOs::Linux,
            paths: install_paths(root.path()),
            host_id_prefix8: String::new(),
            run_check: true,
            config: PathBuf::from("/nonexistent/config.toml"),
        };
        let err = run(opts).expect_err("post-check must fail-closed");
        assert!(matches!(err, EnrollError::PostCheckFailed));
    }

    #[test]
    fn managed_reimport_same_version_is_noop() {
        let key = gen_key();
        let pkg = build_managed_pkg(&key, 5);
        let root = tempfile::tempdir().unwrap();
        let pubkey = write_pubkey(root.path(), &key.pub_pem);
        let mk_opts = || EnrollOptions {
            import: pkg.path().to_path_buf(),
            mode: ImportMode::Managed,
            manifest_pubkey: Some(pubkey.clone()),
            os: RoleOs::Linux,
            paths: install_paths(root.path()),
            host_id_prefix8: String::new(),
            run_check: false,
            config: PathBuf::from("/nonexistent/config.toml"),
        };
        let first = run(mk_opts()).expect("first import ok");
        assert!(!first.outcome.no_op);
        let second = run(mk_opts()).expect("re-import ok");
        assert!(second.outcome.no_op);
        assert_eq!(second.outcome.bundle_version, 5);
    }

    #[test]
    fn parse_os_rejects_unknown() {
        assert!(parse_os("bsd").is_err());
        assert_eq!(parse_os("astra").unwrap(), RoleOs::Astra);
    }
}
