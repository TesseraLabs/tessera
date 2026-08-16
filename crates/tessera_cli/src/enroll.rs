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
//! serial — empty until it comes from a signed source, applied
//! `bundle_version`, mode) and runs the existing
//! [`crate::check`] preflight against the device config — a failed post-import
//! check is surfaced as a non-zero exit (fail-closed). On any import error the
//! command exits non-zero; the import core guarantees the device is left in its
//! prior consistent state (atomic rollback).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;

use tessera_core::config::ValidatedConfig;
use tessera_core::enrollment::audit::EnrollAuditIds;
use tessera_core::enrollment::{
    EnrollmentPackage, ImportError, ImportMode, ImportOutcome, InstallPaths,
};
use tessera_core::host_identity::HostIdentityResolver;
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
    /// Per-host leaf certificate serial, uppercase hex.
    ///
    /// Always empty today; see where [`run`] sets it for why the package
    /// `.p12` cannot supply it and what source would.
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
    /// The device config could not be loaded for the post-import check —
    /// unreadable, unparseable, or not root-controlled.
    #[error("post-import check could not load config {path}: {reason}")]
    ConfigLoad {
        /// Config path that failed to load.
        path: String,
        /// Why it failed, including the ownership/mode detail when the path
        /// failed the root-control policy.
        reason: String,
    },
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
///
/// The config is read under the same root-control policy as PAM and the
/// daemon, so a config the operator cannot trust never contributes an
/// identifier to a long-lived audit event. The reason is logged rather than
/// returned: unless the operator passed `--skip-check`, the same load runs
/// again in [`load_preflight_config`], which is where it becomes fatal.
fn resolve_host_id_prefix8(config: &Path) -> String {
    let validated = match tessera_core::config::load_privileged_validated_config(config) {
        Ok(validated) => validated,
        Err(e) => {
            tracing::warn!(
                target: "tessera.enroll",
                config = %config.display(),
                error = %e,
                "cannot load config for host_id resolution; reporting an empty host_id"
            );
            return String::new();
        }
    };
    let resolver =
        HostIdentityResolver::from_validated(&validated.host_identity, PathBuf::from("/"));
    match resolver.resolve() {
        Ok(r) => r.hash_prefix().to_owned(),
        Err(_) => String::new(),
    }
}

/// Settle gost-engine readiness from the config's engine path alone, before
/// anything in this process has reached libcrypto.
///
/// The probe belongs here and nowhere later. Verifying the enrollment manifest
/// calls into libcrypto (`role::verify_signature` on the managed path), and on
/// Astra the first call into libcrypto registers gost-engine ambiently from
/// `openssl.cnf`; the engine then refuses our own explicit load. A probe run
/// after the import would report a broken engine — and fail the enrollment of
/// a perfectly good package — on a host where authentication works and where
/// `tessera check` in a fresh process passes.
///
/// Only the engine path is read, because the full config is routinely
/// unloadable at this point: a first managed enrollment runs against a config
/// naming `/var/lib/tessera/device.crl`, a file this very command creates. The
/// path still goes through the root-control policy — an engine named by a
/// config anyone but root can rewrite is loaded into the authentication
/// process, so a raw TOML value would be no safer here than in the daemon.
///
/// A config that cannot be read at all leaves the engine unprobed and silent:
/// the same file is loaded again after the import, under a strictly stricter
/// policy, and the operator's error comes from there.
fn probe_engine_before_import(config: &Path) -> crate::startup_check::gost::EngineReadiness {
    match tessera_core::config::load_privileged_gost_engine_path(config) {
        Ok(engine_path) => crate::startup_check::gost::probe_path(engine_path.as_deref()),
        Err(e) => {
            tracing::warn!(
                target: "tessera.enroll",
                config = %config.display(),
                error = %e,
                "cannot read the gost-engine path from the config; leaving the engine unprobed"
            );
            crate::startup_check::gost::not_probed()
        }
    }
}

/// Load the device config for the post-import preflight.
///
/// # Errors
///
/// [`EnrollError::ConfigLoad`] when the config cannot be read, parsed, or does
/// not pass the root-control policy — the message carries the underlying
/// reason so the operator knows which path to fix.
fn load_preflight_config<L>(config: &Path, load_config: L) -> Result<ValidatedConfig, EnrollError>
where
    L: FnOnce(&Path) -> Result<ValidatedConfig, tessera_core::Error>,
{
    load_config(config).map_err(|e| EnrollError::ConfigLoad {
        path: config.display().to_string(),
        reason: e.to_string(),
    })
}

/// Run the post-import `tessera check` preflight. Reuses the exact
/// [`crate::check`] machinery (no duplicate validation), including its
/// root-control policy on the config and every path it names.
///
/// # Errors
///
/// [`EnrollError::PostCheckFailed`] when a startup check reported an ERROR.
fn post_import_check(
    config: &ValidatedConfig,
    gost: crate::startup_check::gost::EngineReadiness,
    check_opts: &crate::startup_check::StartupCheckOptions,
) -> Result<(), EnrollError> {
    let report = crate::startup_check::run_startup_checks_with_gost(config, check_opts, gost);
    if report.has_errors() {
        Err(EnrollError::PostCheckFailed)
    } else {
        Ok(())
    }
}

/// Import the package and run the post-import preflight, in the order that
/// keeps the engine probe ahead of the import's first call into libcrypto.
///
/// The install step, the config loader, and the engine probe are parameters so
/// a test can watch that order directly; production wiring is in [`run`].
///
/// # Errors
///
/// Whatever `install` returns, or the preflight errors described on
/// [`load_preflight_config`] and [`post_import_check`].
fn import_and_check<L, G, I>(
    opts: &EnrollOptions,
    check_opts: &crate::startup_check::StartupCheckOptions,
    load_config: L,
    probe_engine: G,
    install: I,
) -> Result<ImportOutcome, EnrollError>
where
    L: FnOnce(&Path) -> Result<ValidatedConfig, tessera_core::Error>,
    G: FnOnce(&Path) -> crate::startup_check::gost::EngineReadiness,
    I: FnOnce() -> Result<ImportOutcome, ImportError>,
{
    // Once, and ahead of the import: the first load of the engine is the one
    // the process keeps, so a second attempt after the import would answer
    // from that same latched result and could only ever contradict a host
    // where authentication works.
    let gost = opts.run_check.then(|| probe_engine(&opts.config));

    let outcome = install()?;

    if let Some(gost) = gost {
        // Now the config loads: this command has just created the artefacts a
        // freshly enrolled device's config names.
        let config = load_preflight_config(&opts.config, load_config)?;
        post_import_check(&config, gost, check_opts)?;
    }

    Ok(outcome)
}

/// Execute the enrollment. Imports the package (emitting the enriched
/// `device_enrolled` / `enrollment_rejected` audit event via the core, with the
/// resolved `host_id` prefix8 and an empty serial), then runs the post-import
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
    // The serial stays empty. Deriving it from the package `.p12` without the
    // PIN would be a guess about bytes nothing has vouched for: which
    // certificate the device authenticates with is decided by which one matches
    // the container's private key, and that key cannot be read without the
    // password. Whatever a password-free walk picks out instead is a property of
    // the container's labelling and layout, both of them chosen by whoever
    // assembled it — and the package is read here before the manifest signature
    // is checked, with no signature at all in standalone mode. The
    // `device_enrolled` event is long-lived and gets read when an incident is
    // reconstructed, so the field carries nothing until there is a source for it
    // covered by a signature.
    let serial = String::new();

    let ids = EnrollAuditIds {
        host_id_prefix8: &opts.host_id_prefix8,
        serial: &serial,
    };
    // The core is the single audit-emission point: it emits the enriched
    // `device_enrolled` on success (non-no-op) or `enrollment_rejected` on
    // failure, fail-closed. The post-import preflight reuses `tessera check`;
    // a failing config is fail-closed — the operator must fix it before the
    // device is trusted.
    let outcome = import_and_check(
        &opts,
        &crate::startup_check::StartupCheckOptions::default(),
        tessera_core::config::load_privileged_validated_config,
        probe_engine_before_import,
        || pkg.install_with_ids(&opts.paths, opts.os, pubkey_bytes.as_deref(), ids),
    )?;

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
    use crate::startup_check::test_config::{base_cfg, write_anchor};
    use crate::startup_check::StartupCheckOptions;
    use openssl::pkey::PKey;
    use openssl::sign::Signer;
    use sha2::{Digest, Sha256};
    use std::cell::{Cell, RefCell};
    use std::fmt::Write as _;
    use std::fs;
    use tempfile::TempDir;
    use tessera_core::gost::GostEngineError;

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
        assert!(
            report.serial.is_empty(),
            "the serial is not derived from the package: the same field feeds the \
             device_enrolled event, and nothing here has vouched for the container"
        );
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
        // run_check = true with a config path that cannot load → enrollment
        // fails and the error names the path and the reason (fail-closed).
        // The package itself imports fine first.
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
        let EnrollError::ConfigLoad { path, reason } = &err else {
            panic!("expected a config-load failure, got {err:?}");
        };
        assert_eq!(path, "/nonexistent/config.toml");
        assert!(!reason.is_empty(), "the operator needs the reason");
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

    thread_local! {
        /// Call journal shared by the injected engine probe (a plain `fn`
        /// pointer, so it cannot capture) and the install stub.
        static CALLS: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
        /// Whether the install stub has run, for the config loader that only
        /// succeeds once the artefacts it names exist.
        static INSTALLED: Cell<bool> = const { Cell::new(false) };
    }

    fn note(what: &'static str) {
        CALLS.with(|c| c.borrow_mut().push(what));
    }

    /// Config with GOST configured, so the engine is probed at all.
    fn gost_cfg(anchor: &Path) -> ValidatedConfig {
        let mut cfg = base_cfg(anchor, "pkcs12");
        cfg.gost_engine_path = Some(anchor.with_file_name("gost.so"));
        cfg.trust
            .allowed_signature_algorithms
            .insert("1.2.643.7.1.1.3.2".to_owned());
        cfg
    }

    /// Startup-check options confined to `tmp`. `gost_probe` stays unset: the
    /// enrollment pipeline probes the engine itself, ahead of the import, and
    /// the check consumes that readiness rather than probing again.
    fn check_opts(tmp: &Path) -> StartupCheckOptions {
        StartupCheckOptions {
            pam_d_root: tmp.join("pam.d"),
            fs_root: Some(tmp.to_path_buf()),
            kernel_parsec_probe: None,
            mrd_probe: None,
            gost_probe: None,
        }
    }

    /// The pre-import engine probe as the tests inject it: it notes the call
    /// and answers with `outcome`, standing in for a `dlopen` of a real
    /// engine module.
    fn engine_probe(
        outcome: crate::startup_check::gost::EnginePathProbe,
    ) -> impl FnOnce(&Path) -> crate::startup_check::gost::EngineReadiness {
        move |_| {
            crate::startup_check::gost::probe_path_with(Some(Path::new("/gost.so")), |path| {
                note("gost.probe");
                outcome(path)
            })
        }
    }

    fn enroll_opts(root: &Path, run_check: bool) -> EnrollOptions {
        EnrollOptions {
            import: root.join("package"),
            mode: ImportMode::Standalone,
            manifest_pubkey: None,
            os: RoleOs::Linux,
            paths: install_paths(root),
            host_id_prefix8: String::new(),
            run_check,
            config: root.join("config.toml"),
        }
    }

    fn stub_outcome() -> ImportOutcome {
        ImportOutcome {
            mode: ImportMode::Standalone,
            bundle_version: 0,
            baseline_established: false,
            no_op: false,
        }
    }

    /// The engine probe has to run before the import — verifying the
    /// enrollment manifest calls into libcrypto, and on Astra the first such
    /// call registers gost-engine ambiently from `openssl.cnf`, after which
    /// our own explicit load is refused. A probe left until after the import
    /// would fail the enrollment on a host where `tessera check` in a fresh
    /// process passes.
    ///
    /// The single `gost.probe` entry is the other half of the guarantee: the
    /// check consumes the readiness obtained up front instead of probing
    /// again once the import has touched OpenSSL.
    #[test]
    fn gost_engine_is_probed_before_the_import_runs() {
        CALLS.with(|c| c.borrow_mut().clear());

        let tmp = tempfile::tempdir().unwrap();
        let anchor = write_anchor(tmp.path());
        let opts = enroll_opts(tmp.path(), true);
        let check_opts = check_opts(tmp.path());

        let err = import_and_check(
            &opts,
            &check_opts,
            |_| Ok(gost_cfg(&anchor)),
            engine_probe(|_| {
                Err(GostEngineError::digest_unavailable(
                    "md_gost12_512 not registered after engine load",
                ))
            }),
            || {
                note("install");
                Ok(stub_outcome())
            },
        )
        .expect_err("a broken engine must fail the post-import check");

        assert!(matches!(err, EnrollError::PostCheckFailed), "{err:?}");
        let calls = CALLS.with(|c| c.borrow().clone());
        assert_eq!(calls, vec!["gost.probe", "install"], "{calls:?}");
    }

    /// The regression this ordering exists for: on a first managed enrollment
    /// the config names artefacts this very command creates
    /// (`/var/lib/tessera/device.crl`), so it does not load until the import
    /// is done. The engine probe must not be tied to that load — otherwise it
    /// lands behind the manifest verification, which is exactly where the
    /// ambient registration from `openssl.cnf` wins and a healthy host is
    /// refused with `gost_engine_load_failed` after its package is already
    /// installed.
    #[test]
    fn gost_engine_is_probed_before_the_import_when_the_config_loads_only_after_it() {
        CALLS.with(|c| c.borrow_mut().clear());
        INSTALLED.with(|i| i.set(false));

        let tmp = tempfile::tempdir().unwrap();
        let anchor = write_anchor(tmp.path());
        let opts = enroll_opts(tmp.path(), true);
        let check_opts = check_opts(tmp.path());

        let err = import_and_check(
            &opts,
            &check_opts,
            |_| {
                note("load_config");
                if INSTALLED.with(Cell::get) {
                    Ok(gost_cfg(&anchor))
                } else {
                    Err(tessera_core::Error::ConfigInvalid {
                        reason: "trust CRL path /var/lib/tessera/device.crl does not exist"
                            .to_owned(),
                    })
                }
            },
            engine_probe(|_| {
                Err(GostEngineError::digest_unavailable(
                    "md_gost12_512 not registered after engine load",
                ))
            }),
            || {
                note("install");
                INSTALLED.with(|i| i.set(true));
                Ok(stub_outcome())
            },
        )
        .expect_err("a broken engine must fail the post-import check");

        // The check ran on the config that only became loadable after the
        // import, and it consumed the readiness obtained before it.
        assert!(matches!(err, EnrollError::PostCheckFailed), "{err:?}");
        let calls = CALLS.with(|c| c.borrow().clone());
        assert_eq!(
            calls,
            vec!["gost.probe", "install", "load_config"],
            "the probe must precede the import even when the config is not \
             loadable yet, and it must happen exactly once: {calls:?}"
        );
    }

    /// `--skip-check` skips the preflight entirely: no config load, no engine
    /// load, and the import still runs.
    #[test]
    fn skipping_the_check_never_probes_the_engine() {
        CALLS.with(|c| c.borrow_mut().clear());

        let tmp = tempfile::tempdir().unwrap();
        let anchor = write_anchor(tmp.path());
        let opts = enroll_opts(tmp.path(), false);
        let check_opts = check_opts(tmp.path());

        let outcome = import_and_check(
            &opts,
            &check_opts,
            |_| {
                note("load_config");
                Ok(gost_cfg(&anchor))
            },
            engine_probe(|_| Ok(())),
            || {
                note("install");
                Ok(stub_outcome())
            },
        )
        .expect("no check, no failure");

        assert!(!outcome.no_op);
        let calls = CALLS.with(|c| c.borrow().clone());
        assert_eq!(calls, vec!["install"], "{calls:?}");
    }

    #[test]
    fn parse_os_rejects_unknown() {
        assert!(parse_os("bsd").is_err());
        assert_eq!(parse_os("astra").unwrap(), RoleOs::Astra);
    }
}
