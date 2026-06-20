//! Enrollment-package import core (`device-enrollment`, section 1).
//!
//! After `clone-image-bootstrap` flips the device to its per-host identity, the
//! device imports an *enrollment package*: a per-host PKCS#12 (`.p12`, PIN-
//! protected — placed as-is, never decrypted here) plus a bundle carrying the
//! device tags, the first role base, and (optionally) a CRL.
//!
//! # Two trust modes (parity with `role::store` / `tags::source`)
//!
//! - **Managed** ([`ImportMode::Managed`]): the bundle is a signed
//!   `manifest.toml`. Verification REUSES [`crate::role::verify_manifest`]
//!   wholesale — signature over the file bytes, anti-rollback against the
//!   single persisted `bundle_version` floor, and per-slice hashes. There is
//!   **no second anti-rollback counter**: the baseline and every later import
//!   share the role-store floor (`<persist_dir>/bundle.version`). The CRL, when
//!   present, is pinned in that same signed manifest
//!   ([`crate::role::ManifestCrl`]) and so inherits the signature and
//!   `bundle_version` without a second signature.
//! - **Standalone** ([`ImportMode::Standalone`]): no signature. The tags file,
//!   role slices, and CRL are laid out under filesystem-permission trust
//!   (root:root, dir `0755`, file `0644` — the sudoers.d model, parity with the
//!   standalone role-store). Deployment without a server MUST work.
//!
//! # Fail-closed atomicity
//!
//! Verification runs on a *staged* copy before any device path is touched, so a
//! broken signature, a rollback, or a CRL hash mismatch installs **nothing**.
//!
//! The commit ordering keeps the anti-rollback floor + role swap as the FINAL
//! durable mutation: every fallible single-file I/O (the tags, CRL, and `.p12`
//! temp writes — where ENOSPC / EROFS / permission failures surface) happens
//! FIRST. The single-file artefacts are then published with the same
//! `tmp → rename` idiom (each prior file moved aside to a `.bak`), and only
//! AFTER they are durably in place does [`crate::role::atomic_update`] advance
//! the floor and swap the role base. If that final step fails, the already-
//! published single-file artefacts are rolled back from their `.bak` siblings.
//! The invariant is that there is **no observable state where the roles or the
//! floor advanced while the CRL or `.p12` are stale**. A partial failure leaves
//! the device in its **prior** consistent state.
//!
//! # Trusted tags source
//!
//! Imported tags are written to the trusted `device-tags` path
//! ([`crate::tags::source`] reads exactly this file). An arbitrary local tag
//! config that did not arrive through a verified import (managed) or the
//! FS-perms-trusted file (standalone) is never consulted as a tag source.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::role::manifest::MANIFEST_FILENAME;
use crate::role::{self, atomic_update, ManifestError, RoleOs, RoleStoreError, UpdateTrust};

use super::audit;

/// Default on-disk path for the installed device CRL (PEM/DER bytes placed as
/// shipped). The revocation config points its CRL store at this path.
pub const DEFAULT_CRL_PATH: &str = "/var/lib/tessera/device.crl";
/// Default on-disk path for the installed per-host PKCS#12 bundle.
pub const DEFAULT_P12_PATH: &str = "/var/lib/tessera/host.p12";
/// Sanity cap on the CRL file size (1 MiB). A device CRL is small.
pub const MAX_CRL_BYTES: usize = 1024 * 1024;
/// Sanity cap on the per-host `.p12` size (256 KiB). It holds one key + chain.
pub const MAX_P12_BYTES: usize = 256 * 1024;
/// Directory mode for created device directories (root:root `0755`).
const DIR_MODE: u32 = 0o755;
/// File mode for installed non-secret artefacts (tags, roles, CRL) — `0644`.
const FILE_MODE: u32 = 0o644;
/// File mode for the installed `.p12` (PIN-protected, but key material — `0600`).
const P12_MODE: u32 = 0o600;

/// Trust mode for an import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportMode {
    /// Filesystem-permission trust; no signature (deployment without a server).
    Standalone,
    /// Signed-manifest trust; signature + anti-rollback `bundle_version`.
    Managed,
}

impl ImportMode {
    /// Audit-label for the `mode` field.
    fn label(self) -> &'static str {
        match self {
            ImportMode::Standalone => audit::MODE_STANDALONE,
            ImportMode::Managed => audit::MODE_MANAGED,
        }
    }
}

/// A parsed-but-not-yet-installed enrollment package rooted at a directory.
///
/// The package directory holds, by convention:
/// - managed: `manifest.toml` (tags + role pins + optional CRL pin) and the
///   role-slice `*.toml` files and the CRL file it pins;
/// - standalone: a `tags.toml` file, role-slice `*.toml` files, and an optional
///   CRL file;
/// - both: the per-host `<host>.p12`.
///
/// Parsing does **not** touch device paths and does **not** decrypt the `.p12`.
#[derive(Debug, Clone)]
pub struct EnrollmentPackage {
    /// Package root directory.
    root: PathBuf,
    /// Trust mode.
    mode: ImportMode,
    /// Per-host `.p12` file name within the package (relative, bare name).
    p12_file: String,
    /// CRL file name within the package, if the package ships one.
    crl_file: Option<String>,
}

/// Where an import installs each artefact on the device. Defaults match the
/// `role-store` / `tags::source` / revocation paths; tests override them onto a
/// tempdir.
#[derive(Debug, Clone)]
pub struct InstallPaths {
    /// Role-base directory (`role::store::DEFAULT_ROLES_DIR`).
    pub roles_dir: PathBuf,
    /// Trusted device-tags file (`tags::source::DEFAULT_TAGS_FILE`).
    pub tags_file: PathBuf,
    /// Installed CRL path ([`DEFAULT_CRL_PATH`]).
    pub crl_path: PathBuf,
    /// Installed per-host `.p12` path ([`DEFAULT_P12_PATH`]).
    pub p12_path: PathBuf,
    /// Anti-rollback persist dir holding `bundle.version`
    /// (`role::manifest::DEFAULT_PERSIST_DIR`); the SAME floor as the role
    /// store — no second counter.
    pub persist_dir: PathBuf,
}

impl Default for InstallPaths {
    fn default() -> Self {
        Self {
            roles_dir: PathBuf::from(role::DEFAULT_ROLES_DIR),
            tags_file: PathBuf::from(crate::tags::DEFAULT_TAGS_FILE),
            crl_path: PathBuf::from(DEFAULT_CRL_PATH),
            p12_path: PathBuf::from(DEFAULT_P12_PATH),
            persist_dir: PathBuf::from(role::manifest::DEFAULT_PERSIST_DIR),
        }
    }
}

/// Outcome of a successful import.
#[derive(Debug, Clone)]
pub struct ImportOutcome {
    /// Trust mode used.
    pub mode: ImportMode,
    /// Applied `bundle_version` (managed); `0` for standalone (no signed
    /// version exists).
    pub bundle_version: u64,
    /// `true` when this import established the anti-rollback baseline (managed
    /// only; always `false` for standalone).
    pub baseline_established: bool,
    /// `true` when nothing changed because the bundle was already applied
    /// (managed idempotent re-import of the same `bundle_version`).
    pub no_op: bool,
}

/// Errors from parsing or importing an enrollment package. Mirrors the
/// `role` / `tags` error style (thiserror, fail-closed).
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// The package root does not exist or is not a directory.
    #[error("enrollment package not found at {path}")]
    PackageMissing {
        /// Package path.
        path: String,
    },
    /// No per-host `.p12` was found in the package (exactly one is required).
    #[error("enrollment package has no per-host .p12")]
    NoP12,
    /// More than one `.p12` was found (ambiguous per-host identity).
    #[error("enrollment package has {count} .p12 files; expected exactly one")]
    MultipleP12 {
        /// How many were found.
        count: usize,
    },
    /// Managed package is missing its `manifest.toml`.
    #[error("managed enrollment package has no manifest.toml")]
    NoManifest,
    /// Standalone package is missing its `tags.toml`.
    #[error("standalone enrollment package has no tags.toml")]
    NoTagsFile,
    /// A managed install was requested without a trusted verification key.
    #[error("managed enrollment requires a trusted verification key")]
    MissingKey,
    /// A package file name is unsafe (path separator / traversal).
    #[error("enrollment package entry {name:?} is not a bare file name")]
    UnsafeName {
        /// The offending name.
        name: String,
    },
    /// An artefact exceeds its size cap.
    #[error("{artefact} is {size} bytes, exceeds the {max}-byte cap")]
    Oversize {
        /// Which artefact.
        artefact: &'static str,
        /// Actual size.
        size: usize,
        /// Cap.
        max: usize,
    },
    /// The CRL file did not match the SHA-256 pinned in the signed manifest.
    #[error("CRL hash mismatch: signed pin does not match the shipped CRL")]
    CrlHashMismatch,
    /// The `.p12` did not match the SHA-256 pinned in the signed manifest.
    #[error("p12 hash mismatch: signed pin does not match the shipped .p12")]
    P12HashMismatch,
    /// The manifest pins a CRL but the file is absent from the package.
    #[error("manifest pins CRL {file:?} but it is missing from the package")]
    CrlMissing {
        /// Pinned file name.
        file: String,
    },
    /// Managed manifest verification failed (signature / anti-rollback / hash).
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// Role-base validation / install failed.
    #[error(transparent)]
    RoleStore(#[from] RoleStoreError),
    /// Filesystem / I/O error during install (the prior state is restored).
    #[error("enrollment I/O error at {path}: {reason}")]
    Io {
        /// Path being touched.
        path: String,
        /// Underlying I/O error message.
        reason: String,
    },
}

impl EnrollmentPackage {
    /// Parse the package rooted at `root` for the given `mode`.
    ///
    /// Locates exactly one `.p12`, the mode-required bundle file
    /// (`manifest.toml` managed / `tags.toml` standalone), and an optional CRL.
    /// Does not touch device paths and does not decrypt the `.p12`.
    ///
    /// # Errors
    ///
    /// [`ImportError::PackageMissing`], [`ImportError::NoP12`] /
    /// [`ImportError::MultipleP12`], [`ImportError::NoManifest`] /
    /// [`ImportError::NoTagsFile`], or [`ImportError::Io`].
    pub fn parse(root: &Path, mode: ImportMode) -> Result<Self, ImportError> {
        if !root.is_dir() {
            return Err(ImportError::PackageMissing {
                path: root.display().to_string(),
            });
        }

        let mut p12s: Vec<String> = Vec::new();
        let mut crl_file: Option<String> = None;
        let entries = fs::read_dir(root).map_err(|e| ImportError::Io {
            path: root.display().to_string(),
            reason: e.to_string(),
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| ImportError::Io {
                path: root.display().to_string(),
                reason: e.to_string(),
            })?;
            let path = entry.path();
            let is_file = matches!(entry.file_type(), Ok(ft) if ft.is_file());
            if !is_file {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if has_ext(&path, "p12") {
                p12s.push(name.to_owned());
            } else if has_ext(&path, "crl") {
                crl_file = Some(name.to_owned());
            }
        }

        match p12s.len() {
            0 => return Err(ImportError::NoP12),
            1 => {}
            n => return Err(ImportError::MultipleP12 { count: n }),
        }
        // Indexing is guarded by the match above; use `into_iter().next()`
        // to avoid any indexing in non-test code.
        let p12_file = p12s.into_iter().next().ok_or(ImportError::NoP12)?;

        match mode {
            ImportMode::Managed => {
                if !root.join(MANIFEST_FILENAME).is_file() {
                    return Err(ImportError::NoManifest);
                }
            }
            ImportMode::Standalone => {
                if !root.join("tags.toml").is_file() {
                    return Err(ImportError::NoTagsFile);
                }
            }
        }

        Ok(Self {
            root: root.to_path_buf(),
            mode,
            p12_file,
            crl_file,
        })
    }

    /// Trust mode of this package.
    #[must_use]
    pub fn mode(&self) -> ImportMode {
        self.mode
    }

    /// The per-host `.p12` file name within the package.
    #[must_use]
    pub fn p12_file(&self) -> &str {
        &self.p12_file
    }

    /// Install this package onto the device at `paths`, for `device_os`.
    ///
    /// `trusted_pubkey` is required for [`ImportMode::Managed`] (the manifest
    /// verification key) and ignored for [`ImportMode::Standalone`]. Verifies on
    /// a staged copy first (managed: [`role::verify_manifest`] + CRL pin;
    /// standalone: schema + FS-perms), then atomically publishes the role base,
    /// tags, CRL, and `.p12`. A failure at any step leaves the device in its
    /// prior consistent state (fail-closed). A managed re-import of the
    /// already-applied `bundle_version` is a no-op.
    ///
    /// # Errors
    ///
    /// Any [`ImportError`]; on `Err` the device is unchanged. A managed install
    /// without a `trusted_pubkey` is [`ImportError::MissingKey`].
    pub fn install(
        &self,
        paths: &InstallPaths,
        device_os: RoleOs,
        trusted_pubkey: Option<&[u8]>,
    ) -> Result<ImportOutcome, ImportError> {
        match self.mode {
            ImportMode::Managed => {
                let key = trusted_pubkey.ok_or(ImportError::MissingKey)?;
                self.install_managed(paths, device_os, key)
            }
            ImportMode::Standalone => self.install_standalone(paths, device_os),
        }
    }

    /// Standalone install: validate role slices + tags file under FS-perms,
    /// then publish atomically (no signature).
    fn install_standalone(
        &self,
        paths: &InstallPaths,
        device_os: RoleOs,
    ) -> Result<ImportOutcome, ImportError> {
        // Stage the role base (copy slices), validate it, swap into place.
        let staged = stage_dir(&paths.roles_dir, "roles")?;
        let stage_guard = StageGuard::new(staged.clone());
        // Standalone: skip any manifest.toml so a planted one cannot later be
        // mistaken for a trusted signed bundle by `load_managed`.
        copy_role_slices(&self.root, &staged, false)?;

        let install_result = (|| -> Result<(), ImportError> {
            // Stage ALL single-file artefacts FIRST (tags, CRL, .p12): write +
            // fsync + chmod the temp files here, so the fallible I/O happens
            // BEFORE the role base is swapped into place.
            let mut tx = FileTx::new();
            let tags_bytes = read_capped(
                &self.root.join("tags.toml"),
                "tags",
                crate::tags::MAX_TAGS_BYTES,
            )?;
            tx.stage(&paths.tags_file, &tags_bytes, FILE_MODE)?;
            self.stage_crl(&mut tx, paths)?;
            // Standalone has no signed pin; trust is FS-perms.
            self.stage_p12(&mut tx, paths, None)?;

            // Publish the single-file artefacts (each with its own `.bak`), but
            // keep the backups so they can be undone if the role swap fails.
            let committed = tx.commit_keeping_backups()?;

            // FINAL durable mutation: validate + swap the role base. On failure
            // restore the single-file artefacts to their prior state.
            if let Err(e) = atomic_update(
                &paths.roles_dir,
                &staged,
                device_os,
                &UpdateTrust::Standalone,
            ) {
                committed.rollback();
                return Err(ImportError::from(e));
            }
            committed.confirm();
            Ok(())
        })();

        match install_result {
            Ok(()) => {
                stage_guard.disarm();
                audit::emit_device_enrolled(self.mode.label(), 0);
                Ok(ImportOutcome {
                    mode: self.mode,
                    bundle_version: 0,
                    baseline_established: false,
                    no_op: false,
                })
            }
            Err(e) => {
                audit::emit_enrollment_rejected(reason_for(&e));
                Err(e)
            }
        }
    }

    /// Stage the CRL file (managed: pin already checked by caller; standalone:
    /// trust is FS-perms). No-op when the package ships no CRL.
    fn stage_crl(&self, tx: &mut FileTx, paths: &InstallPaths) -> Result<(), ImportError> {
        let Some(crl_file) = &self.crl_file else {
            return Ok(());
        };
        ensure_bare_name(crl_file)?;
        let crl_bytes = read_capped(&self.root.join(crl_file), "crl", MAX_CRL_BYTES)?;
        tx.stage(&paths.crl_path, &crl_bytes, FILE_MODE)
    }

    /// Stage the per-host `.p12` (placed as-is, never decrypted; mode `0600`).
    ///
    /// `pin_sha256`, when present (managed manifests carrying a `p12_sha256`),
    /// is verified against the SHA-256 of the bytes read here — the same single
    /// in-memory buffer that is staged, so there is no check-then-use re-read.
    fn stage_p12(
        &self,
        tx: &mut FileTx,
        paths: &InstallPaths,
        pin_sha256: Option<&str>,
    ) -> Result<(), ImportError> {
        ensure_bare_name(&self.p12_file)?;
        let p12_bytes = read_capped(&self.root.join(&self.p12_file), "p12", MAX_P12_BYTES)?;
        if let Some(pin) = pin_sha256 {
            let actual = hex::encode(Sha256::digest(&p12_bytes));
            if !actual.eq_ignore_ascii_case(pin.trim()) {
                return Err(ImportError::P12HashMismatch);
            }
        }
        tx.stage(&paths.p12_path, &p12_bytes, P12_MODE)
    }
}

// Map an import error to the audit reason for `enrollment_rejected`.
fn reason_for(e: &ImportError) -> &'static str {
    match e {
        ImportError::Manifest(_) | ImportError::P12HashMismatch => audit::REASON_MANIFEST,
        ImportError::CrlHashMismatch | ImportError::CrlMissing { .. } => audit::REASON_CRL,
        _ => audit::REASON_INSTALL,
    }
}

/// Best-effort removal of a temp/leftover file; a not-found is fine and any
/// other failure is logged, never propagated (these run on cleanup paths).
fn best_effort_remove(path: &Path) {
    if let Err(e) = fs::remove_file(path) {
        if e.kind() != io::ErrorKind::NotFound {
            tracing::warn!(
                target: "enrollment.audit",
                path = %path.display(),
                error = %e,
                "failed to remove enrollment temp/leftover file"
            );
        }
    }
}

/// Best-effort restore of the anti-rollback floor to its `prior` value on a
/// failure path. `atomic_update` persists the new floor just before its
/// directory rename, so a rename failure can leave the floor advanced while the
/// roles reverted; this puts it back. `None` means there was no prior floor
/// (the failed import would have been the baseline) → remove the file so the
/// "absent" TOFU state is restored. Errors are logged, never propagated.
fn restore_prior_floor(persist_dir: &Path, prior: Option<u64>) {
    if let Some(v) = prior {
        if let Err(e) = role::persist_bundle_version(persist_dir, v) {
            tracing::error!(
                target: "enrollment.audit",
                error = %e,
                "failed to restore prior bundle.version floor during rollback"
            );
        }
    } else {
        // No prior floor: the failed import would have been the baseline.
        // Remove the file so the "absent" TOFU state is restored.
        let path = persist_dir.join(role::manifest::BUNDLE_VERSION_FILENAME);
        if let Err(e) = fs::remove_file(&path) {
            if e.kind() != io::ErrorKind::NotFound {
                tracing::error!(
                    target: "enrollment.audit",
                    path = %path.display(),
                    error = %e,
                    "failed to remove baseline bundle.version floor during rollback"
                );
            }
        }
    }
}

/// Best-effort restore rename (`from → to`) on a rollback path; logged on
/// failure, never propagated.
fn best_effort_restore(from: &Path, to: &Path) {
    if let Err(e) = fs::rename(from, to) {
        tracing::error!(
            target: "enrollment.audit",
            path = %to.display(),
            error = %e,
            "failed to restore enrollment file during rollback"
        );
    }
}

/// Whether `path` has the (ASCII-case-insensitive) extension `ext` (no dot).
fn has_ext(path: &Path, ext: &str) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

/// Reject a name that is not a bare file name (contains a path separator, is
/// empty, or is a `.`/`..` traversal component).
fn ensure_bare_name(name: &str) -> Result<(), ImportError> {
    let bad =
        name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\\');
    if bad {
        Err(ImportError::UnsafeName {
            name: name.to_owned(),
        })
    } else {
        Ok(())
    }
}

/// Read `path` with a size cap, mapping I/O and oversize to [`ImportError`].
fn read_capped(path: &Path, artefact: &'static str, max: usize) -> Result<Vec<u8>, ImportError> {
    let bytes = fs::read(path).map_err(|e| ImportError::Io {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;
    if bytes.len() > max {
        return Err(ImportError::Oversize {
            artefact,
            size: bytes.len(),
            max,
        });
    }
    Ok(bytes)
}

/// Create (if needed) the parent dir of `target` with `0755` and return a fresh
/// staged sibling dir name `<target>.staged.<pid>` on the same filesystem.
fn stage_dir(target: &Path, _kind: &str) -> Result<PathBuf, ImportError> {
    if let Some(parent) = target.parent() {
        ensure_dir(parent)?;
    }
    let mut name = target.file_name().map_or_else(
        || std::ffi::OsString::from("roles"),
        std::ffi::OsStr::to_os_string,
    );
    name.push(format!(".staged.{}", std::process::id()));
    let staged = match target.parent() {
        Some(parent) => parent.join(name),
        None => PathBuf::from(name),
    };
    // A leftover staged dir from a crashed run must not poison this one.
    if staged.exists() {
        fs::remove_dir_all(&staged).map_err(|e| ImportError::Io {
            path: staged.display().to_string(),
            reason: e.to_string(),
        })?;
    }
    fs::create_dir(&staged).map_err(|e| ImportError::Io {
        path: staged.display().to_string(),
        reason: e.to_string(),
    })?;
    set_mode(&staged, DIR_MODE)?;
    Ok(staged)
}

/// Ensure `dir` exists with mode `0755` (created if absent).
fn ensure_dir(dir: &Path) -> Result<(), ImportError> {
    if dir.exists() {
        return Ok(());
    }
    fs::create_dir_all(dir).map_err(|e| ImportError::Io {
        path: dir.display().to_string(),
        reason: e.to_string(),
    })?;
    set_mode(dir, DIR_MODE)
}

/// Set a path's mode, mapping the error to [`ImportError::Io`].
fn set_mode(path: &Path, mode: u32) -> Result<(), ImportError> {
    fs::set_permissions(path, PermissionsExt::from_mode(mode)).map_err(|e| ImportError::Io {
        path: path.display().to_string(),
        reason: e.to_string(),
    })
}

/// Copy the role-slice `*.toml` files from `src` into `dst`. Skips the tags
/// file and the `.p12`/`.crl`.
///
/// `include_manifest` controls `manifest.toml`: managed installs copy it (the
/// signed manifest must ride into the role dir for `tags::source`); standalone
/// installs SKIP it, so a `manifest.toml` planted in an unsigned package can
/// never be picked up later by `load_managed` as if it were trusted.
fn copy_role_slices(src: &Path, dst: &Path, include_manifest: bool) -> Result<(), ImportError> {
    let entries = fs::read_dir(src).map_err(|e| ImportError::Io {
        path: src.display().to_string(),
        reason: e.to_string(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| ImportError::Io {
            path: src.display().to_string(),
            reason: e.to_string(),
        })?;
        let path = entry.path();
        let is_file = matches!(entry.file_type(), Ok(ft) if ft.is_file());
        if !is_file {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name == MANIFEST_FILENAME && !include_manifest {
            // Standalone: never carry a (possibly planted) manifest into the
            // trusted role dir.
            continue;
        }
        // Only role slices and the manifest belong in the role dir.
        let is_slice = has_ext(&path, "toml") && name != "tags.toml";
        if !is_slice {
            continue;
        }
        // The manifest is a single aggregate file with a far larger cap than an
        // individual slice; applying the slice cap to it spuriously rejects a
        // valid 64–256 KiB manifest.
        let (artefact, cap) = if name == MANIFEST_FILENAME {
            ("manifest", role::manifest::MAX_MANIFEST_BYTES)
        } else {
            ("slice", role::schema::MAX_SLICE_BYTES)
        };
        let bytes = read_capped(&path, artefact, cap)?;
        let dst_path = dst.join(name);
        write_atomic(&dst_path, &bytes, FILE_MODE)?;
    }
    Ok(())
}

/// Atomic single-file write (`tmp → fsync → rename`, then pin mode). Mirrors
/// `role::manifest::persist_bundle_version`.
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), ImportError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("artefact");
    let tmp = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let result = (|| -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::set_permissions(&tmp, PermissionsExt::from_mode(mode))?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        best_effort_remove(&tmp);
    }
    result.map_err(|e| ImportError::Io {
        path: path.display().to_string(),
        reason: e.to_string(),
    })
}

/// A transactional installer for single-file artefacts: each `stage` writes the
/// new content to a temp file and records the prior file (moved aside to
/// `<path>.bak`). [`FileTx::commit`] renames every temp into place; on a
/// mid-commit failure every already-committed file is rolled back from its
/// `.bak` and the device is left in its prior state.
struct FileTx {
    /// One pending file install: (final path, temp path, optional `.bak`).
    pending: Vec<PendingFile>,
}

/// A single staged file install within a [`FileTx`].
struct PendingFile {
    /// Final destination.
    final_path: PathBuf,
    /// Temp file holding the new bytes (same dir as `final_path`).
    tmp_path: PathBuf,
    /// `.bak` of the prior file, if one existed.
    bak_path: Option<PathBuf>,
    /// Whether the prior file existed (so commit knows to expect a `.bak`).
    had_prior: bool,
}

impl FileTx {
    fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    /// Stage `bytes` for `final_path` (write temp, do not publish yet).
    fn stage(&mut self, final_path: &Path, bytes: &[u8], mode: u32) -> Result<(), ImportError> {
        if let Some(parent) = final_path.parent() {
            ensure_dir(parent)?;
        }
        let parent = final_path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = final_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("artefact");
        let tmp_path = parent.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            self.pending.len()
        ));
        // Write the temp file (mode pinned).
        let result = (|| -> io::Result<()> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(mode)
                .open(&tmp_path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::set_permissions(&tmp_path, PermissionsExt::from_mode(mode))
        })();
        if let Err(e) = result {
            best_effort_remove(&tmp_path);
            return Err(ImportError::Io {
                path: tmp_path.display().to_string(),
                reason: e.to_string(),
            });
        }
        let had_prior = final_path.exists();
        let bak_path = if had_prior {
            Some(parent.join(format!("{file_name}.bak")))
        } else {
            None
        };
        self.pending.push(PendingFile {
            final_path: final_path.to_path_buf(),
            tmp_path,
            bak_path,
            had_prior,
        });
        Ok(())
    }

    /// Publish every staged file but KEEP each prior file's `.bak` sibling so
    /// the whole set can still be rolled back by a LATER step (the role swap +
    /// floor persist). On a mid-commit error, roll back all already-committed
    /// files from their `.bak` siblings and return the error (fail-closed).
    ///
    /// On success returns a [`CommittedTx`]: the caller MUST call either
    /// [`CommittedTx::confirm`] (later step succeeded — drop the `.bak`s) or
    /// [`CommittedTx::rollback`] (later step failed — restore from `.bak`s).
    fn commit_keeping_backups(mut self) -> Result<CommittedTx, ImportError> {
        let mut committed: Vec<PendingFile> = Vec::with_capacity(self.pending.len());
        for item in std::mem::take(&mut self.pending) {
            if let Err(e) = Self::publish_one(&item) {
                Self::rollback(&committed);
                Self::cleanup_remaining(&item);
                return Err(e);
            }
            committed.push(item);
        }
        Ok(CommittedTx { committed })
    }

    /// Publish one staged file: move prior aside to `.bak`, rename temp in.
    fn publish_one(item: &PendingFile) -> Result<(), ImportError> {
        if item.had_prior {
            if let Some(bak) = &item.bak_path {
                fs::rename(&item.final_path, bak).map_err(|e| ImportError::Io {
                    path: item.final_path.display().to_string(),
                    reason: e.to_string(),
                })?;
            }
        }
        match fs::rename(&item.tmp_path, &item.final_path) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Restore this file's prior content before surfacing the error.
                if item.had_prior {
                    if let Some(bak) = &item.bak_path {
                        best_effort_restore(bak, &item.final_path);
                    }
                }
                Err(ImportError::Io {
                    path: item.final_path.display().to_string(),
                    reason: e.to_string(),
                })
            }
        }
    }

    /// Restore already-committed files from their `.bak` siblings.
    fn rollback(committed: &[PendingFile]) {
        for item in committed {
            if item.had_prior {
                if let Some(bak) = &item.bak_path {
                    best_effort_restore(bak, &item.final_path);
                }
            } else {
                // No prior: the file we wrote must be removed to restore
                // "absent" state.
                best_effort_remove(&item.final_path);
            }
        }
    }

    /// Remove the temp of a failed (uncommitted) item.
    fn cleanup_remaining(item: &PendingFile) {
        best_effort_remove(&item.tmp_path);
    }
}

impl Drop for FileTx {
    fn drop(&mut self) {
        // Any pending (uncommitted) temp files are abandoned — remove them.
        for item in &self.pending {
            best_effort_remove(&item.tmp_path);
        }
    }
}

/// A [`FileTx`] whose temp files have been renamed into place, but whose prior
/// files are still held aside as `.bak` siblings so a LATER step (the role swap
/// and floor persist, which must be the final durable mutation) can still undo
/// the whole single-file set. The caller MUST resolve it by calling either
/// `confirm` (the later step succeeded, drop the `.bak`s) or `rollback` (it
/// failed, restore the prior bytes).
#[must_use = "a CommittedTx must be confirmed or rolled back"]
struct CommittedTx {
    /// Published files whose `.bak` siblings are still present.
    committed: Vec<PendingFile>,
}

impl CommittedTx {
    /// The later step succeeded: drop every retained `.bak` sibling.
    fn confirm(self) {
        for item in &self.committed {
            if let Some(bak) = &item.bak_path {
                if let Err(e) = fs::remove_file(bak) {
                    if e.kind() != io::ErrorKind::NotFound {
                        tracing::warn!(
                            target: "enrollment.audit",
                            path = %bak.display(),
                            error = %e,
                            "failed to remove enrollment .bak after commit"
                        );
                    }
                }
            }
        }
    }

    /// The later step failed: restore every published file from its `.bak`
    /// sibling (or remove it when there was no prior file) so the device is
    /// fully back in its prior state.
    fn rollback(self) {
        FileTx::rollback(&self.committed);
    }
}

/// RAII cleanup of a staged role directory on the error path.
struct StageGuard {
    /// Staged directory to remove on drop unless disarmed.
    dir: Option<PathBuf>,
}

impl StageGuard {
    fn new(dir: PathBuf) -> Self {
        Self { dir: Some(dir) }
    }

    /// Disarm (a successful swap consumes the staged dir).
    fn disarm(mut self) {
        self.dir = None;
    }
}

impl Drop for StageGuard {
    fn drop(&mut self) {
        if let Some(dir) = &self.dir {
            role::cleanup_staged(dir);
        }
    }
}

impl EnrollmentPackage {
    /// Read the CRL named by a verified (signature-covered) manifest pin
    /// EXACTLY ONCE, verify its SHA-256 against the pin on those in-memory
    /// bytes, and return the verified bytes for staging. Reading once and
    /// staging the same buffer closes the check-then-use TOCTOU window: on
    /// attacker-writable removable media the file could otherwise change
    /// between a verify-read and a separate install-read. Fail-closed.
    fn read_pinned_crl(&self, pin: &role::ManifestCrl) -> Result<Vec<u8>, ImportError> {
        ensure_bare_name(&pin.file).map_err(|_| ImportError::UnsafeName {
            name: pin.file.clone(),
        })?;
        let crl_path = self.root.join(&pin.file);
        let bytes = match fs::read(&crl_path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(ImportError::CrlMissing {
                    file: pin.file.clone(),
                })
            }
            Err(e) => {
                return Err(ImportError::Io {
                    path: crl_path.display().to_string(),
                    reason: e.to_string(),
                })
            }
        };
        if bytes.len() > MAX_CRL_BYTES {
            return Err(ImportError::Oversize {
                artefact: "crl",
                size: bytes.len(),
                max: MAX_CRL_BYTES,
            });
        }
        let actual = hex::encode(Sha256::digest(&bytes));
        if actual.eq_ignore_ascii_case(pin.sha256.trim()) {
            Ok(bytes)
        } else {
            Err(ImportError::CrlHashMismatch)
        }
    }

    /// Managed install with an explicit trusted verification key.
    ///
    /// Flow (every verification reuses the role-store primitives — no forked
    /// crypto, no second anti-rollback counter):
    ///
    /// 1. Peek the manifest's `bundle_version`; if it equals the persisted
    ///    floor, the bundle is already applied → idempotent no-op.
    /// 2. Stage the role base + manifest into a sibling dir.
    /// 3. **Pre-validate on the staged copy without mutating the device or the
    ///    floor**: [`role::verify_signature`] over [`role::signed_payload`]
    ///    (the exact primitives `verify_manifest` uses), an anti-rollback check
    ///    against [`role::last_accepted_bundle_version`], and the CRL pin —
    ///    verified on the CRL bytes read ONCE (no check-then-use re-read). A
    ///    failure here installs nothing and does not touch the floor.
    /// 4. Stage the CRL + `.p12` temp files (the fallible I/O — ENOSPC / EROFS /
    ///    permission — happens here, before anything is durably swapped) and
    ///    publish them keeping each prior file's `.bak`.
    /// 5. [`atomic_update`] with [`UpdateTrust::Managed`] performs the single
    ///    authoritative verification + `bundle_version` persist + role swap. It
    ///    is the FINAL durable mutation, so the floor (the SAME shared
    ///    `<persist_dir>/bundle.version` — no second counter) never advances
    ///    while the CRL/.p12 are stale. If it fails, the published CRL/.p12 are
    ///    rolled back from their `.bak` siblings to the prior state.
    fn install_managed(
        &self,
        paths: &InstallPaths,
        device_os: RoleOs,
        trusted_pubkey: &[u8],
    ) -> Result<ImportOutcome, ImportError> {
        // The anti-rollback floor lives under persist_dir; ensure it exists so
        // verify_manifest's persist step can write bundle.version.
        ensure_dir(&paths.persist_dir)?;

        let manifest_bytes = read_capped(
            &self.root.join(MANIFEST_FILENAME),
            "manifest",
            role::manifest::MAX_MANIFEST_BYTES,
        )?;
        let manifest = role::parse_manifest(&manifest_bytes)?;
        let already =
            role::last_accepted_bundle_version(&paths.persist_dir).map_err(ImportError::from)?;
        let baseline_established = already.is_none();

        // 1) Idempotent no-op: same version already applied.
        if already == Some(manifest.bundle_version) {
            return Ok(ImportOutcome {
                mode: self.mode,
                bundle_version: manifest.bundle_version,
                baseline_established: false,
                no_op: true,
            });
        }

        // 2) Stage the role base + manifest.
        let staged = stage_dir(&paths.roles_dir, "roles")?;
        let stage_guard = StageGuard::new(staged.clone());
        // Managed: the signed manifest must ride into the role dir so
        // `tags::source::load_managed` can re-verify it against the same key.
        copy_role_slices(&self.root, &staged, true)?;

        let outcome = (|| -> Result<ImportOutcome, ImportError> {
            // 3) Pre-validate WITHOUT touching the floor or the device.
            //    Signature over the file bytes (reusing the role-store
            //    primitives), anti-rollback against the persisted floor, and
            //    the CRL pin. This guarantees a bad signature / rollback / CRL
            //    installs nothing and leaves the anti-rollback floor untouched.
            //
            //    The CRL pin is checked on the SAME in-memory bytes that get
            //    staged below (read-once, no TOCTOU re-read from removable
            //    media).
            let payload = role::signed_payload(&manifest_bytes)?;
            role::verify_signature(&payload, &manifest.signature, trusted_pubkey)?;
            if let Some(prev) = already {
                if manifest.bundle_version < prev {
                    return Err(ImportError::Manifest(ManifestError::Rollback {
                        found: manifest.bundle_version,
                        persisted: prev,
                    }));
                }
            }
            let crl_bytes = match &manifest.crl {
                Some(pin) => Some(self.read_pinned_crl(pin)?),
                None => None,
            };

            // 4) Stage ALL single-file artefacts FIRST: the CRL and the .p12
            //    temp files are written+fsync'd+chmod'd here, so the fallible
            //    I/O (ENOSPC / EROFS / permission) happens BEFORE anything is
            //    durably swapped or the floor advances.
            let mut tx = FileTx::new();
            if let Some(bytes) = &crl_bytes {
                tx.stage(&paths.crl_path, bytes, FILE_MODE)?;
            }
            // Verify the .p12 against the optional signed pin (closes the last
            // otherwise-unauthenticated managed byte stream) on the same bytes
            // that get staged.
            self.stage_p12(&mut tx, paths, manifest.p12_sha256.as_deref())?;

            // 5) Publish the CRL + .p12 (each gets its own `.bak`), but KEEP
            //    those backups so the whole single-file set can still be undone
            //    if the FINAL role swap / floor persist fails below.
            let committed = tx.commit_keeping_backups()?;

            // 6) FINAL durable mutation: authoritative verify + persist(floor) +
            //    role swap, via the reused atomic_update. This is the LAST step,
            //    so the floor never advances unless the CRL + .p12 are already
            //    durably in place. On failure, roll the CRL/.p12 back to prior
            //    AND restore the prior floor: atomic_update persists the floor
            //    just before its directory rename, so a rename failure could
            //    otherwise leave the floor advanced while the roles reverted.
            if let Err(e) = atomic_update(
                &paths.roles_dir,
                &staged,
                device_os,
                &UpdateTrust::Managed {
                    trusted_pubkey,
                    persist_dir: &paths.persist_dir,
                },
            ) {
                committed.rollback();
                restore_prior_floor(&paths.persist_dir, already);
                return Err(ImportError::from(e));
            }
            committed.confirm();

            Ok(ImportOutcome {
                mode: self.mode,
                bundle_version: manifest.bundle_version,
                baseline_established,
                no_op: false,
            })
        })();

        match outcome {
            Ok(o) => {
                stage_guard.disarm();
                audit::emit_device_enrolled(self.mode.label(), o.bundle_version);
                Ok(o)
            }
            Err(e) => {
                audit::emit_enrollment_rejected(reason_for(&e));
                Err(e)
            }
        }
    }
}

/// Read the trusted device-tags for the installed managed bundle.
///
/// After a managed install the tags live in the installed `manifest.toml`
/// under `roles_dir`; this reuses [`crate::tags::source::load_managed`] against
/// the SAME signature + floor (no re-verification fork). Provided so callers
/// can confirm the imported tags are readable via the trusted source.
///
/// # Errors
///
/// Propagates [`crate::tags::TagsSourceError`].
pub fn installed_managed_tags(
    paths: &InstallPaths,
    device_os: RoleOs,
    trusted_pubkey: &[u8],
) -> Result<crate::tags::DeviceTags, crate::tags::TagsSourceError> {
    crate::tags::load_managed(
        &paths.roles_dir,
        device_os,
        trusted_pubkey,
        &paths.persist_dir,
    )
}

#[cfg(test)]
#[path = "import_tests.rs"]
mod tests;
