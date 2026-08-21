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
use std::path::{Path, PathBuf};

use secrecy::SecretString;
use sha2::{Digest, Sha256};

use crate::role::manifest::MANIFEST_FILENAME;
use crate::role::{
    self, atomic_update, ManifestError, RoleOs, RoleStoreError, SystemAccounts, UpdateTrust,
    DEFAULT_ACCOUNT_LOOKUP_TIMEOUT,
};

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

/// Everything an import needs in order to accept the Codes part of a package.
///
/// Handed in rather than configured, because both of its parts are decisions of
/// the operator running the import: where this device keeps its Codes artefacts
/// and the PIN the delivery container was closed with. An import without this
/// value ignores the Codes part of a package entirely — which is what a fleet
/// that has not enabled the method wants, and what every caller predating the
/// method gets for free.
#[derive(Debug, Clone)]
pub struct CodesImport<'a> {
    /// Where the artefacts are to live on the device.
    pub paths: crate::codes::CodesPaths,
    /// PIN that opens the delivery container.
    ///
    /// Never carried by the package: a container whose password travels beside
    /// it is not a protected container. `None` is meaningful — a package that
    /// rotates tickets alone needs no PIN — and a package that does carry a
    /// container is then refused with [`ImportError::CodesPinRequired`] rather
    /// than half-applied.
    pub container_pin: Option<&'a SecretString>,
    /// Path to the GOST engine, forwarded to the container.
    pub gost_engine_path: Option<&'a Path>,
    /// Whether the finished store is walked with the ownership policy a login
    /// applies.
    ///
    /// A device enrols with [`crate::codes::artefacts::StoreCheck::Enforced`];
    /// the value exists because a store under a temporary directory cannot
    /// satisfy any ownership policy, which is the same reason the login path
    /// has both [`crate::codes::CodeMethod::open`] and
    /// [`crate::codes::CodeMethod::open_privileged`].
    pub store_check: crate::codes::artefacts::StoreCheck,
    /// Key epoch the configuration of this device runs on, when it could be
    /// read.
    ///
    /// The floor a device with no epoch file has: without it a delivery naming
    /// an older epoch is written down, and every login afterwards refuses
    /// because the configuration is ahead of the store. [`None`] where the
    /// store was named on the command line and the configuration could not be
    /// loaded — there is nothing to compare against then, and inventing a floor
    /// would refuse deliveries a fleet has every right to apply.
    pub configured_epoch: Option<crate::codes::Epoch>,
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
    /// What the Codes part of the package did, when the package carried one and
    /// the caller asked for it to be applied. `None` covers both "no Codes part
    /// in the package" (an Access-only fleet) and "the caller did not ask" —
    /// neither is a failure.
    pub codes: Option<crate::codes::artefacts::Applied>,
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
    #[error("{artefact} exceeds the {max}-byte cap (the read stopped after {read} bytes)")]
    Oversize {
        /// Which artefact.
        artefact: &'static str,
        /// How many bytes were read before the read was stopped; the file is at
        /// least this large, and how much larger is deliberately not measured.
        read: usize,
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
    /// The Codes section of the package does not hold what its format
    /// describes.
    #[error("the Codes part of the package is invalid: {reason}")]
    CodesSection {
        /// What was wrong with it.
        reason: String,
    },
    /// A managed package names a Codes file without pinning its hash.
    #[error("managed enrollment names Codes file {file:?} without a sha256 pin")]
    CodesUnpinned {
        /// The unpinned file.
        file: String,
    },
    /// A Codes file did not match the SHA-256 the package pins it at.
    #[error("Codes hash mismatch: the pin does not match the shipped {file:?}")]
    CodesHashMismatch {
        /// The offending file.
        file: String,
    },
    /// The Codes section names a file that is absent from the package.
    #[error("the Codes part names {file:?} but it is missing from the package")]
    CodesMissing {
        /// The named file.
        file: String,
    },
    /// The package carries a Codes key container and the import was not given
    /// the PIN that opens it.
    #[error("the package carries a Codes key container and no PIN was supplied")]
    CodesPinRequired,
    /// Applying the Codes artefacts to the device failed.
    #[error(transparent)]
    Codes(#[from] crate::codes::ArtefactError),
}

impl EnrollmentPackage {
    /// Parse the package rooted at `root` for the given `mode`.
    ///
    /// Locates exactly one `.p12`, the mode-required bundle file
    /// (`manifest.toml` managed / `tags.toml` standalone), and an optional CRL.
    /// Does not touch device paths and does not decrypt the `.p12`.
    ///
    /// A package carrying a Codes part carries a second `.p12` — the delivery
    /// container of the device key — and "exactly one" still means the per-host
    /// identity: the container the Codes section names is not counted. When the
    /// section cannot be read at all, the container is counted like any other
    /// file and the package is reported as ambiguous; a package whose section
    /// does not parse is broken either way, and the install says so precisely.
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
        let codes_container = codes_container_name(root, mode)?;
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
                if codes_container.as_deref() != Some(name) {
                    p12s.push(name.to_owned());
                }
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
        self.install_with_ids(
            paths,
            device_os,
            trusted_pubkey,
            audit::EnrollAuditIds::default(),
        )
    }

    /// Like [`Self::install_with_ids`], but also applies the Codes part of the
    /// package when it carries one.
    ///
    /// `codes` names where the artefacts go and carries the PIN of the delivery
    /// container. Passing `None` is the Access-only import: a Codes part in the
    /// package is then left where it is, and the device stays a device without
    /// the code method.
    ///
    /// The Codes part is read and applied **after** the Access part has been
    /// committed, and deliberately so: for a managed package the pins that
    /// authenticate the Codes files live in the manifest, and the manifest is
    /// authenticated by the install itself. Verifying them earlier would mean
    /// acting on a signature nobody had checked yet.
    ///
    /// The consequence is stated rather than hidden. A package whose Codes part
    /// is broken leaves a device that is a working Access device and does not
    /// offer the code method, and the command reports the failure. What does
    /// *not* happen is a half-applied Codes store: every file of the part is
    /// read and verified before the first of them is written, and the key epoch
    /// — the value everything else is ordered against — is written last, so a
    /// repeat of the same import finishes the job rather than duplicating it.
    ///
    /// The section itself travels from the install rather than being read again
    /// afterwards — see [`Self::apply_codes`].
    ///
    /// # Errors
    ///
    /// Any [`ImportError`], including the `Codes*` variants and
    /// [`ImportError::Codes`] for a failure of the artefact store itself.
    pub fn install_with_codes(
        &self,
        paths: &InstallPaths,
        device_os: RoleOs,
        trusted_pubkey: Option<&[u8]>,
        ids: audit::EnrollAuditIds<'_>,
        codes: Option<&CodesImport<'_>>,
    ) -> Result<ImportOutcome, ImportError> {
        let (mut outcome, section) =
            self.install_capturing_codes(paths, device_os, trusted_pubkey, ids)?;
        outcome.codes = self.apply_codes(codes, section)?;
        Ok(outcome)
    }

    /// Applies the Codes part the install carried out of the verified package.
    ///
    /// `Ok(None)` when the package carries no Codes part or the caller asked
    /// for none: an Access-only fleet has nothing to apply here, and saying so
    /// is not the same as failing.
    ///
    /// `section` is a value rather than a path, and that is the whole point of
    /// the signature. In a managed package the section is what decides which
    /// ticket authority this device believes, and it is authenticated by the
    /// manifest signature — which was checked on the bytes the install read.
    /// Reading `manifest.toml` a second time here would authenticate one byte
    /// stream and act on another, with the entire Access install in between:
    /// the package sits on a removable medium its owner may rewrite, and the
    /// second read is not covered by any signature.
    fn apply_codes(
        &self,
        codes: Option<&CodesImport<'_>>,
        section: Option<role::ManifestCodes>,
    ) -> Result<Option<crate::codes::artefacts::Applied>, ImportError> {
        let Some(codes) = codes else {
            return Ok(None);
        };
        let Some(section) = section else {
            return Ok(None);
        };
        let pin = match (&section.key_container, codes.container_pin) {
            (Some(_), None) => return Err(ImportError::CodesPinRequired),
            (_, supplied) => supplied
                .cloned()
                .unwrap_or_else(|| SecretString::from(String::new())),
        };
        let delivery = super::codes::read_delivery(&section, &self.root, self.mode, &pin)?;
        let applied = crate::codes::artefacts::apply(
            &codes.paths,
            &delivery,
            codes.gost_engine_path,
            codes.store_check,
            codes.configured_epoch,
        )?;

        // The container was a way to carry the key here, and the key now lives
        // in the store under root-only permissions. Leaving the delivery copy
        // in the package directory would keep a second, PIN-protected copy of
        // the device key on whatever medium the package arrived on.
        if let Some(named) = &section.key_container {
            let delivered = self.root.join(&named.file);
            if let Err(error) = crate::codes::artefacts::shred_delivered_key(&delivered) {
                // A read-only medium is the ordinary case and must not fail an
                // import that has already succeeded; it is the operator who
                // then has to account for the medium.
                tracing::warn!(
                    target: "enrollment.audit",
                    path = %delivered.display(),
                    error = %error,
                    "the delivered Codes key container could not be removed from the package"
                );
            }
        }
        Ok(Some(applied))
    }

    /// Like [`Self::install`], but emits the enrollment audit event enriched
    /// with the caller-supplied identifiers ([`audit::EnrollAuditIds`]): the
    /// `host_id` prefix8, plus a `serial` field that every caller leaves empty
    /// until a source under signature carries it. This is the single emission
    /// point for the `device_enrolled` / `enrollment_rejected` events, so the
    /// CLI gets exactly one enriched event per import (no double-emit). A
    /// managed re-import of the already-applied `bundle_version` is a no-op and
    /// emits nothing.
    ///
    /// # Errors
    ///
    /// Any [`ImportError`]; on `Err` the device is unchanged and an
    /// `enrollment_rejected` event was emitted. A managed install without a
    /// `trusted_pubkey` is [`ImportError::MissingKey`].
    pub fn install_with_ids(
        &self,
        paths: &InstallPaths,
        device_os: RoleOs,
        trusted_pubkey: Option<&[u8]>,
        ids: audit::EnrollAuditIds<'_>,
    ) -> Result<ImportOutcome, ImportError> {
        self.install_capturing_codes(paths, device_os, trusted_pubkey, ids)
            .map(|(outcome, _)| outcome)
    }

    /// The Access half of the import, plus the Codes section exactly as the
    /// trusted read of the package saw it.
    ///
    /// Managed: the section comes out of the parse whose signature was
    /// verified. Standalone: out of the single read of `codes.toml`. Either
    /// way the caller receives a value and never a path to read again — see
    /// [`Self::apply_codes`] for why a second read of a removable medium is not
    /// the same bytes.
    fn install_capturing_codes(
        &self,
        paths: &InstallPaths,
        device_os: RoleOs,
        trusted_pubkey: Option<&[u8]>,
        ids: audit::EnrollAuditIds<'_>,
    ) -> Result<(ImportOutcome, Option<role::ManifestCodes>), ImportError> {
        let result = match self.mode {
            ImportMode::Managed => match trusted_pubkey {
                Some(key) => self.install_managed(paths, device_os, key),
                None => Err(ImportError::MissingKey),
            },
            ImportMode::Standalone => self.install_standalone(paths, device_os),
        };
        match &result {
            // A no-op (same bundle already applied) changed nothing, so it
            // emits no `device_enrolled`.
            Ok((outcome, _)) if !outcome.no_op => {
                audit::emit_device_enrolled_full(self.mode.label(), outcome.bundle_version, ids);
            }
            Ok(_) => {}
            Err(e) => {
                audit::emit_enrollment_rejected_full(reason_for(e), ids);
            }
        }
        result
    }

    /// Standalone install: validate role slices + tags file under FS-perms,
    /// then publish atomically (no signature).
    fn install_standalone(
        &self,
        paths: &InstallPaths,
        device_os: RoleOs,
    ) -> Result<(ImportOutcome, Option<role::ManifestCodes>), ImportError> {
        // The Codes section is read once, here, and carried out rather than
        // re-read after the install: a standalone package is trusted by the
        // permissions of the medium it sits on, and reading the same file twice
        // would still let what is installed differ from what was checked.
        let codes_section = super::codes::read_standalone_section(&self.root)?;

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
                // The default bound, not a configured one: an import is an
                // operator command, not a login, and the device configuration
                // it would read is part of what enrollment puts in place.
                SystemAccounts::device(DEFAULT_ACCOUNT_LOOKUP_TIMEOUT),
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
                Ok((
                    ImportOutcome {
                        mode: self.mode,
                        bundle_version: 0,
                        baseline_established: false,
                        no_op: false,
                        codes: None,
                    },
                    codes_section,
                ))
            }
            Err(e) => Err(e),
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

/// The file name the Codes section of this package names as the delivery
/// container, when the section names one.
///
/// The job is narrow: keep the delivery container out of the count of per-host
/// identities. The two trust modes are treated differently on purpose. A
/// standalone `codes.toml` is this module's own surface and a broken one is
/// reported here, precisely. A managed section lives inside the manifest, whose
/// verification belongs to the install and not to a parse that trusts nothing
/// yet; a manifest that does not even parse therefore yields `Ok(None)` here,
/// and the package is then reported as ambiguous rather than diagnosed — a
/// package with a broken manifest is refused either way, and the install says
/// which.
///
/// # Errors
///
/// [`ImportError::CodesSection`] for a standalone section that does not parse,
/// [`ImportError::UnsafeName`] for a name that is not a bare file name, and
/// [`ImportError::Io`] for a read that failed.
fn codes_container_name(root: &Path, mode: ImportMode) -> Result<Option<String>, ImportError> {
    let section = match mode {
        ImportMode::Standalone => super::codes::read_standalone_section(root)?,
        // Under the manifest cap, like every other read of this file: a parse
        // that trusts nothing yet is the first thing a package directory gets
        // to run, and it must not be the place where the size of a file on
        // somebody's medium decides how much memory this process asks for.
        ImportMode::Managed => match read_capped(
            &root.join(MANIFEST_FILENAME),
            "manifest",
            role::manifest::MAX_MANIFEST_BYTES,
        ) {
            Ok(bytes) => role::parse_manifest(&bytes).ok().and_then(|m| m.codes),
            Err(_) => None,
        },
    };
    let Some(named) = section.and_then(|section| section.key_container) else {
        return Ok(None);
    };
    ensure_bare_name(&named.file)?;
    Ok(Some(named.file))
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
///
/// The cap bounds the read itself rather than the buffer that comes back: a
/// package sits on a medium whose owner may have put a file of any size on it,
/// and a read that allocates first and measures afterwards is an out-of-memory
/// kill of the import process on demand.
fn read_capped(path: &Path, artefact: &'static str, max: usize) -> Result<Vec<u8>, ImportError> {
    match crate::fs_mode::read_capped_regular(path, max) {
        Ok(crate::fs_mode::CappedRead::Whole(bytes)) => Ok(bytes),
        Ok(crate::fs_mode::CappedRead::TooLarge) => Err(ImportError::Oversize {
            artefact,
            read: max.saturating_add(1),
            max,
        }),
        Err(e) => Err(ImportError::Io {
            path: path.display().to_string(),
            reason: e.to_string(),
        }),
    }
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
    crate::fs_mode::pin_mode(path, mode).map_err(|e| ImportError::Io {
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
        // Only role slices and the manifest belong in the role dir. The two
        // package files that are TOML but not slices are named here rather than
        // filtered by shape: a file that rides into the role directory is
        // re-parsed as a slice on every load, fails, and writes a line to the
        // journal each time — and it also counts against the bound on how many
        // candidates a role base may hold, so a package with a full complement
        // of slices would stop loading because of a file that is not one.
        let is_slice = has_ext(&path, "toml")
            && name != "tags.toml"
            && name != super::codes::STANDALONE_CODES_FILENAME;
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
        let mut file = crate::fs_mode::create_with_mode(&tmp, mode)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        crate::fs_mode::pin_mode(&tmp, mode)?;
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
            let mut file = crate::fs_mode::create_with_mode(&tmp_path, mode)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            crate::fs_mode::pin_mode(&tmp_path, mode)
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
        // The same capped, symlink-refusing read the rest of the package goes
        // through: the cap has to bound the read rather than the buffer that
        // comes back, and a name in a package must not redirect it elsewhere.
        // The absent file keeps its own diagnostic — a manifest that pins a CRL
        // the package does not carry is a different mistake from a medium that
        // would not read, and the operator fixes the two differently.
        let bytes = match crate::fs_mode::read_capped_regular(&crl_path, MAX_CRL_BYTES) {
            Ok(crate::fs_mode::CappedRead::Whole(bytes)) => bytes,
            Ok(crate::fs_mode::CappedRead::TooLarge) => {
                return Err(ImportError::Oversize {
                    artefact: "crl",
                    read: MAX_CRL_BYTES.saturating_add(1),
                    max: MAX_CRL_BYTES,
                })
            }
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
    ) -> Result<(ImportOutcome, Option<role::ManifestCodes>), ImportError> {
        // The anti-rollback floor lives under persist_dir; ensure it exists so
        // verify_manifest's persist step can write bundle.version.
        ensure_dir(&paths.persist_dir)?;

        let manifest_bytes = read_capped(
            &self.root.join(MANIFEST_FILENAME),
            "manifest",
            role::manifest::MAX_MANIFEST_BYTES,
        )?;
        let manifest = role::parse_manifest(&manifest_bytes)?;
        // The signature is checked here, on the bytes that were just read, and
        // before anything at all is decided from the manifest's contents.
        //
        // Two reasons, and the second is the one that bites. Everything below
        // — including the idempotent no-op — acts on values taken from this
        // file, and a no-op that returned before the check would report success
        // for a package nobody signed. And the Codes section travels out of
        // this parse rather than a second read of the same path: a package sits
        // on removable media, so bytes re-read after a check are not the bytes
        // that were checked. That is the same read-once rule the CRL pin below
        // already follows.
        let payload = role::signed_payload(&manifest_bytes)?;
        role::verify_signature(&payload, &manifest.signature, trusted_pubkey)?;
        let codes_section = manifest.codes.clone();

        let already =
            role::last_accepted_bundle_version(&paths.persist_dir).map_err(ImportError::from)?;
        let baseline_established = already.is_none();

        // 1) Idempotent no-op: same version already applied.
        if already == Some(manifest.bundle_version) {
            return Ok((
                ImportOutcome {
                    mode: self.mode,
                    bundle_version: manifest.bundle_version,
                    baseline_established: false,
                    no_op: true,
                    codes: None,
                },
                codes_section,
            ));
        }

        // 2) Stage the role base + manifest.
        let staged = stage_dir(&paths.roles_dir, "roles")?;
        let stage_guard = StageGuard::new(staged.clone());
        // Managed: the signed manifest must ride into the role dir so
        // `tags::source::load_managed` can re-verify it against the same key.
        copy_role_slices(&self.root, &staged, true)?;

        let outcome = (|| -> Result<ImportOutcome, ImportError> {
            // 3) Pre-validate WITHOUT touching the floor or the device: the
            //    anti-rollback check against the persisted floor and the CRL
            //    pin. The signature held before this closure was entered. This
            //    guarantees a rollback or a bad CRL installs nothing and leaves
            //    the anti-rollback floor untouched.
            //
            //    The CRL pin is checked on the SAME in-memory bytes that get
            //    staged below (read-once, no TOCTOU re-read from removable
            //    media).
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
                // See the standalone path: an import runs the default bound.
                SystemAccounts::device(DEFAULT_ACCOUNT_LOOKUP_TIMEOUT),
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
                codes: None,
            })
        })();

        match outcome {
            Ok(outcome) => {
                stage_guard.disarm();
                Ok((outcome, codes_section))
            }
            Err(e) => Err(e),
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

// Importing a package installs artefacts under pinned POSIX modes, so the
// whole path — and everything that asserts on it — is Unix-only.
#[cfg(all(test, unix))]
#[path = "import_tests.rs"]
mod tests;
