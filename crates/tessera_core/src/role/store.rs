//! On-device role store: a validated `RoleId -> RoleSlice` map loaded from a
//! directory of `*.toml` slices.
//!
//! Two trust modes (design.md «Два режима доверия»):
//!
//! - **Standalone** ([`RoleStore::load`]): trust is the filesystem
//!   permissions (the sudoers.d model — `root:root 0755/0644`). No manifest.
//!   Each slice is parsed independently; a broken or foreign-OS slice is
//!   *skipped* with a `role_slice_invalid` audit event so one bad file never
//!   takes down the rest of the base.
//! - **Managed** ([`RoleStore::load_managed`]): the base is a signed bundle.
//!   [`crate::role::manifest::verify_manifest`] gates the whole set
//!   (signature + anti-rollback + per-slice hash); any invalidity rejects
//!   the entire base (fail-closed). Slices are only loaded after the manifest
//!   verifies.
//!
//! Both modes consult a [`SystemAccounts`] view: a slice whose name is an
//! account this device already owns (a uid outside the regular range, at
//! either end) never becomes a role. Because the role is the login account,
//! such a slice would turn `root` or `daemon` into an ordinary role login;
//! catching it at load puts the provisioning mistake in front of the
//! administrator instead of leaving it to the login path.
//!
//! Calling [`RoleStore::load`] with [`TrustMode::Managed`] is a hard error
//! ([`RoleStoreError::ManagedRequiresManifest`]): managed loads need a
//! trusted key and persist dir, so they must go through `load_managed`.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use super::audit;
use super::manifest::{self, ManifestError, MANIFEST_FILENAME};
use super::schema::{parse_slice, RoleId, RoleOs, RoleSlice};
use super::system_account::{AccountSnapshot, SystemAccountError, SystemAccounts};

/// Hard cap on the number of roles in a single base. A base larger than this
/// is a validation error, not a silent truncation.
pub const MAX_ROLES: usize = 256;
/// Default on-disk directory for role slices.
pub const DEFAULT_ROLES_DIR: &str = "/var/lib/tessera/roles";

/// Trust mode for loading a role base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustMode {
    /// Filesystem-permission trust (sudoers.d model); no manifest.
    Standalone,
    /// Signed-manifest trust (enrolled device). Use [`RoleStore::load_managed`].
    Managed,
}

/// A validated set of role slices keyed by [`RoleId`].
#[derive(Debug, Clone, Default)]
pub struct RoleStore {
    /// Validated slices, one per role id.
    roles: HashMap<RoleId, RoleSlice>,
    /// What both account sources said about the slice names while this base was
    /// being loaded, kept so a caller judging one of those names does not have
    /// to ask again. `None` for a store that was not built from a directory.
    accounts: Option<AccountSnapshot>,
    /// The view [`Self::accounts`] was taken through.
    ///
    /// Kept beside the snapshot because a snapshot alone says nothing about the
    /// device it describes: a load against a view that knows no accounts clears
    /// every name, `root` included, and a caller that paired such verdicts with
    /// the device's real view would be letting a login into an account the
    /// system owns. Handing both out together
    /// ([`super::AccountCheck::from_store`]) is what makes that pair
    /// unbuildable.
    ///
    /// A store that was not built from a directory has no verdicts to offer,
    /// and its view is the device's own — the answer that refuses rather than
    /// the one that clears.
    view: SystemAccounts,
}

/// Errors from loading a role store. Per-slice schema failures in standalone
/// mode are *not* represented here — they are skipped and audited.
#[derive(Debug, thiserror::Error)]
pub enum RoleStoreError {
    /// Directory read / I/O failure (e.g. missing directory).
    #[error("role store I/O error at {path}: {reason}")]
    Io {
        /// Path being read when the error occurred.
        path: String,
        /// Underlying I/O error message.
        reason: String,
    },
    /// The number of successfully loaded slices exceeds [`MAX_ROLES`].
    #[error("role base has {count} roles, exceeds the {max} cap")]
    TooManyRoles {
        /// Number of valid slices found.
        count: usize,
        /// The cap.
        max: usize,
    },
    /// [`RoleStore::load`] was called with [`TrustMode::Managed`]; use
    /// [`RoleStore::load_managed`] (which takes a trusted key + persist dir).
    #[error("managed mode requires a manifest; call load_managed")]
    ManagedRequiresManifest,
    /// Managed-bundle manifest verification failed (fail-closed).
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// A standalone policy directory or slice failed the root-controlled path
    /// policy.
    #[error("standalone role-store path is not root-controlled: {0}")]
    UntrustedPath(#[from] crate::privileged_path::PrivilegedPathError),
    /// A slice's role id names a system account of this device.
    #[error("role slice `{role}` cannot be loaded: {source}")]
    SystemAccount {
        /// The role id (slice file stem).
        role: String,
        /// Why the name cannot be a role.
        #[source]
        source: SystemAccountError,
    },
    /// The local account database could not be consulted, so no slice name can
    /// be cleared against the device's accounts.
    ///
    /// Separate from [`Self::SystemAccount`] on purpose. A slice named after a
    /// system account is one bad file among good ones and is skipped like any
    /// other invalid slice; an unusable account database disqualifies *every*
    /// slice, and reporting that as a pile of per-slice skips would hand the
    /// operator an empty, successfully loaded base and no word about why.
    #[error("cannot check role names against the device's accounts: {source}")]
    AccountsUnavailable {
        /// The lookup failure that stopped the check.
        #[source]
        source: SystemAccountError,
    },
}

impl RoleStore {
    /// Load a role base from `dir`.
    ///
    /// Only [`TrustMode::Standalone`] is handled here; [`TrustMode::Managed`]
    /// returns [`RoleStoreError::ManagedRequiresManifest`] (managed loads
    /// need a key + persist dir — see [`RoleStore::load_managed`]).
    ///
    /// Standalone behaviour: iterate `*.toml` files in `dir` (skip subdirs,
    /// non-`.toml`, and `manifest.toml`). The role id is the file stem. Each
    /// slice is parsed via [`parse_slice`]; a per-slice error (bad schema,
    /// foreign OS, non-role-id stem, role/stem mismatch, or a stem that names
    /// a system account of this device per `accounts`) is skipped with a
    /// `role_slice_invalid` audit event naming the reason. If the number of
    /// candidate files — or, after parsing, the count of *valid* slices —
    /// exceeds [`MAX_ROLES`], the whole load fails with
    /// [`RoleStoreError::TooManyRoles`]. An empty directory yields an empty
    /// store. A missing/unreadable directory is [`RoleStoreError::Io`].
    ///
    /// # Errors
    ///
    /// [`RoleStoreError::Io`], [`RoleStoreError::TooManyRoles`], or
    /// [`RoleStoreError::ManagedRequiresManifest`].
    pub fn load(
        dir: &Path,
        device_os: RoleOs,
        trust: TrustMode,
        accounts: SystemAccounts,
    ) -> Result<Self, RoleStoreError> {
        match trust {
            TrustMode::Managed => Err(RoleStoreError::ManagedRequiresManifest),
            TrustMode::Standalone => Self::load_slices(dir, device_os, false, accounts),
        }
    }

    /// Load a standalone role base for use by a root authentication path.
    ///
    /// This has the same schema and per-slice behaviour as [`Self::load`], but
    /// additionally requires the directory, every slice, and every ancestor
    /// to be root-owned and non-writable by group/other. A path-integrity
    /// failure rejects the whole base rather than skipping the affected slice.
    ///
    /// # Errors
    ///
    /// Returns [`RoleStoreError::UntrustedPath`] for an unsafe path, plus the
    /// standalone load errors documented by [`Self::load`].
    pub fn load_privileged(
        dir: &Path,
        device_os: RoleOs,
        trust: TrustMode,
        accounts: SystemAccounts,
    ) -> Result<Self, RoleStoreError> {
        match trust {
            TrustMode::Managed => Err(RoleStoreError::ManagedRequiresManifest),
            TrustMode::Standalone => Self::load_slices(dir, device_os, true, accounts),
        }
    }

    /// Load and validate a managed (signed) role bundle from `dir`.
    ///
    /// Verifies `manifest.toml` first via
    /// [`manifest::verify_manifest`] (signature + anti-rollback + per-slice
    /// hash, persisting the accepted `bundle_version`); only on success are
    /// the slices listed in the manifest parsed into the store. Any manifest
    /// invalidity rejects the whole base (fail-closed).
    ///
    /// `trusted_pubkey` is the enrollment-provided verification key (PEM or
    /// DER); `persist_dir` holds the anti-rollback `bundle.version`.
    ///
    /// # Errors
    ///
    /// [`RoleStoreError::Manifest`] on any verification failure,
    /// [`RoleStoreError::Io`] reading a slice,
    /// [`RoleStoreError::TooManyRoles`], or
    /// [`RoleStoreError::SystemAccount`] when a listed role names a system
    /// account of this device — a signed bundle that claims such a role is
    /// internally wrong about the device, and the whole base is refused
    /// (fail-closed, as everywhere on the managed path).
    ///
    /// The bundle's `bundle_version` is accepted (the anti-rollback floor
    /// advances) only after every check here has passed. Accepting at
    /// verification time would mean a bundle this function goes on to reject
    /// still raises the floor above the base the device is running, turning the
    /// active base into a rollback and locking the device out of its own roles.
    pub fn load_managed(
        dir: &Path,
        device_os: RoleOs,
        trusted_pubkey: &[u8],
        persist_dir: &Path,
        accounts: SystemAccounts,
    ) -> Result<Self, RoleStoreError> {
        let verified = manifest::verify_manifest_without_accepting(
            dir,
            device_os,
            trusted_pubkey,
            persist_dir,
        )?;
        if verified.manifest.roles.len() > MAX_ROLES {
            return Err(RoleStoreError::TooManyRoles {
                count: verified.manifest.roles.len(),
                max: MAX_ROLES,
            });
        }
        let mut roles = HashMap::with_capacity(verified.manifest.roles.len());
        // Both account sources are asked once for the whole bundle: this load
        // runs on the login path too, and asking per role would multiply a file
        // read and a name-service run by the number of roles in the bundle.
        let names: Vec<&str> = verified
            .manifest
            .roles
            .keys()
            .map(super::schema::RoleId::as_str)
            .collect();
        let device_accounts = accounts.snapshot(&names);
        // The manifest's hashes already matched the on-disk slices, so the
        // schema parse below should succeed; a schema error here is still a
        // hard error (a hash-matching slice that fails schema means the
        // signed bundle is internally inconsistent → fail-closed).
        for role_id in verified.manifest.roles.keys() {
            match device_accounts.check(role_id.as_str()) {
                Ok(()) => {}
                Err(source) if names_a_system_account(&source) => {
                    return Err(RoleStoreError::SystemAccount {
                        role: role_id.to_string(),
                        source,
                    })
                }
                Err(source) => return Err(RoleStoreError::AccountsUnavailable { source }),
            }
            let slice_path = dir.join(format!("{role_id}.toml"));
            let bytes = fs::read(&slice_path).map_err(|e| RoleStoreError::Io {
                path: slice_path.display().to_string(),
                reason: e.to_string(),
            })?;
            match parse_slice(&bytes, role_id.as_str(), device_os) {
                Ok(slice) => {
                    roles.insert(slice.role.clone(), slice);
                }
                Err(e) => {
                    return Err(RoleStoreError::Manifest(ManifestError::HashMismatch {
                        role: format!("{role_id}: slice schema invalid after hash match: {e}"),
                    }));
                }
            }
        }
        // Everything checked out: only now is this bundle_version the one the
        // device stands on.
        manifest::accept_bundle_version(persist_dir, &verified)?;
        Ok(Self {
            roles,
            accounts: Some(device_accounts),
            view: accounts,
        })
    }

    /// Standalone slice iteration (shared by [`Self::load`]).
    fn load_slices(
        dir: &Path,
        device_os: RoleOs,
        privileged: bool,
        accounts: SystemAccounts,
    ) -> Result<Self, RoleStoreError> {
        let load_dir: PathBuf = if privileged {
            crate::privileged_path::validate_directory(
                dir,
                crate::privileged_path::ExecTrust::Root,
            )?
            .canonical()
            .to_path_buf()
        } else {
            dir.to_path_buf()
        };
        let entries = fs::read_dir(&load_dir).map_err(|e| RoleStoreError::Io {
            path: load_dir.display().to_string(),
            reason: e.to_string(),
        })?;
        let mut candidates: Vec<(PathBuf, String)> = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| RoleStoreError::Io {
                path: load_dir.display().to_string(),
                reason: e.to_string(),
            })?;
            let path = entry.path();
            // Skip non-`.toml`, the manifest, and anything that isn't a file.
            if path.extension() != Some(OsStr::new("toml")) {
                continue;
            }
            if path.file_name() == Some(OsStr::new(MANIFEST_FILENAME)) {
                continue;
            }
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(e) => {
                    audit::emit_role_slice_invalid(&path.display().to_string(), &e.to_string());
                    continue;
                }
            };
            if !file_type.is_file() {
                continue;
            }
            // Role id = file stem. A non-role-id stem is a per-slice skip.
            let Some(stem) = path.file_stem().and_then(OsStr::to_str).map(str::to_owned) else {
                audit::emit_role_slice_invalid(
                    &path.display().to_string(),
                    "file stem is not valid UTF-8",
                );
                continue;
            };
            candidates.push((path, stem));
        }

        // The cap is applied to the candidates, before anything is done with
        // their names. A directory holding thousands of files is a
        // provisioning fault, and every name in it would otherwise become a
        // word on the resolver's command line: the run would fail inside the
        // child on an argument list the kernel refuses, and reach the log as
        // silence indistinguishable from a resolver that is simply broken.
        // The count of *valid* slices is checked again after parsing — this
        // one is about what the load is allowed to attempt.
        if candidates.len() > MAX_ROLES {
            return Err(RoleStoreError::TooManyRoles {
                count: candidates.len(),
                max: MAX_ROLES,
            });
        }

        // Both account sources are asked once for the whole base. This load
        // runs on every login, before any credential is presented, so a source
        // consulted per slice would put the number of slices as a multiplier on
        // a file read — and on a name-service run, which costs a process.
        let names: Vec<&str> = candidates.iter().map(|(_, stem)| stem.as_str()).collect();
        let device_accounts = accounts.snapshot(&names);

        let mut roles: HashMap<RoleId, RoleSlice> = HashMap::new();
        for (path, stem) in &candidates {
            // A slice named after an account the system already owns is
            // refused here, where the administrator sees it, instead of at the
            // first login attempt. The login path refuses it again on its own.
            //
            // An account database that cannot answer is a different failure: it
            // disqualifies every slice, so it fails the load outright rather
            // than emptying the base one "invalid slice" at a time.
            match device_accounts.check(stem) {
                Ok(()) => {}
                Err(source) if names_a_system_account(&source) => {
                    audit::emit_role_slice_invalid(
                        &path.display().to_string(),
                        &source.to_string(),
                    );
                    continue;
                }
                Err(source) => return Err(RoleStoreError::AccountsUnavailable { source }),
            }
            let bytes = if privileged {
                crate::privileged_path::read_file(path, crate::privileged_path::ExecTrust::Root)?
            } else {
                match fs::read(path) {
                    Ok(b) => b,
                    Err(e) => {
                        audit::emit_role_slice_invalid(&path.display().to_string(), &e.to_string());
                        continue;
                    }
                }
            };
            match parse_slice(&bytes, stem, device_os) {
                Ok(slice) => {
                    roles.insert(slice.role.clone(), slice);
                }
                Err(e) => {
                    audit::emit_role_slice_invalid(&path.display().to_string(), &e.to_string());
                }
            }
        }
        if roles.len() > MAX_ROLES {
            return Err(RoleStoreError::TooManyRoles {
                count: roles.len(),
                max: MAX_ROLES,
            });
        }
        Ok(Self {
            roles,
            accounts: Some(device_accounts),
            view: accounts,
        })
    }

    /// The account view this base was loaded through.
    ///
    /// Only meaningful together with [`Self::account_snapshot`], which is why
    /// [`super::AccountCheck::from_store`] is what callers use: the verdicts and
    /// the view they were reached under are one thing, and pairing a snapshot
    /// with some other view is how a name the device refuses becomes a name it
    /// clears.
    #[must_use]
    pub(super) const fn account_view(&self) -> SystemAccounts {
        self.view
    }

    /// What the account sources said about the slice names while this base was
    /// loaded, for a caller that has to judge one of those names again.
    ///
    /// The load asks both sources — the second of them by running a process —
    /// about every name in the base. On the login path the account being logged
    /// into is normally one of them, so the verdict is already paid for; asking
    /// again would make a login into a role wait out the additive source's
    /// bound twice.
    ///
    /// A name the snapshot was not taken for ([`AccountSnapshot::covers`]) must
    /// still be asked about separately: the mandatory source answers about it in
    /// full, but the additive one was never asked, and it is the only source
    /// that sees an account no local file holds.
    ///
    /// To *judge* a name, take [`super::AccountCheck::from_store`] instead: it
    /// carries these verdicts together with the view they were reached under
    /// and applies both rules on its own.
    #[must_use]
    pub const fn account_snapshot(&self) -> Option<&AccountSnapshot> {
        self.accounts.as_ref()
    }

    /// Look up a role by id.
    #[must_use]
    pub fn get(&self, id: &RoleId) -> Option<&RoleSlice> {
        self.roles.get(id)
    }

    /// Iterate the loaded slices (unordered).
    pub fn list(&self) -> impl Iterator<Item = &RoleSlice> {
        self.roles.values()
    }

    /// Number of loaded roles.
    #[must_use]
    pub fn len(&self) -> usize {
        self.roles.len()
    }

    /// Whether the store holds no roles.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roles.is_empty()
    }
}

/// Whether a refusal says the name is one the system holds for itself, rather
/// than that the question could not be answered at all.
///
/// The two are handled differently — the first disqualifies one slice, the
/// second disqualifies every slice — and which refusals belong to which group
/// is a decision that must read the same in both load paths.
fn names_a_system_account(error: &SystemAccountError) -> bool {
    matches!(
        error,
        SystemAccountError::SystemAccount { .. } | SystemAccountError::SystemPrincipal { .. }
    )
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
    use crate::role::system_account::PasswdLookup;
    use std::fs;
    use tempfile::TempDir;

    fn slice_doc(role: &str, version: u32, os: &str) -> String {
        format!(
            "role = \"{role}\"\nversion = {version}\nos = \"{os}\"\nname = \"{role}\"\nlevel = 1\n"
        )
    }

    fn write_slice(dir: &TempDir, role: &str, version: u32, os: &str) {
        fs::write(
            dir.path().join(format!("{role}.toml")),
            slice_doc(role, version, os).as_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn good_and_bad_slice_good_loaded_bad_skipped() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "oper", 1, "linux");
        // Broken: unknown field.
        fs::write(
            dir.path().join("serv.toml"),
            b"role = \"serv\"\nversion = 1\nos = \"linux\"\nname = \"s\"\nlevel = 1\nbogus = 1\n",
        )
        .unwrap();
        let store = RoleStore::load(
            dir.path(),
            RoleOs::Linux,
            TrustMode::Standalone,
            SystemAccounts::empty(),
        )
        .unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.get(&RoleId::new("oper").unwrap()).is_some());
        assert!(store.get(&RoleId::new("serv").unwrap()).is_none());
    }

    #[test]
    fn foreign_os_slice_skipped() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "oper", 1, "linux");
        write_slice(&dir, "admin", 1, "astra"); // foreign OS for a linux device
        let store = RoleStore::load(
            dir.path(),
            RoleOs::Linux,
            TrustMode::Standalone,
            SystemAccounts::empty(),
        )
        .unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.get(&RoleId::new("admin").unwrap()).is_none());
    }

    #[test]
    fn non_role_id_stem_skipped() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "oper", 1, "linux");
        // Stem "Bad-Stem" is not a valid role id; parse_slice rejects on
        // role-mismatch and the slice is skipped.
        fs::write(
            dir.path().join("Bad-Stem.toml"),
            slice_doc("oper", 1, "linux").as_bytes(),
        )
        .unwrap();
        let store = RoleStore::load(
            dir.path(),
            RoleOs::Linux,
            TrustMode::Standalone,
            SystemAccounts::empty(),
        )
        .unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn more_than_max_roles_rejected() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..=MAX_ROLES {
            // role ids must match ^[a-z][a-z0-9-]{0,15}$
            let role = format!("r{i}");
            write_slice(&dir, &role, 1, "linux");
        }
        let err = RoleStore::load(
            dir.path(),
            RoleOs::Linux,
            TrustMode::Standalone,
            SystemAccounts::empty(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            RoleStoreError::TooManyRoles {
                count,
                max: MAX_ROLES
            } if count == MAX_ROLES + 1
        ));
    }

    #[test]
    fn more_candidates_than_the_cap_are_refused_before_their_names_are_used() {
        // None of these files parses, so the count of valid slices stays zero
        // and the load would once have succeeded with an empty base — after
        // handing every one of those names to the account check, which puts
        // them on a command line. The refusal has to name the real fault.
        let dir = tempfile::tempdir().unwrap();
        for i in 0..=MAX_ROLES {
            std::fs::write(dir.path().join(format!("r{i}.toml")), b"not a slice").unwrap();
        }

        let err = RoleStore::load(
            dir.path(),
            RoleOs::Linux,
            TrustMode::Standalone,
            SystemAccounts::empty(),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            RoleStoreError::TooManyRoles {
                count,
                max: MAX_ROLES
            } if count == MAX_ROLES + 1
        ));
    }

    #[test]
    fn empty_dir_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = RoleStore::load(
            dir.path(),
            RoleOs::Linux,
            TrustMode::Standalone,
            SystemAccounts::empty(),
        )
        .unwrap();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn missing_dir_is_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        let err = RoleStore::load(
            &missing,
            RoleOs::Linux,
            TrustMode::Standalone,
            SystemAccounts::empty(),
        )
        .unwrap_err();
        assert!(matches!(err, RoleStoreError::Io { .. }));
    }

    #[test]
    fn get_and_list() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "oper", 3, "linux");
        write_slice(&dir, "serv", 7, "linux");
        let store = RoleStore::load(
            dir.path(),
            RoleOs::Linux,
            TrustMode::Standalone,
            SystemAccounts::empty(),
        )
        .unwrap();
        assert_eq!(store.len(), 2);
        let oper = store.get(&RoleId::new("oper").unwrap()).unwrap();
        assert_eq!(oper.version, 3);
        let mut versions: Vec<u32> = store.list().map(|s| s.version).collect();
        versions.sort_unstable();
        assert_eq!(versions, vec![3, 7]);
    }

    #[test]
    fn manifest_toml_skipped_in_standalone() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "oper", 1, "linux");
        // A stray manifest.toml must be ignored (not parsed as a slice).
        fs::write(dir.path().join(MANIFEST_FILENAME), b"bundle_version = 1\n").unwrap();
        let store = RoleStore::load(
            dir.path(),
            RoleOs::Linux,
            TrustMode::Standalone,
            SystemAccounts::empty(),
        )
        .unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn managed_via_load_guard_errors() {
        let dir = tempfile::tempdir().unwrap();
        let err = RoleStore::load(
            dir.path(),
            RoleOs::Linux,
            TrustMode::Managed,
            SystemAccounts::empty(),
        )
        .unwrap_err();
        assert!(matches!(err, RoleStoreError::ManagedRequiresManifest));
    }

    /// Build a signed managed bundle in a fresh dir; returns the role dir, the
    /// anti-rollback persist dir, and the public key to verify with.
    fn build_signed_bundle(bundle_version: u64, slices: &[&str]) -> (TempDir, TempDir, Vec<u8>) {
        use openssl::pkey::PKey;
        use openssl::sign::Signer;
        use sha2::{Digest, Sha256};
        use std::fmt::Write as _;

        let key = PKey::generate_ed25519().unwrap();
        let pub_pem = key.public_key_to_pem().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let persist = tempfile::tempdir().unwrap();

        let mut roles_toml = String::new();
        for role in slices {
            let body = slice_doc(role, 1, "linux");
            fs::write(dir.path().join(format!("{role}.toml")), body.as_bytes()).unwrap();
            let sha = hex::encode(Sha256::digest(body.as_bytes()));
            let _ = write!(
                roles_toml,
                "[roles.{role}]\nversion = 1\nsha256 = \"{sha}\"\n"
            );
        }
        let unsigned = format!("bundle_version = {bundle_version}\nos = \"linux\"\n{roles_toml}");
        let mut signer = Signer::new_without_digest(&key).unwrap();
        let sig = hex::encode(signer.sign_oneshot_to_vec(unsigned.as_bytes()).unwrap());
        let full = format!(
            "bundle_version = {bundle_version}\nos = \"linux\"\nsignature = \"{sig}\"\n{roles_toml}"
        );
        fs::write(dir.path().join(MANIFEST_FILENAME), full.as_bytes()).unwrap();

        (dir, persist, pub_pem)
    }

    #[test]
    fn a_rejected_managed_bundle_does_not_advance_the_rollback_floor() {
        // The bundle is properly signed and its hashes match, so verification
        // passes; it is the role names that disqualify it. If acceptance were
        // recorded during verification, this rejected version would become the
        // floor, and the base the device is actually running — an earlier
        // version — would count as a rollback from then on.
        let (dir, persist, pub_pem) = build_signed_bundle(9, &["serv", "root"]);

        let err = RoleStore::load_managed(
            dir.path(),
            RoleOs::Linux,
            &pub_pem,
            persist.path(),
            device_accounts(),
        )
        .expect_err("a bundle claiming a system account as a role must be refused");
        assert!(matches!(err, RoleStoreError::SystemAccount { .. }));

        assert_eq!(
            super::super::manifest::last_accepted_bundle_version(persist.path()).unwrap(),
            None,
            "a refused bundle must leave the anti-rollback floor where it was"
        );
    }

    // Accepting a bundle writes the anti-rollback floor with a pinned POSIX
    // mode, which the platform has to support for the floor to advance at
    // all. The refusal paths above need no such write and stay portable.
    #[cfg(unix)]
    #[test]
    fn an_accepted_managed_bundle_advances_the_rollback_floor() {
        let (dir, persist, pub_pem) = build_signed_bundle(9, &["serv"]);

        let store = RoleStore::load_managed(
            dir.path(),
            RoleOs::Linux,
            &pub_pem,
            persist.path(),
            device_accounts(),
        )
        .expect("a clean bundle must load");

        assert_eq!(store.len(), 1);
        assert_eq!(
            super::super::manifest::last_accepted_bundle_version(persist.path()).unwrap(),
            Some(9),
            "an accepted bundle must advance the floor"
        );
    }

    /// A account view of a device where `root` and `mail` are system accounts
    /// and `serv` is a provisioned role account. Tests must not consult the
    /// passwd file of the machine running them.
    fn device_accounts() -> SystemAccounts {
        SystemAccounts::with_lookup(|account| match account {
            "root" => PasswdLookup::Uid(0),
            "mail" => PasswdLookup::Uid(8),
            "serv" => PasswdLookup::Uid(4000),
            _ => PasswdLookup::NoEntry,
        })
    }

    /// A account view of a device whose name service is broken.
    fn unusable_accounts() -> SystemAccounts {
        SystemAccounts::with_lookup(|_| PasswdLookup::Unavailable)
    }

    #[test]
    fn an_unusable_passwd_database_fails_the_whole_load() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "oper", 1, "linux");
        write_slice(&dir, "serv", 1, "linux");

        // Without a passwd database no slice name can be cleared, so the load
        // must say so once — not hand back an empty base and a pile of
        // "invalid slice" events that blame the slices for a device fault.
        let err = RoleStore::load(
            dir.path(),
            RoleOs::Linux,
            TrustMode::Standalone,
            unusable_accounts(),
        )
        .expect_err("an unusable passwd database must fail the load");

        assert!(matches!(err, RoleStoreError::AccountsUnavailable { .. }));
    }

    #[test]
    fn slice_named_after_a_system_account_is_not_loaded() {
        let dir = tempfile::tempdir().unwrap();
        // A provisioning typo or a copied sample: `root.toml` next to a real
        // role. The good slice must still load; `root` must not.
        write_slice(&dir, "root", 1, "linux");
        write_slice(&dir, "serv", 1, "linux");

        let store = RoleStore::load(
            dir.path(),
            RoleOs::Linux,
            TrustMode::Standalone,
            device_accounts(),
        )
        .unwrap();

        assert!(store.get(&RoleId::new("root").unwrap()).is_none());
        assert!(store.get(&RoleId::new("serv").unwrap()).is_some());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn packaged_system_account_name_is_not_loaded() {
        let dir = tempfile::tempdir().unwrap();
        // `mail` is a legal role id and a Debian system account at once; what
        // decides is the uid this device gives it, not the name.
        write_slice(&dir, "mail", 1, "linux");
        let store = RoleStore::load(
            dir.path(),
            RoleOs::Linux,
            TrustMode::Standalone,
            device_accounts(),
        )
        .unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn role_account_outside_the_system_range_loads() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "serv", 2, "linux");
        let store = RoleStore::load(
            dir.path(),
            RoleOs::Linux,
            TrustMode::Standalone,
            device_accounts(),
        )
        .unwrap();
        assert_eq!(store.get(&RoleId::new("serv").unwrap()).unwrap().version, 2);
    }

    /// How many times the local account database was read during a load.
    static PASSWD_READS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    /// The device's account database, in the shape the loader consumes it.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "the shape is the account source's: `None` is a database that could not be read"
    )]
    fn counted_passwd() -> Option<Vec<u8>> {
        PASSWD_READS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(
            b"root:x:0:0:root:/root:/bin/bash\n\
              serv:x:4000:4000::/home/serv:/bin/sh\n\
              oper:x:4001:4001::/home/oper:/bin/sh\n"
                .to_vec(),
        )
    }

    #[test]
    fn the_account_database_is_read_once_for_the_whole_base() {
        use std::sync::atomic::Ordering::Relaxed;

        // A load happens on every login, before any credential is presented.
        // Re-reading the database per slice would put the size of the base on
        // the login path as a multiplier.
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "serv", 1, "linux");
        write_slice(&dir, "oper", 1, "linux");
        write_slice(&dir, "root", 1, "linux");
        PASSWD_READS.store(0, Relaxed);

        let store = RoleStore::load(
            dir.path(),
            RoleOs::Linux,
            TrustMode::Standalone,
            SystemAccounts::with_database(counted_passwd),
        )
        .unwrap();

        assert_eq!(store.len(), 2, "the slice named after `root` must not load");
        assert_eq!(
            PASSWD_READS.load(Relaxed),
            1,
            "one read for the base, whatever the number of slices in it"
        );
    }

    #[test]
    fn privileged_standalone_rejects_untrusted_temp_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "oper", 1, "linux");

        let err = RoleStore::load_privileged(
            dir.path(),
            RoleOs::Linux,
            TrustMode::Standalone,
            SystemAccounts::empty(),
        )
        .expect_err("temporary user-controlled role base must be rejected");

        assert!(matches!(err, RoleStoreError::UntrustedPath(_)));
    }
}
