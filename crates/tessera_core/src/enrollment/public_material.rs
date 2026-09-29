//! Public-material enrollment with locally retained keys.
//!
//! Verification of the outer delivery protocol, server identity, certificate
//! chain/profile and current admission remains the caller's responsibility.
//! This module validates the existing owner-signed role/Codes material and key
//! binding, and never changes config, TLS trust, PAM policy or transport state.
use super::{local_keys::LocalEnrollmentKeys, owned_fs as disk};
use crate::codes::{
    artefacts::{self, CodesDelivery},
    tickets::{TicketAnchor, TicketStore},
    CodesPaths, Epoch,
};
use crate::role::{self, CatalogueCheckpoint, RoleOs, SystemAccounts, UpdateTrust};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[path = "public_material_validation.rs"]
mod validation;
pub use validation::{verify_public_material, VerifiedPublicMaterial};

const STATE_CAP: usize = 1024;
const STATE_FILE: &str = "public-material.json";
/// Maximum combined public package bytes, including the manifest and leaf.
pub const MAX_PUBLIC_BYTES: usize = 20 * 1024 * 1024;

/// Explicit local installation destinations. No path is taken from the server.
#[derive(Debug, Clone)]
pub struct PublicInstallPaths {
    /// Existing role-store destination.
    pub roles_dir: PathBuf,
    /// Existing shared bundle.version floor directory.
    pub persist_dir: PathBuf,
    /// Public CRL destination, when the manifest pins one.
    pub crl_path: PathBuf,
    /// Public returned certificate only; not a trusted-CA/config destination.
    pub tls_leaf_path: PathBuf,
    /// Existing Codes store destinations.
    pub codes: CodesPaths,
}

/// A durable application state for exactly these prepared bytes and paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicApplyState {
    /// No application record exists.
    Absent,
    /// A durable attempt exists, but its completion is not proven.
    Pending,
    /// All installed bytes/floors/keys were rechecked against this input.
    Complete,
}

/// Result of writing public material, not an enrollment receipt or activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicMaterialApplied {
    digest: [u8; 32],
    bundle_version: u64,
}
impl PublicMaterialApplied {
    /// Exact public input and destination digest associated with completion.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Version accepted under the existing role-store anti-rollback floor.
    #[must_use]
    pub const fn bundle_version(&self) -> u64 {
        self.bundle_version
    }
}

/// Immutable verified bytes. Fields are private so parsing cannot be bypassed.
pub struct PreparedPublicEnrollment {
    manifest: role::Manifest,
    manifest_bytes: Vec<u8>,
    files: BTreeMap<String, Vec<u8>>,
    leaf: Vec<u8>,
    trust: Vec<u8>,
    codes_point: Vec<u8>,
    tls_spki: Vec<u8>,
    input_digest: [u8; 32],
}
impl std::fmt::Debug for PreparedPublicEnrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedPublicEnrollment")
            .field("bundle_version", &self.manifest.bundle_version)
            .field("files", &self.files.len())
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: u8,
    digest: String,
    complete: bool,
}

impl PreparedPublicEnrollment {
    /// Read each bounded public file once and validate the existing manifest,
    /// roles, pins, Codes signatures, and local TLS key binding. No state writes.
    /// Private-delivery fields/files are refused, never stripped from signatures.
    /// `persist_dir` is the existing shared floor, not a new counter.
    /// # Errors
    /// Refuses malformed/untrusted/foreign/rollback material or changed local keys.
    pub fn prepare(
        root: &Path,
        os: RoleOs,
        trusted_manifest_key: &[u8],
        persist_dir: &Path,
        keys: &LocalEnrollmentKeys,
        tls_leaf_der: &[u8],
    ) -> io::Result<Self> {
        keys.recheck()?;
        keys.require_tls_leaf_key(tls_leaf_der)?;
        let raw = public_read(
            &root.join(role::manifest::MANIFEST_FILENAME),
            role::manifest::MAX_MANIFEST_BYTES,
        )?;
        let manifest = role::parse_manifest(&raw).map_err(other)?;
        let files = read_declared_files(
            root,
            &manifest,
            raw.len().saturating_add(tls_leaf_der.len()),
        )?;
        let floor = role::last_accepted_bundle_version(persist_dir).map_err(other)?;
        let verified = verify_public_material(&raw, &files, os, trusted_manifest_key, floor, None)?;
        let result = Self {
            manifest: verified.manifest,
            manifest_bytes: verified.manifest_bytes,
            files: verified.files,
            leaf: tls_leaf_der.to_vec(),
            trust: trusted_manifest_key.to_vec(),
            codes_point: keys.codes_public_key()?,
            tls_spki: keys.tls_spki()?,
            input_digest: [0; 32],
        };
        let mut result = result;
        result.input_digest = result.hash_inputs();
        Ok(result)
    }

    /// Apply exact verified bytes, preserving the locally owned keys. Pending is
    /// durable before the first target mutation. A retry must have the same input
    /// and destination digest; success is written only after durable rechecks.
    /// This is recoverable multi-file application, not instantaneous activation.
    /// # Errors
    /// Refuses changed source/floors/keys, conflicting attempts or partial I/O.
    pub fn apply(
        &self,
        paths: &PublicInstallPaths,
        keys: &LocalEnrollmentKeys,
        configured_epoch: Option<Epoch>,
        accounts: SystemAccounts,
    ) -> io::Result<PublicMaterialApplied> {
        let _lock = disk::lock(keys.root())?;
        self.preflight(paths, keys, configured_epoch)?;
        let digest = self.application_digest(paths)?;
        let record = read_journal(keys.root())?;
        if let Some(record) = &record {
            if record.digest != hex::encode(digest) {
                return Err(disk::invalid("conflicting public enrollment attempt"));
            }
        }
        if record.as_ref().is_some_and(|r| r.complete) && self.installed(paths, keys).is_ok() {
            return Ok(PublicMaterialApplied {
                digest,
                bundle_version: self.manifest.bundle_version,
            });
        }
        // Target parents are protected and supplied locally. Create only the
        // dedicated absent leaves after every validation above has succeeded.
        let parent = paths
            .roles_dir
            .parent()
            .ok_or_else(|| disk::invalid("role parent"))?;
        let staged = parent.join(format!(".public-roles-{}", uuid::Uuid::new_v4()));
        disk::make_directory(&staged)?;
        let mut stage = Stage(staged.clone());
        disk::write_new(
            &staged.join(role::manifest::MANIFEST_FILENAME),
            &self.manifest_bytes,
            0o644,
        )?;
        for id in self.manifest.roles.keys() {
            let name = format!("{id}.toml");
            disk::write_new(&staged.join(&name), required(&self.files, &name)?, 0o644)?;
        }
        disk::sync_directory(&staged)?;
        // Validate OS/account resolution before publishing any material.
        role::RoleStore::load(
            &staged,
            self.manifest.os,
            role::TrustMode::Standalone,
            accounts,
        )
        .map_err(other)?;
        write_journal(keys.root(), digest, false)?;
        #[cfg(test)]
        fault("pending")?;
        ensure_directory(&paths.persist_dir)?;
        if let Some(crl) = &self.manifest.crl {
            disk::replace(&paths.crl_path, required(&self.files, &crl.file)?, 0o644)?;
        }
        disk::replace(&paths.tls_leaf_path, &self.leaf, 0o644)?;
        #[cfg(test)]
        fault("leaf")?;
        if let Some(section) = &self.manifest.codes {
            artefacts::apply_owned(
                &paths.codes,
                self.delivery()?,
                keys.codes_key(),
                Epoch::new(section.epoch),
                configured_epoch,
            )
            .map_err(other)?;
        }
        #[cfg(test)]
        fault("codes")?;
        // Legacy atomic_update remains the authority for schema/account checks
        // and the shared floor. A failure leaves Pending, never Complete.
        role::atomic_update(
            &paths.roles_dir,
            &staged,
            self.manifest.os,
            &UpdateTrust::Managed {
                trusted_pubkey: &self.trust,
                persist_dir: &paths.persist_dir,
            },
            accounts,
        )
        .map_err(other)?;
        stage.0 = PathBuf::new();
        disk::sync_directory(parent)?;
        disk::sync_directory(&paths.roles_dir)?;
        disk::sync_directory(&paths.persist_dir)?;
        self.installed(paths, keys)?;
        #[cfg(test)]
        fault("verified")?;
        write_journal(keys.root(), digest, true)?;
        Ok(PublicMaterialApplied {
            digest,
            bundle_version: self.manifest.bundle_version,
        })
    }

    /// Recheck completion against actual installed bytes and keys; a journal
    /// flag alone never establishes an applied package.
    /// # Errors
    /// Refuses unsafe/corrupt state or an attempt for different input/paths.
    pub fn state(
        &self,
        paths: &PublicInstallPaths,
        keys: &LocalEnrollmentKeys,
    ) -> io::Result<PublicApplyState> {
        let _lock = disk::lock(keys.root())?;
        let Some(record) = read_journal(keys.root())? else {
            return Ok(PublicApplyState::Absent);
        };
        if record.digest != hex::encode(self.application_digest(paths)?) {
            return Err(disk::invalid("different public enrollment attempt"));
        }
        Ok(if record.complete && self.installed(paths, keys).is_ok() {
            PublicApplyState::Complete
        } else {
            PublicApplyState::Pending
        })
    }

    fn preflight(
        &self,
        paths: &PublicInstallPaths,
        keys: &LocalEnrollmentKeys,
        configured: Option<Epoch>,
    ) -> io::Result<()> {
        keys.recheck()?;
        keys.require_codes_public_key(&self.codes_point)?;
        if keys.tls_spki()? != self.tls_spki {
            return Err(disk::invalid("TLS key changed"));
        }
        keys.require_tls_leaf_key(&self.leaf)?;
        validate_destinations(paths, keys)?;
        validate_existing(paths)?;
        let floor = role::last_accepted_bundle_version(&paths.persist_dir).map_err(other)?;
        let checkpoint = if floor == Some(self.manifest.bundle_version)
            && paths
                .roles_dir
                .join(role::manifest::MANIFEST_FILENAME)
                .exists()
        {
            let bytes = public_read(
                &paths.roles_dir.join(role::manifest::MANIFEST_FILENAME),
                role::manifest::MAX_MANIFEST_BYTES,
            )?;
            let installed = role::parse_manifest(&bytes).map_err(other)?;
            if installed.bundle_version == self.manifest.bundle_version {
                Some(CatalogueCheckpoint::new(
                    installed.bundle_version,
                    Sha256::digest(bytes).into(),
                ))
            } else if read_journal(keys.root())?.is_some() {
                None
            } else {
                return Err(disk::invalid("floor and installed bundle disagree"));
            }
        } else {
            if floor == Some(self.manifest.bundle_version) && read_journal(keys.root())?.is_none() {
                return Err(disk::invalid(
                    "accepted version has no installed checkpoint or pending attempt",
                ));
            }
            None
        };
        role::catalogue::verify_catalogue(
            &self.manifest_bytes,
            &role_files(&self.manifest, &self.files)?,
            &self.trust,
            floor,
            checkpoint.as_ref(),
        )
        .map_err(other)?;
        if let Some(section) = &self.manifest.codes {
            artefacts::preflight_owned(
                &paths.codes,
                &self.delivery()?,
                Epoch::new(section.epoch),
                configured,
            )
            .map_err(other)?;
            if paths.codes.device_key_container.exists() {
                let key =
                    crate::codes::store::load_device_key(&paths.codes.device_key_container, None)
                        .map_err(other)?;
                if !key.public_eq(keys.codes_key()) {
                    return Err(disk::invalid("refusing to replace a different Codes key"));
                }
            }
        }
        Ok(())
    }

    fn delivery(&self) -> io::Result<CodesDelivery> {
        codes_delivery(&self.manifest, &self.files)
    }

    fn installed(&self, paths: &PublicInstallPaths, keys: &LocalEnrollmentKeys) -> io::Result<()> {
        keys.recheck()?;
        keys.require_codes_public_key(&self.codes_point)?;
        if keys.tls_spki()? != self.tls_spki {
            return Err(disk::invalid("TLS key changed"));
        }
        if role::last_accepted_bundle_version(&paths.persist_dir).map_err(other)?
            != Some(self.manifest.bundle_version)
        {
            return Err(disk::invalid("bundle floor differs"));
        }
        same(
            &paths.roles_dir.join(role::manifest::MANIFEST_FILENAME),
            &self.manifest_bytes,
        )?;
        for id in self.manifest.roles.keys() {
            let name = format!("{id}.toml");
            same(&paths.roles_dir.join(&name), required(&self.files, &name)?)?;
        }
        same(&paths.tls_leaf_path, &self.leaf)?;
        if let Some(crl) = &self.manifest.crl {
            same(&paths.crl_path, required(&self.files, &crl.file)?)?;
        }
        if let Some(section) = &self.manifest.codes {
            paths
                .codes
                .check_trusted()
                .map_err(|_| disk::invalid("Codes store trust"))?;
            let key = crate::codes::store::load_device_key(&paths.codes.device_key_container, None)
                .map_err(other)?;
            if !key.public_eq(keys.codes_key())
                || crate::codes::epoch::read(&paths.codes.state_dir)?
                    != Some(Epoch::new(section.epoch))
            {
                return Err(disk::invalid("Codes key or epoch differs"));
            }
            for (entry, path) in [
                (&section.tickets, &paths.codes.tickets),
                (&section.ticket_revocations, &paths.codes.ticket_revocations),
                (&section.ticket_authority, &paths.codes.ticket_authority),
                (&section.page_urls, &paths.codes.page_urls),
            ] {
                if let Some(entry) = entry {
                    same(path, required(&self.files, &entry.file)?)?;
                }
            }
        }
        Ok(())
    }
    fn hash_inputs(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        for bytes in [
            &self.manifest_bytes,
            &self.leaf,
            &self.codes_point,
            &self.tls_spki,
        ] {
            part(&mut hash, bytes);
        }
        for (name, bytes) in &self.files {
            part(&mut hash, name.as_bytes());
            part(&mut hash, bytes);
        }
        hash.finalize().into()
    }
    fn application_digest(&self, paths: &PublicInstallPaths) -> io::Result<[u8; 32]> {
        let mut hash = Sha256::new();
        part(&mut hash, b"tessera-local-public-apply/v1");
        part(&mut hash, &self.input_digest);
        for path in [
            &paths.roles_dir,
            &paths.persist_dir,
            &paths.crl_path,
            &paths.tls_leaf_path,
            &paths.codes.state_dir,
            &paths.codes.device_key_container,
            &paths.codes.tickets,
            &paths.codes.ticket_revocations,
            &paths.codes.ticket_authority,
            &paths.codes.page_urls,
        ] {
            part(
                &mut hash,
                path.to_str()
                    .ok_or_else(|| disk::invalid("non UTF-8 target"))?
                    .as_bytes(),
            );
        }
        Ok(hash.finalize().into())
    }
}
fn part(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}
fn other(error: impl std::fmt::Display) -> io::Error {
    disk::invalid(&error.to_string())
}
fn public_read(path: &Path, cap: usize) -> io::Result<Vec<u8>> {
    match crate::fs_mode::read_capped_regular(path, cap)? {
        crate::fs_mode::CappedRead::Whole(bytes) => Ok(bytes),
        crate::fs_mode::CappedRead::TooLarge => Err(disk::invalid("public file bound")),
    }
}
fn required<'a>(files: &'a BTreeMap<String, Vec<u8>>, name: &str) -> io::Result<&'a [u8]> {
    files
        .get(name)
        .map(Vec::as_slice)
        .ok_or_else(|| disk::invalid("missing declared file"))
}
fn hash_matches(bytes: &[u8], pin: &str) -> io::Result<()> {
    if hex::encode(Sha256::digest(bytes)).eq_ignore_ascii_case(pin.trim()) {
        Ok(())
    } else {
        Err(disk::invalid("public file hash differs"))
    }
}
fn text(bytes: Option<&[u8]>) -> io::Result<Option<&str>> {
    bytes
        .map(|b| std::str::from_utf8(b).map_err(other))
        .transpose()
}
fn declare(files: &mut BTreeMap<String, usize>, name: &str, cap: usize) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.contains(['/', '\\'])
        || name.to_ascii_lowercase().ends_with(".p12")
        || name.to_ascii_lowercase().ends_with(".pfx")
        || name == role::manifest::MANIFEST_FILENAME
        || files.insert(name.to_owned(), cap).is_some()
    {
        return Err(disk::invalid("invalid or duplicate public file name"));
    }
    Ok(())
}
fn ensure_directory(path: &Path) -> io::Result<()> {
    if path.exists() {
        disk::directory(path)
    } else {
        disk::make_directory(path)
    }
}
fn same(path: &Path, expected: &[u8]) -> io::Result<()> {
    if disk::read(path, expected.len(), false)? == expected {
        Ok(())
    } else {
        Err(disk::invalid("installed public bytes differ"))
    }
}
fn read_journal(root: &Path) -> io::Result<Option<Journal>> {
    let raw = match disk::read(&root.join(STATE_FILE), STATE_CAP, true) {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let journal: Journal = serde_json::from_slice(&raw).map_err(other)?;
    if journal.schema != 1
        || journal.digest.len() != 64
        || !journal
            .digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(disk::invalid("invalid application journal"));
    }
    Ok(Some(journal))
}
fn write_journal(root: &Path, digest: [u8; 32], complete: bool) -> io::Result<()> {
    disk::replace(
        &root.join(STATE_FILE),
        &serde_json::to_vec(&Journal {
            schema: 1,
            digest: hex::encode(digest),
            complete,
        })
        .map_err(other)?,
        0o600,
    )
}
struct Stage(PathBuf);
impl Drop for Stage {
    fn drop(&mut self) {
        if !self.0.as_os_str().is_empty() {
            drop(fs::remove_dir_all(&self.0));
        }
    }
}

fn codes_delivery(
    manifest: &role::Manifest,
    files: &BTreeMap<String, Vec<u8>>,
) -> io::Result<CodesDelivery> {
    let Some(section) = &manifest.codes else {
        return Ok(CodesDelivery::default());
    };
    let get = |entry: &Option<role::ManifestCodesFile>| -> io::Result<Option<Vec<u8>>> {
        entry
            .as_ref()
            .map(|e| {
                let bytes = required(files, &e.file)?;
                hash_matches(
                    bytes,
                    e.sha256
                        .as_deref()
                        .ok_or_else(|| disk::invalid("unbound Codes file"))?,
                )?;
                Ok(bytes.to_vec())
            })
            .transpose()
    };
    let delivery = CodesDelivery {
        key: None,
        tickets: get(&section.tickets)?,
        revocations: get(&section.ticket_revocations)?,
        ticket_authority: get(&section.ticket_authority)?,
        page_urls: get(&section.page_urls)?,
    };
    let tickets = TicketStore::parse(
        text(delivery.tickets.as_deref())?,
        text(delivery.revocations.as_deref())?,
    )
    .map_err(other)?;
    let anchor = TicketAnchor::parse(
        delivery
            .ticket_authority
            .as_deref()
            .ok_or_else(|| disk::invalid("missing ticket anchor"))?,
    )
    .map_err(other)?;
    tickets.verify_signatures(&anchor).map_err(other)?;
    if crate::codes::store::parse_page_urls(
        text(delivery.page_urls.as_deref())?.ok_or_else(|| disk::invalid("missing addresses"))?,
    )
    .is_empty()
    {
        return Err(disk::invalid("empty page addresses"));
    }
    Ok(delivery)
}

fn role_files(
    manifest: &role::Manifest,
    files: &BTreeMap<String, Vec<u8>>,
) -> io::Result<BTreeMap<role::RoleId, Vec<u8>>> {
    manifest
        .roles
        .keys()
        .map(|id| Ok((id.clone(), required(files, &format!("{id}.toml"))?.to_vec())))
        .collect()
}

#[cfg(test)]
thread_local! {static FAILURE: std::cell::Cell<Option<&'static str>> = const {std::cell::Cell::new(None)};}
#[cfg(test)]
fn fault(at: &str) -> io::Result<()> {
    if FAILURE.get() == Some(at) {
        Err(disk::invalid("injected interruption"))
    } else {
        Ok(())
    }
}
#[cfg(test)]
#[path = "public_material_tests.rs"]
mod tests;

fn declared_files(manifest: &role::Manifest) -> io::Result<BTreeMap<String, usize>> {
    let mut declared = BTreeMap::new();
    for name in manifest.roles.keys() {
        declared.insert(format!("{name}.toml"), role::schema::MAX_SLICE_BYTES);
    }
    if let Some(crl) = &manifest.crl {
        declare(&mut declared, &crl.file, super::import::MAX_CRL_BYTES)?;
    }
    if let Some(codes) = &manifest.codes {
        for entry in [
            &codes.tickets,
            &codes.ticket_revocations,
            &codes.ticket_authority,
            &codes.page_urls,
        ]
        .into_iter()
        .flatten()
        {
            declare(
                &mut declared,
                &entry.file,
                crate::codes::tickets::MAX_ARTEFACT_BYTES,
            )?;
        }
        if codes.tickets.is_none() || codes.ticket_authority.is_none() || codes.page_urls.is_none()
        {
            return Err(disk::invalid(
                "public Codes provisioning requires tickets, anchor and page addresses",
            ));
        }
    }
    Ok(declared)
}

fn read_declared_files(
    root: &Path,
    manifest: &role::Manifest,
    initial_bytes: usize,
) -> io::Result<BTreeMap<String, Vec<u8>>> {
    let declared = declared_files(manifest)?;
    let expected: BTreeSet<_> = declared
        .keys()
        .map(String::as_str)
        .chain([role::manifest::MANIFEST_FILENAME])
        .collect();
    let mut found = BTreeSet::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| disk::invalid("non UTF-8 file name"))?;
        if !entry.file_type()?.is_file() || !expected.contains(name.as_str()) || !found.insert(name)
        {
            return Err(disk::invalid(
                "unexpected or non-regular public package entry",
            ));
        }
        if found.len() > 262 {
            return Err(disk::invalid("too many public package files"));
        }
    }
    if found.len() != expected.len() {
        return Err(disk::invalid("missing public package file"));
    }
    let mut files = BTreeMap::new();
    let mut total = initial_bytes;
    for (name, cap) in declared {
        let bytes = public_read(&root.join(&name), cap)?;
        total = total.saturating_add(bytes.len());
        if total > MAX_PUBLIC_BYTES {
            return Err(disk::invalid("public package total bound"));
        }
        files.insert(name, bytes);
    }
    Ok(files)
}

fn validate_destinations(paths: &PublicInstallPaths, keys: &LocalEnrollmentKeys) -> io::Result<()> {
    validate_swap_boundaries(paths, keys)?;
    let mut destinations = vec![
        &paths.roles_dir,
        &paths.persist_dir,
        &paths.crl_path,
        &paths.tls_leaf_path,
        &paths.codes.state_dir,
        &paths.codes.device_key_container,
        &paths.codes.tickets,
        &paths.codes.ticket_revocations,
        &paths.codes.ticket_authority,
        &paths.codes.page_urls,
    ];
    destinations.sort();
    if destinations.windows(2).any(|w| w.first() == w.get(1)) {
        return Err(disk::invalid("aliased install paths"));
    }
    for path in &destinations {
        if path.starts_with(keys.root()) {
            return Err(disk::invalid("install path overlaps local key store"));
        }
        if *path != &paths.roles_dir
            && *path != &paths.persist_dir
            && path.starts_with(&paths.roles_dir)
        {
            return Err(disk::invalid("install path overlaps role directory"));
        }
    }
    for path in destinations {
        let parent = path
            .parent()
            .ok_or_else(|| disk::invalid("target parent"))?;
        if parent.exists() {
            disk::directory(parent)?;
        } else {
            disk::directory(
                parent
                    .parent()
                    .ok_or_else(|| disk::invalid("target ancestor"))?,
            )?;
        }
        if let Ok(meta) = fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                return Err(disk::invalid("symlink destination"));
            }
        }
    }
    Ok(())
}

fn validate_existing(paths: &PublicInstallPaths) -> io::Result<()> {
    for path in [&paths.roles_dir, &paths.persist_dir] {
        if path.exists() {
            disk::directory(path)?;
        }
    }
    for path in [
        &paths.codes.state_dir,
        paths
            .codes
            .device_key_container
            .parent()
            .ok_or_else(|| disk::invalid("Codes parent"))?,
    ] {
        if path.exists() {
            disk::private_directory(path)?;
        }
    }
    for path in [
        &paths.crl_path,
        &paths.tls_leaf_path,
        &paths.codes.tickets,
        &paths.codes.ticket_revocations,
        &paths.codes.ticket_authority,
        &paths.codes.page_urls,
    ] {
        if path.exists() {
            disk::read(path, MAX_PUBLIC_BYTES, false)?;
        }
    }
    if paths.codes.device_key_container.exists() {
        disk::read(
            &paths.codes.device_key_container,
            crate::codes::store::MAX_KEY_CONTAINER_BYTES,
            true,
        )?;
    }
    for (path, private) in [
        (
            paths
                .persist_dir
                .join(role::manifest::BUNDLE_VERSION_FILENAME),
            false,
        ),
        (
            paths
                .codes
                .state_dir
                .join(crate::codes::epoch::EPOCH_FILENAME),
            true,
        ),
        (
            paths
                .codes
                .state_dir
                .join(crate::codes::lock::LOCK_FILENAME),
            true,
        ),
    ] {
        if fs::symlink_metadata(&path).is_ok() {
            disk::read(&path, STATE_CAP, private)?;
        }
    }
    Ok(())
}

/// The role swap removes both its old tree and its reserved `.bak` tree.
/// Protect actual persistent files, rather than banning a shared parent such
/// as `persist_dir` that legitimately contains both roles and `bundle.version`.
fn validate_swap_boundaries(
    paths: &PublicInstallPaths,
    keys: &LocalEnrollmentKeys,
) -> io::Result<()> {
    let mut backup_name = paths
        .roles_dir
        .file_name()
        .ok_or_else(|| disk::invalid("role directory has no name"))?
        .to_os_string();
    backup_name.push(".bak");
    let backup = paths.roles_dir.with_file_name(backup_name);
    let floor = paths
        .persist_dir
        .join(role::manifest::BUNDLE_VERSION_FILENAME);
    let files = [
        &paths.crl_path,
        &paths.tls_leaf_path,
        &paths.codes.device_key_container,
        &paths.codes.tickets,
        &paths.codes.ticket_revocations,
        &paths.codes.ticket_authority,
        &paths.codes.page_urls,
        &floor,
    ];
    let intersects = |left: &Path, right: &Path| left.starts_with(right) || right.starts_with(left);
    for destructive in [&paths.roles_dir, &backup] {
        for protected in files
            .iter()
            .copied()
            .map(PathBuf::as_path)
            .chain([keys.root(), paths.codes.state_dir.as_path()])
        {
            if intersects(destructive, protected) {
                return Err(disk::invalid(
                    "role swap or backup overlaps persistent enrollment state",
                ));
            }
        }
    }
    // A file cannot also be an ancestor/container of another destination.
    // Conversely Codes files beneath their own state directory remain valid.
    for (index, file) in files.iter().enumerate() {
        if files
            .iter()
            .skip(index + 1)
            .any(|other| intersects(file, other))
        {
            return Err(disk::invalid("persistent file destinations overlap"));
        }
        for directory in [&paths.roles_dir, &paths.persist_dir, &paths.codes.state_dir] {
            if directory.starts_with(file) {
                return Err(disk::invalid(
                    "file destination contains a persistent directory",
                ));
            }
        }
    }
    Ok(())
}
