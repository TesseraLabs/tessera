//! Byte-only verification shared by source readers and local enrollment.
use super::{codes_delivery, declared_files, disk, hash_matches, other, required, role_files};
use super::{role, CatalogueCheckpoint, RoleOs, MAX_PUBLIC_BYTES};
use std::collections::BTreeMap;
use std::io;

/// Exact public bytes verified under the supplied trust and checkpoint.
/// This is neither installed device state nor an attestation of source freshness,
/// filesystem safety, operating system, key custody or current ticket admission.
#[derive(Debug)]
pub struct VerifiedPublicMaterial {
    pub(super) manifest: role::Manifest,
    pub(super) manifest_bytes: Vec<u8>,
    pub(super) files: BTreeMap<String, Vec<u8>>,
    checkpoint: CatalogueCheckpoint,
    trust_sha256: [u8; 32],
}

impl VerifiedPublicMaterial {
    /// Unchanged raw signed manifest bytes.
    #[must_use]
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }
    /// Exact declared public files, excluding the manifest itself.
    #[must_use]
    pub fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }
    /// Verified parsed manifest, without mutable access to its claims.
    #[must_use]
    pub const fn manifest(&self) -> &role::Manifest {
        &self.manifest
    }
    /// Verified version and raw manifest digest; acceptance remains external.
    #[must_use]
    pub const fn checkpoint(&self) -> CatalogueCheckpoint {
        self.checkpoint
    }
    /// Fingerprint of the actual independently supplied Ed25519 public key.
    #[must_use]
    pub const fn trust_sha256(&self) -> [u8; 32] {
        self.trust_sha256
    }
}

/// Verify exact owner-signed public material without filesystem access or writes.
///
/// `files` excludes `manifest.toml`. Callers converting a list or frame to this
/// map must reject duplicate names before insertion; a map cannot reveal an
/// overwritten duplicate. The OS and public key are independently selected by
/// the caller. Supplied floors/checkpoints are checked, never advanced. An absent
/// checkpoint makes no assertion about a remote device's installed state.
///
/// Uses the same public-delivery restrictions, role validation, file bounds and
/// Codes signature checks as local enrollment. Certificate validation, local
/// keys/accounts, ticket admission and an enclosing delivery's size are separate.
/// # Errors
/// Refuses malformed, private, missing, extra, oversized, untrusted, foreign-OS,
/// rolled-back or same-version conflicting material.
pub fn verify_public_material(
    manifest_bytes: &[u8],
    files: &BTreeMap<String, Vec<u8>>,
    os: RoleOs,
    trusted_manifest_key: &[u8],
    minimum_bundle_version: Option<u64>,
    accepted: Option<&CatalogueCheckpoint>,
) -> io::Result<VerifiedPublicMaterial> {
    if trusted_manifest_key.is_empty() || trusted_manifest_key.len() > 16 * 1024 {
        return Err(disk::invalid("manifest key bound"));
    }
    let manifest = role::parse_manifest(manifest_bytes).map_err(other)?;
    if manifest.os != os {
        return Err(disk::invalid("foreign manifest OS"));
    }
    if manifest.p12_sha256.is_some()
        || manifest
            .codes
            .as_ref()
            .is_some_and(|c| c.key_container.is_some())
    {
        return Err(disk::invalid(
            "public material contains private-delivery fields",
        ));
    }
    let declared = declared_files(&manifest)?;
    if files.len() > 261 || files.len() != declared.len() {
        return Err(disk::invalid("unexpected public package file count"));
    }
    let mut total = manifest_bytes.len();
    for (name, bytes) in files {
        let cap = declared
            .get(name)
            .ok_or_else(|| disk::invalid("unexpected public package file"))?;
        total = total.saturating_add(bytes.len());
        if bytes.len() > *cap || total > MAX_PUBLIC_BYTES {
            return Err(disk::invalid("public package byte bound"));
        }
    }
    let catalogue = role::verify_catalogue(
        manifest_bytes,
        &role_files(&manifest, files)?,
        trusted_manifest_key,
        minimum_bundle_version,
        accepted,
    )
    .map_err(other)?;
    if let Some(crl) = &manifest.crl {
        hash_matches(required(files, &crl.file)?, &crl.sha256)?;
    }
    codes_delivery(&manifest, files)?;
    Ok(VerifiedPublicMaterial {
        manifest,
        manifest_bytes: manifest_bytes.to_vec(),
        files: files.clone(),
        checkpoint: catalogue.checkpoint(),
        trust_sha256: catalogue.trust_sha256(),
    })
}
