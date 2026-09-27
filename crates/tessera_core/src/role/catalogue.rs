//! Host-independent verified projection of an existing signed role bundle.
//!
//! No account lookup, host-OS detection, filesystem mutation or issuance occurs.
//! Callers supply the existing owner trust and persist the returned checkpoint
//! atomically with publication. They must recheck that checkpoint at issuance
//! time and implement publication freshness: signature verification alone does
//! not establish that a bundle is the currently published one.

use std::collections::BTreeMap;

use openssl::pkey::{Id, PKey};
use sha2::{Digest, Sha256};

use super::issuance::RoleIssuance;
use super::manifest::{
    parse_manifest, signed_payload, verify_role_hash, verify_signature, ManifestError, ManifestRole,
};
use super::schema::{parse_slice, RoleId, RoleOs, RoleSchemaError, RoleSlice, MAX_SLICE_BYTES};
use super::store::MAX_ROLES;

/// Accepted bundle identity. Persist both coordinates in the consumer's CAS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogueCheckpoint {
    bundle_version: u64,
    manifest_sha256: [u8; 32],
}

impl CatalogueCheckpoint {
    /// Restore a checkpoint from trusted persistent state.
    ///
    /// The digest covers the complete raw manifest, including its signature.
    pub fn new(bundle_version: u64, manifest_sha256: [u8; 32]) -> Self {
        Self {
            bundle_version,
            manifest_sha256,
        }
    }

    /// Monotonic version of the accepted bundle.
    pub fn bundle_version(self) -> u64 {
        self.bundle_version
    }

    /// SHA-256 of the complete accepted manifest bytes.
    pub fn manifest_sha256(self) -> [u8; 32] {
        self.manifest_sha256
    }
}

/// A verified role and its separately declared issuance bounds.
#[derive(Debug, Clone)]
pub struct CatalogueRole {
    slice: RoleSlice,
    pin: ManifestRole,
    issuance: Option<RoleIssuance>,
}

impl CatalogueRole {
    /// Verified role data. `level` is only a display hint; payload fields do
    /// not themselves establish that an enforcement adapter applies them.
    pub fn slice(&self) -> &RoleSlice {
        &self.slice
    }

    /// Version and raw-file hash pinned by the signed manifest.
    pub fn pin(&self) -> &ManifestRole {
        &self.pin
    }

    /// Explicit method bounds. Missing role metadata grants no issuance method.
    pub fn issuance(&self) -> Option<&RoleIssuance> {
        self.issuance.as_ref()
    }
}

/// Immutable cryptographically verified bundle facts, not an authorization.
#[derive(Debug, Clone)]
pub struct VerifiedRoleCatalogue {
    checkpoint: CatalogueCheckpoint,
    trust_sha256: [u8; 32],
    os: RoleOs,
    issuance_schema_version: Option<u32>,
    roles: BTreeMap<RoleId, CatalogueRole>,
}

impl VerifiedRoleCatalogue {
    /// Bundle identity to compare and persist at the publication boundary.
    pub fn checkpoint(&self) -> CatalogueCheckpoint {
        self.checkpoint
    }

    /// Canonical SPKI SHA-256 of the exact Ed25519 key that verified this bundle.
    /// PEM/DER spellings of the same key have the same fingerprint.
    pub fn trust_sha256(&self) -> [u8; 32] {
        self.trust_sha256
    }

    /// The single target OS declared by this bundle, independent of the host.
    pub fn os(&self) -> RoleOs {
        self.os
    }

    /// `None` means a valid legacy bundle with no published issuance catalogue.
    pub fn issuance_schema_version(&self) -> Option<u32> {
        self.issuance_schema_version
    }

    /// All verified roles, in deterministic identifier order.
    pub fn roles(&self) -> &BTreeMap<RoleId, CatalogueRole> {
        &self.roles
    }
}

/// Failures of the bounded catalogue projection.
#[derive(Debug, thiserror::Error)]
pub enum CatalogueError {
    /// Manifest syntax, metadata, signature, rollback or file-hash failure.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// A catalogue source uses a key outside its Ed25519 signature profile.
    #[error("catalogue signing key is not Ed25519")]
    SigningKeyProfile,
    /// Input includes more roles than the existing role-store cap.
    #[error("catalogue exceeds the {MAX_ROLES}-role cap")]
    TooManyRoles,
    /// An input file has no signed pin.
    #[error("unlisted role file: {role}")]
    UnlistedRole {
        /// Identifier of the unlisted file.
        role: RoleId,
    },
    /// A role fails the existing role-slice schema.
    #[error("invalid catalogue slice {role}: {source}")]
    Slice {
        /// Identifier of the invalid role.
        role: RoleId,
        /// Schema failure, including the existing per-slice size bound.
        #[source]
        source: RoleSchemaError,
    },
    /// A signed version pin disagrees with the signed slice bytes.
    #[error("catalogue slice version does not match its pin: {role}")]
    SliceVersion {
        /// Identifier of the inconsistent role.
        role: RoleId,
    },
    /// The accepted version was reused with different manifest bytes.
    #[error("catalogue bundle version {version} was reused with different bytes")]
    Equivocation {
        /// Reused bundle version.
        version: u64,
    },
}

/// Verify existing owner-signed bytes and project role metadata without using
/// the server's OS or account database.
///
/// `minimum_bundle_version` can carry an existing device/publication floor.
/// `accepted` additionally prevents same-version replacement. The caller must
/// CAS the resulting checkpoint against the state used here; this pure call
/// cannot serialize concurrent publications or establish ongoing freshness.
/// Missing issuance metadata is valid but unavailable for product issuance.
///
/// # Errors
/// Rejects oversized or inconsistent input, invalid signatures or metadata,
/// rollback, same-version different bytes and schema/version/hash mismatches.
pub fn verify_catalogue(
    manifest_bytes: &[u8],
    role_files: &BTreeMap<RoleId, Vec<u8>>,
    trusted_pubkey: &[u8],
    minimum_bundle_version: Option<u64>,
    accepted: Option<&CatalogueCheckpoint>,
) -> Result<VerifiedRoleCatalogue, CatalogueError> {
    let manifest = parse_manifest(manifest_bytes)?;
    if manifest.roles.len() > MAX_ROLES || role_files.len() > MAX_ROLES {
        return Err(CatalogueError::TooManyRoles);
    }
    for (role, bytes) in role_files {
        if bytes.len() > MAX_SLICE_BYTES {
            return Err(CatalogueError::Slice {
                role: role.clone(),
                source: RoleSchemaError::Oversize {
                    size: bytes.len(),
                    max: MAX_SLICE_BYTES,
                },
            });
        }
        if !manifest.roles.contains_key(role) {
            return Err(CatalogueError::UnlistedRole { role: role.clone() });
        }
    }
    let trust_sha256 = signing_key_fingerprint(trusted_pubkey)?;
    verify_signature(
        &signed_payload(manifest_bytes)?,
        &manifest.signature,
        trusted_pubkey,
    )?;
    let floor = minimum_bundle_version.max(accepted.map(|state| state.bundle_version));
    if let Some(persisted) = floor {
        if manifest.bundle_version < persisted {
            return Err(ManifestError::Rollback {
                found: manifest.bundle_version,
                persisted,
            }
            .into());
        }
    }
    let checkpoint = CatalogueCheckpoint::new(
        manifest.bundle_version,
        Sha256::digest(manifest_bytes).into(),
    );
    if accepted.is_some_and(|state| {
        state.bundle_version == checkpoint.bundle_version
            && state.manifest_sha256 != checkpoint.manifest_sha256
    }) {
        return Err(CatalogueError::Equivocation {
            version: manifest.bundle_version,
        });
    }
    let mut roles = BTreeMap::new();
    for (role, pin) in &manifest.roles {
        let bytes = role_files
            .get(role)
            .ok_or_else(|| ManifestError::SliceMissing {
                role: role.to_string(),
            })?;
        verify_role_hash(role, pin, bytes)?;
        let slice = parse_slice(bytes, role.as_str(), manifest.os).map_err(|source| {
            CatalogueError::Slice {
                role: role.clone(),
                source,
            }
        })?;
        if slice.version != pin.version {
            return Err(CatalogueError::SliceVersion { role: role.clone() });
        }
        let issuance = manifest
            .issuance
            .as_ref()
            .and_then(|metadata| metadata.roles().get(role))
            .cloned();
        roles.insert(
            role.clone(),
            CatalogueRole {
                slice,
                pin: pin.clone(),
                issuance,
            },
        );
    }
    Ok(VerifiedRoleCatalogue {
        checkpoint,
        trust_sha256,
        os: manifest.os,
        issuance_schema_version: manifest
            .issuance
            .as_ref()
            .map(super::issuance::IssuanceMetadata::schema_version),
        roles,
    })
}

/// Preserve actual key provenance independently of a caller's source label.
fn signing_key_fingerprint(trusted_pubkey: &[u8]) -> Result<[u8; 32], CatalogueError> {
    let key = PKey::public_key_from_pem(trusted_pubkey)
        .or_else(|_| PKey::public_key_from_der(trusted_pubkey))
        .map_err(|e| ManifestError::Openssl {
            reason: e.to_string(),
        })?;
    if key.id() != Id::ED25519 {
        return Err(CatalogueError::SigningKeyProfile);
    }
    let trust_sha256 =
        Sha256::digest(
            key.public_key_to_der()
                .map_err(|e| ManifestError::Openssl {
                    reason: e.to_string(),
                })?,
        )
        .into();
    Ok(trust_sha256)
}
