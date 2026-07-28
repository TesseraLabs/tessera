//! On-device role store: role-slice schema and strict TOML parsing.
//!
//! A role slice is a single TOML file (`/var/lib/tessera/roles/<role>.toml`)
//! describing one role for the host's own OS. Parsing is strict
//! (`deny_unknown_fields`): unknown keys or wrong types are validation
//! errors (design decision D9, `PwnKit` lesson — privileged code makes no
//! silent assumptions about input).
//!
//! The schema and parser are part of the open core. Payload sections for
//! every OS parse in any build (open or commercial); only enforcement of
//! `mac`/`selinux` payloads is a commercial extension (design.md
//! open/commercial table).

pub mod audit;
mod getent;
pub mod manifest;
pub mod schema;
pub mod selection;
pub mod store;
pub mod system_account;
pub mod update;

pub use manifest::{
    accept_bundle_version, last_accepted_bundle_version, parse_manifest, persist_bundle_version,
    signed_payload, verify_manifest, verify_manifest_without_accepting, verify_signature, Manifest,
    ManifestCrl, ManifestError, ManifestRole, VerifiedManifest,
};
pub use schema::{parse_slice, Payload, RoleId, RoleOs, RoleSchemaError, RoleSlice, SessionLimits};
pub use selection::{
    bounded_ttl, payload_backend_available, resolve_and_cover, CoverageMethod, Resolution,
    RoleDenyReason, SessionFixError, SessionRolePayload,
};
pub use store::{RoleStore, RoleStoreError, TrustMode, DEFAULT_ROLES_DIR, MAX_ROLES};
pub use system_account::{
    AccountCheck, AccountSnapshot, PasswdLookup, SystemAccountError, SystemAccounts,
    DEFAULT_ACCOUNT_LOOKUP_TIMEOUT, FIRST_REGULAR_UID, LAST_REGULAR_UID,
    MAX_ACCOUNT_LOOKUP_TIMEOUT,
};
pub use update::{atomic_update, cleanup_staged, UpdateTrust};
