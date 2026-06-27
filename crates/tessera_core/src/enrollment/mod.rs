//! Enrollment-package import (`device-enrollment`, section 1).
//!
//! After `clone-image-bootstrap` flips a clone to its per-host identity, the
//! device imports an *enrollment package*: a per-host PKCS#12 (`.p12`, PIN-
//! protected, placed as-is) plus a bundle of device tags, the first role base,
//! and an optional CRL. Two trust modes (parity with `role::store` /
//! `tags::source`): **managed** (signed manifest, anti-rollback `bundle_version`
//! baseline) and **standalone** (filesystem-permission trust, no server).
//!
//! The import REUSES the role-store machinery wholesale:
//! [`crate::role::verify_manifest`] (signature + anti-rollback floor +
//! per-slice hash), the single persisted `bundle.version` floor (no second
//! anti-rollback counter), and [`crate::role::atomic_update`] (validate →
//! `tmp → rename` swap with `.bak` rollback). Imported tags land in the trusted
//! `device-tags` source that [`crate::tags::source`] reads; an arbitrary local
//! tag config is never accepted. Everything is fail-closed: a broken signature,
//! a rollback, a CRL hash mismatch, or a partial install leaves the device in
//! its prior consistent state.

pub mod audit;
pub mod import;

pub use import::{
    installed_managed_tags, EnrollmentPackage, ImportError, ImportMode, ImportOutcome,
    InstallPaths, DEFAULT_CRL_PATH, DEFAULT_P12_PATH, MAX_CRL_BYTES, MAX_P12_BYTES,
};
