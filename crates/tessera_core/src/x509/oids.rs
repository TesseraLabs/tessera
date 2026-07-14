//! Project-private OIDs used by the Tessera extensions.
//!
//! The canonical definitions live in [`tessera_ext::oids`] so the issuer
//! tooling and the Engine share one on-the-wire contract.  They are re-exported
//! here under the historical `x509::oids` path.

pub use tessera_ext::oids::{
    ALLOWED_ROLES_OID, DELEGATION_CONSTRAINTS_OID, HOST_BINDING_OID, MAX_INTEGRITY_OID,
    PROFILE_VERSION_OID, USER_BINDING_OID,
};
