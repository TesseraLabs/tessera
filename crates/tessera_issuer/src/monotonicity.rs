//! Pre-sign monotonicity checks: a child's scope must not widen its parent's.
//!
//! The parent envelope is read from the parent certificate with the same
//! shared code the Engine uses — [`tessera_ext::ext::extract_extension_value`]
//! to pull the `extnValue`, then [`tessera_ext::delegation::parse_constraints`]
//! to decode it — so the issuer bounds a request against exactly what the Engine
//! will later enforce.

use tessera_ext::delegation::{narrows, DelegationConstraints};
use tessera_ext::ext::extract_extension_value;
use tessera_ext::oids::DELEGATION_CONSTRAINTS_OID;

use crate::error::IssueError;
use crate::profile::{CaRequest, LeafRequest};

/// Reads the parent CA's delegation envelope from its certificate DER, or
/// `Ok(None)` if the parent carries none (e.g. a fleet root that has not yet
/// been constrained).
///
/// # Errors
///
/// [`IssueError::ExtCodec`] if the extension is present but malformed, or the
/// certificate structure is unreadable.
pub fn parent_constraints(parent_der: &[u8]) -> Result<Option<DelegationConstraints>, IssueError> {
    let Some(value) = extract_extension_value(parent_der, DELEGATION_CONSTRAINTS_OID)? else {
        return Ok(None);
    };
    let constraints = tessera_ext::delegation::parse_constraints(&value)
        .map_err(|e| IssueError::InvalidParentCertificate(e.to_string()))?;
    Ok(Some(constraints))
}

/// Checks that a child CA's assigned envelope narrows-or-equals the parent's.
///
/// A parent with no envelope (`None`) is a root establishing the first
/// envelope: any child scope is accepted.
///
/// # Errors
///
/// [`IssueError::ScopeWidened`] naming the first widened dimension.
pub fn check_ca_within_parent(
    req: &CaRequest,
    parent: Option<&DelegationConstraints>,
) -> Result<(), IssueError> {
    if let Some(parent) = parent {
        narrows(&req.constraints, parent).map_err(|w| IssueError::ScopeWidened(w.dimension))?;
    }
    Ok(())
}

/// Checks that a leaf request stays inside the parent CA's envelope along the
/// dimensions the predicate covers for a leaf: `allowed_roles ⊆ allow_roles`,
/// `max_integrity.level ≤ max_level`, and validity duration `≤ max_ttl`.
///
/// Host binding and tag addressing are runtime Engine semantics and are not
/// checked here (design: the issuer enforces only what the shared predicate
/// covers).
///
/// # Errors
///
/// A typed [`IssueError`] naming the violated dimension.
pub fn check_leaf_within_parent(
    req: &LeafRequest,
    parent: &DelegationConstraints,
) -> Result<(), IssueError> {
    // allowed_roles ⊆ parent.allow_roles
    for role in &req.allowed_roles {
        if !parent.allow_roles.iter().any(|allowed| allowed == role) {
            return Err(IssueError::ScopeWidened(
                tessera_ext::delegation::ScopeDimension::AllowRoles,
            ));
        }
    }
    // max_integrity.level ≤ parent.max_level
    if let Some(ceiling) = req.max_integrity {
        if ceiling.level > parent.max_level {
            return Err(IssueError::IntegrityExceedsParent {
                requested: ceiling.level,
                ceiling: parent.max_level,
            });
        }
    }
    // validity duration ≤ parent.max_ttl
    let duration = req.validity.duration_secs();
    if duration > parent.max_ttl {
        return Err(IssueError::ValidityExceedsParent {
            requested_secs: duration,
            max_ttl: parent.max_ttl,
        });
    }
    Ok(())
}
