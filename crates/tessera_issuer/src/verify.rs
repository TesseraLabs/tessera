//! Post-sign self-verification: re-parse the assembled artifact with the same
//! shared code the Engine uses, and refuse to return anything it would reject.
//!
//! This is the `cert-issuance` contract requirement made executable: the issuer
//! decodes each custom extension out of its own output via [`tessera_ext`] and
//! re-affirms the monotonicity relation on the *parsed* bytes — so a subtle
//! encoding bug is caught here, before an operator ever receives the artifact.

use tessera_ext::delegation::{narrows, DelegationConstraints, ScopeDimension};
use tessera_ext::ext::{
    extract_basic_constraints, extract_extension_value, parse_max_integrity, parse_seq_of_utf8,
};
use tessera_ext::oids::{
    ALLOWED_ROLES_OID, DELEGATION_CONSTRAINTS_OID, HOST_BINDING_OID, MAX_INTEGRITY_OID,
    PROFILE_VERSION_OID, USER_BINDING_OID,
};

use crate::error::IssueError;
use crate::profile::{CaRequest, LeafRequest};

/// A self-check failure with a fixed reason.
fn reject(reason: impl Into<String>) -> IssueError {
    IssueError::SelfCheckFailed(reason.into())
}

/// Reads one custom extension's `extnValue` from the artifact, rejecting if it
/// is absent.
fn require_extension(cert_der: &[u8], oid: &str, name: &str) -> Result<Vec<u8>, IssueError> {
    extract_extension_value(cert_der, oid)?
        .ok_or_else(|| reject(format!("{name} extension absent")))
}

/// Re-parses a leaf artifact and checks it against the request and the parent
/// envelope.
pub(crate) fn self_check_leaf(
    cert_der: &[u8],
    req: &LeafRequest,
    parent: &DelegationConstraints,
) -> Result<(), IssueError> {
    // basicConstraints present and cA=FALSE.
    let basic = extract_basic_constraints(cert_der)?
        .ok_or_else(|| reject("basicConstraints absent on leaf"))?;
    if basic.ca {
        return Err(reject("leaf certificate asserts cA=TRUE"));
    }

    // Leaf must NOT carry a delegation envelope (malformed on a leaf).
    if extract_extension_value(cert_der, DELEGATION_CONSTRAINTS_OID)?.is_some() {
        return Err(reject("leaf carries a delegation_constraints extension"));
    }

    // host_binding / user_binding: present, non-empty, equal to the request.
    let hosts = parse_seq_of_utf8(&require_extension(
        cert_der,
        HOST_BINDING_OID,
        "host_binding",
    )?)?;
    if hosts.is_empty() {
        return Err(reject("host_binding is empty"));
    }
    if hosts != req.host_binding {
        return Err(reject("host_binding does not match the request"));
    }
    let users = parse_seq_of_utf8(&require_extension(
        cert_der,
        USER_BINDING_OID,
        "user_binding",
    )?)?;
    if users.is_empty() {
        return Err(reject("user_binding is empty"));
    }
    if users != req.user_binding {
        return Err(reject("user_binding does not match the request"));
    }

    // allowed_roles: present, equal to the request, and a subset of the parent.
    let roles = parse_seq_of_utf8(&require_extension(
        cert_der,
        ALLOWED_ROLES_OID,
        "allowed_roles",
    )?)?;
    if roles != req.allowed_roles {
        return Err(reject("allowed_roles does not match the request"));
    }
    for role in &roles {
        if !parent.allow_roles.iter().any(|allowed| allowed == role) {
            return Err(IssueError::ScopeWidened(ScopeDimension::AllowRoles));
        }
    }

    // profile_version: present and equal to the request.
    let version = tessera_ext::ext::parse_profile_version(&require_extension(
        cert_der,
        PROFILE_VERSION_OID,
        "profile_version",
    )?)?;
    if version != req.profile_version {
        return Err(reject("profile_version does not match the request"));
    }

    // max_integrity: presence and value must match the request, and stay within
    // the parent ceiling.
    let extracted = extract_extension_value(cert_der, MAX_INTEGRITY_OID)?;
    match (req.max_integrity, extracted) {
        (Some(ceiling), Some(value)) => {
            let (level, categories) = parse_max_integrity(&value)?;
            if (level, categories) != (ceiling.level, ceiling.categories) {
                return Err(reject("max_integrity does not match the request"));
            }
            if level > parent.max_level {
                return Err(IssueError::IntegrityExceedsParent {
                    requested: level,
                    ceiling: parent.max_level,
                });
            }
        }
        (None, None) => {}
        (Some(_), None) => return Err(reject("max_integrity requested but absent")),
        (None, Some(_)) => return Err(reject("max_integrity present but not requested")),
    }

    Ok(())
}

/// Re-parses a CA artifact and checks it against the request and, if any, the
/// parent envelope.
pub(crate) fn self_check_ca(
    cert_der: &[u8],
    req: &CaRequest,
    parent: Option<&DelegationConstraints>,
) -> Result<(), IssueError> {
    // basicConstraints present and cA=TRUE.
    let basic = extract_basic_constraints(cert_der)?
        .ok_or_else(|| reject("basicConstraints absent on CA"))?;
    if !basic.ca {
        return Err(reject("CA certificate asserts cA=FALSE"));
    }

    // keyUsage present.
    require_extension(cert_der, "2.5.29.15", "keyUsage")?;

    // delegation_constraints: present, parses, equals the request, and narrows
    // the parent (when there is one).
    let value = require_extension(
        cert_der,
        DELEGATION_CONSTRAINTS_OID,
        "delegation_constraints",
    )?;
    let constraints = tessera_ext::delegation::parse_constraints(&value)
        .map_err(|e| reject(format!("delegation_constraints reparse failed: {e}")))?;
    if constraints != req.constraints {
        return Err(reject("delegation_constraints does not match the request"));
    }
    if let Some(parent) = parent {
        narrows(&constraints, parent).map_err(|w| IssueError::ScopeWidened(w.dimension))?;
    }

    // profile_version present and equal to the request.
    let version = tessera_ext::ext::parse_profile_version(&require_extension(
        cert_der,
        PROFILE_VERSION_OID,
        "profile_version",
    )?)?;
    if version != req.profile_version {
        return Err(reject("profile_version does not match the request"));
    }

    Ok(())
}
