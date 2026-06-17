//! Delegation-envelope enforcement on a verified certificate chain
//! (`trust-chain-validation` delta spec, tasks 4.2 / 4.3 / 4.4, design
//! decision 4).
//!
//! The trust layer builds and cryptographically verifies the chain, but the
//! delegation envelope needs runtime inputs the trust layer does not own — the
//! device's signed tags and the requested role/level. [`enforce_delegation`]
//! is therefore a standalone function the auth flow calls with explicit
//! context once those inputs are known.
//!
//! ## Semantics (AND/MIN across ALL CA links)
//!
//! For **every** CA certificate in the chain that carries a
//! `pam_cert_delegation_constraints` extension, the following must all hold:
//!
//! * **Tag envelope (4.2).** `device_tags ⊇ requireTags` (generic superset).
//!   A non-matching device — or a device with no tags when `requireTags` is
//!   non-empty — is rejected. The check is conjunctive across every CA link, so
//!   a misissued child CA that declares a *wider* (e.g. empty) `requireTags`
//!   cannot escape a parent CA's envelope.
//!
//! * **Role ceiling (4.3).** `requested_role` ∈ `allowRoles` of every such CA,
//!   and ∈ the leaf's allowed-roles list when present.
//!
//! * **Level ceiling (4.3).** `requested_level ≤ maxLevel` of every such CA,
//!   and `≤` the leaf `max_integrity` level when present.
//!
//! * **TTL ceiling (4.3).** each chain link's lifetime
//!   `(notAfter − notBefore)` ≤ the `maxTtl` of its **parent** CA.
//!
//! A `pam_cert_delegation_constraints` extension on a non-CA (leaf) cert is a
//! placement violation and rejects the chain (enforced by
//! [`extract_delegation_constraints`], surfaced here as
//! [`DelegationError::Malformed`]).
//!
//! ## Wildcard `host_binding` (4.4)
//!
//! The wildcard `host_binding=*` semantics themselves live in `pam_tessera`
//! (`verify_host_binding`); the *group scoping* is enforced here by the tag
//! envelope: when the chain carries constraints, a wildcard leaf authenticates
//! only on devices whose tags satisfy the envelope, because this function
//! rejects a non-matching device regardless of the wildcard. When the chain
//! carries no constraints, no new restriction is added (prior semantics).
//!
//! All checks are fail-closed: any malformed extension, missing tag, or
//! exceeded ceiling rejects the whole chain.

use std::time::Duration;

use crate::role::RoleId;
use crate::tags::DeviceTags;
use crate::x509::delegation_constraints_ext::{
    extract_delegation_constraints, DelegationConstraintsExtError,
};
use crate::x509::{Certificate, VerifiedX509};

/// Errors raised by [`enforce_delegation`]. Every variant is a fail-closed
/// rejection of the authentication attempt.
#[derive(Debug, thiserror::Error)]
pub enum DelegationError {
    /// A `delegation_constraints` extension was present but malformed — bad
    /// DER, an invalid `role_id`, a duplicate tag key, or placement on a
    /// non-CA (leaf) certificate.
    #[error("malformed delegation_constraints at chain index {index}: {source}")]
    Malformed {
        /// Chain index of the offending certificate (0 = leaf).
        index: usize,
        /// Underlying extraction error.
        #[source]
        source: DelegationConstraintsExtError,
    },

    /// The device's tags do not satisfy a CA's `requireTags` envelope.
    #[error("device tags do not satisfy requireTags of CA at chain index {index}")]
    TagEnvelope {
        /// Chain index of the CA whose envelope was violated.
        index: usize,
    },

    /// The requested role is not permitted by a CA's `allowRoles`, or by the
    /// leaf's allowed-roles list.
    #[error("role {role} not allowed by {scope}")]
    RoleNotAllowed {
        /// The requested role.
        role: String,
        /// Which check rejected it (a CA index, or the leaf list).
        scope: String,
    },

    /// The requested integrity level exceeds a CA's `maxLevel`, or the leaf's
    /// `max_integrity` ceiling.
    #[error("requested level {requested} exceeds ceiling {ceiling} ({scope})")]
    LevelCeiling {
        /// The requested integrity level.
        requested: i8,
        /// The ceiling that was exceeded.
        ceiling: i8,
        /// Which ceiling rejected it (a CA index, or the leaf `max_integrity`).
        scope: String,
    },

    /// A chain link's lifetime exceeds the `maxTtl` declared by its parent CA.
    #[error(
        "link at chain index {link_index} lifetime {link_ttl_secs}s exceeds maxTtl \
         {max_ttl_secs}s of parent CA at index {parent_index}"
    )]
    TtlCeiling {
        /// Chain index of the over-long link.
        link_index: usize,
        /// Chain index of the parent CA imposing the ceiling.
        parent_index: usize,
        /// The link's lifetime in seconds.
        link_ttl_secs: u64,
        /// The parent's `maxTtl` in seconds.
        max_ttl_secs: u64,
    },
}

impl DelegationError {
    /// Chain index (0 = leaf) of the certificate that triggered this
    /// rejection: the CA whose envelope/ceiling was violated, the over-long
    /// link's parent CA, or the malformed cert. Leaf-list role/level
    /// rejections (which carry no chain index) map to the leaf (0). Used to
    /// resolve the culprit serial for the `delegation_denied` audit event.
    #[must_use]
    pub fn culprit_index(&self) -> usize {
        match self {
            DelegationError::Malformed { index, .. } | DelegationError::TagEnvelope { index } => {
                *index
            }
            DelegationError::TtlCeiling { parent_index, .. } => *parent_index,
            // Role/level rejections carry a textual scope (a CA index or the
            // leaf list) rather than a numeric index; attribute them to the
            // leaf, which is always present. The full scope is in the error's
            // Display, captured in the audit `detail` field.
            DelegationError::RoleNotAllowed { .. } | DelegationError::LevelCeiling { .. } => 0,
        }
    }
}

/// Enforces the delegation envelope, role/level/TTL ceilings, and wildcard
/// group-scoping over a verified `chain` (leaf → anchor ordering, as produced
/// by [`crate::x509::chain::build_chain`]).
///
/// * `device_tags` — this device's trusted, signed tag set.
/// * `requested_role` — the role the session is activating.
/// * `requested_level` — the requested integrity level (Astra МКЦ linear `i8`).
/// * `leaf_max_integrity_level` — the leaf `max_integrity` ceiling level, if the
///   leaf carries that extension (`None` = no leaf level ceiling).
/// * `leaf_allowed_roles` — the leaf `allowed_roles` list, if present (`None` =
///   no leaf role list; an empty slice = the leaf grants no roles).
///
/// The link-lifetime ceiling is intrinsic to the certificates
/// (`notAfter − notBefore`), so no wall-clock `now` is needed here; expiry of
/// the chain against the current time is checked separately by the trust
/// verifier.
///
/// # Errors
///
/// Any [`DelegationError`] — every one is a fail-closed rejection.
pub fn enforce_delegation(
    chain: &[Certificate],
    device_tags: &DeviceTags,
    requested_role: &RoleId,
    requested_level: i8,
    leaf_max_integrity_level: Option<i8>,
    leaf_allowed_roles: Option<&[RoleId]>,
) -> Result<(), DelegationError> {
    // Leaf-level ceilings first (cheap, independent of the chain walk).
    if let Some(allowed) = leaf_allowed_roles {
        if !allowed.contains(requested_role) {
            return Err(DelegationError::RoleNotAllowed {
                role: requested_role.to_string(),
                scope: "leaf allowed_roles".to_owned(),
            });
        }
    }
    if let Some(ceiling) = leaf_max_integrity_level {
        if requested_level > ceiling {
            return Err(DelegationError::LevelCeiling {
                requested: requested_level,
                ceiling,
                scope: "leaf max_integrity".to_owned(),
            });
        }
    }

    // Walk every cert.  `extract_delegation_constraints` self-enforces CA-only
    // placement: it returns `Err(NotCa)` for the extension on a leaf, which we
    // surface as `Malformed`.  `Ok(Some)` therefore implies a CA carrying a
    // well-formed envelope.
    for (index, cert) in chain.iter().enumerate() {
        let verified = VerifiedX509::new(cert.x509().clone());
        let constraints = match extract_delegation_constraints(&verified) {
            Ok(Some(c)) => c,
            Ok(None) => continue,
            Err(source) => return Err(DelegationError::Malformed { index, source }),
        };

        // 4.2 — tag envelope (AND across all CA links).
        if !constraints.require_tags.is_empty() {
            let require = DeviceTags::from_pairs(
                constraints
                    .require_tags
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone())),
            )
            .map_err(|_| DelegationError::TagEnvelope { index })?;
            if !device_tags.satisfies(&require) {
                return Err(DelegationError::TagEnvelope { index });
            }
        }

        // 4.3 — role ceiling (AND across all CA links).
        if !constraints.allow_roles.contains(requested_role) {
            return Err(DelegationError::RoleNotAllowed {
                role: requested_role.to_string(),
                scope: format!("allowRoles of CA at chain index {index}"),
            });
        }

        // 4.3 — level ceiling (MIN across all CA links).
        if requested_level > constraints.max_level {
            return Err(DelegationError::LevelCeiling {
                requested: requested_level,
                ceiling: constraints.max_level,
                scope: format!("maxLevel of CA at chain index {index}"),
            });
        }

        // 4.3 — TTL ceiling: the direct child of this CA (chain[index - 1])
        // must have a lifetime ≤ this CA's maxTtl.  A CA carrying constraints
        // is always above the leaf (index ≥ 1), so `index - 1` is in range.
        if let Some(child) = index.checked_sub(1).and_then(|i| chain.get(i)) {
            let link_ttl = link_lifetime(child);
            let max_ttl = Duration::from_secs(constraints.max_ttl);
            if link_ttl > max_ttl {
                return Err(DelegationError::TtlCeiling {
                    link_index: index - 1,
                    parent_index: index,
                    link_ttl_secs: link_ttl.as_secs(),
                    max_ttl_secs: constraints.max_ttl,
                });
            }
        }
    }

    Ok(())
}

/// `true` if any certificate in `chain` carries a well-formed
/// `pam_cert_delegation_constraints` extension (i.e. the chain is
/// envelope-scoped). A malformed/mis-placed extension is reported as
/// `Err(Malformed)` — fail-closed, same as [`enforce_delegation`].
///
/// # Errors
///
/// [`DelegationError::Malformed`] for a malformed or mis-placed extension.
pub fn chain_carries_constraints(chain: &[Certificate]) -> Result<bool, DelegationError> {
    for (index, cert) in chain.iter().enumerate() {
        let verified = VerifiedX509::new(cert.x509().clone());
        match extract_delegation_constraints(&verified) {
            Ok(Some(_)) => return Ok(true),
            Ok(None) => {}
            Err(source) => return Err(DelegationError::Malformed { index, source }),
        }
    }
    Ok(false)
}

/// Like [`enforce_delegation`] but for a possibly-absent requested role.
///
/// When `requested_role` is `Some`, this delegates verbatim to
/// [`enforce_delegation`]. When it is `None` (no role was selected — e.g.
/// `[roles].enforce = false`), an envelope-scoped chain cannot be satisfied:
/// a group-delegation login that names no role cannot be proven to fall within
/// any CA's `allowRoles`, so the chain is rejected fail-closed. A chain that
/// carries NO delegation constraints is unaffected (prior per-host semantics).
///
/// # Errors
///
/// Any [`DelegationError`] — every one is a fail-closed rejection.
pub fn enforce_delegation_opt(
    chain: &[Certificate],
    device_tags: &DeviceTags,
    requested_role: Option<&RoleId>,
    requested_level: i8,
    leaf_max_integrity_level: Option<i8>,
    leaf_allowed_roles: Option<&[RoleId]>,
) -> Result<(), DelegationError> {
    if let Some(role) = requested_role {
        return enforce_delegation(
            chain,
            device_tags,
            role,
            requested_level,
            leaf_max_integrity_level,
            leaf_allowed_roles,
        );
    }
    // No role selected: only envelope-free (per-host) chains are allowed
    // through. An envelope-scoped chain rejects fail-closed — we attribute it
    // to the first constraint-bearing CA so the audit culprit serial is
    // meaningful.
    for (index, cert) in chain.iter().enumerate() {
        let verified = VerifiedX509::new(cert.x509().clone());
        match extract_delegation_constraints(&verified) {
            Ok(Some(_)) => {
                return Err(DelegationError::RoleNotAllowed {
                    role: String::new(),
                    scope: format!("allowRoles of CA at chain index {index} (no role selected)"),
                });
            }
            Ok(None) => {}
            Err(source) => return Err(DelegationError::Malformed { index, source }),
        }
    }
    Ok(())
}

/// A certificate link's lifetime, `notAfter − notBefore`, clamped at zero for
/// the pathological case of a cert whose `notAfter` precedes its `notBefore`.
fn link_lifetime(cert: &Certificate) -> Duration {
    cert.not_after()
        .duration_since(cert.not_before())
        .unwrap_or(Duration::ZERO)
}
