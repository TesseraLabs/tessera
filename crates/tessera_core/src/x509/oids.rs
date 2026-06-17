//! Project-private OIDs used by the Tessera extensions.
//!
//! These OIDs are allocated in the RFC 4530 unregistered arc `2.25.<UUID>`
//! (the OID-from-UUID range), so they are guaranteed unique without going
//! through any external registry.  They are stable across versions and form
//! part of the on-the-wire X.509 certificate contract — do **not** change
//! these values.

/// OID of the `pam_cert_host_binding` X.509 extension.
///
/// `extnValue ::= SEQUENCE OF UTF8String`, where each entry is a host
/// descriptor (`"*"`, `"sha256:<hex>"`, or a raw `machine_id`).
pub const HOST_BINDING_OID: &str = "2.25.183976554325829274683049824615098";

/// OID of the `pam_cert_user_binding` X.509 extension.
///
/// `extnValue ::= SEQUENCE OF UTF8String`, where each entry is either `"*"`
/// (matches any user) or an exact PAM username.
pub const USER_BINDING_OID: &str = "2.25.215438916728501023845629178354627";

/// OID of the `pam_cert_max_integrity` X.509 extension.
///
/// `extnValue ::= SEQUENCE { level INTEGER (-128..127), categories BIT STRING DEFAULT ''B }`.
/// Marks the upper bound of Astra МКЦ integrity for the engineer session.
/// Non-critical. See `docs/superpowers/specs/2026-05-14-mac-integrity-design.md`.
pub const MAX_INTEGRITY_OID: &str = "2.25.273824307386008814506455310913083078403";

/// OID of the `pam_cert_allowed_roles` X.509 extension.
/// `extnValue ::= SEQUENCE OF UTF8String`, each entry a `role_id` the leaf may activate.
/// Non-critical. Allocated 2026-06 (RFC 4530 2.25.<UUID> arc).
pub const ALLOWED_ROLES_OID: &str = "2.25.185305973969816596290730578528098241367";

/// OID of the `pam_cert_delegation_constraints` X.509 extension.
///
/// `extnValue ::= SEQUENCE { requireTags SEQUENCE OF SEQUENCE { key UTF8String, value UTF8String },
/// allowRoles SEQUENCE OF UTF8String, maxLevel INTEGER, maxTtl INTEGER }`.
/// Carries the delegation envelope on an intermediate CA: every chain link's
/// envelope is applied with AND/MIN semantics so a misissued child CA cannot
/// widen the scope it inherited.  Valid **only** on a cert with
/// basicConstraints `cA = TRUE`; presence on a leaf (`cA = FALSE`) is malformed
/// and rejects the chain.
///
/// **Critical.** Unlike the leaf scope extensions (all non-critical), ignoring
/// this extension would bypass the delegation envelope, so a verifier that does
/// not understand it MUST reject the certificate.  Allocated 2026-06 from the
/// RFC 4530 `2.25.<UUID>` arc (UUID `b634b091-47d7-4e54-a0fc-3f7dc4a56f97`).
pub const DELEGATION_CONSTRAINTS_OID: &str = "2.25.242193075883906031821745064285793775511";

/// OID of the `pam_cert_profile_version` X.509 extension.
///
/// `extnValue ::= INTEGER`.  Declares the certificate-format version; the chain
/// verifier rejects any cert whose value exceeds
/// `max_supported_profile_version` (fail-closed version gate — the comparison
/// itself lives in `trust-chain-validation`; this OID names the format and
/// extraction).
///
/// **Critical.** A verifier that does not understand this extension MUST reject
/// the certificate rather than silently skip the version gate.  Allocated
/// 2026-06 from the RFC 4530 `2.25.<UUID>` arc (UUID
/// `513cd696-16f7-4de7-8b14-f675c71284e8`).
pub const PROFILE_VERSION_OID: &str = "2.25.107983357797077476746994938370032043240";
