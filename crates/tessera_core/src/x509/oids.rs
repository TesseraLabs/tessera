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
