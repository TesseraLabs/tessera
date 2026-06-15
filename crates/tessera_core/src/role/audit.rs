//! Audit events for the role-store subsystem.
//!
//! Every event uses the `role.audit` tracing target (per the logging-audit
//! spec) and carries plain field names (`event`, `path`, `error`, `reason`,
//! `bundle_version`) — *not* the `F_*` prefix the MAC subsystem uses. The
//! `emit_*` helpers freeze the event name and field schema in code so tests
//! can assert on the `EVENT_*`/`REASON_*` constants without mistyping a
//! string literal.
//!
//! `tracing` has no `critical` level; "severity critical" maps to the
//! `error` level (the highest tracing has), used for the fail-closed bundle
//! rejections below.

/// `role_session_open` — a session was opened with a resolved, covered role.
pub const EVENT_ROLE_SESSION_OPEN: &str = "role_session_open";
/// `role_deny` — a login was denied (or, under `warn`, would have been) for a
/// role reason. Carries the `reason` field (see `RoleDenyReason`).
pub const EVENT_ROLE_DENY: &str = "role_deny";
/// `role_slice_invalid` — a single `*.toml` slice failed to parse/validate
/// in standalone mode and was skipped (other slices keep working).
pub const EVENT_ROLE_SLICE_INVALID: &str = "role_slice_invalid";
/// `bundle_rejected` — a managed bundle failed verification; the whole base
/// is rejected (fail-closed). Severity critical → tracing `error` level.
pub const EVENT_BUNDLE_REJECTED: &str = "bundle_rejected";
/// `bundle_baseline_established` — first managed bundle accepted with no
/// persisted `bundle_version` (TOFU baseline).
pub const EVENT_BUNDLE_BASELINE: &str = "bundle_baseline_established";
/// `cert_allowed_roles_parse_failed` — the cert's `pam_cert_allowed_roles`
/// extension is malformed; coverage fails closed (treated as no roles).
pub const EVENT_CERT_ALLOWED_ROLES_PARSE_FAILED: &str = "cert_allowed_roles_parse_failed";

/// `bundle_rejected` reason: manifest signature did not verify.
pub const REASON_SIGNATURE: &str = "signature";
/// `bundle_rejected` reason: `bundle_version` regressed below the persisted
/// value (anti-rollback).
pub const REASON_ROLLBACK: &str = "rollback";
/// `bundle_rejected` reason: a slice's SHA-256 did not match the manifest
/// (mix-and-match), or a listed slice was missing.
pub const REASON_HASH_MISMATCH: &str = "hash_mismatch";

/// Emit `role_session_open` — a session opened with a resolved role.
///
/// `method` is `cert` or `code`; `ttl_seconds` is the bounded session TTL.
/// The canonical user name and the role are always separate fields (never a
/// `user+role` splice).
pub fn emit_role_session_open(
    user: &str,
    role: &str,
    role_version: u32,
    method: &str,
    ttl_seconds: u64,
) {
    tracing::info!(
        target: "role.audit",
        event = EVENT_ROLE_SESSION_OPEN,
        user,
        role,
        role_version,
        method,
        ttl = ttl_seconds,
    );
}

/// Emit `role_deny` — a login denied for a role reason.
///
/// `reason` is one of `not_found` / `not_covered` / `backend_unavailable` /
/// `mask_exceeds_ceiling` / `syntax`. The canonical user and the requested
/// role are separate fields; the raw login string is only logged for
/// `reason = syntax` (handled at the parse site, not here).
pub fn emit_role_deny(user: &str, requested_role: &str, reason: &str) {
    tracing::warn!(
        target: "role.audit",
        event = EVENT_ROLE_DENY,
        user,
        requested_role,
        reason,
    );
}

/// Emit `role_slice_invalid` — a per-slice skip in standalone load.
pub fn emit_role_slice_invalid(path: &str, error: &str) {
    tracing::warn!(
        target: "role.audit",
        event = EVENT_ROLE_SLICE_INVALID,
        path,
        error,
    );
}

/// Emit `cert_allowed_roles_parse_failed` — the cert's `allowed_roles`
/// extension is malformed and is treated as granting no roles (fail-closed).
///
/// `subject` identifies the offending certificate (subject CN / serial); the
/// raw extension bytes are never logged.
pub fn emit_cert_allowed_roles_parse_failed(subject: &str) {
    tracing::warn!(
        target: "role.audit",
        event = EVENT_CERT_ALLOWED_ROLES_PARSE_FAILED,
        subject,
    );
}

/// Emit `bundle_rejected` — whole managed base rejected (fail-closed).
///
/// `reason` is one of [`REASON_SIGNATURE`], [`REASON_ROLLBACK`],
/// [`REASON_HASH_MISMATCH`]. Severity critical → tracing `error` level.
pub fn emit_bundle_rejected(reason: &str, bundle_version: u64) {
    tracing::error!(
        target: "role.audit",
        event = EVENT_BUNDLE_REJECTED,
        reason,
        bundle_version,
    );
}

/// Emit `bundle_baseline_established` — first managed bundle accepted under
/// trust-on-first-use (no persisted `bundle_version`).
pub fn emit_bundle_baseline_established(bundle_version: u64) {
    tracing::warn!(
        target: "role.audit",
        event = EVENT_BUNDLE_BASELINE,
        bundle_version,
    );
}
