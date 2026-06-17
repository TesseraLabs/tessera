//! Audit events for the device-tags subsystem.
//!
//! Mirrors `role::audit`: every event uses a dedicated tracing target and
//! plain field names, and the `emit_*` helpers freeze the event name + field
//! schema in code so tests can assert on the `EVENT_*` constants without
//! mistyping a string literal.

/// `tags_source_rejected` — a tags source failed verification/parsing; no tags
/// are applied (fail-closed). Severity critical → tracing `error` level.
pub const EVENT_TAGS_SOURCE_REJECTED: &str = "tags_source_rejected";

/// `tags_source_rejected` reason: managed manifest verification failed
/// (signature / anti-rollback / hash), surfaced from the role-store machinery.
pub const REASON_MANIFEST: &str = "manifest";
/// `tags_source_rejected` reason: the tags payload itself is malformed
/// (duplicate/empty key, empty value, non-UTF-8, oversize).
pub const REASON_MALFORMED: &str = "malformed";

/// Emit `tags_source_rejected` — the device-tags source was not applied
/// (fail-closed). `reason` is one of [`REASON_MANIFEST`] / [`REASON_MALFORMED`].
/// The previous tag set (if any) is retained by the caller.
pub fn emit_tags_source_rejected(reason: &str) {
    tracing::error!(
        target: "tags.audit",
        event = EVENT_TAGS_SOURCE_REJECTED,
        reason,
    );
}
