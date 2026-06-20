//! Audit events for the enrollment subsystem.
//!
//! Mirrors `role::audit` / `tags::audit`: every event uses a dedicated tracing
//! target and plain field names, and the `emit_*` helpers freeze the event
//! name + field schema in code so tests can assert on the `EVENT_*` constants
//! without mistyping a string literal.
//!
//! Only the minimal `device_enrolled` hook is defined here (section 1). Full
//! CLI-side emission with `host_id`/serial enrichment is section 2/4 of the
//! `device-enrollment` change; this module fixes the event name and the
//! field schema so the CLI can call into it later.

/// `device_enrolled` — an enrollment package was successfully imported.
/// Carries the applied `bundle_version` and the trust `mode`
/// (`standalone` / `managed`). `host_id` prefix8 and the per-host serial are
/// added by the CLI caller (section 2/4) which holds that context.
pub const EVENT_DEVICE_ENROLLED: &str = "device_enrolled";

/// `enrollment_rejected` — an import was rejected (fail-closed); the device
/// is left in its prior state. Severity critical → tracing `error` level.
pub const EVENT_ENROLLMENT_REJECTED: &str = "enrollment_rejected";

/// `enrollment_rejected` reason: managed manifest verification failed
/// (signature / anti-rollback / hash), surfaced from the role-store machinery.
pub const REASON_MANIFEST: &str = "manifest";
/// `enrollment_rejected` reason: the co-located CRL did not match its signed
/// pin (hash mismatch) or is otherwise malformed.
pub const REASON_CRL: &str = "crl";
/// `enrollment_rejected` reason: the atomic install step failed; the prior
/// device state was restored.
pub const REASON_INSTALL: &str = "install";

/// Trust-mode label `standalone` for the `mode` field.
pub const MODE_STANDALONE: &str = "standalone";
/// Trust-mode label `managed` for the `mode` field.
pub const MODE_MANAGED: &str = "managed";

/// Emit `device_enrolled` — an enrollment package imported successfully.
///
/// `mode` is one of [`MODE_STANDALONE`] / [`MODE_MANAGED`]; `bundle_version`
/// is the applied (managed) bundle version (`0` for standalone, which has no
/// signed version). The CLI enriches the log line with `host_id` prefix8 and the
/// per-host serial.
pub fn emit_device_enrolled(mode: &str, bundle_version: u64) {
    tracing::info!(
        target: "enrollment.audit",
        event = EVENT_DEVICE_ENROLLED,
        mode,
        bundle_version,
    );
}

/// Emit `enrollment_rejected` — an import was rejected (fail-closed).
///
/// `reason` is one of [`REASON_MANIFEST`] / [`REASON_CRL`] / [`REASON_INSTALL`].
/// The device is left in its prior state.
pub fn emit_enrollment_rejected(reason: &str) {
    tracing::error!(
        target: "enrollment.audit",
        event = EVENT_ENROLLMENT_REJECTED,
        reason,
    );
}
