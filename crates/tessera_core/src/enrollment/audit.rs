//! Audit events for the enrollment subsystem.
//!
//! Mirrors `role::audit` / `tags::audit`: every event uses a dedicated tracing
//! target and plain field names, and the `emit_*` helpers freeze the event
//! name + field schema in code so tests can assert on the `EVENT_*` constants
//! without mistyping a string literal.
//!
//! The bare [`emit_device_enrolled`] / [`emit_enrollment_rejected`] hooks
//! (section 1) fix the event name and field schema. The enriched
//! [`emit_device_enrolled_full`] / [`emit_enrollment_rejected_full`] variants
//! (section 4) add the `host_id` prefix8 and the per-host certificate `serial`
//! that only the CLI caller holds — these are the events the CLI emits on the
//! enrollment path.

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

/// Enrichment the CLI caller adds to an enrollment audit event: the device's
/// `host_id` prefix8 and the per-host certificate serial, neither of which the
/// core import has in hand. Both are short, eyeballable identifiers; absent
/// values are emitted as empty strings (the core-only call sites pass empties).
#[derive(Debug, Clone, Copy, Default)]
pub struct EnrollAuditIds<'a> {
    /// First 8 hex chars of the device `host_id` hash (`""` when unknown).
    pub host_id_prefix8: &'a str,
    /// Per-host leaf certificate serial, uppercase hex (`""` when unknown).
    pub serial: &'a str,
}

/// Emit `device_enrolled` — an enrollment package imported successfully.
///
/// `mode` is one of [`MODE_STANDALONE`] / [`MODE_MANAGED`]; `bundle_version`
/// is the applied (managed) bundle version (`0` for standalone, which has no
/// signed version). This bare variant carries empty `host_id`/`serial` fields;
/// the CLI uses [`emit_device_enrolled_full`] to populate them.
pub fn emit_device_enrolled(mode: &str, bundle_version: u64) {
    emit_device_enrolled_full(mode, bundle_version, EnrollAuditIds::default());
}

/// Emit `device_enrolled` with the CLI-supplied `host_id` prefix8 and per-host
/// certificate serial (section 4 field layout: `host_id`, `serial`, `mode`,
/// `bundle_version`).
pub fn emit_device_enrolled_full(mode: &str, bundle_version: u64, ids: EnrollAuditIds<'_>) {
    tracing::info!(
        target: "enrollment.audit",
        event = EVENT_DEVICE_ENROLLED,
        host_id = ids.host_id_prefix8,
        serial = ids.serial,
        mode,
        bundle_version,
    );
}

/// Emit `enrollment_rejected` — an import was rejected (fail-closed).
///
/// `reason` is one of [`REASON_MANIFEST`] / [`REASON_CRL`] / [`REASON_INSTALL`].
/// The device is left in its prior state. This bare variant carries empty
/// `host_id`/`serial` fields; the CLI uses [`emit_enrollment_rejected_full`].
pub fn emit_enrollment_rejected(reason: &str) {
    emit_enrollment_rejected_full(reason, EnrollAuditIds::default());
}

/// Emit `enrollment_rejected` with the CLI-supplied `host_id` prefix8 and (when
/// known) the per-host certificate serial.
pub fn emit_enrollment_rejected_full(reason: &str, ids: EnrollAuditIds<'_>) {
    tracing::error!(
        target: "enrollment.audit",
        event = EVENT_ENROLLMENT_REJECTED,
        host_id = ids.host_id_prefix8,
        serial = ids.serial,
        reason,
    );
}
