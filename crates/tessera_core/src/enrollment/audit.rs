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
//! (section 4) carry the `host_id` prefix8 and the per-host certificate
//! `serial` that the caller supplies — these are the events the CLI emits on
//! the enrollment path.
//!
//! `serial` is always empty today. It cannot be read out of the enrollment
//! package's `.p12` without the PIN, and nothing else on the import path
//! vouches for a value, so the field carries none; it stays in the schema and
//! waits for a source that will be covered by a signature.

/// `device_enrolled` — an enrollment package was successfully imported.
/// Carries the applied `bundle_version` and the trust `mode`
/// (`standalone` / `managed`). The `host_id` prefix8 comes from the CLI caller
/// (section 2/4), which holds that context; the `serial` field is emitted
/// empty until a source under signature supplies it.
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

/// Enrichment the caller adds to an enrollment audit event: the device's
/// `host_id` prefix8 and the per-host certificate serial, neither of which the
/// core import has in hand. Both are short, eyeballable identifiers; absent
/// values are emitted as empty strings (the core-only call sites pass empties).
#[derive(Debug, Clone, Copy, Default)]
pub struct EnrollAuditIds<'a> {
    /// First 8 hex chars of the device `host_id` hash (`""` when unknown).
    pub host_id_prefix8: &'a str,
    /// Per-host leaf certificate serial, uppercase hex.
    ///
    /// Every caller passes `""` today: the serial cannot be derived from the
    /// package `.p12` without the PIN, and no signed source carries it yet.
    pub serial: &'a str,
}

/// Emit `device_enrolled` — an enrollment package imported successfully.
///
/// `mode` is one of [`MODE_STANDALONE`] / [`MODE_MANAGED`]; `bundle_version`
/// is the applied (managed) bundle version (`0` for standalone, which has no
/// signed version). This bare variant carries empty `host_id`/`serial` fields;
/// the CLI uses [`emit_device_enrolled_full`] to fill in the `host_id`.
pub fn emit_device_enrolled(mode: &str, bundle_version: u64) {
    emit_device_enrolled_full(mode, bundle_version, EnrollAuditIds::default());
}

/// Emit `device_enrolled` with the caller-supplied identifiers (section 4 field
/// layout: `host_id`, `serial`, `mode`, `bundle_version`). `serial` is empty
/// until a signed source for it exists.
pub fn emit_device_enrolled_full(mode: &str, bundle_version: u64, ids: EnrollAuditIds<'_>) {
    tracing::info!(
        target: "enrollment.audit",
        event = EVENT_DEVICE_ENROLLED,
        host_id = ids.host_id_prefix8,
        serial = ids.serial,
        mode,
        bundle_version,
    );
    mirror(ids, mode, bundle_version, None);
}

/// Emit `enrollment_rejected` — an import was rejected (fail-closed).
///
/// `reason` is one of [`REASON_MANIFEST`] / [`REASON_CRL`] / [`REASON_INSTALL`].
/// The device is left in its prior state. This bare variant carries empty
/// `host_id`/`serial` fields; the CLI uses [`emit_enrollment_rejected_full`].
pub fn emit_enrollment_rejected(reason: &str) {
    emit_enrollment_rejected_full(reason, EnrollAuditIds::default());
}

/// Emit `enrollment_rejected` with the caller-supplied identifiers: the
/// `host_id` prefix8, and the `serial` field that stays empty until a signed
/// source for it exists.
pub fn emit_enrollment_rejected_full(reason: &str, ids: EnrollAuditIds<'_>) {
    tracing::error!(
        target: "enrollment.audit",
        event = EVENT_ENROLLMENT_REJECTED,
        host_id = ids.host_id_prefix8,
        serial = ids.serial,
        reason,
    );
    mirror(ids, "", 0, Some(reason));
}

/// Put the same enrollment outcome on the device's hash-chained journal.
///
/// The `enrollment.audit` tracing event above is unchanged — its target and its
/// fields are what operators grep. This is the second destination, and it is the
/// one where removing the line leaves a mark.
///
/// Enrollment is recorded after the fact on purpose: by the time either event is
/// emitted the import has already been applied or already been rolled back, and
/// refusing at that point would leave the device changed with nothing saying so.
fn mirror(ids: EnrollAuditIds<'_>, mode: &str, bundle_version: u64, reason: Option<&str>) {
    crate::audit::sink::mirror(&crate::audit::AuditRecord::Enrollment {
        host_id_prefix8: ids.host_id_prefix8.to_owned(),
        serial: ids.serial.to_owned(),
        bundle_version,
        mode: mode.to_owned(),
        reason: reason.map(str::to_owned),
    });
}
