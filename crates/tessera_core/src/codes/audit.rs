//! Audit events of the code login method.
//!
//! One event carries the outcome of an attempt, and it is emitted on success
//! and on refusal alike: the reconciliation an auditor performs is between the
//! logins a fleet saw and the receipts its operators wrote, and a refusal that
//! left no line makes an operator receipt look unpaired.
//!
//! The event names the nonce and the ticket number because those are what the
//! two sides have in common. It never carries the code, the derived key or the
//! shared secret.
//!
//! Each event goes two places: the `codes.audit` tracing target it has always
//! gone to — that name is an API, and consumers grep it — and, in addition, the
//! device's hash-chained journal, where removing it leaves a mark. The tracing
//! call is untouched by the second: a chain that is not configured, or that
//! cannot be written, changes nothing about what an operator sees in the
//! journal (see [`crate::audit::sink`]).
//!
//! One exception, and it is the point of the chain rather than a wrinkle in it:
//! [`emit_success`] returns a [`Result`]. A successful login is the one event
//! here that describes something the device has not finished doing, so a device
//! that has a chain and cannot write to it refuses the session instead of
//! opening one nothing can account for.

use crate::audit::AuditError;

/// `qr_code_login` — the outcome of a code login attempt.
pub const EVENT_QR_CODE_LOGIN: &str = "qr_code_login";

/// Outcome recorded by [`emit_qr_code_login`].
pub const OUTCOME_SUCCESS: &str = "success";
/// Outcome recorded when the attempt was refused.
pub const OUTCOME_DENIED: &str = "denied";
/// Outcome recorded when the attempt budget of the nonce ran out.
pub const OUTCOME_ATTEMPTS_EXHAUSTED: &str = "attempts_exhausted";

/// Refusal detail: no ticket of that operator is on the device.
pub const REASON_NO_TICKET: &str = "no_ticket";
/// Refusal detail: the signature of the ticket authority did not hold.
pub const REASON_TICKET_SIGNATURE: &str = "ticket_signature";
/// Refusal detail: the term of the ticket has passed.
pub const REASON_TICKET_EXPIRED: &str = "ticket_expired";
/// Refusal detail: the ticket is on the revocation list.
pub const REASON_TICKET_REVOKED: &str = "ticket_revoked";
/// Refusal detail: the scope of the ticket does not reach this device.
pub const REASON_TICKET_SCOPE_DEVICE: &str = "ticket_scope_device";
/// Refusal detail: the scope of the ticket does not name the asked role.
pub const REASON_TICKET_SCOPE_ROLE: &str = "ticket_scope_role";
/// Refusal detail: the scope of the ticket does not reach the asked level.
pub const REASON_TICKET_SCOPE_LEVEL: &str = "ticket_scope_level";
/// Refusal detail: this device does not define the role that was asked for.
pub const REASON_ROLE_UNKNOWN: &str = "role_unknown";
/// Refusal detail: no attempt is pending for that nonce — it was never issued,
/// it was already spent, or it did not survive a reboot.
pub const REASON_NO_PENDING_ATTEMPT: &str = "no_pending_attempt";
/// Refusal detail: the nonce was already consumed.
pub const REASON_NONCE_CONSUMED: &str = "nonce_consumed";
/// Refusal detail: the local lifetime of the code has passed.
pub const REASON_TTL: &str = "ttl";
/// Refusal detail: the code did not meet the one the device computed.
pub const REASON_CODE_MISMATCH: &str = "code_mismatch";
/// Refusal detail: the key agreement or the key material failed.
pub const REASON_KEY_MATERIAL: &str = "key_material";
/// Refusal detail: the device has issued its budget of challenges for now.
///
/// Not a verdict about the caller: it is what stops a stream of challenge
/// requests from spending the nonce counter of the device to exhaustion.
pub const REASON_ISSUANCE_THROTTLED: &str = "issuance_throttled";
/// Refusal detail: a run of failed attempts has locked this role for a while.
pub const REASON_ROLE_LOCKED: &str = "role_locked";
/// Refusal detail: the artefact store could not be read.
pub const REASON_ARTEFACTS: &str = "artefacts";

/// Emit `qr_code_login` for a successful login, and refuse if it cannot be
/// recorded.
///
/// Called by the PAM branch after the *whole* attempt has succeeded, not by
/// [`super::CodeMethod`] when the code meets. A code that meets is one step of
/// several: the level is re-read, the role payload is fixed and the session is
/// registered afterwards, and any of those can still refuse. See the note on
/// [`super::Accepted`].
///
/// This one returns a [`Result`], and the successful login is the only event of
/// the method that does. The record is part of the decision to let the engineer
/// in: the control over an operator is the reconciliation between the logins a
/// fleet saw and the receipts its operators wrote, and a session that reached
/// no journal is exactly the session an operator would want. So a device that
/// has a chain and cannot write to it does not grant the session.
///
/// "Has a chain" means the device's configuration says so and
/// [`crate::audit::sink::install_from_config`] opened it before authentication
/// began. That sentence is load-bearing: while nothing called that function,
/// every device read as "has no chain", this returned `Ok` for that reason
/// alone, and the guarantee above was words.
///
/// The tracing event goes out either way, before the chain is touched. It is
/// what an operator greps, and losing it as well would leave the refusal
/// itself unexplained.
///
/// # Errors
///
/// [`AuditError`] when this device has an audit chain and the chain would not
/// take the record. A device with no chain configured returns `Ok`: the chain
/// is opt-in, and its absence is not a reason to stop authenticating.
pub fn emit_success(
    nonce: &str,
    role_id: &str,
    level: u32,
    epoch: u32,
    ticket_number: &str,
) -> Result<(), AuditError> {
    tracing::info!(
        target: "codes.audit",
        event = EVENT_QR_CODE_LOGIN,
        nonce_ref = nonce,
        role_id,
        level,
        epoch,
        ticket_no = ticket_number,
        outcome = OUTCOME_SUCCESS,
    );
    record_required(&Mirrored {
        nonce,
        role_id,
        level,
        epoch,
        ticket_number,
        outcome: OUTCOME_SUCCESS,
        reason: None,
    })
}

/// Emit `qr_code_login` for a refused attempt.
///
/// `reason` is one of the `REASON_*` constants of this module; it is the field
/// the caller never receives, and the only place the refusal is spelled out.
pub fn emit_denied(
    nonce: Option<&str>,
    role_id: &str,
    level: u32,
    epoch: u32,
    ticket_number: Option<&str>,
    reason: &str,
) {
    tracing::warn!(
        target: "codes.audit",
        event = EVENT_QR_CODE_LOGIN,
        nonce_ref = nonce.unwrap_or("-"),
        role_id,
        level,
        epoch,
        ticket_no = ticket_number.unwrap_or("-"),
        outcome = OUTCOME_DENIED,
        reason,
    );
    mirror(&Mirrored {
        nonce: nonce.unwrap_or("-"),
        role_id,
        level,
        epoch,
        ticket_number: ticket_number.unwrap_or("-"),
        outcome: OUTCOME_DENIED,
        reason: Some(reason),
    });
}

/// `codes_artefacts_applied` — a consignment of Codes artefacts was installed.
pub const EVENT_ARTEFACTS_APPLIED: &str = "codes_artefacts_applied";

/// `codes_artefacts_wiped` — the Codes artefacts were removed from the device.
pub const EVENT_ARTEFACTS_WIPED: &str = "codes_artefacts_wiped";

/// Emit `codes_artefacts_applied` for an import or a courier rotation.
///
/// The epoch is the field an owner reconciles against the registry record of
/// the device, and `counter_reset` is what tells them whether the nonces of the
/// previous key were retired or carried on.
pub fn emit_artefacts_applied(applied: &super::artefacts::Applied) {
    tracing::info!(
        target: "codes.audit",
        event = EVENT_ARTEFACTS_APPLIED,
        epoch = applied.epoch.map_or(0, tessera_codes_contract::key::Epoch::get),
        key_replaced = applied.key_replaced,
        counter_reset = applied.counter_reset,
        tickets = applied.tickets_applied,
        revocations = applied.revocations_applied,
    );
}

/// Emit `codes_artefacts_wiped` for a device leaving the fleet.
///
/// The last epoch is the whole reason this event exists: after the wipe nothing
/// on the device says which key the fleet has to withdraw from its registry.
pub fn emit_artefacts_wiped(wiped: &super::artefacts::Wiped) {
    tracing::info!(
        target: "codes.audit",
        event = EVENT_ARTEFACTS_WIPED,
        last_epoch = wiped.last_epoch.map_or(0, tessera_codes_contract::key::Epoch::get),
        artefacts_found = wiped.found_anything(),
        removed = wiped.removed.join(","),
    );
}

/// Emit `qr_code_login` for an attempt whose budget ran out.
pub fn emit_attempts_exhausted(
    nonce: &str,
    role_id: &str,
    level: u32,
    epoch: u32,
    ticket_number: &str,
) {
    tracing::error!(
        target: "codes.audit",
        event = EVENT_QR_CODE_LOGIN,
        nonce_ref = nonce,
        role_id,
        level,
        epoch,
        ticket_no = ticket_number,
        outcome = OUTCOME_ATTEMPTS_EXHAUSTED,
    );
    mirror(&Mirrored {
        nonce,
        role_id,
        level,
        epoch,
        ticket_number,
        outcome: OUTCOME_ATTEMPTS_EXHAUSTED,
        reason: None,
    });
}

/// One decided attempt, as the hash-chained journal records it.
///
/// The fields travel as a struct rather than as a parameter list because the
/// list is long enough for two `&str` of the same shape to be swapped at a call
/// site without the compiler saying a word — and the two that would be swapped
/// are the nonce and the ticket number, which are exactly the pair an auditor
/// reconciles the journal against the operator receipts by.
struct Mirrored<'a> {
    /// Nonce of the attempt.
    nonce: &'a str,
    /// Role account that was asked for.
    role_id: &'a str,
    /// Level that was asked for.
    level: u32,
    /// Key epoch of the device.
    epoch: u32,
    /// Number of the operator ticket, or `-` when none was admitted.
    ticket_number: &'a str,
    /// One of the `OUTCOME_*` constants.
    outcome: &'a str,
    /// One of the `REASON_*` constants, for a refusal.
    reason: Option<&'a str>,
}

/// Put a refused attempt on the device's hash-chained journal.
///
/// The tracing event above stays exactly as it was; this is the second
/// destination. Best-effort by construction, and rightly so: everything routed
/// here describes something already settled, and refusing a refusal a second
/// time would change nothing. A device with no chain configured records nothing
/// here and authenticates as before.
///
/// The successful login does **not** come through this function — it goes
/// through [`record_required`], because its record is part of granting the
/// session rather than a report about it.
fn mirror(attempt: &Mirrored<'_>) {
    crate::audit::sink::mirror(&chain_record(attempt));
}

/// Put a decided attempt on the chain, and report whether it landed.
///
/// The fail-closed half of the pair above: same record, same shape, but the
/// caller is told what happened instead of the sink swallowing it.
///
/// # Errors
///
/// [`AuditError`] when the device has a chain that would not take the record.
fn record_required(attempt: &Mirrored<'_>) -> Result<(), AuditError> {
    crate::audit::sink::record_required(&chain_record(attempt))
}

/// The chain record one decided attempt turns into.
fn chain_record(attempt: &Mirrored<'_>) -> crate::audit::AuditRecord {
    crate::audit::AuditRecord::CodeLogin {
        nonce_ref: attempt.nonce.to_owned(),
        role_id: attempt.role_id.to_owned(),
        level: attempt.level,
        epoch: attempt.epoch,
        ticket_no: attempt.ticket_number.to_owned(),
        outcome: attempt.outcome.to_owned(),
        reason: attempt.reason.map(str::to_owned),
    }
}
