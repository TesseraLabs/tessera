//! The device's hash-chained audit journal.
//!
//! # Why a journal at all, when there is already a log
//!
//! Everything security-significant this device does already goes to `journald`
//! through a `tracing` target. That is enough to see what happened and not
//! enough to show that nothing was removed: a line comes out of `journald`
//! without leaving a mark, and the device's own operator is the party with root
//! on it.
//!
//! For the telephone channel that stops being a theoretical objection. The
//! control over an operator there *is* the reconciliation between the logins a
//! fleet saw and the receipts its operators wrote — a login without a receipt is
//! the finding. A reconciliation against a record one side can quietly edit is
//! not a reconciliation.
//!
//! So the events go, in addition, onto a chain: each line carries the hash of
//! the one before it, and removing, editing or reordering any of them shows up
//! at a named position on the next verification.
//!
//! # What this module is made of
//!
//! - [`AuditRecord`] — what a line says. Fixed shapes, no secrets among their
//!   fields, plus one free-form annotation for somebody else's data.
//! - [`AuditJournal`] — the chain on disk, its ceiling, its attestation and its
//!   verification.
//! - [`sink`] — the process-wide handle the existing `emit_*` call sites mirror
//!   into, so the chain is added beside the tracing targets rather than in place
//!   of them.
//! - [`secrets`] — the one filter that decides whether a field name may be
//!   written at all.
//!
//! The chain construction itself is [`tessera_hashchain`], shared with the
//! issuance journal of the cabinet. The two records are one format on purpose:
//! an auditor learns it once.
//!
//! # The three limits, stated once
//!
//! 1. **Genesis is not attested.** Before the first head signature nothing
//!    outside the file vouches for it, so a wiped journal and a new device look
//!    alike. Enrolment is what closes that, not the journal — see
//!    [`AuditJournal`].
//! 2. **The newest line is covered by nothing.** A chain covers a line by the
//!    `prev_hash` of the line after it; the last line has none.
//! 3. **The whole file can be deleted.** Nothing on a machine its owner
//!    controls prevents that. What the chain changes is that anything short of
//!    deleting all of it leaves a mark, and that the deletion of all of it is
//!    itself conspicuous.

pub mod attest;
pub mod journal;
pub mod record;
pub mod secrets;
pub mod signer;
pub mod sink;

#[cfg(test)]
pub(crate) mod testing;

pub use attest::{
    verify_attestations, AttestationReport, AttestationStatus, HeadVerifier, KeyFileVerifier,
};
pub use journal::{
    AuditError, AuditJournal, AuditPolicy, HeadSigner, AUDIT_FILENAME,
    DEFAULT_ATTEST_INTERVAL_SECS, DEFAULT_CEILING_BYTES, ROTATED_SUFFIX,
};
pub use record::{outcome, AuditRecord, WhenFull, WriteDiscipline, GENESIS_PREIMAGE};
pub use signer::KeyFileSigner;

/// The tracing target the journal's own diagnostics go to.
///
/// It is the journal talking about itself — reaching its ceiling, failing to
/// record, rotating — and never a duplicate of an event's own target. The
/// events keep going to the targets they always went to.
pub const TRACING_TARGET: &str = "tessera.audit_chain";
