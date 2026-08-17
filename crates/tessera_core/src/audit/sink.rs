//! The process-wide sink the existing audit call sites mirror into.
//!
//! The security-significant events of this product already go somewhere: a
//! `tracing` target an operator greps. Those targets are an API — the
//! `logging-audit` specification says so, and there are consumers pinned to
//! them — so the chain is added *beside* them and changes nothing about them.
//! The call sites keep emitting exactly what they emitted; each one gains one
//! line that also puts the event on the chain.
//!
//! A sink is process-wide because the call sites are: they are `emit_*`
//! functions on the auth path, reached from a PAM module loaded into somebody
//! else's process, with no place to thread a journal handle through. The
//! alternative — plumbing a handle down every path — would have meant changing
//! signatures across the PAM branch, which is a larger blast radius than a
//! process-wide handle for a process that holds exactly one device journal.
//!
//! # When nothing is installed
//!
//! A device that was never given a journal has no sink, and
//! [`mirror`] is then a no-op: the chain is opt-in, and a device without one
//! must go on authenticating exactly as it did. [`record`] is the other face of
//! the same fact — it returns [`AuditError::NotConfigured`] so a caller that
//! *needs* the record (see [`super::WriteDiscipline::FailClosed`]) can tell
//! "recorded" from "nowhere to record it" instead of reading `Ok(())` as proof.

use parking_lot::Mutex;
use std::sync::OnceLock;

use super::journal::{AuditError, AuditJournal};
use super::record::{AuditRecord, WriteDiscipline};

/// The journal this process records to, once one is installed.
static SINK: OnceLock<Mutex<Option<AuditJournal>>> = OnceLock::new();

/// The slot, created on first use.
fn slot() -> &'static Mutex<Option<AuditJournal>> {
    SINK.get_or_init(|| Mutex::new(None))
}

/// Installs `journal` as the process's audit chain, returning the one it
/// replaced.
///
/// Called once, where the device's configuration is read. A second call
/// replaces the handle rather than refusing: a daemon that re-reads its
/// configuration must be able to follow the journal to a new path.
pub fn install(journal: AuditJournal) -> Option<AuditJournal> {
    slot().lock().replace(journal)
}

/// Opens the journal this configuration describes and installs it, if the
/// device keeps one.
///
/// **This is the production entry point, and the reason the rest of the module
/// is worth anything.** A journal that is never installed makes every
/// fail-closed call site return `Ok` for the wrong reason — the chain is not
/// refusing the record, there is simply no chain — and the guarantee reads as
/// present while being absent. So this is called once, early, from every
/// process that can produce an audit event: the PAM module before it
/// authenticates anybody, and the CLI before it imports an enrolment package.
///
/// Returns whether a journal was installed. `false` means the device keeps
/// none, which is a configuration, not a failure.
///
/// # Errors
///
/// [`AuditError`] when the device is configured to keep a journal and it could
/// not be opened. That is deliberately not swallowed: a device told to keep a
/// journal, which cannot, is misconfigured, and the caller decides whether that
/// stops it. Silently continuing without one would reproduce exactly the hole
/// this function exists to close.
pub fn install_from_config(config: &crate::config::ValidatedConfig) -> Result<bool, AuditError> {
    let Some(section) = config.audit.policy.as_ref() else {
        // Said out loud, once, where the decision is made.
        //
        // A device with no chain and a device with a working one otherwise look
        // identical in the system journal, and the fail-closed guarantee is
        // present on one and absent on the other. Leaving that invisible means
        // an operator learns which kind they have during an incident. It is
        // emitted here, at configuration time, and deliberately not at each
        // record: `sshd` forks per connection, and a line per login attempt
        // would drown the journal it is warning about.
        tracing::warn!(
            target: super::TRACING_TARGET,
            configured = false,
            "this device keeps no hash-chained audit journal: logins are not recorded on a \
             chain, and the refusal that would follow an unrecordable login does not apply",
        );
        return Ok(false);
    };
    let journal = AuditJournal::open(super::AuditPolicy::from(section))?;
    tracing::info!(
        target: super::TRACING_TARGET,
        configured = true,
        path = %section.file.display(),
        ceiling_bytes = section.ceiling_bytes,
        "the device audit journal is open",
    );
    install(journal);
    Ok(true)
}

/// Removes the installed journal, if any.
pub fn uninstall() -> Option<AuditJournal> {
    slot().lock().take()
}

/// Whether this process has an audit chain.
#[must_use]
pub fn is_installed() -> bool {
    slot().lock().is_some()
}

/// Records `record` on the chain and reports what happened.
///
/// This is the entry point for a caller whose action depends on the record —
/// one whose [`AuditRecord::write_discipline`] is
/// [`WriteDiscipline::FailClosed`]. Any `Err` means the event is not on the
/// chain, and the caller is expected to refuse the action rather than proceed
/// unrecorded.
///
/// # Errors
///
/// [`AuditError::NotConfigured`] when this process holds no journal, and
/// otherwise whatever [`AuditJournal::record`] reports: a full journal, a
/// refused field, a storage failure.
pub fn record(record: &AuditRecord, now_unix: u64) -> Result<(), AuditError> {
    let mut guard = slot().lock();
    let Some(journal) = guard.as_mut() else {
        return Err(AuditError::NotConfigured);
    };
    journal.record(record, now_unix)
}

/// Records an event the caller's action depends on, and reports whether the
/// action may go ahead.
///
/// This is what a fail-closed call site uses. It draws the one distinction that
/// [`record`] deliberately leaves to the caller, and that every such call site
/// would otherwise have to draw for itself — wrongly, sooner or later:
///
/// - **No journal on this device** — `Ok`. The chain is opt-in. A device that
///   was never given one is not thereby forbidden from authenticating, or
///   shipping this change would lock every existing device out.
/// - **A journal that would not take the record** — `Err`. Full, unwritable, or
///   refusing the content: the device has a journal, and the journal does not
///   have this event. That is precisely the state where an unrecorded action
///   must not proceed.
///
/// # Errors
///
/// Whatever [`AuditJournal::record`] reported, except
/// [`AuditError::NotConfigured`], which is not an error here.
pub fn record_required(record: &AuditRecord) -> Result<(), AuditError> {
    match self::record(record, now_unix()) {
        Ok(()) | Err(AuditError::NotConfigured) => Ok(()),
        Err(error) => {
            tracing::error!(
                target: super::TRACING_TARGET,
                event = record.event_name(),
                error = %error,
                "the audit chain would not take a record the action depends on; refusing the action"
            );
            Err(error)
        }
    }
}

/// Puts an already-settled event on the chain, escalating if it cannot.
///
/// This is the after-the-fact half of the discipline: the thing being recorded
/// has happened, refusing now would un-do nothing, so a failure is escalated to
/// the system log and the caller carries on. The escalation is at `error`
/// level under [`super::TRACING_TARGET`] and names the event, because a chain
/// with a hole in it that nobody was told about is worse than no chain.
///
/// A [`WriteDiscipline::FailClosed`] record passed here is recorded all the
/// same, and a failure is escalated with a message saying the boundary that
/// should have refused has not been wired: mirroring such an event silently
/// would turn a fail-closed guarantee into a log line without anybody deciding
/// to.
pub fn mirror(record: &AuditRecord) {
    let now = now_unix();
    match self::record(record, now) {
        // Recorded, or there was nowhere to record it: the chain is opt-in and
        // a device without one is not an incident. Neither case has anything
        // left to say.
        Ok(()) | Err(AuditError::NotConfigured) => {}
        Err(error) => match record.write_discipline() {
            WriteDiscipline::EscalateAfterTheFact => {
                tracing::error!(
                    target: super::TRACING_TARGET,
                    event = record.event_name(),
                    error = %error,
                    "the event happened but could not be put on the audit chain"
                );
            }
            WriteDiscipline::FailClosed => {
                tracing::error!(
                    target: super::TRACING_TARGET,
                    event = record.event_name(),
                    error = %error,
                    "an event that must not proceed unrecorded was mirrored after the fact: \
                     the caller has no fail-closed boundary wired and did not refuse"
                );
            }
        },
    }
}

/// Wall-clock seconds, for the mirroring path that has no clock of its own.
///
/// The call sites this serves are `emit_*` helpers that take no timestamp, and
/// giving them one would change signatures across the PAM branch. A record
/// carries the device's own clock either way; nothing in the chain depends on
/// it being right, only on it being recorded.
fn now_unix() -> u64 {
    use chrono::Utc;
    u64::try_from(Utc::now().timestamp()).unwrap_or(0)
}
