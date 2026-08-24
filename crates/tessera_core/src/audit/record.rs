//! What a line of the device's audit chain says, and what a failure to write it
//! costs.

use serde::{Deserialize, Serialize};
use tessera_hashchain::{Annotation, ChainPayload, EntryKind, HeadSignature};

/// The anchor of every device audit chain.
///
/// It is part of the on-disk format twice over: it separates this journal from
/// the issuance journal, so a line cannot be carried between them, and it pins
/// the format version.
///
/// Re-exported rather than declared: the value lives with the format, in
/// [`tessera_hashchain::domain`], because the reconciliation on the operator's
/// side has to verify this chain and cannot depend on this crate.
pub use tessera_hashchain::domain::DEVICE_AUDIT as GENESIS_PREIMAGE;

/// What a failed write costs, decided by what the record is about.
///
/// The two are not a preference. A record of something that has not happened yet
/// is part of the decision to let it happen: if the login cannot be recorded,
/// the login does not proceed, because a session nobody can prove was opened is
/// exactly the session an operator would want. A record of something already
/// done cannot un-do it, and refusing at that point would only mean the event
/// happened *and* went unrecorded — so it escalates loudly instead.
///
/// "Always fail" and "always shrug" are both wrong, and both are easy to reach
/// for; this type is what keeps the choice deliberate at every call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteDiscipline {
    /// The action has not happened yet. A failed write refuses it (fail-closed).
    FailClosed,
    /// The action is already done. A failed write is escalated to the system
    /// log and the action stands.
    EscalateAfterTheFact,
}

/// Outcome of a code login attempt, as the chain records it.
///
/// The words are the contract's — [`tessera_codes_contract::outcome`] — and not
/// a copy of them. This module decides the write discipline of a record by the
/// outcome it carries, and a second spelling of "success" here would mean a
/// word added to the vocabulary reaching the emitter and not this decision: a
/// login that opened a session would be written the way a refusal is, best
/// effort, instead of the way an admission must be, fail-closed.
pub mod outcome {
    pub use tessera_codes_contract::outcome::{
        OUTCOME_ATTEMPTS_EXHAUSTED as ATTEMPTS_EXHAUSTED, OUTCOME_DENIED as DENIED,
        OUTCOME_SUCCESS as SUCCESS,
    };
}

/// What the device does once its journal has reached its ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum WhenFull {
    /// Refuse new records. Nothing is lost, and everything whose discipline is
    /// [`WriteDiscipline::FailClosed`] stops working — which is the point: a
    /// device that can no longer account for logins does not grant them.
    Refuse,
    /// Rotate: the filled chain is moved aside and a new one begins with a
    /// record naming what was rotated away. The history is no longer one chain,
    /// and the record of the break is what keeps that from looking like a
    /// deletion.
    Rotate,
}

/// One line of the device's audit chain.
///
/// Every variant's fields are named here, in the type, and none of them is a
/// secret — that is what makes the fixed records safe by construction. The one
/// free-form door is [`AuditRecord::Annotation`], and it is the one the secret
/// filter guards (see [`super::secrets`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op")]
#[non_exhaustive]
pub enum AuditRecord {
    /// The outcome of a code login attempt — success and refusal alike.
    ///
    /// A refusal that left no line would make an operator's receipt look
    /// unpaired, and the reconciliation between the logins a fleet saw and the
    /// receipts its operators wrote is the whole point of the record.
    #[serde(rename = "code_login")]
    CodeLogin {
        /// The nonce the attempt ran under; a reference, never the code.
        nonce_ref: String,
        /// Role the attempt asked for.
        role_id: String,
        /// Level the attempt asked for.
        level: u32,
        /// Key epoch the attempt ran under.
        epoch: u32,
        /// Ticket the operator worked under, `"-"` when there was none.
        ticket_no: String,
        /// Personal number of the engineer **as they gave it**, `"-"` when the
        /// attempt was refused before they were asked.
        ///
        /// Claimed, not established, and the name says so: an offline device
        /// holds no registry of people and checks nothing about the value. What
        /// it is good for is the reconciliation this field exists for — the
        /// logins a fleet saw against the grants its server issued — and for
        /// that a claimed number is exactly what has to be recorded: the number
        /// the code was computed for. A journal claiming more than it knows is
        /// worse than one that stays quiet.
        claimed_engineer_no: String,
        /// One of [`outcome`].
        outcome: String,
        /// The refusal detail, absent on success.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// An enrollment package was imported, or refused.
    #[serde(rename = "enrollment")]
    Enrollment {
        /// First 8 hex chars of the device `host_id` hash (`""` when unknown).
        host_id_prefix8: String,
        /// Per-host leaf certificate serial (`""` until a signed source
        /// carries one).
        serial: String,
        /// The applied bundle version.
        bundle_version: u64,
        /// Trust mode: `standalone` or `managed`.
        mode: String,
        /// The refusal reason, absent on a successful import.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// The journal has reached its ceiling.
    ///
    /// It is an event of the journal about itself, and it exists so that "no
    /// records for that fortnight" is never something an auditor has to infer.
    #[serde(rename = "journal_full")]
    JournalFull {
        /// The configured ceiling, in bytes.
        ceiling_bytes: u64,
        /// What the journal occupied when it hit the ceiling.
        used_bytes: u64,
        /// What the device does next.
        when_full: WhenFull,
    },
    /// The first line of a chain that begins where another was cut off.
    ///
    /// Written only under [`WhenFull::Rotate`], and written *first*, so a reader
    /// of the new file learns on line 0 that there is an older one and what its
    /// last head was. Rotation without this line would be indistinguishable
    /// from somebody having deleted the journal — which is the hole the chain
    /// exists to close.
    #[serde(rename = "chain_break")]
    ChainBreak {
        /// Head of the rotated-away chain, lowercase hex.
        previous_head: String,
        /// How many lines it held.
        previous_entries: u64,
        /// Where it was moved to.
        rotated_to: String,
    },
    /// A signature over the head as it stood before this line.
    #[serde(rename = "head_signature")]
    HeadSignature(HeadSignature),
    /// Somebody else's data, carried under the same chain and interpreted by
    /// nobody here.
    #[serde(rename = "annotation")]
    Annotation(Annotation),
}

impl AuditRecord {
    /// What a failed write of this record costs.
    ///
    /// A successful login is the one record written about something the device
    /// has not finished doing; everything else describes something already
    /// settled, including a refusal — refusing the refusal a second time would
    /// change nothing.
    #[must_use]
    pub fn write_discipline(&self) -> WriteDiscipline {
        match self {
            // Asked of the vocabulary rather than compared against one word,
            // and an outcome the vocabulary does not carry lands on the
            // fail-closed side too. A word this build cannot classify may name
            // an opened session, and the cost of the two mistakes is not
            // symmetric: writing a settled refusal fail-closed costs a refused
            // login on a device whose journal is broken, while writing an
            // opened session best-effort costs a session nothing can account
            // for.
            AuditRecord::CodeLogin { outcome, .. }
                if !matches!(
                    tessera_codes_contract::outcome::classify(outcome),
                    tessera_codes_contract::outcome::Outcome::Refusal
                ) =>
            {
                WriteDiscipline::FailClosed
            }
            _ => WriteDiscipline::EscalateAfterTheFact,
        }
    }

    /// The stable event name, for the tracing escalation and for diagnostics.
    #[must_use]
    pub fn event_name(&self) -> &'static str {
        match self {
            AuditRecord::CodeLogin { .. } => "code_login",
            AuditRecord::Enrollment { .. } => "enrollment",
            AuditRecord::JournalFull { .. } => "journal_full",
            AuditRecord::ChainBreak { .. } => "chain_break",
            AuditRecord::HeadSignature(_) => "head_signature",
            AuditRecord::Annotation(_) => "annotation",
        }
    }
}

impl ChainPayload for AuditRecord {
    const GENESIS_PREIMAGE: &'static [u8] = GENESIS_PREIMAGE;

    fn kind(&self) -> EntryKind {
        match self {
            AuditRecord::HeadSignature(_) => EntryKind::HeadSignature,
            _ => EntryKind::Record,
        }
    }

    fn is_structurally_valid(&self) -> bool {
        match self {
            AuditRecord::Annotation(annotation) => annotation.is_structurally_valid(),
            _ => true,
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{outcome, AuditRecord, WhenFull, WriteDiscipline};
    use crate::audit::secrets::find_secret_field;

    fn login(outcome: &str) -> AuditRecord {
        AuditRecord::CodeLogin {
            nonce_ref: "0000014711".to_owned(),
            role_id: "ops.dc.senior".to_owned(),
            level: 1,
            epoch: 7,
            ticket_no: "tk-17".to_owned(),
            claimed_engineer_no: "eng-1".to_owned(),
            outcome: outcome.to_owned(),
            reason: None,
        }
    }

    #[test]
    fn a_login_about_to_be_granted_is_fail_closed_and_everything_else_is_not() {
        assert_eq!(
            login(outcome::SUCCESS).write_discipline(),
            WriteDiscipline::FailClosed
        );
        assert_eq!(
            login(outcome::DENIED).write_discipline(),
            WriteDiscipline::EscalateAfterTheFact
        );
        assert_eq!(
            login(outcome::ATTEMPTS_EXHAUSTED).write_discipline(),
            WriteDiscipline::EscalateAfterTheFact
        );
        assert_eq!(
            AuditRecord::JournalFull {
                ceiling_bytes: 1,
                used_bytes: 2,
                when_full: WhenFull::Refuse,
            }
            .write_discipline(),
            WriteDiscipline::EscalateAfterTheFact
        );
    }

    /// An outcome this build cannot classify is written fail-closed.
    ///
    /// The two mistakes do not cost the same. Writing a settled refusal
    /// fail-closed costs a refused login on a device whose journal is broken;
    /// writing an opened session best-effort costs a session nothing can
    /// account for. A word that may mean either belongs on the first side.
    #[test]
    fn an_outcome_this_build_cannot_classify_is_fail_closed() {
        for word in ["granted", "success_after_retry", ""] {
            assert_eq!(
                login(word).write_discipline(),
                WriteDiscipline::FailClosed,
                "outcome: {word:?}"
            );
        }
    }

    /// The fixed records are supposed to be safe by construction. This is what
    /// makes that a checked claim rather than a promise: every field name of
    /// every variant is put past the same filter the free-form path uses.
    #[test]
    fn no_fixed_record_carries_a_field_the_secret_filter_would_refuse() {
        let records = [
            login(outcome::SUCCESS),
            AuditRecord::Enrollment {
                host_id_prefix8: "0a1b2c3d".to_owned(),
                serial: String::new(),
                bundle_version: 4,
                mode: "standalone".to_owned(),
                reason: None,
            },
            AuditRecord::JournalFull {
                ceiling_bytes: 1,
                used_bytes: 2,
                when_full: WhenFull::Rotate,
            },
            AuditRecord::ChainBreak {
                previous_head: "ab".to_owned(),
                previous_entries: 9,
                rotated_to: "audit.ndjson.1".to_owned(),
            },
        ];
        for record in records {
            let value = serde_json::to_value(&record).unwrap();
            assert_eq!(
                find_secret_field(&value),
                None,
                "{} carries a refused field",
                record.event_name()
            );
        }
    }
}
