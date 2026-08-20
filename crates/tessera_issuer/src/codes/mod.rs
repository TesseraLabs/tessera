//! The operator side of the Tessera Codes phone channel.
//!
//! The device computes a code and the operator computes the same code; what
//! lives here is everything the operator side needs around that computation and
//! nothing of the computation itself. The formula, the canonical bytes, the
//! documents and their parsers come from [`tessera_codes_contract`] — a second
//! implementation of any of them would part ways with the device's, and the
//! divergence would surface as "the code does not fit" at a site rather than as
//! a red test.
//!
//! The modules are split by what they are allowed to touch, so that the browser
//! cabinet and the command line run the same checks:
//!
//! - [`scope`], [`counter`], [`annex`], [`reconcile`], [`trust`] and
//!   [`agreement`] are pure: no clock, no filesystem, no environment. They build
//!   for `wasm32-unknown-unknown` and are what the cabinet calls.
//! - [`issue`] is the whole refusal ladder of one issuance, in one function, for
//!   the same reason: a wrapper that assembled the steps in its own order would
//!   be a second policy.
//! - [`store`] and [`ledger`] are the only modules that read and write files,
//!   and they exist only in a native build. The ledger is where the counter
//!   history lives; the store is where the receipts do.
//!
//! # Refusals
//!
//! Every refusal of an issuance is a [`Refusal`]. The value names the axis that
//! did not cover the request, because the operator on the telephone has to be
//! able to say what is missing; nothing here is a security oracle towards a
//! caller at the device, since the caller never sees these messages — they are
//! printed on the operator's own terminal.

pub mod agreement;
pub mod annex;
pub mod counter;
pub mod issue;
#[cfg(feature = "native")]
pub mod ledger;
pub mod reconcile;
pub mod scope;
#[cfg(feature = "native")]
pub mod store;
#[cfg(feature = "pkcs11")]
pub mod token;
pub mod trust;

#[cfg(test)]
pub(crate) mod tests;

use tessera_codes_contract::canon::CanonError;
use tessera_codes_contract::code::CodeError;
use tessera_codes_contract::key::KeyAgreementError;
use tessera_codes_contract::receipt::ReceiptError;
use tessera_codes_contract::registry::RecordError;
use tessera_codes_contract::ticket::TicketError;

use crate::codes::annex::AnnexError;
use crate::codes::counter::CounterRefusal;

/// Why an issuance was refused.
///
/// The variants are the axes of the check, not the steps of the code: a
/// consumer that renders a refusal to an operator names the axis and the two
/// values that did not meet on it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// The challenge and the device record are about different devices.
    #[error("the challenge names device {challenge}, the record is for {record}")]
    DeviceNumber {
        /// Number read out over the telephone.
        challenge: String,
        /// Number the signed record carries.
        record: String,
    },
    /// The challenge and the device record name different key epochs.
    #[error("the challenge is for key epoch {challenge}, the record carries epoch {record}")]
    Epoch {
        /// Epoch read out over the telephone.
        challenge: u32,
        /// Epoch the signed record carries.
        record: u32,
    },
    /// The challenge names an operator other than the holder of the ticket.
    #[error("the challenge names operator `{challenge}`, the ticket belongs to `{ticket}`")]
    Operator {
        /// Operator identifier read out over the telephone.
        challenge: String,
        /// Operator the ticket was issued to.
        ticket: String,
    },
    /// The ticket is scoped to another region than the one the device stands in.
    #[error("the ticket is scoped to region `{ticket}`, the device stands in `{device}`")]
    ScopeRegion {
        /// Region of the ticket.
        ticket: String,
        /// Region declared for the device.
        device: String,
    },
    /// The ticket carries no tag of the device.
    #[error("the ticket reaches no site the device is tagged with")]
    ScopeTags,
    /// The ticket does not admit the role being asked for.
    #[error("the ticket does not admit the role `{role}`")]
    ScopeRole {
        /// Role the challenge asks for.
        role: String,
    },
    /// The ticket does not reach the level being asked for.
    #[error("the ticket admits level {ceiling} at most, the request asks for {level}")]
    ScopeLevel {
        /// Level the challenge asks for.
        level: u32,
        /// Highest level the ticket admits.
        ceiling: u32,
    },
    /// No grounds were recorded for the issuance.
    #[error("the issuance records no grounds; a code handed out for no stated reason is a code nobody can answer for")]
    MissingReason,
    /// The nonce counter of the challenge was refused.
    #[error(transparent)]
    Counter(#[from] CounterRefusal),
    /// An override was supplied for a challenge the counter did not refuse.
    ///
    /// The refusal is not pedantry: a receipt carrying an override says two
    /// people decided to answer a challenge that looked wrong, and an audit
    /// reading it will go looking for what that was. Recording one where nothing
    /// was overridden spends somebody's afternoon.
    #[error("the counter did not refuse this challenge; there is nothing for a second operator to approve")]
    OverrideNotNeeded,
    /// The device record did not verify.
    #[error("the device record was rejected: {0}")]
    Record(#[from] RecordError),
    /// The operator ticket did not verify, or its term has passed.
    #[error("the operator ticket was rejected: {0}")]
    Ticket(#[from] TicketError),
    /// The key performing the agreement is not the key the ticket carries.
    ///
    /// Deriving with another key would produce a shared secret the device never
    /// arrives at, so the code would simply not fit — and the operator would
    /// spend the call looking for the reason at the device.
    #[error("the operator key does not match the public key of the ticket")]
    OperatorKeyMismatch,
    /// The key agreement failed.
    #[error("the key agreement failed: {0}")]
    Agreement(#[from] KeyAgreementError),
    /// The code could not be computed.
    #[error("the code could not be computed: {0}")]
    Code(#[from] CodeError),
    /// The receipt could not be assembled.
    #[error("the receipt could not be assembled: {0}")]
    Receipt(#[from] ReceiptError),
    /// The annex of the receipt could not be assembled.
    #[error("the receipt annex could not be assembled: {0}")]
    Annex(#[from] AnnexError),
    /// A document could not be encoded canonically.
    #[error(transparent)]
    Canon(#[from] CanonError),
}

/// What kind of answer a refusal is.
///
/// The class token says which check refused; the group says what the refusal
/// *means* to somebody deciding what to do next. Two consumers need exactly this
/// split and no more:
///
/// - a harness asserting a guarantee ("the operator could not step outside their
///   ticket") acts on the group and reads the token only when it fails;
/// - a cabinet routing an operator mid-call needs the same distinction — the
///   conversation after "your ticket does not cover this role" is a different
///   conversation from the one after "the token did not answer".
///
/// [`RefusalGroup::Environment`] is the one that must never be confused with the
/// rest: it does not say the request was turned away, it says the check never
/// happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RefusalGroup {
    /// The request fell outside the operator's ticket, on any of its axes.
    TicketScope,
    /// The nonce counter of the challenge does not fit the receipts.
    Counter,
    /// A signature, an anchor or a key did not hold.
    Trust,
    /// The issuance carried no grounds.
    Grounds,
    /// A refusal of the issuance that is none of the above.
    Other,
    /// The check did not happen: something the operator's own side needed was
    /// unusable — a file that is not the document it claims to be, a token that
    /// stopped answering.
    Environment,
}

impl RefusalGroup {
    /// The token this group is written under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TicketScope => "ticket_scope",
            Self::Counter => "counter",
            Self::Trust => "trust",
            Self::Grounds => "grounds",
            Self::Other => "other",
            Self::Environment => "environment",
        }
    }
}

impl Refusal {
    /// What kind of answer this refusal is — see [`RefusalGroup`].
    ///
    /// The grouping follows one rule: a document that fails a check is a
    /// verdict, a document that is not the document at all is an environment
    /// failure. An expired ticket is an answer about the request; a ticket file
    /// somebody truncated is a stand that has not been set up.
    #[must_use]
    pub const fn group(&self) -> RefusalGroup {
        match self {
            // The identity axes belong to the ticket as much as the scope ones:
            // a challenge for another device or another operator is a request
            // this ticket does not cover.
            Self::DeviceNumber { .. }
            | Self::Epoch { .. }
            | Self::Operator { .. }
            | Self::ScopeRegion { .. }
            | Self::ScopeTags
            | Self::ScopeRole { .. }
            | Self::ScopeLevel { .. } => RefusalGroup::TicketScope,
            Self::Counter(_) => RefusalGroup::Counter,
            // A point the profile rejects belongs here too: it is key material
            // that does not hold, which is a verdict about the documents.
            Self::Record(_)
            | Self::Ticket(_)
            | Self::OperatorKeyMismatch
            | Self::Agreement(KeyAgreementError::InvalidPublicPoint) => RefusalGroup::Trust,
            Self::MissingReason => RefusalGroup::Grounds,
            // A backend that failed for its own reason is the token not
            // answering, and that is not an answer about the request at all.
            Self::Agreement(KeyAgreementError::Backend(_)) => RefusalGroup::Environment,
            Self::OverrideNotNeeded
            | Self::Code(_)
            | Self::Receipt(_)
            | Self::Annex(_)
            | Self::Canon(_) => RefusalGroup::Other,
        }
    }

    /// The stable class token of this refusal.
    ///
    /// The message beside it is prose, and prose is translated, reworded and
    /// improved; a consumer that has to *act* on which check refused — an
    /// automated harness asserting that a request outside a ticket is turned
    /// away, a cabinet routing an operator to the right correction — matches on
    /// this instead. The tokens are part of the interface: renaming one is a
    /// breaking change, and a new refusal gets a new token rather than reusing
    /// a neighbour's.
    ///
    /// The scope tokens share the `ticket_scope_` prefix on purpose, so a
    /// consumer can ask the broader question ("was this outside the ticket at
    /// all") without enumerating the axes.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::DeviceNumber { .. } => "device_number_mismatch",
            Self::Epoch { .. } => "epoch_mismatch",
            Self::Operator { .. } => "operator_mismatch",
            Self::ScopeRegion { .. } => "ticket_scope_region",
            Self::ScopeTags => "ticket_scope_tags",
            Self::ScopeRole { .. } => "ticket_scope_role",
            Self::ScopeLevel { .. } => "ticket_scope_level",
            Self::MissingReason => "missing_reason",
            Self::Counter(refusal) => refusal.class(),
            Self::OverrideNotNeeded => "override_not_needed",
            Self::Record(_) => "device_record_rejected",
            Self::Ticket(_) => "ticket_rejected",
            Self::OperatorKeyMismatch => "operator_key_mismatch",
            Self::Agreement(_) => "key_agreement_failed",
            Self::Code(_) => "code_computation_failed",
            Self::Receipt(_) => "receipt_rejected",
            Self::Annex(_) => "annex_rejected",
            Self::Canon(_) => "encoding_failed",
        }
    }
}

#[cfg(test)]
mod class_tests {
    use super::Refusal;
    use crate::codes::counter::CounterRefusal;

    #[test]
    fn the_axes_of_a_ticket_share_one_prefix_and_stay_distinct() {
        let axes = [
            Refusal::ScopeRegion {
                ticket: "a".to_owned(),
                device: "b".to_owned(),
            }
            .class(),
            Refusal::ScopeTags.class(),
            Refusal::ScopeRole {
                role: "r".to_owned(),
            }
            .class(),
            Refusal::ScopeLevel {
                level: 2,
                ceiling: 1,
            }
            .class(),
        ];
        assert!(axes.iter().all(|class| class.starts_with("ticket_scope_")));
        let mut sorted = axes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), axes.len());
    }

    #[test]
    fn a_refusal_that_is_not_about_the_ticket_scope_does_not_borrow_its_prefix() {
        for class in [
            Refusal::MissingReason.class(),
            Refusal::OperatorKeyMismatch.class(),
            Refusal::OverrideNotNeeded.class(),
            Refusal::Counter(CounterRefusal::Ahead { known: 1, got: 5 }).class(),
        ] {
            assert!(!class.starts_with("ticket_scope_"));
        }
    }

    #[test]
    fn the_counter_keeps_its_own_classes() {
        assert_eq!(
            Refusal::Counter(CounterRefusal::Ahead { known: 1, got: 5 }).class(),
            "counter_ahead"
        );
        assert_eq!(
            Refusal::Counter(CounterRefusal::Behind { known: 5, got: 1 }).class(),
            "counter_behind"
        );
    }
}
