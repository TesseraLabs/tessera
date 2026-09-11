//! Two-sided reconciliation: what the devices saw against what the operators
//! wrote.
//!
//! A grant says the issuing side handed out a code. A device journal line says a
//! device was asked to accept one. Neither side is evidence on its own — the
//! grants are written by the side that computed the code, and the journals
//! sit on the machines the codes let people into — so the question an audit
//! actually asks is where the two sides disagree:
//!
//! - a **login without a grant**: a device answered a challenge nobody wrote
//!   down, which is what a code handed out off the books looks like;
//! - a **grant without a login**: a code was issued and never used, which is
//!   ordinary once and a pattern of stockpiling when it repeats;
//! - a **series on one nonce**: one device, one epoch, one nonce, and more than
//!   one issuance or more than one *admission* on it. A nonce belongs to one
//!   attempt and an attempt is answered once, so a repetition is either a call
//!   that was answered twice or a device that is not the device it claims to be;
//! - a **disagreement**: the two sides paired on device, epoch and nonce, and
//!   then said different things about the role, the level or the ticket.
//!
//! # A refusal is not a login
//!
//! Every one of those classes is about codes that were handed out and sessions
//! that were opened, so only the journal lines that record an *admission* enter
//! them ([`tessera_codes_contract::outcome::classify`]). A device writes a
//! line for every attempt it decides, refusals included, and reading a refusal
//! as a login turns two ordinary things into accusations:
//!
//! - an engineer who mistypes a code once and gets it right on the second try
//!   leaves two lines on one nonce. Counted as logins, that is a series on one
//!   nonce — a finding whose documented meaning is a device that is not the
//!   device it claims to be;
//! - anyone at all standing at a console can type a role account name and any
//!   code they like. No code is issued for it, so every one of those refusals
//!   would be a login without a grant — the class that describes a code
//!   handed out off the books, generated at will by a passer-by, in the volume
//!   it takes to bury a real finding.
//!
//! Refusals are not discarded silently: the report says how many were read, so
//! an auditor knows the lines existed and were not interpreted as admissions.
//! They are evidence of something — a device under a stream of wrong codes is
//! worth a look — but not of an issuance, and this module answers only about
//! issuances. The count includes the refusals that never got as far as a nonce
//! — no ticket, a role the device does not define, a throttle — which carry
//! `-` where a nonce would be and pair with nothing by construction.
//!
//! # A word this build does not know is not a refusal
//!
//! The vocabulary of outcomes lives in the contract and can grow; a journal can
//! also arrive from a device whose build is newer than this one. A reader that
//! answered "admission?" with yes or no would file every unfamiliar word under
//! refusal — and if that word meant an opened session, every one of those
//! sessions would drop out of all four classes while the report printed "no
//! findings" over a journal where the thing had happened.
//!
//! So the third answer is kept. An unknown word does not enter the classes, is
//! not counted as a refusal, and makes the report **incomplete**: the same
//! statement the report makes when the device side was not supplied at all,
//! for the same reason — what it did not understand, it does not get to call
//! clean.
//!
//! # What a device journal is, and what is checked about it
//!
//! A device writes its audit records as a hash chain
//! ([`tessera_hashchain`]): one JSON object per line, `seq`, `prev_hash`, `ts`
//! and the record flattened beside them, a code login carrying `op` =
//! `code_login`. That is the form this module reads, and the chain is verified
//! before a single line is interpreted — a journal somebody removed their own
//! logins from is not a journal with fewer findings, it is a broken chain, and
//! the position of the break is reported.
//!
//! A second form is accepted: the flat `tracing` line, `event` =
//! `qr_code_login`, which is what a machine's log sink emits when the fleet
//! collects records that way. It carries no chain, so nothing about it can be
//! verified, and the report says so in as many words. Accepting it silently
//! would be worse than refusing it: a run that deletes a line from a chain is
//! caught, and the same run against an export of the same journal is not.
//!
//! # One list, one verdict
//!
//! What a report says is a list of [`Statement`]s — caveats, findings and
//! notes — and everything else is read off that list: the printing walks it
//! without a branch of its own, the verdict counts what kinds it holds, and the
//! guard of the tests demands that the fixtures produce every kind there is.
//!
//! This is not decoration. Four rounds of review found the same defect four
//! times: a caveat added to the structure and forgotten in one of the three
//! places that had to know about it — printed but not counted, counted but
//! silenced by the caveat above it, printed and counted but not covered by the
//! guard. The list is what removes the three places. A field added to
//! [`Report`] stops compiling in [`Report::statements`] until it is said, and a
//! new kind of statement stops compiling in [`Statement::kind`] until it is
//! classified, so neither can be added and quietly not mean anything.
//!
//! # Incompleteness is a finding
//!
//! A report assembled without the device side is not a clean report with fewer
//! sources: three of the four classes cannot be computed at all, and the fourth
//! degrades to "these grants exist". [`Report::is_complete`] is false there,
//! and every consumer prints it — an auditor who reads a partial report as a
//! clean one has been told the fleet is fine by a report that never looked.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use tessera_codes_contract::nonce::Nonce;
use tessera_codes_contract::outcome::{self, Outcome};
use tessera_codes_contract::params::FleetParams;
use tessera_hashchain::{verify_lines, ChainPayload, ChainStatus, EntryKind, OP_HEAD_SIGNATURE};

use tessera_codes_contract::revocation::SubjectKind;

use tessera_codes_contract::signature::{Signature, SignatureError, SignatureVerifier, SignerRef};

use crate::codes::agreement::KeyStorage;
use crate::codes::trust::AnchorKey;
use crate::codes::{IssuanceRecord, IssuanceRecordError};

/// Operation a code login carries in the device's audit chain.
///
/// It is the `op` of `tessera_core::audit::AuditRecord::CodeLogin`. The name is
/// matched rather than assumed, so a journal carrying every other record of the
/// machine reconciles without being filtered first.
pub const LOGIN_OP: &str = "code_login";

/// Operation an issuance carries in the chain of the issuing side.
pub const ISSUANCE_OP: &str = "codes.issuance";

/// Field of that line holding the wire form of the record.
pub const ISSUANCE_RECORD_FIELD: &str = "record";

/// Line the issuing side writes when it refuses to issue.
pub const REFUSAL_OP: &str = "codes.refusal";

/// Line the issuing side writes when it signs an authorisation.
pub const AUTHORISATION_OP: &str = "codes.authorisation";

/// Lines the issuing side writes into the same chain beside its issuances.
///
/// The list exists to tell two things apart that a reader would otherwise
/// confuse. A chain made only of these is an issuing side that has not issued
/// anything YET — a node freshly stood up that has so far only refused — and
/// reconciling against it is legitimate: every login in the device journal
/// comes out as a login no issuance accounts for, which is the class the whole
/// reconciliation exists for.
///
/// A chain carrying an op that is on neither list is a different matter: it is
/// a journal of something else handed over by mistake, and reading it as an
/// empty issuance side would produce a report that found nothing because it
/// looked at nothing.
///
/// Deliberately a list of names and not a namespace test. `codes.` as a prefix
/// would accept every op a future version of any component invents, including
/// the one that turns out to carry issuances under a name this build does not
/// know — and that failure is silent and looks like a clean reconciliation.
const KNOWN_NON_ISSUANCE_OPS: [&str; 4] = [
    REFUSAL_OP,
    AUTHORISATION_OP,
    // The chain crate's own two: a signed head and an operator's note.
    tessera_hashchain::OP_HEAD_SIGNATURE,
    tessera_hashchain::OP_ANNOTATION,
];

/// Event name the same login carries in a flat `tracing` export.
///
/// A different name for the same fact, because it is written by a different
/// sink. Both are accepted; only the chain form can be verified.
pub const LOGIN_EVENT: &str = "qr_code_login";

/// Genesis anchor of the device's audit chain.
///
/// Taken from the crate that owns the format rather than copied. It used to be
/// a copy — this crate builds for `wasm32-unknown-unknown` and cannot depend on
/// the device crate, where the constant was declared — and the copy failed
/// closed, but it was still a second home for a value that trust in the journal
/// rests on. It now lives with the format, in `tessera_hashchain::domain`,
/// which both sides already depend on.
use tessera_hashchain::domain::DEVICE_AUDIT as DEVICE_GENESIS_PREIMAGE;

/// Value the device writes for a field it has nothing to put in.
const ABSENT: &str = "-";

/// One code login attempt, as a device journal recorded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginEntry {
    /// Device the journal came from. The journal does not name it — the caller
    /// says which device it exported.
    pub device_number: String,
    /// Key epoch of the attempt.
    pub epoch: u32,
    /// Nonce of the attempt.
    pub nonce: Nonce,
    /// Role the attempt asked for.
    pub role_id: String,
    /// Level the attempt asked for.
    pub level: u32,
    /// Ticket the device attributed the attempt to, when it got that far.
    pub ticket_number: Option<String>,
    /// Personal number the engineer gave at the device, when they had been
    /// asked for one.
    ///
    /// Read because the two sides are supposed to name one person: a grant
    /// issued to one number and a session opened under another is the class the
    /// personal number exists to make visible, and a reader that dropped the
    /// field could not raise it.
    pub engineer_id: Option<String>,
    /// What the device did with the attempt.
    ///
    /// One of the words of [`tessera_codes_contract::outcome`], as the device
    /// wrote it. A word this vocabulary does not know is carried verbatim and
    /// is not an admission.
    pub outcome: String,
}

impl LoginEntry {
    /// Classifies what the device said it did with the attempt.
    ///
    /// Three answers and not two. The four classes of the report are about
    /// issuances, and a refused attempt is not one — but a word this build does
    /// not know is not a refusal either, and calling it one would drop a
    /// session that was opened out of every class of the report while it printed
    /// "no findings". See the module documentation.
    #[must_use]
    pub fn outcome(&self) -> Outcome {
        outcome::classify(&self.outcome)
    }
}

/// One issuance, as a grant recorded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantEntry {
    /// Device the code was issued for.
    pub device_number: String,
    /// Key epoch the code was issued under.
    pub epoch: u32,
    /// Nonce of the issuance.
    pub nonce: Nonce,
    /// Role the code granted.
    pub role_id: String,
    /// Level of that role.
    pub level: u32,
    /// Ticket the issuing side worked under.
    pub ticket_number: String,
    /// The side that says it issued this grant, as the grant names it.
    ///
    /// Its own field rather than a lookup at report time: what an auditor needs
    /// to be told when no anchor matches is WHICH side was named, and a report
    /// that could only say "some side you did not anchor" would send them back
    /// to the file this reader has already read.
    pub server_id: String,
    /// Personal number of the engineer the code was issued to.
    pub engineer_id: String,
    /// Organisation the device record was signed by.
    pub organisation_id: String,
    /// The moment the engineer's side claimed when it asked.
    ///
    /// Not a trusted clock and not treated as one: it is what the signed
    /// request says about itself, and the only thing a reconciliation can put
    /// beside the moment a right was withdrawn.
    pub requested_at: u64,
    /// Custody tier of the agreement key this code was computed with.
    ///
    /// In a report rather than in a footnote: a fleet that moves the agreement
    /// key onto a token has no other way to confirm from the journal that the
    /// move actually happened, and the confirmation is the whole reason the
    /// tier is written into every issuance.
    pub key_storage: KeyStorage,
    /// What became of the signature of the issuing side on this grant.
    ///
    /// The reconciliation reads a file somebody handed it. Until this was
    /// checked, every signature in that file — the issuing side's on the grant,
    /// the engineer's on the request — was taken on the word of the file, and a
    /// grant assembled by anybody at all read exactly like one the issuing side
    /// signed.
    pub signature: SignatureState,
    /// Whether the identity of the engineer was taken on trust.
    pub identity_unverified: bool,
    /// Where the grant was read from, for a report a human can act on.
    pub source: String,
}

/// A device, an epoch and a nonce that carry more than one issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceSeries {
    /// Device the series is on.
    pub device_number: String,
    /// Key epoch of the series.
    pub epoch: u32,
    /// Nonce that repeated.
    pub nonce: String,
    /// How many grants sit on this nonce.
    pub grants: u64,
    /// How many logins sit on this nonce.
    pub logins: u64,
}

/// A grant and a login that paired but do not agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disagreement {
    /// The grant of the pair.
    pub grant: GrantEntry,
    /// The login of the pair.
    pub login: LoginEntry,
    /// The fields the two disagree on.
    pub fields: Vec<&'static str>,
}

/// What could be established about the device side of a reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// Whether every journal carried a hash chain that verified.
    pub chain_verified: bool,
    /// The earliest `seq` from which no head signature covers a journal.
    pub unsigned_from_seq: Option<u64>,
    /// The `seq` from which no head signature covers the chain of the issuing
    /// side.
    ///
    /// The same caveat as the one above, about the other half of the pair: the
    /// hash chain proves nothing was edited inside what was handed over, and
    /// says nothing about what may have been dropped from the end of it.
    pub server_unsigned_from_seq: Option<u64>,
    /// Lines of the issuing side's chain that this build could not read.
    ///
    /// See [`ServerChain::unread_lines`]. A report carrying any of them is not
    /// complete, whatever else it found.
    pub server_unread_lines: usize,
    /// Refusals the journals carried that never got as far as a nonce.
    ///
    /// A device refused before it drew one — no ticket, a role it does not
    /// define, a throttle — and wrote `-` where the nonce would be. Such a line
    /// pairs with nothing by construction, so it does not become a
    /// [`LoginEntry`] at all; it is counted here instead, because the report
    /// promises to say how many refusals were read, and a promise kept for some
    /// of them is not kept.
    ///
    /// Refusals, counted by their outcome and not by the missing nonce: what a
    /// line without a nonce records is what its outcome says, and everything
    /// else about it is inference.
    pub refusals_without_nonce: u64,
    /// Lines with no nonce that record something other than a refusal.
    ///
    /// Two kinds land here, and they part company in the report. A word this
    /// build does not know is a caveat: the reader cannot say what happened. An
    /// admission with no nonce is a finding: the device says it opened a
    /// session and names no attempt, so no grant can answer for it, and an
    /// auditor needs the device and the line — not a word in a list.
    pub unpairable_lines: Vec<UnpairableLine>,
}

/// A journal line the reconciliation cannot pair with anything.
///
/// It carries no nonce, which is the key everything here pairs on, so it names
/// where it was found instead.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnpairableLine {
    /// Device whose journal carried the line.
    pub device_number: String,
    /// Number of the line in that journal, from one.
    pub line: usize,
    /// The outcome word, verbatim.
    pub outcome: String,
}

impl Provenance {
    /// The provenance of a device side that was not supplied at all.
    #[must_use]
    pub const fn absent() -> Self {
        Self {
            chain_verified: false,
            unsigned_from_seq: None,
            server_unsigned_from_seq: None,
            server_unread_lines: 0,
            refusals_without_nonce: 0,
            unpairable_lines: Vec::new(),
        }
    }
}

/// A right the fleet withdrew, and when.
///
/// The withdrawal itself is the server's business: an authorisation is checked
/// at the moment of issuance, and whether it held then is not a question a
/// reconciliation can reopen. What a reconciliation *can* say, months later and
/// off the documents alone, is that an issuance is dated after a right was
/// taken away. That is a lead, not a proof — the moment inside a request is
/// what the engineer's side claimed — and the report says it in those terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    /// Whose right was withdrawn — a person or an organisation.
    ///
    /// Not inferred from the identifier. A fleet may number an organisation and
    /// a person alike, and a match on the identifier alone would raise the
    /// alarm against the wrong party — or, worse, silently against both.
    pub kind: SubjectKind,
    /// Who lost the right: a personal number of an engineer, or an
    /// organisation identifier.
    pub subject: String,
    /// The moment it was withdrawn, in Unix seconds.
    pub at: u64,
}

/// What the fleet says its own issuances should look like.
///
/// Both members are statements a fleet makes about itself, and both are only
/// useful because the issuing side wrote the corresponding fact into every
/// issuance at the time. A reconciliation that took either from a configuration
/// file alone would be comparing one opinion with another.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Expectations {
    /// The custody tier the fleet declares for the agreement key.
    ///
    /// `None` means the fleet has not declared one, and the tier is then
    /// reported without being judged. A tier *below* the declared one is an
    /// alarm; above it is not — that is a fleet that strengthened its custody,
    /// and an alarm there would teach an operator to ignore the class.
    pub declared_key_storage: Option<KeyStorage>,
    /// Rights the fleet withdrew, with the moment of each.
    pub revocations: Vec<Revocation>,
    /// How many of those arrived unsigned — from a command line rather than
    /// from a published list.
    ///
    /// Counted rather than hidden: a report built on withdrawals nobody signed
    /// cannot call itself complete, and an auditor reading it has to know which
    /// of the two it is.
    pub unsigned_revocations: usize,
    /// The signed list of withdrawals this run read, and its serial.
    ///
    /// [`None`] when no list was supplied. The serial is reported, because a
    /// reader who is told which withdrawals were applied and not which LIST
    /// they came from has been told half of it.
    pub revocation_list: Option<RevocationListUsed>,
}

/// The signed list of withdrawals a run was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationListUsed {
    /// Serial of the list.
    pub serial: u64,
    /// The serial the caller declared as already applied, if they declared one.
    ///
    /// [`None`] is not "zero". Zero is a caller who says nothing has been
    /// applied yet; `None` is a caller who did not say, and then ANY correctly
    /// signed list passes — including yesterday's, which is signed just as
    /// validly and is the one that still admits whoever was cut off this
    /// morning. The difference is a caveat in the report.
    pub waterline: Option<u64>,
}

/// Orders the custody tiers by how much they withhold from whoever holds the
/// machine.
///
/// One comparison, in one place: "below the declared tier" is the whole
/// question the class asks, and two spellings of it would eventually disagree.
const fn custody_rank(storage: KeyStorage) -> u8 {
    match storage {
        KeyStorage::Software => 0,
        KeyStorage::Token => 1,
    }
}

/// An issuance whose custody tier is below what the fleet declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyShortfall {
    /// The issuance.
    pub grant: GrantEntry,
    /// The tier the fleet declared.
    pub declared: KeyStorage,
}

/// An issuance dated after the right behind it was withdrawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LateGrant {
    /// The issuance.
    pub grant: GrantEntry,
    /// The withdrawal it is dated after.
    pub revocation: Revocation,
}

/// The outcome of a reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Logins the grants do not account for.
    pub logins_without_grant: Vec<LoginEntry>,
    /// Grants no login accounts for.
    pub grants_without_login: Vec<GrantEntry>,
    /// Counters carrying more than one challenge.
    pub series_on_one_nonce: Vec<NonceSeries>,
    /// Pairs that met and then disagreed.
    pub disagreements: Vec<Disagreement>,
    /// Issuances whose custody tier is below the declared one.
    pub custody_shortfalls: Vec<CustodyShortfall>,
    /// Grants the issuing side's own key does not stand behind.
    pub rejected_signatures: Vec<GrantEntry>,
    /// Grants naming a side none of the supplied anchors knows.
    pub unknown_issuers: Vec<GrantEntry>,
    /// Grants nobody supplied a key for.
    unchecked_signatures: usize,
    /// The signed list of withdrawals this run read.
    revocation_list: Option<RevocationListUsed>,
    /// Issuances dated after the right behind them was withdrawn.
    pub late_grants: Vec<LateGrant>,
    /// Whether the device side was present at all.
    device_side: bool,
    /// Whether every device journal read was chain-verified.
    chain_verified: bool,
    /// The earliest `seq` of an unsigned tail across the journals read.
    unsigned_from_seq: Option<u64>,
    /// The `seq` from which no head signature covers the chain of the issuing
    /// side.
    server_unsigned_from_seq: Option<u64>,
    /// Lines of that chain this build could not read.
    server_unread_lines: usize,
    /// Withdrawals that arrived unsigned.
    unsigned_revocations: usize,
    /// Refused attempts read from the device side.
    ///
    /// Not a finding and not a class: a count, so that lines the report did not
    /// interpret are still known to have been there. An auditor who sees none
    /// of the four classes and a large number here has been told something.
    refusals_read: u64,
    /// Outcome words the reader could not classify, in the order they sort.
    ///
    /// Words carried by lines that DID name a nonce: the line was read, its
    /// outcome was not, and the classes it would have entered were not computed
    /// for it.
    unknown_outcomes: BTreeSet<String>,
    /// Lines with no nonce that are not refusals.
    ///
    /// Kept whole rather than as words, because one of them is a finding an
    /// auditor has to be able to act on: which device, which line of its
    /// journal. See [`Provenance::unpairable_lines`].
    unpairable_lines: Vec<UnpairableLine>,
}

impl Report {
    /// Everything this report says, in the order it says it.
    ///
    /// The one place that knows which fields a report has. Printing walks this
    /// list and branches on nothing; the verdict is read off the same list; and
    /// the guard of the tests demands that the fixtures produce every kind of
    /// statement there is. A tenth field added to the structure has to appear
    /// here before any of the three can see it, and the destructuring below —
    /// written without `..` on purpose — is what makes that a compiler error
    /// rather than something to remember.
    ///
    /// Four rounds of review found the same defect four times: a caveat added
    /// to the structure and forgotten in one of the three places. This is the
    /// answer to the class, not to the last instance of it.
    #[must_use]
    pub fn statements(&self) -> Vec<Statement<'_>> {
        let Self {
            logins_without_grant,
            grants_without_login,
            series_on_one_nonce,
            disagreements,
            custody_shortfalls,
            rejected_signatures,
            unknown_issuers,
            unchecked_signatures,
            revocation_list,
            late_grants,
            device_side,
            chain_verified,
            unsigned_from_seq,
            server_unsigned_from_seq,
            server_unread_lines,
            unsigned_revocations,
            refusals_read,
            unknown_outcomes,
            unpairable_lines,
        } = self;

        // Three lists rather than one, and the order between them is the
        // structure rather than the order these lines happen to be written in:
        // the caveats come first because what could not be established
        // qualifies everything under it, and a reader who met a finding first
        // would carry it over the sentence that limits it. Written as one list,
        // the loop below — which produces a caveat and a finding from the same
        // source — put a finding above two caveats.
        let mut caveats = Vec::new();
        let mut findings = Vec::new();
        let mut notes = Vec::new();

        if !*device_side {
            caveats.push(Statement::NoDeviceSide);
        }
        if !unknown_outcomes.is_empty() {
            caveats.push(Statement::UnreadableOutcomes(unknown_outcomes));
        }
        for line in unpairable_lines {
            // Classified here and nowhere else. An admission with no nonce is a
            // finding — a device saying it opened a session without naming the
            // attempt — and a word this build cannot read is a caveat. A
            // refusal cannot reach this list by construction; if one ever does,
            // it is something the reader did not expect, which is a caveat too.
            match outcome::classify(&line.outcome) {
                Outcome::Admission => findings.push(Statement::AdmissionWithoutNonce(line)),
                Outcome::Unknown | Outcome::Refusal => {
                    caveats.push(Statement::UnreadableLine(line));
                }
            }
        }
        if *device_side && !*chain_verified {
            caveats.push(Statement::NoChain);
        }
        if let Some(seq) = *unsigned_from_seq {
            caveats.push(Statement::UnsignedTail(seq));
        }
        if let Some(seq) = *server_unsigned_from_seq {
            caveats.push(Statement::ServerUnsignedTail(seq));
        }
        if *server_unread_lines > 0 {
            caveats.push(Statement::UnreadServerLines(*server_unread_lines));
        }
        if *unchecked_signatures > 0 {
            caveats.push(Statement::SignaturesNotChecked(*unchecked_signatures));
        }
        // One or the other, never both: the caveat names the serial itself, so
        // a note beside it would say the same thing twice and put the weaker
        // sentence under the stronger one.
        if let Some(used) = revocation_list {
            if used.waterline.is_none() {
                caveats.push(Statement::RevocationWaterlineUnset(used.serial));
            } else {
                notes.push(Statement::RevocationListRead(*used));
            }
        }
        if *unsigned_revocations > 0 {
            caveats.push(Statement::UnsignedRevocations(*unsigned_revocations));
        }

        for login in logins_without_grant {
            findings.push(Statement::LoginWithoutGrant(login));
        }
        for grant in grants_without_login {
            findings.push(Statement::GrantWithoutLogin(grant));
        }
        for series in series_on_one_nonce {
            findings.push(Statement::SeriesOnOneNonce(series));
        }
        for disagreement in disagreements {
            findings.push(Statement::Disagreement(disagreement));
        }
        for shortfall in custody_shortfalls {
            findings.push(Statement::CustodyBelowDeclared(shortfall));
        }
        for grant in rejected_signatures {
            findings.push(Statement::GrantSignatureRejected(grant));
        }
        for grant in unknown_issuers {
            findings.push(Statement::GrantIssuerUnknown(grant));
        }
        for late in late_grants {
            findings.push(Statement::GrantAfterRevocation(late));
        }

        if *refusals_read > 0 {
            notes.push(Statement::RefusalsRead(*refusals_read));
        }

        caveats.extend(findings);
        caveats.extend(notes);
        caveats
    }

    /// What the report amounts to, as one answer.
    ///
    /// Read off [`Report::statements`] and not off a predicate over some of the
    /// fields: "clean" is the absence of anything to say, and a predicate that
    /// looked at four fields out of ten called a report clean over lines it had
    /// not read. A statement of any kind that is not a note is enough to keep
    /// the word "clean" off the page.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        let mut verdict = Verdict::Clean;
        for statement in self.statements() {
            match statement.kind() {
                StatementKind::Finding => return Verdict::Findings,
                StatementKind::Caveat => verdict = Verdict::Incomplete,
                StatementKind::Note => {}
            }
        }
        verdict
    }

    /// Reports whether the report was able to look at everything it names.
    ///
    /// False when it carries a caveat — whichever one. Listing the reasons here
    /// was a fourth place that had to be kept in step with the others, and it
    /// was already out of step: it named three of the five.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self
            .statements()
            .iter()
            .any(|statement| statement.kind() == StatementKind::Caveat)
    }

    /// Returns the outcome words the reader could not account for.
    ///
    /// Two kinds share this list, and the name says what they have in common
    /// rather than what one of them is: a word this build does not know, and a
    /// word it knows perfectly well — `success` — arriving on a line with no
    /// nonce, which it cannot pair with anything.
    pub fn unaccounted_outcomes(&self) -> impl Iterator<Item = &str> {
        self.unknown_outcomes.iter().map(String::as_str).chain(
            self.unpairable_lines
                .iter()
                .map(|line| line.outcome.as_str()),
        )
    }

    /// Reports whether the device side came with a chain that verified.
    ///
    /// False when a journal was a flat export: its lines can be removed without
    /// a trace, so the absence of a finding says less than it appears to.
    #[must_use]
    pub const fn chain_verified(&self) -> bool {
        self.chain_verified
    }

    /// Returns how many refused attempts the device side carried.
    ///
    /// Refusals take part in none of the four classes — see the module
    /// documentation — and this is what says they were read rather than lost.
    #[must_use]
    pub const fn refusals_read(&self) -> u64 {
        self.refusals_read
    }
}

/// What a report amounts to.
///
/// Ordered by what a reader must do about it: a finding outranks an
/// incompleteness, which outranks nothing to report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Everything was read and nothing was found.
    Clean,
    /// Nothing was found among what could be read, and something could not be.
    Incomplete,
    /// The two sides disagree somewhere.
    Findings,
}

/// One thing a report says.
///
/// Every line a report can print is a variant here, and every variant is
/// classified by [`Statement::kind`] — an exhaustive match, so a new kind of
/// statement cannot be added without deciding whether it keeps the word
/// "clean" off the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Statement<'a> {
    /// No device journal was supplied at all.
    NoDeviceSide,
    /// Journals carried outcome words this build cannot read.
    UnreadableOutcomes(&'a BTreeSet<String>),
    /// A line with no nonce whose outcome this build cannot account for.
    UnreadableLine(&'a UnpairableLine),
    /// A line saying a session opened without naming the attempt.
    AdmissionWithoutNonce(&'a UnpairableLine),
    /// A journal carried no hash chain.
    NoChain,
    /// No head signature covers a journal past this point.
    UnsignedTail(u64),
    /// No head signature covers the chain of the issuing side past this point.
    ServerUnsignedTail(u64),
    /// Lines of the issuing side's chain the reader could not read.
    UnreadServerLines(usize),
    /// Grants whose signature nobody supplied a key for.
    SignaturesNotChecked(usize),
    /// A list of withdrawals was taken without a waterline to measure it by.
    RevocationWaterlineUnset(u64),
    /// Which list of withdrawals this run applied.
    RevocationListRead(RevocationListUsed),
    /// A grant the issuing side's own key does not stand behind.
    GrantSignatureRejected(&'a GrantEntry),
    /// A grant naming an issuing side none of the supplied anchors knows.
    GrantIssuerUnknown(&'a GrantEntry),
    /// Some withdrawals were taken on a caller's word rather than from a
    /// published list.
    UnsignedRevocations(usize),
    /// A login the grants do not account for.
    LoginWithoutGrant(&'a LoginEntry),
    /// A grant no login accounts for.
    GrantWithoutLogin(&'a GrantEntry),
    /// More than one issuance or admission on one nonce.
    SeriesOnOneNonce(&'a NonceSeries),
    /// A pair that met and then disagreed.
    Disagreement(&'a Disagreement),
    /// An issuance whose custody tier is below the declared one.
    CustodyBelowDeclared(&'a CustodyShortfall),
    /// An issuance dated after the right behind it was withdrawn.
    GrantAfterRevocation(&'a LateGrant),
    /// How many refusals were read.
    RefusalsRead(u64),
}

/// What kind of thing a statement is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementKind {
    /// Something the report could not establish. It qualifies everything else.
    Caveat,
    /// The two sides disagree here.
    Finding,
    /// Neither: a number that says what was read.
    Note,
}

impl Statement<'_> {
    /// Classifies this statement.
    ///
    /// Exhaustive on purpose: this is the match a new variant has to pass
    /// through, and passing through it is what makes the verdict and the
    /// completeness see it without anybody remembering to look.
    #[must_use]
    pub const fn kind(&self) -> StatementKind {
        match self {
            Self::NoDeviceSide
            | Self::UnreadableOutcomes(_)
            | Self::UnreadableLine(_)
            | Self::NoChain
            | Self::UnsignedTail(_)
            | Self::ServerUnsignedTail(_)
            | Self::UnreadServerLines(_)
            | Self::SignaturesNotChecked(_)
            | Self::RevocationWaterlineUnset(_)
            | Self::UnsignedRevocations(_) => StatementKind::Caveat,
            Self::AdmissionWithoutNonce(_)
            | Self::LoginWithoutGrant(_)
            | Self::GrantWithoutLogin(_)
            | Self::SeriesOnOneNonce(_)
            | Self::Disagreement(_)
            | Self::CustodyBelowDeclared(_)
            | Self::GrantAfterRevocation(_)
            | Self::GrantSignatureRejected(_)
            | Self::GrantIssuerUnknown(_) => StatementKind::Finding,
            Self::RefusalsRead(_) | Self::RevocationListRead(_) => StatementKind::Note,
        }
    }
}

impl fmt::Display for Statement<'_> {
    /// Writes the one line of this statement.
    ///
    /// One `match` over every statement there is, and its length is the number
    /// of statements: splitting it would mean a second place where a variant
    /// can be forgotten, which is the defect this file is built to prevent.
    ///
    /// The values are identifiers, numbers and nonces — the same bytes in every
    /// locale; a consumer that heads the report with a caption localizes the
    /// caption.
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per statement: a shorter function would be a second place to forget one"
    )]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDeviceSide => write!(
                f,
                "incomplete: no device journal was supplied; only grants were read"
            ),
            Self::UnreadableOutcomes(words) => write!(
                f,
                "incomplete: the device journal carries outcomes this build cannot account for \
                 ({}); lines with them counted as neither logins nor refusals, so the classes \
                 above were not computed for them",
                words
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::UnreadableLine(line) => write!(
                f,
                "unreadable-line device={} line={} outcome={}: a line with no nonce whose \
                 outcome this build cannot account for",
                line.device_number, line.line, line.outcome
            ),
            Self::AdmissionWithoutNonce(line) => write!(
                f,
                "admission-without-nonce device={} line={} outcome={}: the device says a \
                 session was opened and names no attempt, so no grant can answer for it",
                line.device_number, line.line, line.outcome
            ),
            Self::NoChain => write!(
                f,
                "unverified: a device journal carried no hash chain; lines could have been \
                 removed from it without a trace"
            ),
            Self::UnsignedTail(seq) => write!(
                f,
                "unsigned-tail from={seq}: the device journal is not covered by a head \
                 signature past this point, so lines could have been dropped from its end; the \
                 signature itself is not checked here"
            ),
            Self::ServerUnsignedTail(seq) => write!(
                f,
                "server-unsigned-tail from={seq}: the issuance chain is not covered by a head \
                 signature past this point, so issuances could have been dropped from its end; \
                 the signature itself is not checked here"
            ),
            Self::UnreadServerLines(count) => write!(
                f,
                "unread-server-lines count={count}: the chain of the issuing side carries \
                 {count} line(s) written under an operation this build does not know, and what \
                 they record was not read; a later build may write issuances under a name this \
                 one has never heard of, so the report cannot claim to have seen everything"
            ),
            Self::RevocationWaterlineUnset(serial) => write!(
                f,
                "revocation-waterline-unset serial={serial}: no already-applied serial was \
                 given, so a list of ANY age would have been accepted — a signature stops \
                 substitution and not replay, and yesterday's list is the one that still admits \
                 whoever was cut off this morning"
            ),
            Self::RevocationListRead(used) => match used.waterline {
                Some(waterline) => write!(
                    f,
                    "revocations-read serial={} above-applied={waterline}",
                    used.serial
                ),
                None => write!(f, "revocations-read serial={}", used.serial),
            },
            Self::SignaturesNotChecked(count) => write!(
                f,
                "signatures-not-checked count={count}: no key was supplied for the side that \
                 issued {count} grant(s), so their signatures were read from the file and \
                 nothing else; a grant assembled by anybody at all reads like one the issuing \
                 side signed"
            ),
            Self::GrantSignatureRejected(grant) => write!(
                f,
                "grant-signature-rejected device={} epoch={} nonce={} server-key-says=no \
                 source={}: the key of the issuing side does not stand behind this grant, so \
                 whatever wrote it was not that side",
                grant.device_number,
                grant.epoch,
                grant.nonce.as_str(),
                grant.source
            ),
            Self::GrantIssuerUnknown(grant) => write!(
                f,
                "grant-issuer-unknown device={} epoch={} nonce={} server={} source={}: keys were \
                 supplied for the sides that may issue, and this grant names another one; a side \
                 the fleet never anchored is a side nothing vouches for",
                grant.device_number,
                grant.epoch,
                grant.nonce.as_str(),
                grant.server_id,
                grant.source
            ),
            Self::UnsignedRevocations(count) => write!(
                f,
                "incomplete: {count} withdrawal(s) were taken from the caller rather than from a \
                 list the fleet signed; an unsigned withdrawal is one anybody on the path can \
                 replace with none at all"
            ),
            Self::CustodyBelowDeclared(shortfall) => write!(
                f,
                "custody-below-declared device={} nonce={} declared={} recorded={} file={}",
                shortfall.grant.device_number,
                shortfall.grant.nonce.as_str(),
                shortfall.declared.as_str(),
                shortfall.grant.key_storage.as_str(),
                shortfall.grant.source
            ),
            Self::GrantAfterRevocation(late) => write!(
                f,
                "grant-after-revocation device={} nonce={} subject={} revoked_at={} \
                 requested_at={} file={}",
                late.grant.device_number,
                late.grant.nonce.as_str(),
                late.revocation.subject,
                late.revocation.at,
                late.grant.requested_at,
                late.grant.source
            ),
            Self::LoginWithoutGrant(login) => write!(
                f,
                "login-without-grant device={} epoch={} nonce={} role={} level={} outcome={}",
                login.device_number,
                login.epoch,
                login.nonce.as_str(),
                login.role_id,
                login.level,
                login.outcome
            ),
            Self::GrantWithoutLogin(grant) => write!(
                f,
                "grant-without-login device={} epoch={} nonce={} role={} level={} ticket={} \
                 key_storage={} identity_unverified={} \
                 file={}",
                grant.device_number,
                grant.epoch,
                grant.nonce.as_str(),
                grant.role_id,
                grant.level,
                grant.ticket_number,
                grant.key_storage.as_str(),
                if grant.identity_unverified {
                    "yes"
                } else {
                    "no"
                },
                grant.source
            ),
            Self::SeriesOnOneNonce(series) => write!(
                f,
                "series-on-one-nonce device={} epoch={} nonce={} grants={} logins={}",
                series.device_number, series.epoch, series.nonce, series.grants, series.logins
            ),
            Self::Disagreement(disagreement) => write!(
                f,
                "disagreement device={} epoch={} nonce={} fields={}",
                disagreement.grant.device_number,
                disagreement.grant.epoch,
                disagreement.grant.nonce.as_str(),
                disagreement.fields.join(",")
            ),
            Self::RefusalsRead(count) => write!(
                f,
                "refusals-read count={count}: attempts the devices refused; they are not logins \
                 and take part in no finding above"
            ),
        }
    }
}

impl fmt::Display for Report {
    /// Writes the report: one statement per line, then the verdict when there
    /// is nothing to say.
    ///
    /// No branching of its own. What is printed is what [`Report::statements`]
    /// returns, so a caveat cannot be silenced by the one above it — which is
    /// what an `else if` did once and an early `return` did after it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for statement in self.statements() {
            writeln!(f, "{statement}")?;
        }
        if self.verdict() == Verdict::Clean {
            writeln!(f, "no findings")?;
        }
        Ok(())
    }
}

/// Reconciles the grants of an operator against the journals of the devices.
///
/// `logins` is [`None`] when the device side was not supplied at all, which is
/// a different statement from an empty journal: an empty journal says the
/// devices saw nothing, and its absence says nobody looked.
///
/// `expectations` is what the fleet says about itself — the custody tier it
/// declared and the rights it withdrew. Both are compared against what the
/// issuing side wrote at the time, never against a second opinion.
///
/// `provenance` says what could be established about the journals behind
/// `logins`. It is not bookkeeping: a report whose device side could have had
/// lines removed from it cannot be read as "nothing was found", and [`Report`]
/// prints the difference.
#[must_use]
pub fn reconcile(
    grants: &[GrantEntry],
    logins: Option<&[LoginEntry]>,
    provenance: &Provenance,
    expectations: &Expectations,
) -> Report {
    // Only the lines that record an admission take part in the four classes:
    // a refusal is an attempt the device turned away, and reading it as a login
    // makes an ordinary mistyped code look like a device answering one
    // challenge twice. A word this build cannot classify goes to neither side —
    // see the module documentation. Counted here rather than filtered twice, so
    // that the three answers are read off one pass and cannot drift apart.
    let mut admissions: Vec<LoginEntry> = Vec::new();
    let mut refusals = 0_u64;
    let mut unknown_outcomes: BTreeSet<String> = BTreeSet::new();
    for login in logins.unwrap_or_default() {
        match login.outcome() {
            Outcome::Admission => admissions.push(login.clone()),
            Outcome::Refusal => refusals = refusals.saturating_add(1),
            Outcome::Unknown => {
                unknown_outcomes.insert(login.outcome.clone());
            }
        }
    }
    let refusals_read = refusals.saturating_add(provenance.refusals_without_nonce);
    // Lines with no nonce travel whole: what a report says about them depends
    // on their outcome — a caveat for a word it cannot read, a finding for a
    // session opened without an attempt named — and that is decided in
    // `statements`, where every other such decision is made.

    let mut report = Report {
        logins_without_grant: Vec::new(),
        grants_without_login: Vec::new(),
        series_on_one_nonce: series(grants, &admissions),
        disagreements: Vec::new(),
        // Both classes are about the issuances alone: they hold whether or not
        // a device journal was supplied, and a report that withheld them until
        // the device side arrived would stay silent about the very thing an
        // auditor came to the server chain for.
        custody_shortfalls: custody_shortfalls(grants, expectations),
        // Read off the entries rather than passed in beside them: the state was
        // decided where the grant and the key were both in hand, and a second
        // opinion assembled here could only ever disagree with it.
        rejected_signatures: grants
            .iter()
            .filter(|grant| grant.signature == SignatureState::Rejected)
            .cloned()
            .collect(),
        unknown_issuers: grants
            .iter()
            .filter(|grant| grant.signature == SignatureState::IssuerUnknown)
            .cloned()
            .collect(),
        unchecked_signatures: grants
            .iter()
            .filter(|grant| grant.signature == SignatureState::NotChecked)
            .count(),
        late_grants: late_grants(grants, expectations),
        device_side: logins.is_some(),
        chain_verified: logins.is_some() && provenance.chain_verified,
        unsigned_from_seq: provenance.unsigned_from_seq,
        server_unsigned_from_seq: provenance.server_unsigned_from_seq,
        server_unread_lines: provenance.server_unread_lines,
        unsigned_revocations: expectations.unsigned_revocations,
        revocation_list: expectations.revocation_list,
        refusals_read,
        unknown_outcomes,
        unpairable_lines: provenance.unpairable_lines.clone(),
    };

    if logins.is_none() {
        return report;
    }
    let logins = &admissions;

    // Every admission on the key, not the last one seen. Two logins on one
    // nonce are a finding of their own — `series_on_one_nonce` raises it — and
    // keeping only one of them would drop the disagreement the other carries:
    // the first login could name a different role or level than the grant,
    // and the report would say the pair agreed.
    let mut by_key: BTreeMap<(String, u32, String), Vec<&LoginEntry>> = BTreeMap::new();
    for login in logins {
        by_key
            .entry(key(&login.device_number, login.epoch, &login.nonce))
            .or_default()
            .push(login);
    }

    let mut paired: BTreeSet<(String, u32, String)> = BTreeSet::new();
    for grant in grants {
        let grant_key = key(&grant.device_number, grant.epoch, &grant.nonce);
        match by_key.get(&grant_key) {
            None => report.grants_without_login.push(grant.clone()),
            Some(logins) => {
                paired.insert(grant_key);
                for login in logins {
                    let fields = disagreeing_fields(grant, login);
                    if !fields.is_empty() {
                        report.disagreements.push(Disagreement {
                            grant: grant.clone(),
                            login: (*login).clone(),
                            fields,
                        });
                    }
                }
            }
        }
    }

    for login in logins {
        if !paired.contains(&key(&login.device_number, login.epoch, &login.nonce)) {
            report.logins_without_grant.push(login.clone());
        }
    }
    report
}

/// Collects the nonces that carry more than one issuance.
///
/// A nonce belongs to one attempt, and an attempt is answered once. Two
/// grants on one nonce are two codes handed out for one challenge; two logins
/// on one nonce are two admissions on an attempt that only ever had one code to
/// give. Neither can happen on a device that is behaving, so either is worth a
/// line of the report.
///
/// `logins` carries admissions only. Several refusals on one nonce are what an
/// engineer mistyping a code leaves behind, and the attempt budget of the nonce
/// exists precisely so that they can happen.
fn series(grants: &[GrantEntry], logins: &[LoginEntry]) -> Vec<NonceSeries> {
    let mut seen: BTreeMap<(String, u32, String), Bucket> = BTreeMap::new();
    for grant in grants {
        seen.entry(key_of(&grant.device_number, grant.epoch, &grant.nonce))
            .or_default()
            .add(Side::Grant);
    }
    for login in logins {
        seen.entry(key_of(&login.device_number, login.epoch, &login.nonce))
            .or_default()
            .add(Side::Login);
    }

    seen.into_iter()
        .filter(|(_, bucket)| bucket.is_a_series())
        .map(|((device_number, epoch, nonce), bucket)| NonceSeries {
            device_number,
            epoch,
            nonce,
            grants: bucket.grants,
            logins: bucket.logins,
        })
        .collect()
}

/// Which side an entry came from.
#[derive(Debug, Clone, Copy)]
enum Side {
    /// A grant of the issuing side.
    Grant,
    /// A device journal line.
    Login,
}

/// What one counter of one device and epoch carries.
#[derive(Debug, Default)]
struct Bucket {
    /// Grants counted on it.
    grants: u64,
    /// Logins counted on it.
    logins: u64,
}

impl Bucket {
    /// Records one entry.
    fn add(&mut self, side: Side) {
        match side {
            Side::Grant => self.grants = self.grants.saturating_add(1),
            Side::Login => self.logins = self.logins.saturating_add(1),
        }
    }

    /// Reports whether this nonce carries more than one issuance.
    const fn is_a_series(&self) -> bool {
        self.grants > 1 || self.logins > 1
    }
}

/// The key a bucket sits under.
fn key_of(device_number: &str, epoch: u32, nonce: &Nonce) -> (String, u32, String) {
    (device_number.to_owned(), epoch, nonce.as_str().to_owned())
}

/// Names the fields a paired grant and login disagree on.
fn disagreeing_fields(grant: &GrantEntry, login: &LoginEntry) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if grant.role_id != login.role_id {
        fields.push("role");
    }
    if grant.level != login.level {
        fields.push("level");
    }
    // A device that refused before it resolved a ticket recorded none; that is
    // the refusal, not a disagreement about which ticket was used.
    if let Some(ticket) = login.ticket_number.as_deref() {
        if ticket != grant.ticket_number {
            fields.push("ticket");
        }
    }
    // The personal number. A line that reaches this comparison is an ADMISSION
    // — refusals are filtered out before the pairing — so "the device recorded
    // no number" is not a device that turned somebody away before asking. It is
    // a session that opened without the device writing down who opened it, and
    // the whole point of the field is that a login names a person.
    //
    // Skipping the comparison read as agreement, which is the worst of the
    // answers available: "nobody was named" came out of the report as clean.
    // Compared as numbers of the channel's format, not as bytes: the device
    // passes the number on as the engineer TYPED it, separators and case
    // included, while the issuing side writes down whatever it was given. Two
    // spellings of one number would come out of here as a disagreement between
    // the two sides — a finding about a person who did nothing but reach for
    // the space bar.
    match login.engineer_id.as_deref() {
        Some(engineer)
            if tessera_codes_contract::revocation::same_subject(
                SubjectKind::Engineer,
                engineer,
                &grant.engineer_id,
            ) => {}
        _ => fields.push("engineer"),
    }
    fields
}

/// Issuances whose custody tier is below the one the fleet declared.
///
/// Strictly below. An issuance recorded on a token where the fleet declared
/// software is a fleet that strengthened its custody, and raising an alarm
/// there would teach an operator to skip the class.
fn custody_shortfalls(grants: &[GrantEntry], expectations: &Expectations) -> Vec<CustodyShortfall> {
    let Some(declared) = expectations.declared_key_storage else {
        return Vec::new();
    };
    grants
        .iter()
        .filter(|grant| custody_rank(grant.key_storage) < custody_rank(declared))
        .map(|grant| CustodyShortfall {
            grant: grant.clone(),
            declared,
        })
        .collect()
}

/// Issuances dated after the right behind them was withdrawn.
///
/// A withdrawal names whose right it took away, and the match uses that pair —
/// kind and identifier — rather than the identifier alone: a fleet may number an
/// organisation and a person alike. One issuance can be late against several
/// withdrawals; each is stated, because "which right" is the first thing
/// anybody will ask.
///
/// # The same second counts as late
///
/// Both moments are Unix seconds, so an issuance stamped with the second of the
/// withdrawal cannot be shown to have happened before it. Reported rather than
/// dropped: an auditor can look at a line and decide it was legitimate, and has
/// no way at all to look at a line the report never printed.
fn late_grants(grants: &[GrantEntry], expectations: &Expectations) -> Vec<LateGrant> {
    let mut late = Vec::new();
    for grant in grants {
        for revocation in &expectations.revocations {
            // The pair, exactly as the contract's own lookup does it: kind and
            // identifier together, never the identifier alone.
            // The same rule the contract's own lookup uses, called rather than
            // repeated: a personal number is matched by the characters the
            // format counts. Matching bytes would let the person a withdrawal
            // names decide whether it applies to them — typing the number with
            // different separators is enough to make the report clean.
            let concerns = match revocation.kind {
                SubjectKind::Engineer => tessera_codes_contract::revocation::same_subject(
                    SubjectKind::Engineer,
                    &revocation.subject,
                    &grant.engineer_id,
                ),
                SubjectKind::Organisation => revocation.subject == grant.organisation_id,
            };
            if concerns && grant.requested_at >= revocation.at {
                late.push(LateGrant {
                    grant: grant.clone(),
                    revocation: revocation.clone(),
                });
            }
        }
    }
    late
}

/// The key the two sides pair on.
fn key(device_number: &str, epoch: u32, nonce: &Nonce) -> (String, u32, String) {
    (device_number.to_owned(), epoch, nonce.as_str().to_owned())
}

/// One line of a device journal, as much of it as this reader needs.
///
/// The payload is kept open (`op` plus whatever else the record carries)
/// because the reconciliation reads one record type and must not refuse a
/// journal for carrying the others: a device writes enrolments, rotations and
/// its own head signatures into the same chain, and a reader that insisted on
/// knowing every variant would break the day a new one is added.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceLine {
    /// The operation this line records.
    pub op: String,
    /// Everything else the record carries.
    #[serde(flatten)]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

impl ChainPayload for DeviceLine {
    const GENESIS_PREIMAGE: &'static [u8] = DEVICE_GENESIS_PREIMAGE;

    fn kind(&self) -> EntryKind {
        if self.op == OP_HEAD_SIGNATURE {
            EntryKind::HeadSignature
        } else {
            EntryKind::Record
        }
    }

    fn is_structurally_valid(&self) -> bool {
        head_signature_is_whole(&self.op, &self.fields)
    }
}

/// A device journal that was read, and what could be established about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceJournal {
    /// The code-login lines it carries.
    pub entries: Vec<LoginEntry>,
    /// Whether the hash chain of the journal was verified.
    ///
    /// False for a flat export, which carries no chain: its lines may have been
    /// removed without a trace, and every consumer says so rather than implying
    /// a check that did not happen.
    pub chain_verified: bool,
    /// The `seq` from which no head-signature line covers the journal, when
    /// such a tail exists.
    ///
    /// A hash chain catches a line changed or dropped from the middle; it
    /// cannot catch lines dropped from the end, because a prefix of a valid
    /// chain is a valid chain. What bounds that is the device's own head
    /// signature: everything before the last one cannot be shortened unnoticed,
    /// everything after it can. The number says where "after it" begins.
    ///
    /// Nothing here checks the signature *cryptographically* — that needs the
    /// device's public key, which a reconciliation does not have. This is the
    /// structural fact only, and it is reported as such.
    pub unsigned_from_seq: Option<u64>,
    /// Refusals the journal carried that never got as far as a nonce.
    ///
    /// They are not entries — nothing pairs with them — but the report counts
    /// them among the refusals it says it read. See
    /// [`Provenance::refusals_without_nonce`].
    pub refusals_without_nonce: u64,
    /// Lines with no nonce that are not refusals.
    ///
    /// A line saying a session was opened but naming no attempt, or one
    /// carrying a word this build does not know — see
    /// [`Provenance::unpairable_lines`].
    pub unpairable_lines: Vec<UnpairableLine>,
}

/// Reads the code-login lines of one device journal.
///
/// The chain is verified before anything is interpreted: a line altered,
/// reordered or removed is [`JournalError::BrokenChain`] with its position, and
/// no findings are drawn from a history somebody edited. A flat export carries
/// no chain and is read unverified — see [`DeviceJournal::chain_verified`].
///
/// Lines of other records are skipped, so a journal of a whole machine
/// reconciles without being filtered first; a line that is not JSON at all is an
/// error, because an export that lost its shape is not one to read a clean
/// report from. Attempts the device refused before a nonce existed carry none
/// and are skipped: there is nothing for them to pair with.
///
/// A journal carrying no login line at all is [`JournalError::NoLoginLines`],
/// not an empty result. An empty result flows into a report that calls itself
/// complete and finds nothing — which is exactly what reading the wrong file, or
/// a form this build does not know, looks like.
///
/// # Errors
///
/// The [`JournalError`] naming what could not be read.
pub fn read_journal(
    device_number: &str,
    text: &str,
    params: &FleetParams,
) -> Result<DeviceJournal, JournalError> {
    let lines: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();

    let (chain_verified, unsigned_from_seq) = match chain_status(&lines) {
        Some(ChainStatus::Broken { position }) => {
            return Err(JournalError::BrokenChain { position })
        }
        Some(ChainStatus::IntactUnsignedTail { unsigned_from_seq }) => {
            (true, Some(unsigned_from_seq))
        }
        Some(_) => (true, None),
        None => (false, None),
    };

    let mut entries = Vec::new();
    let mut refusals_without_nonce = 0_u64;
    let mut unpairable_lines: Vec<UnpairableLine> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let number = index + 1;
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|_| JournalError::NotJson { line: number })?;
        if !is_login(&value) {
            continue;
        }

        let text_field = |name: &str| {
            value
                .get(name)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        let number_field = |name: &str| value.get(name).and_then(serde_json::Value::as_u64);

        // Every field a code-login line owes, read before anything is decided
        // about the line. The doctrine of this parser is that nothing is
        // repaired and nothing is skipped, and a line with no nonce used to
        // leave through a shortcut that read none of them.
        let nonce_text = text_field("nonce_ref").ok_or(JournalError::MissingField {
            line: number,
            field: "nonce_ref",
        })?;
        let outcome = text_field("outcome").ok_or(JournalError::MissingField {
            line: number,
            field: "outcome",
        })?;
        let role_id = text_field("role_id").ok_or(JournalError::MissingField {
            line: number,
            field: "role_id",
        })?;
        let epoch = number_field("epoch").ok_or(JournalError::MissingField {
            line: number,
            field: "epoch",
        })?;
        let level = number_field("level").ok_or(JournalError::MissingField {
            line: number,
            field: "level",
        })?;

        if nonce_text == ABSENT {
            // The device refused before it drew a nonce: no ticket, a role it
            // does not define, a throttle. Such a line pairs with nothing, so
            // it is not an entry — but what it *is* has to be asked of the
            // outcome, not assumed from the missing nonce.
            //
            // Assuming was the defect: a line saying `success` with no nonce,
            // or one carrying a word this build does not know, was counted as a
            // refusal and the report called itself complete. The reader accepts
            // that a journal can come from a build whose vocabulary is wider
            // than its own; accepting that for the lines with a nonce and
            // refusing it for the lines beside them is not a position.
            match outcome::classify(&outcome) {
                Outcome::Refusal => {
                    refusals_without_nonce = refusals_without_nonce.saturating_add(1);
                }
                Outcome::Admission | Outcome::Unknown => {
                    unpairable_lines.push(UnpairableLine {
                        device_number: device_number.to_owned(),
                        line: number,
                        outcome,
                    });
                }
            }
            continue;
        }
        let nonce = Nonce::parse(&nonce_text, params).map_err(|_| JournalError::UnusableField {
            line: number,
            field: "nonce_ref",
        })?;

        entries.push(LoginEntry {
            device_number: device_number.to_owned(),
            epoch: u32::try_from(epoch).map_err(|_| JournalError::UnusableField {
                line: number,
                field: "epoch",
            })?,
            nonce,
            role_id,
            level: u32::try_from(level).map_err(|_| JournalError::UnusableField {
                line: number,
                field: "level",
            })?,
            ticket_number: text_field("ticket_no").filter(|ticket| ticket != ABSENT),
            // The device writes the same placeholder here as everywhere else
            // when it has nothing to put in: a refusal can happen before the
            // engineer is asked for a number. Read as "not stated", never as a
            // number somebody could be held to.
            engineer_id: text_field("claimed_engineer_no").filter(|engineer| engineer != ABSENT),
            outcome,
        });
    }

    // A journal of nothing but refusals that never reached a nonce is a journal
    // of a device that spent the period turning people away. It has no entries
    // and it is not empty: refusing to read it fails the whole reconciliation
    // on `?`, and the count this journal carries — the one the report promises
    // to state — never reaches the report at all.
    if entries.is_empty() && refusals_without_nonce == 0 && unpairable_lines.is_empty() {
        return Err(JournalError::NoLoginLines);
    }
    Ok(DeviceJournal {
        entries,
        chain_verified,
        unsigned_from_seq,
        refusals_without_nonce,
        unpairable_lines,
    })
}

/// Reports whether an open line is well formed beyond parsing.
///
/// Both journals keep their payload open — a device writes enrolments and
/// rotations into the same chain the reconciliation reads, and a reader that
/// insisted on knowing every variant would break the day one is added — so
/// "names an operation" is all that can be asked of an ordinary line.
///
/// A head signature is the exception, and the reason is what it does: it closes
/// the unsigned tail, which is the caveat saying lines could have been dropped
/// from the end. An empty one removes the warning and protects nothing. The
/// rule lives with the format, in [`tessera_hashchain::HeadSignature`], so the
/// two journals cannot come to differ about what a signature is.
fn head_signature_is_whole(op: &str, fields: &serde_json::Map<String, serde_json::Value>) -> bool {
    if op.is_empty() {
        return false;
    }
    if op != OP_HEAD_SIGNATURE {
        return true;
    }
    serde_json::from_value::<tessera_hashchain::HeadSignature>(serde_json::Value::Object(
        fields.clone(),
    ))
    .is_ok_and(|signature| signature.is_structurally_valid())
}

/// The chain of the issuing side, as it was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerChain {
    /// The issuances it carries, in the order they were written.
    pub entries: Vec<GrantEntry>,
    /// The `seq` from which no head signature covers the chain, when such a
    /// tail exists.
    pub unsigned_from_seq: Option<u64>,
    /// Lines of the chain this build could not read.
    ///
    /// Lines whose `op` is neither an issuance nor one of the kinds this build
    /// knows the issuing side writes beside them. They are counted rather than
    /// refused, because a chain that also carries issuances IS the journal that
    /// was asked for — but a report built over it has not looked at everything
    /// it names, and saying so is the whole of what this number is for.
    pub unread_lines: usize,
}

/// What a reconciliation could establish about the signature on a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureState {
    /// The issuing side signed it, and the anchor says so.
    Verified,
    /// The anchor says otherwise. A finding, and a loud one.
    Rejected,
    /// No anchor was supplied for the side that issued it.
    ///
    /// Not a finding: an auditor who has no key cannot be told that a signature
    /// is wrong. It is a CAVEAT — the report has not looked at something it
    /// names — and it keeps that report from calling itself complete.
    NotChecked,
    /// Anchors were supplied, and none of them is the side this grant names.
    ///
    /// A finding, and not the same one as [`SignatureState::NotChecked`]. An
    /// auditor who supplied keys HAS said which sides may issue, and a grant
    /// naming another one is a grant from a side this fleet does not know. Left
    /// as a caveat it would be worse than silent: whoever assembled the grant
    /// would choose the diagnosis by inventing a name nobody anchored.
    IssuerUnknown,
}

/// One line of the chain of the issuing side, as much of it as this reader
/// needs.
///
/// Open like [`DeviceLine`] and for the same reason: the issuing side writes
/// its own head signatures and whatever else it keeps into one chain, and a
/// reader that insisted on knowing every variant would break the day one is
/// added.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerLine {
    /// The operation this line records.
    pub op: String,
    /// Everything else the record carries.
    #[serde(flatten)]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

impl ChainPayload for ServerLine {
    const GENESIS_PREIMAGE: &'static [u8] = tessera_hashchain::domain::CODES_ISSUANCE;

    fn kind(&self) -> EntryKind {
        if self.op == OP_HEAD_SIGNATURE {
            EntryKind::HeadSignature
        } else {
            EntryKind::Record
        }
    }

    fn is_structurally_valid(&self) -> bool {
        head_signature_is_whole(&self.op, &self.fields)
    }
}

/// Reads the chain of the issuing side into the issuance side of a
/// reconciliation.
///
/// Unlike a device journal, this one is a hash chain always: the issuing side
/// writes into one by construction, so a file that carries no chain is not a
/// flat export to be read with a caveat — it is not the journal that was asked
/// for. That difference is the reason the two readers do not share a body.
///
/// Nothing is repaired and nothing is skipped. A record that does not parse
/// stops the whole reading, because a chain quietly missing half its issuances
/// reconciles to a clean report, and a clean report is the one answer an
/// auditor must never be handed by accident.
///
/// # Errors
///
/// [`ServerChainError`] naming what stopped the reading: a chain that does not
/// verify, a line that is not JSON, a record that does not parse, or a chain
/// carrying no issuance at all.
pub fn read_server_chain(
    text: &str,
    params: &FleetParams,
    anchors: &IssuingAnchors,
) -> Result<ServerChain, ServerChainError> {
    let lines: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    // A file with nothing in it is an issuance side that recorded nothing, and
    // that is a legitimate audit scenario rather than a broken hand-over: the
    // device journal is then reconciled against an empty set, and every login
    // in it comes out as a login no issuance accounts for — which is the class
    // the whole reconciliation exists for. Refusing here made that class
    // unreachable by any input at all.
    if lines.is_empty() {
        return Ok(ServerChain {
            entries: Vec::new(),
            unsigned_from_seq: None,
            unread_lines: 0,
        });
    }

    // A file with lines and no framing at all is not an edited chain, and
    // saying "broken at position 0" about it would send an auditor looking for
    // a line somebody altered. The issuing side writes a chain by construction,
    // so the only thing this can be is a different file.
    if chain_status(&lines).is_none() {
        return Err(ServerChainError::NotAChain);
    }

    let report = verify_lines::<ServerLine>(&lines);
    let unsigned_from_seq = match report.status {
        ChainStatus::Broken { position } => return Err(ServerChainError::BrokenChain { position }),
        ChainStatus::IntactUnsignedTail { unsigned_from_seq } => Some(unsigned_from_seq),
        // Intact, and whatever a later version of the chain crate adds: neither
        // is a tail this reader has to warn about, and a reader that refused an
        // unknown status would break on the day one is introduced.
        _ => None,
    };

    let mut entries = Vec::new();
    // Lines this build could not read. The number answers two different
    // questions, and answering only the first was the defect: with no issuances
    // at all it decides whether this is a side that has not issued yet or a
    // journal of something else, and WITH issuances it decides whether a report
    // built over the chain may call itself complete. A chain of one issuance
    // and one unknown line used to read as one issuance and a clean report —
    // which claims to have looked at a file it had only partly read.
    let mut unread_lines = 0_usize;
    for (index, line) in lines.iter().enumerate() {
        let number = index + 1;
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|_| ServerChainError::NotJson { line: number })?;
        let op = value.get("op").and_then(serde_json::Value::as_str);
        if op != Some(ISSUANCE_OP) {
            if !op.is_some_and(|op| KNOWN_NON_ISSUANCE_OPS.contains(&op)) {
                unread_lines = unread_lines.saturating_add(1);
            }
            continue;
        }
        let wire = value
            .get(ISSUANCE_RECORD_FIELD)
            .and_then(serde_json::Value::as_str)
            .ok_or(ServerChainError::MissingRecord { line: number })?;
        let record = IssuanceRecord::parse(wire.trim(), params).map_err(|error| {
            ServerChainError::MalformedRecord {
                line: number,
                error,
            }
        })?;
        entries.push(entry_of(&record, number, check_signature(&record, anchors)));
    }

    // No issuances, and the question is why. Every line recognised means an
    // issuing side that has not issued anything yet — a node freshly stood up
    // that has so far only refused, or only signed authorisations — and
    // reconciling against it is legitimate: every login the device recorded
    // comes out as a login no issuance accounts for, which is the class the
    // whole reconciliation exists for. Refusing that would accuse a side that
    // was working correctly of having been substituted.
    //
    // A line this build does not recognise means the other thing: a journal of
    // something else, handed over by mistake. Reading THAT as an empty issuance
    // side would produce a report that found nothing because it looked at
    // nothing, and it would look exactly like the honest case.
    if entries.is_empty() && unread_lines > 0 {
        return Err(ServerChainError::NoIssuances);
    }
    Ok(ServerChain {
        entries,
        unsigned_from_seq,
        unread_lines,
    })
}

/// The keys of the issuing sides a reconciliation was given.
///
/// Empty is the ordinary case and not a failure: an auditor reconciling a
/// journal they were handed may have no key for the side that issued it, and a
/// reconciliation that refused to run without one would be a reconciliation
/// nobody could run. What an empty set costs is stated in the report as a
/// caveat, not swallowed.
#[derive(Debug, Default)]
pub struct IssuingAnchors {
    keys: BTreeMap<String, AnchorKey>,
}

impl IssuingAnchors {
    /// Adds the key of one issuing side, by the identifier it signs under.
    pub fn insert(&mut self, server_id: String, key: AnchorKey) {
        self.keys.insert(server_id, key);
    }

    /// Reports whether any key was supplied at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// A verifier over one issuing side's key.
///
/// Deliberately narrow. The signature of the ENGINEER is not resolved here and
/// must not be: in this release nobody signs a request — the identity provider
/// is a stub by decision, and every record carries the mark that says so — and
/// a verifier that pretended to resolve an engineer would turn an honest "not
/// vouched for" into a verification that passed.
struct IssuingSideOnly<'a> {
    server_id: &'a str,
    key: &'a AnchorKey,
}

impl SignatureVerifier for IssuingSideOnly<'_> {
    fn verify(
        &self,
        signer: SignerRef<'_>,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        match signer {
            SignerRef::Named(name) if name == self.server_id => self.key.verify(message, signature),
            _ => Err(SignatureError::UnknownSigner),
        }
    }
}

/// Checks the signature of the issuing side on one grant.
///
/// Only that one. `Grant::verify` would also demand the engineer's, and in this
/// release there is never one to demand: refusing every honest record is not a
/// stricter check, it is a check that cannot be read.
fn check_signature(record: &IssuanceRecord, anchors: &IssuingAnchors) -> SignatureState {
    let grant = record.grant();
    let Some(key) = anchors.keys.get(grant.server_id()) else {
        // With no anchors at all the caller said nothing about who may issue,
        // and a reader that turned silence into an accusation would report a
        // finding against every honest fleet that audits without keys. With
        // anchors, the caller HAS said it, and this grant names somebody else.
        return if anchors.keys.is_empty() {
            SignatureState::NotChecked
        } else {
            SignatureState::IssuerUnknown
        };
    };
    let verifier = IssuingSideOnly {
        server_id: grant.server_id(),
        key,
    };
    match grant.verify_issuing_side(&verifier) {
        Ok(()) => SignatureState::Verified,
        Err(_) => SignatureState::Rejected,
    }
}

/// Turns one record into the entry a reconciliation pairs on.
///
/// Everything comes out of the signed objects: the device, the epoch, the
/// nonce, the role, the level and the personal number are read out of the
/// challenge inside the request the engineer signed, not out of fields repeated
/// beside it. There is nothing here for a writer to get wrong twice.
fn entry_of(record: &IssuanceRecord, line: usize, signature: SignatureState) -> GrantEntry {
    let request = record.request().request();
    let challenge = request.challenge();
    GrantEntry {
        device_number: challenge.device_number().significant().to_owned(),
        epoch: challenge.epoch().get(),
        nonce: challenge.nonce().clone(),
        role_id: challenge.role_id().to_owned(),
        level: challenge.level().get(),
        ticket_number: record.ticket_number().as_str().to_owned(),
        server_id: record.grant().server_id().to_owned(),
        engineer_id: challenge.engineer_id().to_owned(),
        organisation_id: record.organisation_id().to_owned(),
        requested_at: request.requested_at().get(),
        key_storage: record.key_storage(),
        identity_unverified: record.identity_unverified(),
        signature,
        source: format!("line {line}"),
    }
}

/// Rejection of the chain of the issuing side.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ServerChainError {
    /// The file carries lines, but no chain framing.
    #[error(
        "the file carries lines that are not a hash chain: the issuing side writes one by \
         construction, so this is not the journal that was asked for"
    )]
    NotAChain,
    /// A line of the chain is not JSON.
    #[error("line {line} of the issuance chain is not JSON")]
    NotJson {
        /// Number of the offending line, from one.
        line: usize,
    },
    /// The hash chain does not verify.
    #[error("the issuance chain is broken at position {position}: a line was altered, reordered or removed, and a history that has been edited is not a history")]
    BrokenChain {
        /// Zero-based position of the first invalid line.
        position: u64,
    },
    /// An issuance line carries no record.
    #[error("line {line} of the issuance chain records an issuance without the record itself")]
    MissingRecord {
        /// Number of the offending line, from one.
        line: usize,
    },
    /// The record of an issuance does not parse.
    #[error("the record on line {line} of the issuance chain was rejected: {error}")]
    MalformedRecord {
        /// Number of the offending line, from one.
        line: usize,
        /// What the record parser said.
        error: IssuanceRecordError,
    },
    /// The chain carries no issuance at all.
    #[error("the issuance chain carries no issuance: this is not the journal you meant to hand over, and reading it as an empty one would produce a report that found nothing because it looked at nothing")]
    NoIssuances,
}

/// Reports whether a line records a code login, in either of the two forms.
fn is_login(value: &serde_json::Value) -> bool {
    let field = |name: &str| value.get(name).and_then(serde_json::Value::as_str);
    field("op") == Some(LOGIN_OP) || field("event") == Some(LOGIN_EVENT)
}

/// Verifies the chain of a journal, or reports that it carries none.
///
/// The question is asked of the whole file, not of its first line. A journal
/// that carries framing anywhere is a chain, and it is verified as one: a file
/// where the framing appears halfway through is not a chain with a preamble, it
/// is a file somebody assembled, and the verifier says so at the position where
/// it stops adding up.
///
/// Asking only the first line would price the whole difference between a
/// verified journal and an unverifiable export at one edited line: strip `seq`
/// from the top of a real chain, and everything below it — including the lines
/// that were removed — becomes a flat export nothing can be checked against.
/// Either field alone is enough to make the file answer as a chain, because a
/// chain line with one of them removed is an edited chain line, not a flat one.
fn chain_status(lines: &[String]) -> Option<ChainStatus> {
    let framed = lines.iter().any(|line| {
        serde_json::from_str::<serde_json::Value>(line)
            .is_ok_and(|value| value.get("seq").is_some() || value.get("prev_hash").is_some())
    });
    if !framed {
        return None;
    }
    Some(verify_lines::<DeviceLine>(lines).status)
}

/// Rejection of a device journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JournalError {
    /// A line of the journal is not JSON.
    #[error("line {line} of the device journal is not JSON")]
    NotJson {
        /// Number of the offending line, from one.
        line: usize,
    },
    /// The hash chain of the journal does not verify.
    #[error("the device journal is broken at position {position}: a line was altered, reordered or removed, and a history that has been edited is not a history")]
    BrokenChain {
        /// Zero-based position of the first invalid line.
        position: u64,
    },
    /// The journal carries no code-login line at all.
    #[error("the journal carries no code login at all: an export of the wrong file, or of a form this build does not read, looks exactly like a device that was never used")]
    NoLoginLines,
    /// A code-login line lacks a field the reconciliation pairs on.
    #[error("line {line} of the device journal carries no `{field}`")]
    MissingField {
        /// Number of the offending line, from one.
        line: usize,
        /// Name of the missing field.
        field: &'static str,
    },
    /// A code-login line carries a field the format cannot hold.
    #[error("line {line} of the device journal carries a `{field}` the format cannot hold")]
    UnusableField {
        /// Number of the offending line, from one.
        line: usize,
        /// Name of the offending field.
        field: &'static str,
    },
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{
        read_journal, read_server_chain, reconcile, Expectations, GrantEntry, IssuingAnchors,
        JournalError, KeyStorage, LoginEntry, Provenance, Report, Revocation, RevocationListUsed,
        ServerChainError, ServerLine, SignatureState, SubjectKind, UnpairableLine, Verdict,
    };
    use tessera_codes_contract::nonce::Nonce;
    use tessera_codes_contract::outcome;
    use tessera_codes_contract::params::FleetParams;

    /// Происхождение «цепочка сошлась и покрыта заверением» — то, что не
    /// добавляет к отчёту оговорок.
    fn verified() -> Provenance {
        Provenance {
            chain_verified: true,
            unsigned_from_seq: None,
            server_unsigned_from_seq: None,
            server_unread_lines: 0,
            refusals_without_nonce: 0,
            unpairable_lines: Vec::new(),
        }
    }

    /// A nonce of the default width, distinguished by the digit it repeats.
    ///
    /// The tests care about which entries share a nonce and which do not, and
    /// nothing else about the value.
    fn nonce(mark: u8) -> Nonce {
        let params = FleetParams::defaults();
        let text = char::from(b'0' + mark % 10)
            .to_string()
            .repeat(usize::from(params.nonce_width()));
        Nonce::parse(&text, &params).unwrap()
    }

    fn grant(mark: u8) -> GrantEntry {
        GrantEntry {
            device_number: "77000123".to_owned(),
            epoch: 7,
            nonce: nonce(mark),
            role_id: "ops.dc.senior".to_owned(),
            level: 2,
            ticket_number: "tk-17".to_owned(),
            server_id: "issuer-1".to_owned(),
            engineer_id: "eng-1".to_owned(),
            organisation_id: "acme".to_owned(),
            // A healthy run: the key of the issuing side was supplied and it
            // held. Tests that are ABOUT the signature set this themselves; the
            // rest are about something else and must not be dragged into a
            // caveat by their fixture.
            signature: SignatureState::Verified,
            requested_at: 1_800_000_000,
            key_storage: KeyStorage::Software,
            identity_unverified: true,
            source: format!("grant-{mark}"),
        }
    }

    fn login(mark: u8) -> LoginEntry {
        login_with(mark, outcome::OUTCOME_SUCCESS)
    }

    /// Строка журнала с названным исходом.
    ///
    /// Отказные строки — не экзотика: устройство пишет их на каждую отвергнутую
    /// попытку, и до этой правки ни одна фикстура их не подавала. Именно
    /// поэтому сверка три задачи подряд считала отказ входом, а тесты молчали.
    fn login_with(mark: u8, outcome: &str) -> LoginEntry {
        LoginEntry {
            device_number: "77000123".to_owned(),
            epoch: 7,
            nonce: nonce(mark),
            role_id: "ops.dc.senior".to_owned(),
            level: 2,
            ticket_number: Some("tk-17".to_owned()),
            engineer_id: Some("eng-1".to_owned()),
            outcome: outcome.to_owned(),
        }
    }

    /// Отвергнутая попытка на том же nonce.
    fn refused(mark: u8) -> LoginEntry {
        login_with(mark, outcome::OUTCOME_DENIED)
    }

    /// Инженер ошибся в коде и со второго раза ввёл верный.
    ///
    /// Бюджет попыток на nonce для этого и существует, поэтому две строки на
    /// одном nonce здесь — норма, а не устройство, ответившее на один challenge
    /// дважды. Класс series-on-one-nonce документирован как «прибор не тот, за
    /// который себя выдаёт», и опечатка на клавиатуре не должна его поднимать.
    #[test]
    fn a_mistyped_code_is_not_a_series_on_one_nonce() {
        let report = reconcile(
            &[grant(1)],
            Some(&[refused(1), login(1)]),
            &verified(),
            &Expectations::default(),
        );
        assert!(
            report.verdict() != Verdict::Findings,
            "штатная опечатка подняла находку: {report}"
        );
        assert!(report.series_on_one_nonce.is_empty());
        assert_eq!(report.refusals_read(), 1);
        assert!(report.to_string().contains("refusals-read count=1"));
    }

    /// Отказ без квитанции — не выдача без квитанции.
    ///
    /// Кто угодно у консоли набирает имя ролевой учётной записи и произвольный
    /// код: кода ему не выдали, но отказная строка запишется. Считая её входом,
    /// сверка позволяла бы прохожему сгенерировать сколько угодно находок
    /// класса «код выдан мимо книг» и утопить в них настоящую.
    #[test]
    fn refusals_do_not_become_logins_without_a_grant() {
        let report = reconcile(
            &[],
            Some(&[refused(1), refused(2)]),
            &verified(),
            &Expectations::default(),
        );
        assert!(
            report.logins_without_grant.is_empty(),
            "отказ прочитан как вход: {report}"
        );
        assert_ne!(report.verdict(), Verdict::Findings);
        assert_eq!(report.refusals_read(), 2);
    }

    /// Исчерпанный бюджет попыток — тоже отказ.
    #[test]
    fn an_exhausted_budget_is_not_an_admission() {
        let report = reconcile(
            &[],
            Some(&[login_with(1, outcome::OUTCOME_ATTEMPTS_EXHAUSTED)]),
            &verified(),
            &Expectations::default(),
        );
        assert!(report.logins_without_grant.is_empty());
        assert_eq!(report.refusals_read(), 1);
    }

    /// Строки отчёта читает человек, и лишних пробелов в них нет.
    ///
    /// Проверка дешёвая и неочевидно нужная: `rustfmt` содержимое строковых
    /// литералов не трогает, поэтому перенос строки в исходнике, сделанный без
    /// экранирования, уезжает в вывод прогоном пробелов посреди фразы и не
    /// ловится ничем. Ожидания кейсов цепляются за префикс и тоже молчат.
    /// Каждое утверждение, которое отчёт умеет сделать, порождается фикстурами.
    ///
    /// Полнота держится компилятором, а не глазом рецензента. `match` в
    /// `mark` исчерпывающий, поэтому новый вариант `Statement` не соберётся,
    /// пока о нём здесь не сказано; `Seen` разбирается без `..`, поэтому
    /// добавленное поле обязано попасть в проверку. Прежний сторож перечислял
    /// префиксы руками и на одной ветке из десяти молчал.
    #[derive(Default)]
    #[expect(
        clippy::struct_excessive_bools,
        reason = "это по одному флагу на вариант Statement, а не состояние: \
                  свести их в множество значило бы вернуть список, набранный руками"
    )]
    struct Seen {
        no_device_side: bool,
        unreadable_outcomes: bool,
        unreadable_line: bool,
        admission_without_nonce: bool,
        no_chain: bool,
        unsigned_tail: bool,
        server_unsigned_tail: bool,
        unread_server_lines: bool,
        signatures_not_checked: bool,
        grant_signature_rejected: bool,
        grant_issuer_unknown: bool,
        revocation_waterline_unset: bool,
        revocations_read: bool,
        unsigned_revocations: bool,
        login_without_grant: bool,
        grant_without_login: bool,
        series_on_one_nonce: bool,
        disagreement: bool,
        custody_below_declared: bool,
        grant_after_revocation: bool,
        refusals_read: bool,
    }

    impl Seen {
        fn mark(&mut self, statement: &super::Statement<'_>) {
            use super::Statement as S;
            match statement {
                S::NoDeviceSide => self.no_device_side = true,
                S::UnreadableOutcomes(_) => self.unreadable_outcomes = true,
                S::UnreadableLine(_) => self.unreadable_line = true,
                S::AdmissionWithoutNonce(_) => self.admission_without_nonce = true,
                S::NoChain => self.no_chain = true,
                S::UnsignedTail(_) => self.unsigned_tail = true,
                S::ServerUnsignedTail(_) => self.server_unsigned_tail = true,
                S::UnreadServerLines(_) => self.unread_server_lines = true,
                S::SignaturesNotChecked(_) => self.signatures_not_checked = true,
                S::RevocationWaterlineUnset(_) => self.revocation_waterline_unset = true,
                S::RevocationListRead(_) => self.revocations_read = true,
                S::GrantSignatureRejected(_) => self.grant_signature_rejected = true,
                S::GrantIssuerUnknown(_) => self.grant_issuer_unknown = true,
                S::UnsignedRevocations(_) => self.unsigned_revocations = true,
                S::LoginWithoutGrant(_) => self.login_without_grant = true,
                S::GrantWithoutLogin(_) => self.grant_without_login = true,
                S::SeriesOnOneNonce(_) => self.series_on_one_nonce = true,
                S::Disagreement(_) => self.disagreement = true,
                S::CustodyBelowDeclared(_) => self.custody_below_declared = true,
                S::GrantAfterRevocation(_) => self.grant_after_revocation = true,
                S::RefusalsRead(_) => self.refusals_read = true,
            }
        }
    }

    /// Каждое утверждение по одному, без соседей.
    ///
    /// Сетка, которая ловит НЕВЕРНУЮ классификацию, а не только пропущенную:
    /// в отчёте ровно одно утверждение, поэтому вердикт целиком определяется
    /// его видом. Оговорка, объявленная заметкой, перестаёт делать отчёт
    /// неполным — и здесь это роняет тест, а не остаётся на прочтение
    /// рецензентом. До этой сетки переворот `UnsignedTail` в заметку проходил
    /// всю сюиту зелёным.
    #[expect(
        clippy::too_many_lines,
        reason = "one fixture per statement, and the guard below demands they all be here"
    )]
    fn every_statement_alone() -> Vec<(&'static str, Report, Verdict)> {
        let mut odd = login(1);
        odd.role_id = "ops.dc.junior".to_owned();

        let with = |chain_verified: bool,
                    unsigned_from_seq: Option<u64>,
                    refusals_without_nonce: u64,
                    unpairable_lines: Vec<UnpairableLine>| Provenance {
            chain_verified,
            unsigned_from_seq,
            server_unsigned_from_seq: None,
            server_unread_lines: 0,
            refusals_without_nonce,
            unpairable_lines,
        };
        let line = |outcome: &str| UnpairableLine {
            device_number: "77000123".to_owned(),
            line: 3,
            outcome: outcome.to_owned(),
        };

        vec![
            (
                "no-device-side",
                reconcile(&[], None, &Provenance::absent(), &Expectations::default()),
                Verdict::Incomplete,
            ),
            (
                "unreadable-outcomes",
                reconcile(
                    &[],
                    Some(&[login_with(1, "granted")]),
                    &verified(),
                    &Expectations::default(),
                ),
                Verdict::Incomplete,
            ),
            (
                "unreadable-line",
                reconcile(
                    &[],
                    Some(&[]),
                    &with(true, None, 0, vec![line("granted")]),
                    &Expectations::default(),
                ),
                Verdict::Incomplete,
            ),
            (
                "admission-without-nonce",
                reconcile(
                    &[],
                    Some(&[]),
                    &with(true, None, 0, vec![line(outcome::OUTCOME_SUCCESS)]),
                    &Expectations::default(),
                ),
                Verdict::Findings,
            ),
            (
                "no-chain",
                reconcile(
                    &[],
                    Some(&[]),
                    &with(false, None, 0, Vec::new()),
                    &Expectations::default(),
                ),
                Verdict::Incomplete,
            ),
            (
                "unsigned-tail",
                reconcile(
                    &[],
                    Some(&[]),
                    &with(true, Some(7), 0, Vec::new()),
                    &Expectations::default(),
                ),
                Verdict::Incomplete,
            ),
            (
                "login-without-grant",
                reconcile(
                    &[],
                    Some(&[login(1)]),
                    &verified(),
                    &Expectations::default(),
                ),
                Verdict::Findings,
            ),
            (
                "grant-without-login",
                reconcile(
                    &[grant(1)],
                    Some(&[]),
                    &verified(),
                    &Expectations::default(),
                ),
                Verdict::Findings,
            ),
            (
                "series-on-one-nonce",
                reconcile(
                    &[grant(1)],
                    Some(&[login(1), login(1)]),
                    &verified(),
                    &Expectations::default(),
                ),
                Verdict::Findings,
            ),
            (
                "disagreement",
                reconcile(
                    &[grant(1)],
                    Some(&[odd]),
                    &verified(),
                    &Expectations::default(),
                ),
                Verdict::Findings,
            ),
            (
                // Withdrawals taken from a caller rather than from a signed
                // list: the report says so, because an unsigned withdrawal is
                // one anybody on the path can replace with none at all.
                "unsigned-revocations",
                reconcile(
                    &[],
                    Some(&[]),
                    &verified(),
                    &Expectations {
                        declared_key_storage: None,
                        revocations: Vec::new(),
                        unsigned_revocations: 1,
                        revocation_list: None,
                    },
                ),
                Verdict::Incomplete,
            ),
            (
                "server-unsigned-tail",
                reconcile(
                    &[],
                    Some(&[]),
                    &Provenance {
                        server_unsigned_from_seq: Some(3),
                        server_unread_lines: 0,
                        ..verified()
                    },
                    &Expectations::default(),
                ),
                Verdict::Incomplete,
            ),
            (
                // Список отзыва взят без ватерлинии: приняли бы список любого
                // возраста. Оговорка, и рядом заметка о том, какой список
                // применён — иначе читатель знает отзывы и не знает, откуда.
                "revocation-waterline-unset",
                reconcile(
                    &[],
                    Some(&[]),
                    &verified(),
                    &Expectations {
                        declared_key_storage: None,
                        revocations: Vec::new(),
                        unsigned_revocations: 0,
                        revocation_list: Some(RevocationListUsed {
                            serial: 7,
                            waterline: None,
                        }),
                    },
                ),
                Verdict::Incomplete,
            ),
            (
                // Ватерлиния названа: остаётся только заметка, вердикт чистый.
                "revocations-read",
                reconcile(
                    &[],
                    Some(&[]),
                    &verified(),
                    &Expectations {
                        declared_key_storage: None,
                        revocations: Vec::new(),
                        unsigned_revocations: 0,
                        revocation_list: Some(RevocationListUsed {
                            serial: 7,
                            waterline: Some(6),
                        }),
                    },
                ),
                Verdict::Clean,
            ),
            (
                // Ключа выдающей стороны никто не дал: подписи прочитаны из
                // файла и больше ниоткуда. Не находка — аудитору без ключа
                // нельзя сказать, что подпись неверна, — а оговорка.
                "signatures-not-checked",
                reconcile(
                    &[GrantEntry {
                        signature: SignatureState::NotChecked,
                        ..grant(1)
                    }],
                    Some(&[login(1)]),
                    &verified(),
                    &Expectations::default(),
                ),
                Verdict::Incomplete,
            ),
            (
                // Ключ выдающей стороны за грант не ручается: значит написала
                // его не та сторона. Находка, и громкая.
                "grant-signature-rejected",
                reconcile(
                    &[GrantEntry {
                        signature: SignatureState::Rejected,
                        ..grant(1)
                    }],
                    Some(&[login(1)]),
                    &verified(),
                    &Expectations::default(),
                ),
                Verdict::Findings,
            ),
            (
                // Ключи выдающих сторон поданы, а грант называет НЕ ИХ.
                // Отдельный класс, а не оговорка: оговорка означала бы, что
                // диагноз выбирает тот, кто собрал грант.
                "grant-issuer-unknown",
                reconcile(
                    &[GrantEntry {
                        signature: SignatureState::IssuerUnknown,
                        ..grant(1)
                    }],
                    Some(&[login(1)]),
                    &verified(),
                    &Expectations::default(),
                ),
                Verdict::Findings,
            ),
            (
                // Строки, которые читатель не смог прочесть: отчёт над такой
                // цепочкой не полон, что бы он ни нашёл.
                "unread-server-lines",
                reconcile(
                    &[],
                    Some(&[]),
                    &Provenance {
                        server_unread_lines: 2,
                        ..verified()
                    },
                    &Expectations::default(),
                ),
                Verdict::Incomplete,
            ),
            (
                // Ступень ниже объявленной: пара сошлась, и единственное, что
                // отчёт говорит, — про кастодию.
                "custody-below-declared",
                reconcile(
                    &[grant(1)],
                    Some(&[login(1)]),
                    &verified(),
                    &Expectations {
                        declared_key_storage: Some(KeyStorage::Token),
                        revocations: Vec::new(),
                        unsigned_revocations: 0,
                        revocation_list: None,
                    },
                ),
                Verdict::Findings,
            ),
            (
                // Выдача датирована позже отзыва того самого инженера.
                "grant-after-revocation",
                reconcile(
                    &[grant(1)],
                    Some(&[login(1)]),
                    &verified(),
                    &Expectations {
                        declared_key_storage: None,
                        revocations: vec![Revocation {
                            kind: SubjectKind::Engineer,
                            subject: "eng-1".to_owned(),
                            at: 1_799_999_999,
                        }],
                        unsigned_revocations: 0,
                        revocation_list: None,
                    },
                ),
                Verdict::Findings,
            ),
            (
                "refusals-read",
                reconcile(
                    &[grant(1)],
                    Some(&[refused(1), login(1)]),
                    &verified(),
                    &Expectations::default(),
                ),
                Verdict::Clean,
            ),
        ]
    }

    /// Настоящая цепочка выдач того же вида, какой её пишет служба.
    ///
    /// Собирается тем же `tessera_hashchain`, которым её соберёт codes-core:
    /// строки, набранные руками, доказали бы только то, что читатель понимает
    /// собственную выдумку.
    fn server_chain_lines(records: usize) -> Vec<String> {
        use crate::codes::scope::SiteScope;
        use crate::codes::tests::fixtures;
        use crate::codes::{IssuanceRecord, IssuanceRecordFields};
        use tessera_codes_contract::grant::UnsignedGrant;
        use tessera_codes_contract::signature::Signature;
        use tessera_codes_contract::ticket::TicketNumber;
        use tessera_hashchain::storage::MemoryStorage;
        use tessera_hashchain::Chain;

        let world = fixtures::world();
        let mut chain: Chain<MemoryStorage, ServerLine> =
            Chain::load(MemoryStorage::new()).unwrap();
        for index in 0..records {
            let grant = UnsignedGrant::new(fixtures::signed_request(&world), "op-42")
                .unwrap()
                .sign(Signature::new(vec![0x11, 0x22]).unwrap(), None)
                .unwrap();
            let record = IssuanceRecord::new(IssuanceRecordFields {
                grant,
                ticket_number: TicketNumber::parse("tk-17").unwrap(),
                organisation_id: "acme".to_owned(),
                key_storage: KeyStorage::Software,
                site_scope: SiteScope::Checked,
                // The fixture request is signed, so the mark is clear: the two
                // have to agree, and the type refuses a record where they do
                // not.
                identity_unverified: false,
            })
            .unwrap();
            let line: ServerLine = serde_json::from_value(serde_json::json!({
                "op": super::ISSUANCE_OP,
                super::ISSUANCE_RECORD_FIELD: record.to_wire(),
            }))
            .unwrap();
            chain.append(&line, 1_800_000_000 + index as u64).unwrap();
        }
        chain.storage().lines()
    }

    #[test]
    fn a_chain_of_issuances_reads_back_into_entries() {
        let chain = read_server_chain(
            &server_chain_lines(2).join("\n"),
            &FleetParams::defaults(),
            &IssuingAnchors::default(),
        )
        .unwrap();
        assert_eq!(chain.entries.len(), 2);
        // Всё берётся из подписанных объектов, а не из полей рядом с ними.
        let first = chain.entries.first().unwrap();
        assert_eq!(first.engineer_id, "eng-1");
        assert_eq!(first.organisation_id, "acme");
        assert_eq!(first.key_storage, KeyStorage::Software);
        // Хвост цепочки не заверен: заверителя на стенде нет, и отчёт обязан
        // сказать об этом, а не промолчать.
        assert_eq!(chain.unsigned_from_seq, Some(0));
    }

    #[test]
    fn a_chain_of_another_journal_is_not_read_as_this_one() {
        // Domain separation, checked rather than assumed. The two journals of a
        // reconciliation are read side by side, and a line carried over from
        // one into the other must fail at its position instead of blending in.
        // Both fixtures used to build their chains under one anchor and never
        // compared them, so replacing the anchor of this reader with the
        // device's left all forty-five tests green.
        use tessera_hashchain::storage::MemoryStorage;
        use tessera_hashchain::Chain;

        // The payload alone, without the framing of the chain it came from:
        // re-chaining a line together with its old `seq` and `prev_hash` would
        // break for that reason instead, and the test would pass while saying
        // nothing about the anchors.
        let source: serde_json::Value =
            serde_json::from_str(server_chain_lines(1).first().unwrap()).unwrap();
        let payload: super::DeviceLine = serde_json::from_value(serde_json::json!({
            "op": source.get("op").unwrap(),
            super::ISSUANCE_RECORD_FIELD: source.get(super::ISSUANCE_RECORD_FIELD).unwrap(),
        }))
        .unwrap();
        // The same record, re-chained under the anchor of a device journal.
        let mut foreign: Chain<MemoryStorage, super::DeviceLine> =
            Chain::load(MemoryStorage::new()).unwrap();
        foreign.append(&payload, 1_800_000_000).unwrap();

        assert_eq!(
            read_server_chain(
                &foreign.storage().lines().join("\n"),
                &FleetParams::defaults(),
                &IssuingAnchors::default(),
            ),
            Err(ServerChainError::BrokenChain { position: 0 })
        );
    }

    #[test]
    fn an_empty_head_signature_does_not_close_the_unsigned_tail() {
        // A line that says `head_signature` and carries neither an algorithm
        // nor a signature would sign nothing and still take away the caveat
        // that says lines could have been dropped from the end — removing the
        // warning and adding no protection.
        use tessera_hashchain::storage::MemoryStorage;
        use tessera_hashchain::Chain;

        // Сцепление у строки ПРАВИЛЬНОЕ — её добавляет сама цепочка. Если бы
        // тест подсовывал строку с выдуманным prev_hash, он краснел бы по
        // сломанному хешу и о проверке заверения не говорил бы ничего.
        let mut chain: Chain<MemoryStorage, ServerLine> =
            Chain::load(MemoryStorage::new()).unwrap();
        let record: ServerLine = serde_json::from_str(server_chain_lines(1).first().unwrap())
            .map(|line: serde_json::Value| {
                serde_json::from_value(serde_json::json!({
                    "op": line.get("op").unwrap(),
                    super::ISSUANCE_RECORD_FIELD: line
                        .get(super::ISSUANCE_RECORD_FIELD)
                        .unwrap(),
                }))
                .unwrap()
            })
            .unwrap();
        chain.append(&record, 1_800_000_000).unwrap();
        let hollow: ServerLine = serde_json::from_value(serde_json::json!({
            "op": tessera_hashchain::OP_HEAD_SIGNATURE,
            "algorithm": "",
            "signature": "",
        }))
        .unwrap();
        chain.append(&hollow, 1_800_000_001).unwrap();

        assert!(
            matches!(
                read_server_chain(
                    &chain.storage().lines().join("\n"),
                    &FleetParams::defaults(),
                    &IssuingAnchors::default(),
                ),
                Err(ServerChainError::BrokenChain { .. })
            ),
            "a head signature with nothing in it closed the unsigned tail"
        );
    }

    #[test]
    fn an_issuance_removed_from_the_middle_breaks_the_chain() {
        // Ровно то, ради чего цепочка и заводилась: строку из середины нельзя
        // уронить, не сломав сцепление. Хвост — другой разговор, и его ведёт
        // оговорка о незаверённом хвосте.
        let mut lines = server_chain_lines(3);
        lines.remove(1);
        assert_eq!(
            read_server_chain(
                &lines.join("\n"),
                &FleetParams::defaults(),
                &IssuingAnchors::default(),
            ),
            Err(ServerChainError::BrokenChain { position: 1 })
        );
    }

    #[test]
    fn a_record_that_lost_its_custody_tier_stops_the_reading() {
        // Не «читается с умолчанием»: ступень — это то, что говорит, чем
        // считался код, и запись без неё не отвечает на вопрос, ради которого
        // её пишут. Правка ломает и цепочку — сначала о ней и сообщается, —
        // поэтому запись портится в файле БЕЗ цепочки, где виден именно разбор.
        let record = server_chain_lines(1)
            .first()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .unwrap()
                    .get(super::ISSUANCE_RECORD_FIELD)
                    .and_then(serde_json::Value::as_str)
                    .unwrap()
                    .to_owned()
            })
            .unwrap();
        let stripped = record.replace(";key_storage=software", "");
        let line = serde_json::json!({
            "seq": 0,
            "op": super::ISSUANCE_OP,
            super::ISSUANCE_RECORD_FIELD: stripped,
        })
        .to_string();
        assert!(matches!(
            read_server_chain(&line, &FleetParams::defaults(), &IssuingAnchors::default(),),
            Err(ServerChainError::BrokenChain { .. } | ServerChainError::MalformedRecord { .. })
        ));
    }

    #[test]
    fn a_file_without_chain_framing_is_named_as_such_and_not_as_a_broken_chain() {
        // Разные находки и разные действия. «Цепочка сломана на позиции N» шлёт
        // аудитора искать подменённую строку; «это не цепочка» говорит, что
        // передан не тот файл. Выдающая сторона пишет цепочку по построению,
        // поэтому файл вообще без обрамления — второе.
        let flat = serde_json::json!({ "op": super::ISSUANCE_OP }).to_string();
        assert!(
            matches!(
                read_server_chain(&flat, &FleetParams::defaults(), &IssuingAnchors::default()),
                Err(ServerChainError::NotAChain)
            ),
            "плоский экспорт прочитан не как «не цепочка»"
        );
    }

    #[test]
    fn an_empty_file_is_an_issuance_side_that_recorded_nothing() {
        // Not a refusal. This is the audit scenario the first class of the
        // report exists for: a device journal full of logins beside an issuance
        // side that has none of them. Refusing here made that class unreachable
        // by any input at all — the case that named it could never have passed.
        let chain =
            read_server_chain("", &FleetParams::defaults(), &IssuingAnchors::default()).unwrap();
        assert!(chain.entries.is_empty());
        assert_eq!(chain.unsigned_from_seq, None);

        let report = reconcile(
            &chain.entries,
            Some(&[login(1)]),
            &verified(),
            &Expectations::default(),
        );
        assert_eq!(report.logins_without_grant.len(), 1, "{report}");
    }

    /// Цепочка выдач с приписанной строкой, чей `op` этой сборке неизвестен.
    fn chain_with_an_unknown_line() -> Vec<String> {
        use crate::codes::scope::SiteScope;
        use crate::codes::tests::fixtures;
        use crate::codes::{IssuanceRecord, IssuanceRecordFields};
        use tessera_codes_contract::grant::UnsignedGrant;
        use tessera_codes_contract::signature::Signature;
        use tessera_codes_contract::ticket::TicketNumber;
        use tessera_hashchain::storage::MemoryStorage;
        use tessera_hashchain::Chain;

        let world = fixtures::world();
        let mut chain: Chain<MemoryStorage, ServerLine> =
            Chain::load(MemoryStorage::new()).unwrap();

        let grant = UnsignedGrant::new(fixtures::signed_request(&world), "op-42")
            .unwrap()
            .sign(Signature::new(vec![0x11, 0x22]).unwrap(), None)
            .unwrap();
        let record = IssuanceRecord::new(IssuanceRecordFields {
            grant,
            ticket_number: TicketNumber::parse("tk-17").unwrap(),
            organisation_id: "acme".to_owned(),
            key_storage: KeyStorage::Software,
            site_scope: SiteScope::Checked,
            identity_unverified: false,
        })
        .unwrap();
        let issuance: ServerLine = serde_json::from_value(serde_json::json!({
            "op": super::ISSUANCE_OP,
            super::ISSUANCE_RECORD_FIELD: record.to_wire(),
        }))
        .unwrap();
        chain.append(&issuance, 1_800_000_000).unwrap();

        let unknown: ServerLine = serde_json::from_value(serde_json::json!({
            "op": "codes.something-a-later-build-invented",
            "note": "a line this build cannot read",
        }))
        .unwrap();
        chain.append(&unknown, 1_800_000_001).unwrap();
        chain.storage().lines()
    }

    /// Подпись выдающей стороны проверяется НАСТОЯЩИМ ключом.
    ///
    /// До этой правки сверка не звала `verify` ни разу: подписи брались на
    /// слово файла, и грант, собранный кем угодно, читался ровно как
    /// подписанный выдающей стороной. Здесь чинится именно это, и проверяется
    /// на цепочке, собранной крейтом цепочки, с подписью, поставленной ключом.
    #[test]
    fn a_grant_the_issuing_key_does_not_stand_behind_is_a_finding() {
        use crate::codes::trust::AnchorKey;
        use p256::ecdsa::signature::hazmat::PrehashSigner as _;
        use p256::pkcs8::EncodePublicKey as _;
        use sha2::{Digest as _, Sha256};
        use tessera_codes_contract::grant::UnsignedGrant;
        use tessera_codes_contract::signature::Signature;
        use tessera_codes_contract::ticket::TicketNumber;
        use tessera_hashchain::storage::MemoryStorage;
        use tessera_hashchain::Chain;

        use crate::codes::scope::SiteScope;
        use crate::codes::tests::fixtures;
        use crate::codes::{IssuanceRecord, IssuanceRecordFields};

        let world = fixtures::world();
        let secret = p256::SecretKey::from_slice(&[0x5a; 32]).unwrap();
        let signing = p256::ecdsa::SigningKey::from(&secret);
        let anchor_der = secret
            .public_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();

        // Собран так, как его собирает выдающая сторона: сначала неподписанный
        // грант, потом подпись НАД ЕГО каноническими байтами.
        let unsigned =
            UnsignedGrant::new(fixtures::signed_request(&world), "codes-core-1").unwrap();
        let message = unsigned.signing_message().unwrap();
        let der: p256::ecdsa::Signature = signing.sign_prehash(&Sha256::digest(&message)).unwrap();
        let honest = unsigned
            .clone()
            .sign(
                Signature::new(der.to_der().as_bytes().to_vec()).unwrap(),
                None,
            )
            .unwrap();
        let forged = unsigned
            .sign(Signature::new(vec![0x11, 0x22, 0x33]).unwrap(), None)
            .unwrap();

        let chain_of = |grant: tessera_codes_contract::grant::Grant| {
            let record = IssuanceRecord::new(IssuanceRecordFields {
                grant,
                ticket_number: TicketNumber::parse("tk-17").unwrap(),
                organisation_id: "acme".to_owned(),
                key_storage: KeyStorage::Software,
                site_scope: SiteScope::Checked,
                identity_unverified: false,
            })
            .unwrap();
            let mut chain: Chain<MemoryStorage, ServerLine> =
                Chain::load(MemoryStorage::new()).unwrap();
            let line: ServerLine = serde_json::from_value(serde_json::json!({
                "op": super::ISSUANCE_OP,
                super::ISSUANCE_RECORD_FIELD: record.to_wire(),
            }))
            .unwrap();
            chain.append(&line, 1_800_000_000).unwrap();
            chain.storage().lines().join("\n")
        };

        let mut anchors = IssuingAnchors::default();
        anchors.insert(
            "codes-core-1".to_owned(),
            AnchorKey::from_spki_der(&anchor_der).unwrap(),
        );

        let good =
            read_server_chain(&chain_of(honest), &FleetParams::defaults(), &anchors).unwrap();
        assert_eq!(
            good.entries.first().unwrap().signature,
            SignatureState::Verified,
            "a grant the key does stand behind was not accepted"
        );

        let bad = read_server_chain(&chain_of(forged), &FleetParams::defaults(), &anchors).unwrap();
        assert_eq!(
            bad.entries.first().unwrap().signature,
            SignatureState::Rejected,
            "a forged grant passed as signed"
        );
        let report = reconcile(
            &bad.entries,
            Some(&[]),
            &verified(),
            &Expectations::default(),
        );
        assert_eq!(report.verdict(), Verdict::Findings, "{report}");
        assert!(
            report.to_string().contains("grant-signature-rejected"),
            "{report}"
        );
    }

    /// Неизвестная выдающая сторона — находка, а не оговорка.
    ///
    /// Пока чужая сторона давала «подписи не проверены», диагноз выбирал тот,
    /// кто собрал грант: достаточно было назваться именем, которого никто не
    /// якорил, и находка превращалась в оговорку. Обратная половина тоже
    /// проверяется здесь: БЕЗ единого якоря это по-прежнему оговорка — аудитору,
    /// у которого ключей нет, нельзя сообщать, что подпись неверна.
    #[test]
    fn a_grant_from_a_side_nobody_anchored_is_a_finding_of_its_own() {
        use crate::codes::trust::AnchorKey;
        use p256::ecdsa::signature::hazmat::PrehashSigner as _;
        use p256::pkcs8::EncodePublicKey as _;
        use sha2::{Digest as _, Sha256};
        use tessera_codes_contract::grant::UnsignedGrant;
        use tessera_codes_contract::signature::Signature;
        use tessera_codes_contract::ticket::TicketNumber;
        use tessera_hashchain::storage::MemoryStorage;
        use tessera_hashchain::Chain;

        use crate::codes::scope::SiteScope;
        use crate::codes::tests::fixtures;
        use crate::codes::{IssuanceRecord, IssuanceRecordFields};

        let world = fixtures::world();
        let secret = p256::SecretKey::from_slice(&[0x5a; 32]).unwrap();
        let signing = p256::ecdsa::SigningKey::from(&secret);
        let anchor_der = secret
            .public_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();

        let sign_honestly = || {
            let unsigned =
                UnsignedGrant::new(fixtures::signed_request(&world), "codes-core-1").unwrap();
            let message = unsigned.signing_message().unwrap();
            let der: p256::ecdsa::Signature =
                signing.sign_prehash(&Sha256::digest(&message)).unwrap();
            unsigned
                .sign(
                    Signature::new(der.to_der().as_bytes().to_vec()).unwrap(),
                    None,
                )
                .unwrap()
        };

        let chain_of = |grant: tessera_codes_contract::grant::Grant| {
            let record = IssuanceRecord::new(IssuanceRecordFields {
                grant,
                ticket_number: TicketNumber::parse("tk-17").unwrap(),
                organisation_id: "acme".to_owned(),
                key_storage: KeyStorage::Software,
                site_scope: SiteScope::Checked,
                identity_unverified: false,
            })
            .unwrap();
            let mut chain: Chain<MemoryStorage, ServerLine> =
                Chain::load(MemoryStorage::new()).unwrap();
            let line: ServerLine = serde_json::from_value(serde_json::json!({
                "op": super::ISSUANCE_OP,
                super::ISSUANCE_RECORD_FIELD: record.to_wire(),
            }))
            .unwrap();
            chain.append(&line, 1_800_000_000).unwrap();
            chain.storage().lines().join("\n")
        };

        // Якорь есть, но он про ДРУГУЮ сторону.
        let mut elsewhere = IssuingAnchors::default();
        elsewhere.insert(
            "codes-core-2".to_owned(),
            AnchorKey::from_spki_der(&anchor_der).unwrap(),
        );
        let stranger = read_server_chain(
            &chain_of(sign_honestly()),
            &FleetParams::defaults(),
            &elsewhere,
        )
        .unwrap();
        assert_eq!(
            stranger.entries.first().unwrap().signature,
            SignatureState::IssuerUnknown,
            "неизвестная выдающая сторона прошла как непроверенная подпись"
        );
        let report = reconcile(
            &stranger.entries,
            Some(&[]),
            &verified(),
            &Expectations::default(),
        );
        assert_eq!(report.verdict(), Verdict::Findings, "{report}");
        let printed = report.to_string();
        assert!(printed.contains("grant-issuer-unknown"), "{printed}");
        // Названа именно та сторона, которую написал грант: отчёт «какая-то
        // сторона, которую вы не якорили» отправил бы аудитора обратно в файл.
        assert!(printed.contains("server=codes-core-1"), "{printed}");

        // А без единого якоря это по-прежнему оговорка: аудитору, у которого
        // ключей нет, нельзя сообщать, что подпись неверна.
        let unanchored = read_server_chain(
            &chain_of(sign_honestly()),
            &FleetParams::defaults(),
            &IssuingAnchors::default(),
        )
        .unwrap();
        assert_eq!(
            unanchored.entries.first().unwrap().signature,
            SignatureState::NotChecked
        );
        let report = reconcile(
            &unanchored.entries,
            Some(&[]),
            &verified(),
            &Expectations::default(),
        );
        assert!(
            report.to_string().contains("signatures-not-checked"),
            "{report}"
        );
    }

    /// Непрочитанная строка цепочки не пропадает молча.
    ///
    /// Прежняя проверка смотрела на неизвестные `op` ТОЛЬКО когда выдач не
    /// нашлось вовсе. Цепочка с одной выдачей и приписанной строкой читалась
    /// как одна выдача и полный отчёт — то есть отчёт утверждал, что посмотрел
    /// на всё, не прочитав часть файла. Это хуже отказа: отказ разбирают, а
    /// «находок нет» закрывает вопрос.
    #[test]
    fn a_line_the_reader_could_not_read_keeps_the_report_from_calling_itself_complete() {
        let chain = read_server_chain(
            &chain_with_an_unknown_line().join("\n"),
            &FleetParams::defaults(),
            &IssuingAnchors::default(),
        )
        .unwrap_or_else(|error| {
            unreachable!("a chain that carries issuances was refused: {error}")
        });
        assert_eq!(chain.entries.len(), 1, "the issuance is still read");
        assert_eq!(
            chain.unread_lines, 1,
            "the line this build cannot read was not counted"
        );

        let report = reconcile(
            &chain.entries,
            Some(&[login(1)]),
            &Provenance {
                server_unread_lines: chain.unread_lines,
                ..verified()
            },
            &Expectations::default(),
        );
        assert!(
            !report.is_complete(),
            "a report that skipped a line called itself complete: {report}"
        );
        assert!(
            report.to_string().contains("unread-server-lines"),
            "the report does not say which lines it could not read: {report}"
        );
    }

    #[test]
    fn a_chain_of_something_else_is_refused_rather_than_read_as_empty() {
        // Lines, but not one of them an issuance. Reading this as an empty
        // issuance side would produce a report that found nothing because it
        // looked at nothing — and it would look exactly like the honest empty
        // case above, which is why the two carry different classes.
        use tessera_hashchain::storage::MemoryStorage;
        use tessera_hashchain::Chain;

        let mut chain: Chain<MemoryStorage, ServerLine> =
            Chain::load(MemoryStorage::new()).unwrap();
        let other: ServerLine = serde_json::from_value(serde_json::json!({
            "op": "codes.something-else",
            "note": "a line of another journal",
        }))
        .unwrap();
        chain.append(&other, 1_800_000_000).unwrap();

        assert_eq!(
            read_server_chain(
                &chain.storage().lines().join("\n"),
                &FleetParams::defaults(),
                &IssuingAnchors::default(),
            ),
            Err(ServerChainError::NoIssuances)
        );
    }

    /// Свежая сторона выдачи, которая пока только отказывала, — не подмена.
    ///
    /// codes-core пишет в ту же цепочку отказы и авторизации. Узел, который
    /// ещё ни разу не выдал код, отдаёт файл со строками и без единой выдачи —
    /// и до этой правки сверка отвечала «это не тот журнал», то есть обвиняла
    /// в подмене сторону, работавшую правильно. Различие важное: «журнал
    /// подменили» требует разбирательства, «выдач ещё не было» не требует
    /// ничего.
    #[test]
    fn a_chain_of_known_lines_without_a_single_issuance_is_an_empty_issuance_side() {
        use tessera_hashchain::storage::MemoryStorage;
        use tessera_hashchain::Chain;

        let mut chain: Chain<MemoryStorage, ServerLine> =
            Chain::load(MemoryStorage::new()).unwrap();
        for op in [super::REFUSAL_OP, super::AUTHORISATION_OP] {
            let line: ServerLine = serde_json::from_value(serde_json::json!({
                "op": op,
                "note": "a line the issuing side writes beside its issuances",
            }))
            .unwrap();
            chain.append(&line, 1_800_000_000).unwrap();
        }

        let read = read_server_chain(
            &chain.storage().lines().join("\n"),
            &FleetParams::defaults(),
            &IssuingAnchors::default(),
        );
        let chain = read.unwrap_or_else(|error| {
            // A `Result` compared with `assert_eq!` would print the whole
            // expected value; naming the refusal is what a reader needs.
            unreachable!("a side that has only refused was called a substituted journal: {error}")
        });
        assert!(
            chain.entries.is_empty(),
            "no issuance was written, so none may be reported"
        );
    }

    /// Ступень ВЫШЕ объявленной тревогой не является.
    ///
    /// Это не мелочь формулировки: парк, перенёсший ключ согласования на
    /// носитель раньше, чем поправил свою декларацию, получил бы тревогу на
    /// каждой выдаче — и научился бы пропускать класс, ради которого он заведён.
    #[test]
    fn a_custody_tier_above_the_declared_one_is_not_an_alarm() {
        let mut on_token = grant(1);
        on_token.key_storage = KeyStorage::Token;
        let report = reconcile(
            &[on_token],
            Some(&[login(1)]),
            &verified(),
            &Expectations {
                declared_key_storage: Some(KeyStorage::Software),
                revocations: Vec::new(),
                unsigned_revocations: 0,
                revocation_list: None,
            },
        );
        assert!(report.custody_shortfalls.is_empty());
        assert_eq!(report.verdict(), Verdict::Clean);
    }

    /// Отзыв чужого права выдачу не задевает, а отзыв ПОСЛЕ неё — не улика.
    ///
    /// Обе половины в одном тесте, потому что порознь каждая проходит на
    /// реализации, которая поднимает тревогу на всё подряд.
    #[test]
    fn a_revocation_that_does_not_concern_the_issuance_is_silent() {
        let elsewhere = Expectations {
            declared_key_storage: None,
            revocations: vec![Revocation {
                kind: SubjectKind::Engineer,
                subject: "eng-2".to_owned(),
                at: 1_799_999_999,
            }],
            unsigned_revocations: 0,
            revocation_list: None,
        };
        let report = reconcile(&[grant(1)], Some(&[login(1)]), &verified(), &elsewhere);
        assert!(report.late_grants.is_empty(), "{report}");

        // Тот же инженер, но право снято ПОЗЖЕ выдачи: в момент выдачи оно
        // действовало, и говорить тут не о чем.
        let later = Expectations {
            declared_key_storage: None,
            revocations: vec![Revocation {
                kind: SubjectKind::Engineer,
                subject: "eng-1".to_owned(),
                at: 1_800_000_001,
            }],
            unsigned_revocations: 0,
            revocation_list: None,
        };
        let report = reconcile(&[grant(1)], Some(&[login(1)]), &verified(), &later);
        assert!(report.late_grants.is_empty(), "{report}");
    }

    /// Отзыв догоняет инженера, как бы тот ни написал свой номер.
    ///
    /// Уклонение выбирает тот, кого контролируют: устройство передаёт номер
    /// КАК НАБРАНО, а разделители и регистр в формате незначащи. Побайтовая
    /// сверка означала бы, что достаточно нажать пробел — и отчёт чист.
    #[test]
    fn a_revocation_reaches_the_engineer_whatever_the_spelling() {
        for spelling in ["ORG1-0000014", "org1 000001 4", "org1.0000014"] {
            let mut issued = grant(1);
            issued.engineer_id = spelling.to_owned();
            let withdrawn = Expectations {
                declared_key_storage: None,
                revocations: vec![Revocation {
                    kind: SubjectKind::Engineer,
                    subject: "ORG1-0000014".to_owned(),
                    at: 1_799_999_999,
                }],
                unsigned_revocations: 0,
                revocation_list: None,
            };
            let report = reconcile(&[issued], Some(&[login(1)]), &verified(), &withdrawn);
            assert_eq!(
                report.late_grants.len(),
                1,
                "выдача под написанием {spelling} не связана с отзывом: {report}"
            );
        }
    }

    /// Разное написание одного номера — не расхождение сторон.
    ///
    /// Та же причина, обратная сторона: устройство пишет набранное, выдающая
    /// сторона — полученное, и два написания одного номера не должны выглядеть
    /// как «стороны называют разных людей».
    #[test]
    fn two_spellings_of_one_number_are_not_a_disagreement() {
        let mut issued = grant(1);
        issued.engineer_id = "ORG1-0000014".to_owned();
        let mut admitted = login(1);
        admitted.engineer_id = Some("org1 000001 4".to_owned());

        let report = reconcile(
            &[issued],
            Some(&[admitted]),
            &verified(),
            &Expectations::default(),
        );
        assert!(report.disagreements.is_empty(), "{report}");

        // А другой номер по-прежнему расхождение: сверка не перестала сверять.
        let mut issued = grant(1);
        issued.engineer_id = "ORG1-0000014".to_owned();
        let mut somebody_else = login(1);
        somebody_else.engineer_id = Some("ORG1-0000022".to_owned());
        let report = reconcile(
            &[issued],
            Some(&[somebody_else]),
            &verified(),
            &Expectations::default(),
        );
        assert_eq!(report.disagreements.len(), 1, "{report}");
    }

    /// Выдача той же секундой, что и отзыв, попадает в отчёт.
    ///
    /// Обе отметки — Unix-секунды, поэтому про выдачу, помеченную секундой
    /// отзыва, НЕЛЬЗЯ сказать, что она была раньше. Аудитор может посмотреть на
    /// напечатанную строку и признать её законной; на строку, которой в отчёте
    /// нет, посмотреть нельзя никак.
    #[test]
    fn an_issuance_in_the_very_second_of_the_revocation_is_reported() {
        let same_second = Expectations {
            declared_key_storage: None,
            revocations: vec![Revocation {
                kind: SubjectKind::Engineer,
                subject: "eng-1".to_owned(),
                at: 1_800_000_000,
            }],
            unsigned_revocations: 0,
            revocation_list: None,
        };
        let report = reconcile(&[grant(1)], Some(&[login(1)]), &verified(), &same_second);
        assert_eq!(report.late_grants.len(), 1, "{report}");
        let late = report.late_grants.first().unwrap();
        assert_eq!(late.revocation.at, 1_800_000_000);
        assert_ne!(report.verdict(), Verdict::Clean, "{report}");
    }

    /// Отзыв организации ловится так же, как отзыв инженера.
    #[test]
    fn a_revoked_organisation_is_named_too() {
        let report = reconcile(
            &[grant(1)],
            Some(&[login(1)]),
            &verified(),
            &Expectations {
                declared_key_storage: None,
                revocations: vec![Revocation {
                    kind: SubjectKind::Organisation,
                    subject: "acme".to_owned(),
                    at: 1_799_999_999,
                }],
                unsigned_revocations: 0,
                revocation_list: None,
            },
        );
        assert_eq!(report.late_grants.len(), 1, "{report}");
        assert_eq!(
            report.late_grants.first().unwrap().revocation.subject,
            "acme"
        );
    }

    /// Сессия, открытая под чужим личным номером, — расхождение пары.
    ///
    /// Класс, ради которого личный номер и стоит в challenge: код выдан одному,
    /// а вошёл по нему другой. Пара сходится по nonce, и без сравнения номеров
    /// отчёт назвал бы её согласной.
    #[test]
    fn a_login_under_another_personal_number_is_a_disagreement() {
        let mut other = login(1);
        other.engineer_id = Some("eng-9".to_owned());
        let report = reconcile(
            &[grant(1)],
            Some(&[other]),
            &verified(),
            &Expectations::default(),
        );
        assert_eq!(report.disagreements.len(), 1, "{report}");
        assert!(report
            .disagreements
            .first()
            .unwrap()
            .fields
            .contains(&"engineer"));
    }

    /// Отказ, случившийся до вопроса о личном номере, расхождением не считается.
    #[test]
    fn an_admission_that_named_no_number_is_a_disagreement() {
        // This test used to assert the opposite, and the reason it did was a
        // case that cannot happen: "a device that refused before asking has
        // nothing to disagree with". Refusals never reach the pairing — they
        // are filtered out before it — so a PAIRED line is always an admission,
        // and an admission without a personal number is a session opened
        // without the device recording who opened it.
        //
        // Skipping the comparison read as agreement, which is the worst answer
        // available: the whole point of the field is that a login names a
        // person, and "nobody was named" came out of the report as clean.
        let mut nameless = login(1);
        nameless.engineer_id = None;
        let report = reconcile(
            &[grant(1)],
            Some(&[nameless]),
            &verified(),
            &Expectations::default(),
        );
        assert_eq!(report.disagreements.len(), 1, "{report}");
        assert_eq!(
            report.disagreements.first().unwrap().fields,
            vec!["engineer"],
            "{report}"
        );
    }

    #[test]
    fn a_refusal_that_named_no_number_is_still_not_a_disagreement() {
        // The other side of it, and the reason the old assertion existed at
        // all: a device that turned an attempt away before it asked for a
        // number recorded none, and that is the refusal rather than a
        // disagreement. It reaches the report as a counted refusal and nothing
        // more, so the class stays for the case it is about.
        let mut nameless = login_with(1, outcome::OUTCOME_DENIED);
        nameless.engineer_id = None;
        let report = reconcile(
            &[grant(1)],
            Some(&[nameless]),
            &verified(),
            &Expectations::default(),
        );
        assert!(report.disagreements.is_empty(), "{report}");
    }

    /// Вид утверждения решает вердикт, и это проверяется на каждом виде.
    ///
    /// Оговорка обязана давать `Incomplete`, находка — `Findings`, заметка —
    /// `Clean`. Компилятор требует классифицировать новый вариант; потребовать
    /// классифицировать ВЕРНО он не может, и вот эта проверка — то, что может.
    #[test]
    fn the_kind_of_a_statement_decides_the_verdict() {
        // Ожидание написано рядом с фикстурой РУКАМИ и не выводится из
        // `kind()`. Первая версия этого теста считала ожидаемый вердикт как раз
        // из `kind()` — и переворот классификации переворачивал обе стороны
        // сравнения разом: мутация «UnsignedTail — заметка» проходила всю сюиту
        // зелёной. Тест, чьё ожидание вычислено из проверяемого, не проверяет
        // ничего.
        for (name, report, expected) in every_statement_alone() {
            let statements = report.statements();
            assert_eq!(
                statements.len(),
                1,
                "{name}: фикстура одиночного утверждения породила не одно: {report}"
            );
            assert_eq!(
                report.verdict(),
                expected,
                "{name}: вердикт не тот, который эта фикстура обязана давать: {report}"
            );
        }
    }

    /// Отчёты, покрывающие все ветки печати.
    fn every_kind_of_report() -> Vec<(&'static str, Report)> {
        let mut odd = login(1);
        odd.role_id = "ops.dc.junior".to_owned();

        let unreadable = Provenance {
            chain_verified: false,
            unsigned_from_seq: Some(4),
            server_unsigned_from_seq: None,
            server_unread_lines: 0,
            refusals_without_nonce: 1,
            unpairable_lines: vec![
                UnpairableLine {
                    device_number: "77000123".to_owned(),
                    line: 4,
                    outcome: "granted".to_owned(),
                },
                UnpairableLine {
                    device_number: "77000123".to_owned(),
                    line: 5,
                    outcome: outcome::OUTCOME_SUCCESS.to_owned(),
                },
            ],
        };

        vec![
            (
                "без устройства",
                reconcile(&[grant(1)], None, &verified(), &Expectations::default()),
            ),
            (
                "чисто",
                reconcile(
                    &[grant(1)],
                    Some(&[login(1)]),
                    &verified(),
                    &Expectations::default(),
                ),
            ),
            (
                "отказы",
                reconcile(
                    &[grant(1)],
                    Some(&[refused(1), login(1)]),
                    &verified(),
                    &Expectations::default(),
                ),
            ),
            (
                "все оговорки сразу",
                reconcile(
                    &[grant(1)],
                    Some(&[login(1), login_with(4, "granted")]),
                    &unreadable,
                    &Expectations::default(),
                ),
            ),
            (
                "все находки сразу",
                reconcile(
                    &[grant(1), grant(3)],
                    Some(&[odd, login(1), login(2)]),
                    &verified(),
                    &Expectations::default(),
                ),
            ),
        ]
    }

    /// Слова «no findings» печатаются ровно тогда, когда сказать нечего.
    ///
    /// Это тот самый инвариант, который четыре круга подряд был невысказанным:
    /// последняя строка отчёта не утверждает больше, чем отчёт установил. Он
    /// проверяется по всему набору фикстур сразу, а не на одном отчёте, и
    /// связан с вердиктом, а не с предикатом над частью полей.
    #[test]
    fn the_words_no_findings_appear_exactly_when_there_is_nothing_to_say() {
        for (name, report) in every_kind_of_report() {
            let text = report.to_string();
            let says_clean = text.contains("no findings");
            assert_eq!(
                says_clean,
                report.verdict() == Verdict::Clean,
                "{name}: строка отчёта и вердикт разошлись: {text}"
            );
            if says_clean {
                // Заметка — не утверждение о парке: счётчик прочитанных
                // отказов говорит, что строки видели, и слова «чисто» не
                // отменяет. Оговорка и находка отменяют обе.
                assert!(
                    report
                        .statements()
                        .iter()
                        .all(|statement| statement.kind() == super::StatementKind::Note),
                    "{name}: «no findings» над оговоркой или находкой: {text}"
                );
            }
        }
    }

    /// Оговорка держит отчёт от слова «чисто» так же, как находка.
    #[test]
    fn a_caveat_alone_is_enough_to_keep_the_report_from_saying_clean() {
        let report = reconcile(
            &[],
            Some(&[]),
            &Provenance {
                chain_verified: false,
                unsigned_from_seq: None,
                server_unsigned_from_seq: None,
                server_unread_lines: 0,
                refusals_without_nonce: 0,
                unpairable_lines: Vec::new(),
            },
            &Expectations::default(),
        );
        assert_eq!(report.verdict(), Verdict::Incomplete);
        assert!(!report.to_string().contains("no findings"), "{report}");
    }

    /// Допуск без nonce — находка, а не строчка в списке слов.
    ///
    /// Устройство говорит, что сессия открыта, и не называет попытки: ответить
    /// за неё не может никакая квитанция. Аудитору нужны прибор и строка, а не
    /// слово через запятую, и вердикт обязан это видеть.
    #[test]
    fn an_admission_with_no_nonce_is_a_finding_that_names_where_it_was_found() {
        let report = reconcile(
            &[],
            Some(&[]),
            &Provenance {
                chain_verified: true,
                unsigned_from_seq: None,
                server_unsigned_from_seq: None,
                server_unread_lines: 0,
                refusals_without_nonce: 0,
                unpairable_lines: vec![UnpairableLine {
                    device_number: "77000123".to_owned(),
                    line: 12,
                    outcome: outcome::OUTCOME_SUCCESS.to_owned(),
                }],
            },
            &Expectations::default(),
        );

        assert_eq!(report.verdict(), Verdict::Findings);
        let text = report.to_string();
        assert!(text.contains("admission-without-nonce"), "{text}");
        assert!(text.contains("device=77000123"), "{text}");
        assert!(text.contains("line=12"), "{text}");
        assert!(!text.contains("no findings"), "{text}");
    }

    #[test]
    fn the_fixtures_cover_every_statement_a_report_can_make() {
        let mut seen = Seen::default();
        let alone = every_statement_alone()
            .into_iter()
            .map(|(name, report, _)| (name, report));
        for (_, report) in every_kind_of_report().into_iter().chain(alone) {
            for statement in report.statements() {
                seen.mark(&statement);
            }
        }

        let Seen {
            no_device_side,
            unreadable_outcomes,
            unreadable_line,
            admission_without_nonce,
            no_chain,
            unsigned_tail,
            server_unsigned_tail,
            unread_server_lines,
            signatures_not_checked,
            grant_signature_rejected,
            grant_issuer_unknown,
            revocation_waterline_unset,
            revocations_read,
            unsigned_revocations,
            login_without_grant,
            grant_without_login,
            series_on_one_nonce,
            disagreement,
            custody_below_declared,
            grant_after_revocation,
            refusals_read,
        } = seen;

        for (name, covered) in [
            ("no-device-side", no_device_side),
            ("unreadable-outcomes", unreadable_outcomes),
            ("unreadable-line", unreadable_line),
            ("admission-without-nonce", admission_without_nonce),
            ("no-chain", no_chain),
            ("unsigned-tail", unsigned_tail),
            ("server-unsigned-tail", server_unsigned_tail),
            ("unread-server-lines", unread_server_lines),
            ("signatures-not-checked", signatures_not_checked),
            ("grant-signature-rejected", grant_signature_rejected),
            ("grant-issuer-unknown", grant_issuer_unknown),
            ("revocation-waterline-unset", revocation_waterline_unset),
            ("revocations-read", revocations_read),
            ("unsigned-revocations", unsigned_revocations),
            ("login-without-grant", login_without_grant),
            ("grant-without-login", grant_without_login),
            ("series-on-one-nonce", series_on_one_nonce),
            ("disagreement", disagreement),
            ("custody-below-declared", custody_below_declared),
            ("grant-after-revocation", grant_after_revocation),
            ("refusals-read", refusals_read),
        ] {
            assert!(covered, "ни одна фикстура не порождает {name}");
        }
    }

    /// Оговорки идут раньше находок, находки раньше заметок.
    ///
    /// Порядок — не украшение: оговорка ограничивает всё, что под ней, и
    /// аудитор, прочитавший «устройство говорит, что сессия открыта» раньше
    /// «журнал вообще без цепочки», унесёт первое без второго. До правки один
    /// цикл клал находку между двумя оговорками, и заметить это можно было
    /// только глазами на выводе.
    #[test]
    fn caveats_come_before_findings_and_findings_before_notes() {
        let rank = |kind: super::StatementKind| match kind {
            super::StatementKind::Caveat => 0_u8,
            super::StatementKind::Finding => 1,
            super::StatementKind::Note => 2,
        };

        for (name, report) in every_kind_of_report() {
            let ranks: Vec<u8> = report
                .statements()
                .iter()
                .map(|statement| rank(statement.kind()))
                .collect();
            assert!(
                ranks.is_sorted(),
                "{name}: порядок утверждений нарушен: {report}"
            );
        }
    }

    #[test]
    fn no_line_of_the_report_carries_a_run_of_spaces() {
        // Ходит по тому же набору, что и сторож полноты выше, поэтому ветка,
        // добавленная в печать, попадает под обе проверки разом.
        for (name, report) in every_kind_of_report() {
            let text = report.to_string();
            assert!(
                !text.contains("  "),
                "{name}: в отчёте прогон пробелов: {text}"
            );
            assert!(
                !text.lines().any(str::is_empty),
                "{name}: в отчёте пустая строка: {text}"
            );
        }

        let refusals = reconcile(
            &[grant(1)],
            Some(&[refused(1), login(1)]),
            &verified(),
            &Expectations::default(),
        );
        assert!(
            refusals
                .to_string()
                .contains("they are not logins and take part in no finding above"),
            "фраза собралась не так: {refusals}"
        );
    }

    /// Все оговорки печатаются, а не первая сработавшая.
    ///
    /// Незнакомое слово и отсутствующая цепочка — независимые утверждения об
    /// одном отчёте. Аудитор, которому сказали только первое, услышал меньшую
    /// половину: строки могли быть удалены без следа, и об этом он не узнает.
    #[test]
    fn every_caveat_that_applies_is_printed() {
        let report = reconcile(
            &[],
            Some(&[login_with(1, "granted")]),
            &Provenance {
                chain_verified: false,
                unsigned_from_seq: Some(9),
                server_unsigned_from_seq: None,
                server_unread_lines: 0,
                refusals_without_nonce: 0,
                unpairable_lines: Vec::new(),
            },
            &Expectations::default(),
        );
        let text = report.to_string();

        assert!(text.contains("granted"), "{text}");
        assert!(text.contains("unverified"), "{text}");
        assert!(text.contains("unsigned-tail from=9"), "{text}");
    }

    /// Расхождение второго входа на том же nonce не теряется.
    ///
    /// Два входа на один nonce сами по себе находка, но пока в спаривании
    /// оставался только последний из них, расхождение первого по роли или
    /// уровню исчезало — отчёт говорил, что пара сошлась.
    #[test]
    fn a_disagreement_of_the_other_login_on_the_same_nonce_is_not_lost() {
        // Обе очерёдности проверяются намеренно. Первая версия этого теста
        // ставила расходящийся вход первым — и мутация «сверять только первый»
        // её не роняла: сверка одного входа из двух проходит, пока в тесте
        // нужный вход стоит первым.
        let mut odd = login(1);
        odd.role_id = "ops.dc.junior".to_owned();

        for (order, logins) in [
            ("расходящийся первым", vec![odd.clone(), login(1)]),
            ("расходящийся вторым", vec![login(1), odd.clone()]),
        ] {
            let report = reconcile(
                &[grant(1)],
                Some(&logins),
                &verified(),
                &Expectations::default(),
            );

            assert_eq!(report.series_on_one_nonce.len(), 1, "{order}");
            assert_eq!(
                report.disagreements.len(),
                1,
                "{order}: расхождение потеряно: {report}"
            );
            assert_eq!(
                report.disagreements.first().unwrap().fields,
                vec!["role"],
                "{order}"
            );
        }
    }

    /// Отказ не закрывает квитанцию собой.
    ///
    /// Код выдан, вошли по нему или нет — вопрос отдельный: если единственная
    /// строка на этом nonce отказная, сессия не открывалась, и квитанция
    /// остаётся неотоваренной. Иначе отказ прятал бы находку.
    #[test]
    fn a_refusal_does_not_answer_a_grant() {
        let report = reconcile(
            &[grant(1)],
            Some(&[refused(1)]),
            &verified(),
            &Expectations::default(),
        );
        assert_eq!(report.grants_without_login.len(), 1);
        assert!(report.disagreements.is_empty());
        assert_eq!(report.refusals_read(), 1);
    }

    /// Незнакомое слово исхода — не вход и НЕ отказ, и отчёт перестаёт быть
    /// полным.
    ///
    /// Словарь исходов живёт в контракте и может пополниться словом, означающим
    /// открытую сессию; журнал может прийти от прошивки новее этой сборки.
    /// Читатель, отвечающий «да или нет», записал бы такие строки в отказы — и
    /// настоящие допуски исчезли бы из всех четырёх классов, пока отчёт печатает
    /// «no findings» над журналом, где всё как раз и произошло.
    #[test]
    fn an_outcome_this_reader_does_not_know_makes_the_report_incomplete() {
        let report = reconcile(
            &[],
            Some(&[login_with(1, "granted")]),
            &verified(),
            &Expectations::default(),
        );

        assert!(report.logins_without_grant.is_empty());
        assert_eq!(
            report.refusals_read(),
            0,
            "незнакомое слово посчитано отказом: {report}"
        );
        assert!(
            !report.is_complete(),
            "отчёт объявил себя полным, не поняв строку: {report}"
        );
        assert_eq!(
            report.unaccounted_outcomes().collect::<Vec<_>>(),
            vec!["granted"]
        );
        assert!(report.to_string().contains("incomplete"));
        assert!(report.to_string().contains("granted"));
    }

    /// Незнакомое слово не прячет находки соседних строк.
    ///
    /// Сессия, открытая по коду без квитанции, обязана быть названа даже если
    /// в том же журнале есть строка, которую сборка не поняла: непонятое —
    /// повод усомниться в полноте, а не повод замолчать понятое.
    #[test]
    fn an_unknown_outcome_does_not_silence_the_lines_that_were_understood() {
        let report = reconcile(
            &[],
            Some(&[login(1), login_with(2, "granted")]),
            &verified(),
            &Expectations::default(),
        );
        assert_eq!(report.logins_without_grant.len(), 1);
        assert_eq!(report.verdict(), Verdict::Findings);
        assert!(!report.is_complete());
    }

    /// Строка без nonce классифицируется по ИСХОДУ, а не по отсутствию nonce.
    ///
    /// Дефект, заведённый починкой предыдущего круга: для строк с nonce вопрос
    /// «допуск или нет» был заменён тремя ответами, а для строк без nonce тот же
    /// двоичный вопрос остался — всё, что не имело nonce, объявлялось отказом.
    /// Слово `success` без nonce и слово, которого сборка не знает, оба уходили
    /// в счётчик отказов, и отчёт называл себя полным.
    #[test]
    fn a_line_without_a_nonce_is_read_by_its_outcome() {
        let text = device_chain(&[
            device_login(nonce(1).as_str(), "success"),
            device_login("-", "denied"),
            device_login("-", "success"),
            device_login("-", "granted"),
        ]);
        let journal = read_journal("77000123", &text, &FleetParams::defaults()).unwrap();

        assert_eq!(journal.refusals_without_nonce, 1, "отказом считается отказ");
        assert_eq!(
            journal
                .unpairable_lines
                .iter()
                .map(|line| line.outcome.as_str())
                .collect::<Vec<_>>(),
            vec!["success", "granted"],
            "допуск без nonce и незнакомое слово — не отказы"
        );

        let report = reconcile(
            &[grant(1)],
            Some(&journal.entries),
            &Provenance {
                chain_verified: journal.chain_verified,
                unsigned_from_seq: None,
                server_unsigned_from_seq: None,
                server_unread_lines: 0,
                refusals_without_nonce: journal.refusals_without_nonce,
                unpairable_lines: journal.unpairable_lines.clone(),
            },
            &Expectations::default(),
        );

        assert_eq!(report.refusals_read(), 1);
        assert!(
            !report.is_complete(),
            "отчёт объявил себя полным над строками, которых не понял: {report}"
        );
        assert!(report.to_string().contains("granted"));
    }

    /// Кривая строка без nonce — тоже кривая строка.
    ///
    /// Доктрина разбора: ничего не чинится и ничего не пропускается. Строка без
    /// nonce уходила через сокращение, которое не читало ни одного из
    /// обязательных полей.
    #[test]
    fn a_line_without_a_nonce_still_owes_its_fields() {
        // Докстрока говорит «ни одного из обязательных полей», а первая версия
        // теста проверяла одно — и мутация, вернувшая сокращение для трёх полей
        // из четырёх, её не роняла. Проверяются все четыре, каждое отдельно.
        for missing in ["outcome", "role_id", "epoch", "level"] {
            let mut line = serde_json::json!({
                "op": "code_login",
                "nonce_ref": "-",
                "role_id": "ops.dc.senior",
                "level": 2,
                "epoch": 7,
                "ticket_no": "tk-17",
                "outcome": "denied",
            });
            line.as_object_mut().unwrap().remove(missing);

            let text = device_chain(&[line]);
            let refusal = read_journal("77000123", &text, &FleetParams::defaults());
            assert!(
                matches!(
                    refusal,
                    Err(JournalError::MissingField { field, .. }) if field == missing
                ),
                "поле {missing} не потребовано: {refusal:?}"
            );
        }
    }

    /// Журнал из одних дононсовых отказов читается, а не отвергается.
    ///
    /// Это журнал прибора, который за период отказал всем и ни разу не дошёл до
    /// nonce. Отказ читателя роняет весь прогон сверки на `?`, а счётчик,
    /// который отчёт обещает назвать, не доезжает до отчёта вовсе.
    #[test]
    fn a_journal_of_nothing_but_pre_nonce_refusals_is_read() {
        let text = device_chain(&[device_login("-", "denied"), device_login("-", "denied")]);
        let journal = read_journal("77000123", &text, &FleetParams::defaults()).unwrap();

        assert!(journal.entries.is_empty());
        assert_eq!(journal.refusals_without_nonce, 2);
    }

    /// Отказы, случившиеся до розыгрыша nonce, входят в счётчик прочитанных.
    ///
    /// Устройство пишет их с `-` вместо nonce: билета нет, роль не определена,
    /// троттлинг. Спариваться им не с чем по построению, поэтому записями они не
    /// становятся — но обещание «отчёт говорит, сколько отказов прочитано»,
    /// выполненное для части из них, не выполнено.
    #[test]
    fn refusals_that_never_reached_a_nonce_are_counted_too() {
        let value = nonce(1).as_str().to_owned();
        let text = device_chain(&[
            device_login(&value, "success"),
            device_login("-", "denied"),
            device_login("-", "denied"),
        ]);
        let journal = read_journal("77000123", &text, &FleetParams::defaults()).unwrap();
        assert_eq!(journal.entries.len(), 1, "дононсовые строки стали записями");
        assert_eq!(journal.refusals_without_nonce, 2);

        let report = reconcile(
            &[grant(1)],
            Some(&journal.entries),
            &Provenance {
                chain_verified: journal.chain_verified,
                unsigned_from_seq: None,
                server_unsigned_from_seq: None,
                server_unread_lines: 0,
                refusals_without_nonce: journal.refusals_without_nonce,
                unpairable_lines: journal.unpairable_lines.clone(),
            },
            &Expectations::default(),
        );
        assert_ne!(report.verdict(), Verdict::Findings);
        assert_eq!(report.refusals_read(), 2);
        assert!(report.to_string().contains("refusals-read count=2"));
    }

    #[test]
    fn a_matching_pair_raises_nothing() {
        let report = reconcile(
            &[grant(1)],
            Some(&[login(1)]),
            &verified(),
            &Expectations::default(),
        );
        assert!(report.is_complete());
        assert_ne!(report.verdict(), Verdict::Findings);
        assert!(report.to_string().contains("no findings"));
    }

    #[test]
    fn a_login_nobody_recorded_an_issuance_for_is_reported() {
        let report = reconcile(
            &[],
            Some(&[login(1)]),
            &verified(),
            &Expectations::default(),
        );
        assert_eq!(report.logins_without_grant.len(), 1);
        assert!(report.to_string().contains("login-without-grant"));
    }

    #[test]
    fn a_grant_no_device_saw_is_reported() {
        let report = reconcile(
            &[grant(1)],
            Some(&[]),
            &verified(),
            &Expectations::default(),
        );
        assert_eq!(report.grants_without_login.len(), 1);
        assert!(report.to_string().contains("grant-without-login"));
    }

    /// Две выдачи на один nonce — два кода на одну попытку, и это находка
    /// независимо от того, чем они отличаются в остальном.
    #[test]
    fn two_issuances_on_one_nonce_are_reported() {
        let report = reconcile(
            &[grant(1), grant(1)],
            Some(&[login(1)]),
            &verified(),
            &Expectations::default(),
        );
        assert_eq!(report.series_on_one_nonce.len(), 1);
        let series = report.series_on_one_nonce.first().unwrap();
        assert_eq!(series.grants, 2);
        assert!(report.to_string().contains("grants=2"));
    }

    #[test]
    fn two_logins_on_one_nonce_are_reported() {
        // Попытка отвечается один раз: два входа на один nonce значат, что одна
        // из сторон не та, за кого себя выдаёт.
        let report = reconcile(
            &[grant(1)],
            Some(&[login(1), login(1)]),
            &verified(),
            &Expectations::default(),
        );
        assert_eq!(report.series_on_one_nonce.len(), 1);
        assert_eq!(
            report
                .series_on_one_nonce
                .first()
                .map(|series| series.logins),
            Some(2)
        );
    }

    #[test]
    fn one_grant_and_its_login_are_not_a_series() {
        let report = reconcile(
            &[grant(1)],
            Some(&[login(1)]),
            &verified(),
            &Expectations::default(),
        );
        assert!(report.series_on_one_nonce.is_empty());
    }

    #[test]
    fn a_pair_that_disagrees_about_the_role_is_reported() {
        let mut login = login(1);
        login.role_id = "ops.dc.root".to_owned();
        let report = reconcile(
            &[grant(1)],
            Some(&[login]),
            &verified(),
            &Expectations::default(),
        );
        assert_eq!(report.disagreements.len(), 1);
        assert_eq!(report.disagreements.first().unwrap().fields, vec!["role"]);
    }

    #[test]
    fn a_report_without_the_device_side_says_so() {
        let report = reconcile(&[grant(1)], None, &verified(), &Expectations::default());
        assert!(!report.is_complete());
        assert!(report.to_string().contains("incomplete"));
        assert!(report.logins_without_grant.is_empty());
        assert!(report.grants_without_login.is_empty());
    }

    /// Строит настоящую цепочку устройства: тот же крейт, тот же жанр строки,
    /// что пишет журнал устройства. Рукописный двойник формата здесь бесполезен
    /// — именно на нём читатель ЧУЖОГО формата и остаётся зелёным.
    fn device_chain(records: &[serde_json::Value]) -> String {
        use tessera_hashchain::storage::MemoryStorage;
        use tessera_hashchain::Chain;

        let mut chain: Chain<MemoryStorage, super::DeviceLine> =
            Chain::load(MemoryStorage::new()).unwrap();
        for (index, record) in records.iter().enumerate() {
            let line: super::DeviceLine = serde_json::from_value(record.clone()).unwrap();
            chain.append(&line, 1_800_000_000 + index as u64).unwrap();
        }
        let mut text = chain.storage().lines().join("\n");
        text.push('\n');
        text
    }

    /// Одна строка входа в том виде, в каком её пишет устройство: `op`, а не
    /// `event`, и имя `code_login`.
    fn device_login(nonce: &str, outcome: &str) -> serde_json::Value {
        // The personal number is written on EVERY line the device emits — on a
        // success it is what the engineer typed, on a refusal that never got
        // that far it is `-`. This fixture omitted it, and a fixture whose
        // comment says it is "the form the device actually writes" must not
        // leave out a field the device always writes: a report over it looked
        // healthy while the very case that field exists for went unexamined.
        let engineer = if outcome == "success" {
            "eng-1"
        } else {
            super::ABSENT
        };
        serde_json::json!({
            "op": "code_login",
            "nonce_ref": nonce,
            "role_id": "ops.dc.senior",
            "level": 2,
            "epoch": 7,
            "ticket_no": "tk-17",
            "claimed_engineer_no": engineer,
            "outcome": outcome,
        })
    }

    /// Тот формат, который устройство пишет на самом деле, читается сверкой.
    ///
    /// До правки каждая строка отбрасывалась как «другое событие», множество
    /// входов выходило пустым — и отчёт объявлялся полным.
    #[test]
    fn the_form_the_device_actually_writes_is_read() {
        let value = nonce(1).as_str().to_owned();
        let text = device_chain(&[device_login(&value, "success")]);
        let journal = read_journal("77000123", &text, &FleetParams::defaults()).unwrap();

        assert_eq!(journal.entries.len(), 1, "строка входа не найдена: {text}");
        assert_eq!(journal.entries.first().unwrap().nonce.as_str(), value);
        assert_eq!(journal.entries.first().unwrap().outcome, "success");
        assert!(journal.chain_verified);
    }

    /// Журнал, в котором нет ни одной строки входа, — это отказ, а не пустое
    /// множество: пустое множество отчёт объявит полным и чистым.
    #[test]
    fn a_journal_without_a_single_login_line_is_refused() {
        let text = device_chain(&[serde_json::json!({
            "op": "enrollment",
            "host": "aa11bb22",
            "outcome": "accepted",
        })]);
        assert!(matches!(
            read_journal("77000123", &text, &FleetParams::defaults()),
            Err(JournalError::NoLoginLines)
        ));
    }

    /// Изъятая строка видна: цепочка для того и есть.
    #[test]
    fn a_line_removed_from_the_journal_is_refused() {
        let text = device_chain(&[
            device_login("0000014711", "success"),
            device_login("0000020815", "success"),
            device_login("0000031234", "denied"),
        ]);
        let kept: Vec<&str> = text
            .lines()
            .filter(|line| !line.contains("0000020815"))
            .collect();

        assert!(matches!(
            read_journal(
                "77000123",
                &format!("{}\n", kept.join("\n")),
                &FleetParams::defaults()
            ),
            Err(JournalError::BrokenChain { position: 1 })
        ));
    }

    /// Снятое обрамление первой строки не превращает цепочку в выгрузку.
    ///
    /// Иначе вся разница между проверяемым журналом и непроверяемой выгрузкой
    /// стоила бы одной правки: оператор, скрывающий внекнижные выдачи, удаляет
    /// неудобные строки, снимает `seq` и `prev_hash` с первой — и файл
    /// принимается как плоская выгрузка, где удалять можно без следа.
    #[test]
    fn a_chain_stripped_of_its_first_framing_is_not_a_flat_export() {
        let text = device_chain(&[
            device_login("0000014711", "success"),
            device_login("0000020815", "success"),
        ]);
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();

        // Ровно то, что сделал бы прячущий: первая строка теряет обрамление,
        // остальные остаются как были.
        let head = lines.first_mut().unwrap();
        let mut first: serde_json::Value = serde_json::from_str(head).unwrap();
        let object = first.as_object_mut().unwrap();
        object.remove("seq");
        object.remove("prev_hash");
        *head = serde_json::to_string(&first).unwrap();

        let stripped = format!("{}\n", lines.join("\n"));
        assert!(
            matches!(
                read_journal("77000123", &stripped, &FleetParams::defaults()),
                Err(JournalError::BrokenChain { .. })
            ),
            "журнал с обрамлением принят как выгрузка без цепочки: {stripped}"
        );
    }

    /// Выгрузка без цепочки принимается, но отчёт об этом говорит: строку из
    /// неё удаляют без следа.
    #[test]
    fn an_export_without_a_chain_is_read_and_marked_unverified() {
        let text = format!(
            concat!(
                r#"{{"event":"qr_code_login","nonce_ref":"{nonce}","role_id":"ops.dc.senior","level":2,"epoch":7,"ticket_no":"tk-17","outcome":"success"}}"#,
                "\n"
            ),
            nonce = nonce(1).as_str()
        );
        let journal = read_journal("77000123", &text, &FleetParams::defaults()).unwrap();
        assert_eq!(journal.entries.len(), 1);
        assert!(!journal.chain_verified);

        let report = reconcile(
            &[],
            Some(&journal.entries),
            &Provenance {
                chain_verified: journal.chain_verified,
                unsigned_from_seq: journal.unsigned_from_seq,
                server_unsigned_from_seq: None,
                server_unread_lines: 0,
                refusals_without_nonce: journal.refusals_without_nonce,
                unpairable_lines: journal.unpairable_lines.clone(),
            },
            &Expectations::default(),
        );
        assert!(report.to_string().contains("unverified"));
    }

    /// Незаверенный хвост назван в отчёте: цепочка держит всё до последнего
    /// заверения, а после него строку можно уронить, оставив валидный префикс.
    #[test]
    fn an_unsigned_tail_is_named_in_the_report() {
        let value = nonce(1).as_str().to_owned();
        let text = device_chain(&[device_login(&value, "success")]);
        let journal = read_journal("77000123", &text, &FleetParams::defaults()).unwrap();
        assert_eq!(journal.unsigned_from_seq, Some(0));

        let report = reconcile(
            &[],
            Some(&journal.entries),
            &Provenance {
                chain_verified: journal.chain_verified,
                unsigned_from_seq: journal.unsigned_from_seq,
                server_unsigned_from_seq: None,
                server_unread_lines: 0,
                refusals_without_nonce: journal.refusals_without_nonce,
                unpairable_lines: journal.unpairable_lines.clone(),
            },
            &Expectations::default(),
        );
        assert!(report.to_string().contains("unsigned-tail from=0"));
    }

    #[test]
    fn a_journal_yields_its_code_login_lines_only() {
        let value = nonce(1).as_str().to_owned();
        let text = format!(
            concat!(
                r#"{{"event":"session_open","user":"root"}}"#,
                "\n",
                r#"{{"event":"qr_code_login","nonce_ref":"{nonce}","role_id":"ops.dc.senior","level":2,"epoch":7,"ticket_no":"tk-17","outcome":"success"}}"#,
                "\n",
                r#"{{"event":"qr_code_login","nonce_ref":"-","role_id":"ops.dc.senior","level":2,"epoch":7,"outcome":"denied","reason":"no_ticket"}}"#,
                "\n"
            ),
            nonce = value
        );
        let journal = read_journal("77000123", &text, &FleetParams::defaults()).unwrap();
        assert_eq!(journal.entries.len(), 1);
        assert_eq!(journal.entries.first().unwrap().nonce.as_str(), value);
    }

    #[test]
    fn a_line_that_is_not_json_is_refused() {
        assert_eq!(
            read_journal("77000123", "not json at all", &FleetParams::defaults()),
            Err(JournalError::NotJson { line: 1 })
        );
    }

    #[test]
    fn a_code_login_line_missing_a_pairing_field_is_refused() {
        let text = format!(
            r#"{{"event":"qr_code_login","nonce_ref":"{nonce}","level":2,"epoch":7,"outcome":"success"}}"#,
            nonce = nonce(1).as_str()
        );
        assert_eq!(
            read_journal("77000123", &text, &FleetParams::defaults()),
            Err(JournalError::MissingField {
                line: 1,
                field: "role_id"
            })
        );
    }
}
