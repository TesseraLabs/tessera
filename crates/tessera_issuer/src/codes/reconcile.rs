//! Two-sided reconciliation: what the devices saw against what the operators
//! wrote.
//!
//! A receipt says an operator handed out a code. A device journal line says a
//! device was asked to accept one. Neither side is evidence on its own — the
//! receipts are written by the people whose work they record, and the journals
//! sit on the machines the codes let people into — so the question an audit
//! actually asks is where the two sides disagree:
//!
//! - a **login without a receipt**: a device answered a challenge nobody wrote
//!   down, which is what a code handed out off the books looks like;
//! - a **receipt without a login**: a code was issued and never used, which is
//!   ordinary once and a pattern of stockpiling when it repeats;
//! - a **series on one counter**: one device, one epoch, one counter, and more
//!   than one issuance on it — whether the nonces differ or not. A repeat with
//!   the same nonce is the legitimate dropped call, and it is *still* reported:
//!   a repetition that is ordinary once is a pattern when it is not, and a
//!   report that only counted distinct nonces would stay silent through a run
//!   of codes issued on one counter;
//! - a **disagreement**: the two sides paired on device, epoch and nonce, and
//!   then said different things about the role, the level or the ticket.
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
//! # Incompleteness is a finding
//!
//! A report assembled without the device side is not a clean report with fewer
//! sources: three of the four classes cannot be computed at all, and the fourth
//! degrades to "these receipts exist". [`Report::is_complete`] is false there,
//! and every consumer prints it — an auditor who reads a partial report as a
//! clean one has been told the fleet is fine by a report that never looked.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use tessera_codes_contract::nonce::Nonce;
use tessera_codes_contract::params::FleetParams;
use tessera_hashchain::{verify_lines, ChainPayload, ChainStatus, EntryKind, OP_HEAD_SIGNATURE};

/// Operation a code login carries in the device's audit chain.
///
/// It is the `op` of `tessera_core::audit::AuditRecord::CodeLogin`. The name is
/// matched rather than assumed, so a journal carrying every other record of the
/// machine reconciles without being filtered first.
pub const LOGIN_OP: &str = "code_login";

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
    /// What the device did with the attempt.
    pub outcome: String,
}

/// One issuance, as a receipt recorded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptEntry {
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
    /// Ticket the operator worked under.
    pub ticket_number: String,
    /// Where the receipt was read from, for a report a human can act on.
    pub source: String,
}

/// A device, an epoch and a counter that carry more than one issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterSeries {
    /// Device the series is on.
    pub device_number: String,
    /// Key epoch of the series.
    pub epoch: u32,
    /// Counter that repeated.
    pub counter: u64,
    /// The nonces seen on that counter, receipts and logins together.
    ///
    /// One nonce with several receipts is a repeated call; several nonces are a
    /// device that drew a new challenge on a counter it had already used.
    pub nonces: Vec<String>,
    /// How many receipts sit on this counter.
    pub receipts: u64,
    /// How many logins sit on this counter.
    pub logins: u64,
}

/// A receipt and a login that paired but do not agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disagreement {
    /// The receipt of the pair.
    pub receipt: ReceiptEntry,
    /// The login of the pair.
    pub login: LoginEntry,
    /// The fields the two disagree on.
    pub fields: Vec<&'static str>,
}

/// What could be established about the device side of a reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provenance {
    /// Whether every journal carried a hash chain that verified.
    pub chain_verified: bool,
    /// The earliest `seq` from which no head signature covers a journal.
    pub unsigned_from_seq: Option<u64>,
}

impl Provenance {
    /// The provenance of a device side that was not supplied at all.
    #[must_use]
    pub const fn absent() -> Self {
        Self {
            chain_verified: false,
            unsigned_from_seq: None,
        }
    }
}

/// The outcome of a reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Logins the receipts do not account for.
    pub logins_without_receipt: Vec<LoginEntry>,
    /// Receipts no login accounts for.
    pub receipts_without_login: Vec<ReceiptEntry>,
    /// Counters carrying more than one challenge.
    pub series_on_one_counter: Vec<CounterSeries>,
    /// Pairs that met and then disagreed.
    pub disagreements: Vec<Disagreement>,
    /// Whether the device side was present at all.
    device_side: bool,
    /// Whether every device journal read was chain-verified.
    chain_verified: bool,
    /// The earliest `seq` of an unsigned tail across the journals read.
    unsigned_from_seq: Option<u64>,
}

impl Report {
    /// Reports whether both sides were present.
    ///
    /// A report of one side is not a clean report: three of the four classes
    /// cannot be computed without the devices.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.device_side
    }

    /// Reports whether the device side came with a chain that verified.
    ///
    /// False when a journal was a flat export: its lines can be removed without
    /// a trace, so the absence of a finding says less than it appears to.
    #[must_use]
    pub const fn chain_verified(&self) -> bool {
        self.chain_verified
    }

    /// Reports whether anything at all was found.
    #[must_use]
    pub fn has_findings(&self) -> bool {
        !self.logins_without_receipt.is_empty()
            || !self.receipts_without_login.is_empty()
            || !self.series_on_one_counter.is_empty()
            || !self.disagreements.is_empty()
    }
}

impl fmt::Display for Report {
    /// Writes the report as lines of technical data, one finding per line.
    ///
    /// The values are identifiers, numbers and nonces — the same bytes in every
    /// locale; a consumer that heads the report with a caption localizes the
    /// caption.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.device_side {
            writeln!(
                f,
                "incomplete: no device journal was supplied; only receipts were read"
            )?;
        } else if !self.chain_verified {
            writeln!(
                f,
                "unverified: a device journal carried no hash chain; lines could have been \
                 removed from it without a trace"
            )?;
        } else if let Some(seq) = self.unsigned_from_seq {
            // The chain held, which settles everything before the last head
            // signature. After it, a dropped line leaves a valid prefix — so the
            // absence of a finding in that range says less than it appears to.
            writeln!(
                f,
                "unsigned-tail from={seq}: the device journal is not covered by a head signature \
                 past this point, so lines could have been dropped from its end; the signature \
                 itself is not checked here"
            )?;
        }
        for login in &self.logins_without_receipt {
            writeln!(
                f,
                "login-without-receipt device={} epoch={} nonce={} role={} level={} outcome={}",
                login.device_number,
                login.epoch,
                login.nonce.as_str(),
                login.role_id,
                login.level,
                login.outcome
            )?;
        }
        for receipt in &self.receipts_without_login {
            writeln!(
                f,
                "receipt-without-login device={} epoch={} nonce={} role={} level={} ticket={} file={}",
                receipt.device_number,
                receipt.epoch,
                receipt.nonce.as_str(),
                receipt.role_id,
                receipt.level,
                receipt.ticket_number,
                receipt.source
            )?;
        }
        for series in &self.series_on_one_counter {
            writeln!(
                f,
                "series-on-one-counter device={} epoch={} counter={} receipts={} logins={} nonces={}",
                series.device_number,
                series.epoch,
                series.counter,
                series.receipts,
                series.logins,
                series.nonces.join(",")
            )?;
        }
        for disagreement in &self.disagreements {
            writeln!(
                f,
                "disagreement device={} epoch={} nonce={} fields={}",
                disagreement.receipt.device_number,
                disagreement.receipt.epoch,
                disagreement.receipt.nonce.as_str(),
                disagreement.fields.join(",")
            )?;
        }
        if !self.has_findings() {
            writeln!(f, "no findings")?;
        }
        Ok(())
    }
}

/// Reconciles the receipts of an operator against the journals of the devices.
///
/// `logins` is [`None`] when the device side was not supplied at all, which is
/// a different statement from an empty journal: an empty journal says the
/// devices saw nothing, and its absence says nobody looked.
///
/// `provenance` says what could be established about the journals behind
/// `logins`. It is not bookkeeping: a report whose device side could have had
/// lines removed from it cannot be read as "nothing was found", and [`Report`]
/// prints the difference.
#[must_use]
pub fn reconcile(
    receipts: &[ReceiptEntry],
    logins: Option<&[LoginEntry]>,
    provenance: Provenance,
) -> Report {
    let mut report = Report {
        logins_without_receipt: Vec::new(),
        receipts_without_login: Vec::new(),
        series_on_one_counter: series(receipts, logins.unwrap_or_default()),
        disagreements: Vec::new(),
        device_side: logins.is_some(),
        chain_verified: logins.is_some() && provenance.chain_verified,
        unsigned_from_seq: provenance.unsigned_from_seq,
    };

    let Some(logins) = logins else {
        return report;
    };

    let by_key: BTreeMap<(String, u32, String), &LoginEntry> = logins
        .iter()
        .map(|login| (key(&login.device_number, login.epoch, &login.nonce), login))
        .collect();

    let mut paired: BTreeSet<(String, u32, String)> = BTreeSet::new();
    for receipt in receipts {
        let receipt_key = key(&receipt.device_number, receipt.epoch, &receipt.nonce);
        match by_key.get(&receipt_key) {
            None => report.receipts_without_login.push(receipt.clone()),
            Some(login) => {
                paired.insert(receipt_key);
                let fields = disagreeing_fields(receipt, login);
                if !fields.is_empty() {
                    report.disagreements.push(Disagreement {
                        receipt: receipt.clone(),
                        login: (*login).clone(),
                        fields,
                    });
                }
            }
        }
    }

    for login in logins {
        if !paired.contains(&key(&login.device_number, login.epoch, &login.nonce)) {
            report.logins_without_receipt.push(login.clone());
        }
    }
    report
}

/// Collects the counters that carry more than one issuance.
///
/// The alarm is on the *count*, not on how many distinct nonces were seen: two
/// receipts on one counter are two codes handed out for one challenge, and that
/// is the finding whether the second one repeated the nonce or not.
fn series(receipts: &[ReceiptEntry], logins: &[LoginEntry]) -> Vec<CounterSeries> {
    let mut seen: BTreeMap<(String, u32, u64), Bucket> = BTreeMap::new();
    for receipt in receipts {
        seen.entry(key_of(
            &receipt.device_number,
            receipt.epoch,
            &receipt.nonce,
        ))
        .or_default()
        .add(&receipt.nonce, Side::Receipt);
    }
    for login in logins {
        seen.entry(key_of(&login.device_number, login.epoch, &login.nonce))
            .or_default()
            .add(&login.nonce, Side::Login);
    }

    seen.into_iter()
        .filter(|(_, bucket)| bucket.is_a_series())
        .map(|((device_number, epoch, counter), bucket)| CounterSeries {
            device_number,
            epoch,
            counter,
            nonces: bucket.nonces,
            receipts: bucket.receipts,
            logins: bucket.logins,
        })
        .collect()
}

/// Which side an entry came from.
#[derive(Debug, Clone, Copy)]
enum Side {
    /// An operator receipt.
    Receipt,
    /// A device journal line.
    Login,
}

/// What one counter of one device and epoch carries.
#[derive(Debug, Default)]
struct Bucket {
    /// Distinct nonces seen on it.
    nonces: Vec<String>,
    /// Receipts counted on it.
    receipts: u64,
    /// Logins counted on it.
    logins: u64,
}

impl Bucket {
    /// Records one entry.
    fn add(&mut self, nonce: &Nonce, side: Side) {
        let value = nonce.as_str().to_owned();
        if !self.nonces.contains(&value) {
            self.nonces.push(value);
        }
        match side {
            Side::Receipt => self.receipts = self.receipts.saturating_add(1),
            Side::Login => self.logins = self.logins.saturating_add(1),
        }
    }

    /// Reports whether this counter carries more than one issuance.
    ///
    /// Several receipts is the operator side handing out more than one code on
    /// a counter. Several nonces is the device side making more than one
    /// challenge on it. Either is the invariant the counter exists to hold.
    const fn is_a_series(&self) -> bool {
        self.receipts > 1 || self.logins > 1 || self.nonces.len() > 1
    }
}

/// The key a counter bucket sits under.
fn key_of(device_number: &str, epoch: u32, nonce: &Nonce) -> (String, u32, u64) {
    (device_number.to_owned(), epoch, nonce.counter())
}

/// Names the fields a paired receipt and login disagree on.
fn disagreeing_fields(receipt: &ReceiptEntry, login: &LoginEntry) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if receipt.role_id != login.role_id {
        fields.push("role");
    }
    if receipt.level != login.level {
        fields.push("level");
    }
    // A device that refused before it resolved a ticket recorded none; that is
    // the refusal, not a disagreement about which ticket was used.
    if let Some(ticket) = login.ticket_number.as_deref() {
        if ticket != receipt.ticket_number {
            fields.push("ticket");
        }
    }
    fields
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
        // The chain's own rules are checked by the verifier; the only thing
        // this reader can add is that a line names an operation at all.
        !self.op.is_empty()
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

        let nonce_text = text_field("nonce_ref").ok_or(JournalError::MissingField {
            line: number,
            field: "nonce_ref",
        })?;
        if nonce_text == ABSENT {
            continue;
        }
        let nonce = Nonce::parse(&nonce_text, params).map_err(|_| JournalError::UnusableField {
            line: number,
            field: "nonce_ref",
        })?;

        let epoch = number_field("epoch").ok_or(JournalError::MissingField {
            line: number,
            field: "epoch",
        })?;
        let level = number_field("level").ok_or(JournalError::MissingField {
            line: number,
            field: "level",
        })?;
        entries.push(LoginEntry {
            device_number: device_number.to_owned(),
            epoch: u32::try_from(epoch).map_err(|_| JournalError::UnusableField {
                line: number,
                field: "epoch",
            })?,
            nonce,
            role_id: text_field("role_id").ok_or(JournalError::MissingField {
                line: number,
                field: "role_id",
            })?,
            level: u32::try_from(level).map_err(|_| JournalError::UnusableField {
                line: number,
                field: "level",
            })?,
            ticket_number: text_field("ticket_no").filter(|ticket| ticket != ABSENT),
            outcome: text_field("outcome").ok_or(JournalError::MissingField {
                line: number,
                field: "outcome",
            })?,
        });
    }

    if entries.is_empty() {
        return Err(JournalError::NoLoginLines);
    }
    Ok(DeviceJournal {
        entries,
        chain_verified,
        unsigned_from_seq,
    })
}

/// Reports whether a line records a code login, in either of the two forms.
fn is_login(value: &serde_json::Value) -> bool {
    let field = |name: &str| value.get(name).and_then(serde_json::Value::as_str);
    field("op") == Some(LOGIN_OP) || field("event") == Some(LOGIN_EVENT)
}

/// Verifies the chain of a journal, or reports that it carries none.
///
/// The question is asked of the first line: a file where the framing appears
/// halfway through is not a chain with a preamble, it is a file somebody
/// assembled, and the verifier says so at the position where it stops adding up.
fn chain_status(lines: &[String]) -> Option<ChainStatus> {
    let first = lines.first()?;
    let value: serde_json::Value = serde_json::from_str(first).ok()?;
    if value.get("seq").is_none() || value.get("prev_hash").is_none() {
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
    use super::{read_journal, reconcile, JournalError, LoginEntry, Provenance, ReceiptEntry};
    use tessera_codes_contract::nonce::Nonce;
    use tessera_codes_contract::params::FleetParams;

    /// Происхождение «цепочка сошлась и покрыта заверением» — то, что не
    /// добавляет к отчёту оговорок.
    fn verified() -> Provenance {
        Provenance {
            chain_verified: true,
            unsigned_from_seq: None,
        }
    }

    fn nonce(counter: u64, tail: &str) -> Nonce {
        Nonce::new(counter, tail, &FleetParams::defaults()).unwrap()
    }

    fn receipt(counter: u64, tail: &str) -> ReceiptEntry {
        ReceiptEntry {
            device_number: "77000123".to_owned(),
            epoch: 7,
            nonce: nonce(counter, tail),
            role_id: "ops.dc.senior".to_owned(),
            level: 2,
            ticket_number: "tk-17".to_owned(),
            source: format!("receipt-{counter}"),
        }
    }

    fn login(counter: u64, tail: &str) -> LoginEntry {
        LoginEntry {
            device_number: "77000123".to_owned(),
            epoch: 7,
            nonce: nonce(counter, tail),
            role_id: "ops.dc.senior".to_owned(),
            level: 2,
            ticket_number: Some("tk-17".to_owned()),
            outcome: "success".to_owned(),
        }
    }

    #[test]
    fn a_matching_pair_raises_nothing() {
        let report = reconcile(&[receipt(1, "4711")], Some(&[login(1, "4711")]), verified());
        assert!(report.is_complete());
        assert!(!report.has_findings());
        assert!(report.to_string().contains("no findings"));
    }

    #[test]
    fn a_login_nobody_wrote_a_receipt_for_is_reported() {
        let report = reconcile(&[], Some(&[login(1, "4711")]), verified());
        assert_eq!(report.logins_without_receipt.len(), 1);
        assert!(report.to_string().contains("login-without-receipt"));
    }

    #[test]
    fn a_receipt_no_device_saw_is_reported() {
        let report = reconcile(&[receipt(1, "4711")], Some(&[]), verified());
        assert_eq!(report.receipts_without_login.len(), 1);
        assert!(report.to_string().contains("receipt-without-login"));
    }

    #[test]
    fn two_challenges_on_one_counter_are_reported() {
        let report = reconcile(
            &[receipt(1, "4711"), receipt(1, "0815")],
            Some(&[login(1, "4711")]),
            verified(),
        );
        assert_eq!(report.series_on_one_counter.len(), 1);
        let series = report.series_on_one_counter.first().unwrap();
        assert_eq!(series.counter, 1);
        assert_eq!(series.nonces.len(), 2);
        assert_eq!(series.receipts, 2);
    }

    /// Повтор с тем же nonce — законный сорванный звонок, и он всё равно виден.
    /// Отчёт, считавший только различные nonce, здесь молчал.
    #[test]
    fn a_repeat_on_one_counter_with_the_same_nonce_is_reported() {
        let report = reconcile(
            &[receipt(1, "4711"), receipt(1, "4711")],
            Some(&[login(1, "4711")]),
            verified(),
        );
        assert_eq!(report.series_on_one_counter.len(), 1);
        let series = report.series_on_one_counter.first().unwrap();
        assert_eq!(series.receipts, 2);
        assert_eq!(series.nonces.len(), 1);
        assert!(report.to_string().contains("receipts=2"));
    }

    #[test]
    fn one_receipt_and_its_login_are_not_a_series() {
        let report = reconcile(&[receipt(1, "4711")], Some(&[login(1, "4711")]), verified());
        assert!(report.series_on_one_counter.is_empty());
    }

    #[test]
    fn a_pair_that_disagrees_about_the_role_is_reported() {
        let mut login = login(1, "4711");
        login.role_id = "ops.dc.root".to_owned();
        let report = reconcile(&[receipt(1, "4711")], Some(&[login]), verified());
        assert_eq!(report.disagreements.len(), 1);
        assert_eq!(report.disagreements.first().unwrap().fields, vec!["role"]);
    }

    #[test]
    fn a_report_without_the_device_side_says_so() {
        let report = reconcile(&[receipt(1, "4711")], None, verified());
        assert!(!report.is_complete());
        assert!(report.to_string().contains("incomplete"));
        assert!(report.logins_without_receipt.is_empty());
        assert!(report.receipts_without_login.is_empty());
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
        serde_json::json!({
            "op": "code_login",
            "nonce_ref": nonce,
            "role_id": "ops.dc.senior",
            "level": 2,
            "epoch": 7,
            "ticket_no": "tk-17",
            "outcome": outcome,
        })
    }

    /// Тот формат, который устройство пишет на самом деле, читается сверкой.
    ///
    /// До правки каждая строка отбрасывалась как «другое событие», множество
    /// входов выходило пустым — и отчёт объявлялся полным.
    #[test]
    fn the_form_the_device_actually_writes_is_read() {
        let text = device_chain(&[device_login("0000014711", "success")]);
        let journal = read_journal("77000123", &text, &FleetParams::defaults()).unwrap();

        assert_eq!(journal.entries.len(), 1, "строка входа не найдена: {text}");
        assert_eq!(journal.entries.first().unwrap().nonce.counter(), 1);
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

    /// Выгрузка без цепочки принимается, но отчёт об этом говорит: строку из
    /// неё удаляют без следа.
    #[test]
    fn an_export_without_a_chain_is_read_and_marked_unverified() {
        let text = concat!(
            r#"{"event":"qr_code_login","nonce_ref":"0000014711","role_id":"ops.dc.senior","level":2,"epoch":7,"ticket_no":"tk-17","outcome":"success"}"#,
            "\n"
        );
        let journal = read_journal("77000123", text, &FleetParams::defaults()).unwrap();
        assert_eq!(journal.entries.len(), 1);
        assert!(!journal.chain_verified);

        let report = reconcile(
            &[],
            Some(&journal.entries),
            Provenance {
                chain_verified: journal.chain_verified,
                unsigned_from_seq: journal.unsigned_from_seq,
            },
        );
        assert!(report.to_string().contains("unverified"));
    }

    /// Незаверенный хвост назван в отчёте: цепочка держит всё до последнего
    /// заверения, а после него строку можно уронить, оставив валидный префикс.
    #[test]
    fn an_unsigned_tail_is_named_in_the_report() {
        let text = device_chain(&[device_login("0000014711", "success")]);
        let journal = read_journal("77000123", &text, &FleetParams::defaults()).unwrap();
        assert_eq!(journal.unsigned_from_seq, Some(0));

        let report = reconcile(
            &[],
            Some(&journal.entries),
            Provenance {
                chain_verified: journal.chain_verified,
                unsigned_from_seq: journal.unsigned_from_seq,
            },
        );
        assert!(report.to_string().contains("unsigned-tail from=0"));
    }

    #[test]
    fn a_journal_yields_its_code_login_lines_only() {
        let text = concat!(
            r#"{"event":"session_open","user":"root"}"#,
            "\n",
            r#"{"event":"qr_code_login","nonce_ref":"0000014711","role_id":"ops.dc.senior","level":2,"epoch":7,"ticket_no":"tk-17","outcome":"success"}"#,
            "\n",
            r#"{"event":"qr_code_login","nonce_ref":"-","role_id":"ops.dc.senior","level":2,"epoch":7,"outcome":"denied","reason":"no_ticket"}"#,
            "\n"
        );
        let journal = read_journal("77000123", text, &FleetParams::defaults()).unwrap();
        assert_eq!(journal.entries.len(), 1);
        assert_eq!(journal.entries.first().unwrap().nonce.counter(), 1);
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
        let text = r#"{"event":"qr_code_login","nonce_ref":"0000014711","level":2,"epoch":7,"outcome":"success"}"#;
        assert_eq!(
            read_journal("77000123", text, &FleetParams::defaults()),
            Err(JournalError::MissingField {
                line: 1,
                field: "role_id"
            })
        );
    }
}
