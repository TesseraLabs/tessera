//! The issuance ledger: where the counter history actually lives.
//!
//! The nonce counter is the only thing standing between a recorded telephone
//! call and a code issued a second time, and it is checked against what the
//! operator's own side remembers. That memory therefore has to be something the
//! operator cannot quietly edit — otherwise the check is a formality that anyone
//! who wants to bypass it simply deletes.
//!
//! A directory of receipt files is not such a memory. Files can be renamed,
//! moved aside or left out one at a time, and a run that reads the directory
//! sees whatever remains as the truth: remove the receipts of counters 41 to 57
//! and a challenge at 41 reads as the ordinary next call. The ledger closes
//! that: it is one hash-chained file (the same chain the issuance journal of
//! this crate uses), it is read instead of the directory, and every issuance
//! appends to it.
//!
//! # What this does and does not prevent
//!
//! Stated plainly, because a memory of this kind is easy to oversell and the
//! difference decides what an auditor may conclude from it:
//!
//! - **Editing a line, reordering lines, or dropping one from the middle is
//!   prevented.** The chain does not verify, and a broken chain is a refusal —
//!   never an empty history. "Somebody edited this" and "this operator has not
//!   issued anything yet" must not lead to the same decision.
//! - **Dropping the tail — or editing its last line — is not caught by the
//!   chain**, and no hash chain catches it: a prefix of a valid chain is a valid
//!   chain, and nothing yet covers the newest line. What catches it is
//!   the second store — the receipt files themselves. The counter control takes
//!   the *later* of what the ledger says and what the receipts say
//!   ([`crate::codes::store::last_known_counter`]), so rolling the counter back
//!   means editing both, and the receipts that would have to disappear are
//!   named after the device, the epoch and the counter they belong to.
//! - **Deleting everything is not prevented** — nothing on a machine its owner
//!   controls can be. It is made expensive and visible instead: a fresh history
//!   admits only the first counter of an epoch, one ledger serves every device
//!   of the operator (so erasing it to replay one device blocks every other
//!   device past its first call), and each receipt records how deep the history
//!   was when it was written ([`crate::codes::annex`]) — a receipt claiming no
//!   history behind a run that claimed one is what a deleted ledger looks like
//!   afterwards.
//! - **The device journals are the backstop.** They are on the devices, and a
//!   code that was used without a receipt shows up in the reconciliation.
//!
//! None of this makes an operator's own machine trustworthy against that
//! operator. It makes a bypass leave marks in places that are not all in one
//! hand.
//!
//! # Why the same chain as the issuance journal
//!
//! Because it is already written, already verified line by line, and already
//! understood by whoever reads issuance journals. A second chain implementation
//! would be a second thing to get wrong, and this one is not a place to be
//! clever.

use std::path::{Path, PathBuf};

use tessera_codes_contract::device_number::CheckedDeviceNumber;
use tessera_codes_contract::key::Epoch;
use tessera_codes_contract::time::ClaimedTime;

use crate::codes::counter::KnownCounter;
use crate::journal::{
    verify_lines, FileStorage, Journal, JournalError, JournalStatus, JournalStorage as _,
};

/// Name of the ledger inside a receipts directory.
pub const LEDGER_FILENAME: &str = "ledger.ndjson";

/// Namespace every issuance is recorded under.
pub const LEDGER_KIND: &str = "codes.issue";

/// One issuance, as the ledger records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    /// Device the code was issued for, in its significant form.
    pub device_number: String,
    /// Key epoch the code was issued under.
    pub epoch: u32,
    /// Nonce counter of the issuance.
    pub counter: u64,
    /// Nonce of the issuance.
    pub nonce: String,
    /// Role the code granted.
    pub role_id: String,
    /// Level of that role.
    pub level: u32,
    /// Ticket the operator worked under.
    pub ticket_number: String,
    /// Operator who handled the call.
    pub operator_id: String,
    /// What the counter said about the call.
    pub counter_note: String,
    /// The second operator who approved an override, if there was one.
    pub approver: Option<String>,
    /// Grounds recorded for the issuance.
    pub reason: String,
    /// Name of the receipt file this issuance was written to.
    ///
    /// It is recorded before the receipt exists, so a ledger entry without its
    /// receipt is a visible fact rather than a silent gap.
    pub receipt: String,
}

/// The issuance history of one operator's directory.
#[derive(Debug)]
pub struct Ledger {
    journal: Journal<FileStorage>,
    entries: Vec<LedgerEntry>,
    path: PathBuf,
}

impl Ledger {
    /// Opens the ledger of a receipts directory, verifying its chain.
    ///
    /// A file that is not there yet is a fresh ledger — the ordinary state of an
    /// operator's first call, and no more permissive than an empty history ever
    /// was: [`Ledger::last_known`] returns [`None`], and the counter control
    /// admits only the first counter of the epoch.
    ///
    /// # Errors
    ///
    /// [`LedgerError::Broken`] when the chain does not verify — a line altered,
    /// reordered or removed. It is a refusal and not an empty history on
    /// purpose: "somebody edited this" and "this operator has not issued
    /// anything yet" must never lead to the same decision.
    ///
    /// [`LedgerError::Io`] when the file cannot be read, and
    /// [`LedgerError::Malformed`] when a line of the chain is not an issuance
    /// this crate wrote.
    pub fn open(path: &Path) -> Result<Self, LedgerError> {
        let journal = Journal::load(FileStorage::new(path)).map_err(LedgerError::from)?;
        let lines = journal.storage().read_lines().map_err(LedgerError::from)?;

        if let JournalStatus::Broken { position } = verify_lines(&lines).status {
            return Err(LedgerError::Broken {
                path: path.to_path_buf(),
                position,
            });
        }

        let mut entries = Vec::new();
        for line in &lines {
            if let Some(entry) = parse_entry(line)? {
                entries.push(entry);
            }
        }
        Ok(Self {
            journal,
            entries,
            path: path.to_path_buf(),
        })
    }

    /// Reports whether the ledger records no issuance at all.
    #[must_use]
    pub fn is_fresh(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns where the ledger says a device was left.
    ///
    /// The latest entry is the one of the highest epoch, and within it the
    /// highest counter — not the last line written: the order of the file is the
    /// order of the calls, but a device can be served between calls to another.
    #[must_use]
    pub fn last_known(&self, device_number: &CheckedDeviceNumber) -> Option<KnownCounter> {
        self.entries
            .iter()
            .filter(|entry| entry.device_number == device_number.significant())
            .max_by_key(|entry| (entry.epoch, entry.counter))
            .map(|entry| KnownCounter {
                epoch: Epoch::new(entry.epoch),
                counter: entry.counter,
                nonce: entry.nonce.clone(),
            })
    }

    /// Returns how many issuances the ledger records for a device.
    ///
    /// The depth travels into the receipt, where it survives the ledger itself:
    /// a receipt claiming no history behind a run of receipts that claimed one
    /// is what a deleted ledger looks like afterwards.
    #[must_use]
    pub fn depth(&self, device_number: &CheckedDeviceNumber) -> u64 {
        self.entries
            .iter()
            .filter(|entry| entry.device_number == device_number.significant())
            .count()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    /// Appends one issuance to the chain.
    ///
    /// # Errors
    ///
    /// [`LedgerError::Io`] when the line cannot be durably appended. The chain
    /// state is left untouched on failure, so a caller that refuses to release
    /// the code after this error leaves neither a code nor a record.
    pub fn record(&mut self, entry: &LedgerEntry, now: ClaimedTime) -> Result<(), LedgerError> {
        let data = serde_json::json!({
            "device": entry.device_number,
            "epoch": entry.epoch,
            "counter": entry.counter,
            "nonce": entry.nonce,
            "role": entry.role_id,
            "level": entry.level,
            "ticket": entry.ticket_number,
            "operator": entry.operator_id,
            "counter_note": entry.counter_note,
            "approver": entry.approver,
            "reason": entry.reason,
            "receipt": entry.receipt,
        });
        self.journal
            .append_annotation(LEDGER_KIND, data, now.get())
            .map_err(LedgerError::from)?;
        self.entries.push(entry.clone());
        Ok(())
    }

    /// Returns the path the ledger lives at.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Reads one chain line as an issuance, or [`None`] when it records something
/// else.
fn parse_entry(line: &str) -> Result<Option<LedgerEntry>, LedgerError> {
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|error| LedgerError::Malformed(error.to_string()))?;
    if value.get("kind").and_then(serde_json::Value::as_str) != Some(LEDGER_KIND) {
        return Ok(None);
    }
    let data = value
        .get("data")
        .ok_or_else(|| LedgerError::Malformed("an issuance line carries no data".to_owned()))?;

    let text = |name: &str| -> Result<String, LedgerError> {
        data.get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| LedgerError::Malformed(format!("an issuance line carries no `{name}`")))
    };
    let number = |name: &str| -> Result<u64, LedgerError> {
        data.get(name)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| LedgerError::Malformed(format!("an issuance line carries no `{name}`")))
    };
    let level = number("level")?;

    Ok(Some(LedgerEntry {
        device_number: text("device")?,
        epoch: u32::try_from(number("epoch")?)
            .map_err(|_| LedgerError::Malformed("an epoch beyond the format".to_owned()))?,
        counter: number("counter")?,
        nonce: text("nonce")?,
        role_id: text("role")?,
        level: u32::try_from(level)
            .map_err(|_| LedgerError::Malformed("a level beyond the format".to_owned()))?,
        ticket_number: text("ticket")?,
        operator_id: text("operator")?,
        counter_note: text("counter_note")?,
        approver: data
            .get("approver")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        reason: text("reason")?,
        receipt: text("receipt")?,
    }))
}

/// Failure of the issuance ledger.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LedgerError {
    /// The chain does not verify.
    #[error("the issuance ledger {path} is broken at position {position}: a line was altered, reordered or removed, and a history that has been edited is not a history")]
    Broken {
        /// The ledger that failed.
        path: PathBuf,
        /// Zero-based position of the first invalid line.
        position: u64,
    },
    /// A line of the chain is not an issuance this crate wrote.
    #[error("the issuance ledger holds a line this build cannot read: {0}")]
    Malformed(String),
    /// The ledger could not be read or written.
    #[error("the issuance ledger could not be read or written: {0}")]
    Io(String),
}

impl From<JournalError> for LedgerError {
    fn from(error: JournalError) -> Self {
        Self::Io(error.to_string())
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{Ledger, LedgerEntry, LedgerError, LEDGER_FILENAME};
    use crate::codes::tests::fixtures;
    use tessera_codes_contract::time::ClaimedTime;

    fn entry(counter: u64, nonce: &str) -> LedgerEntry {
        LedgerEntry {
            device_number: "77000123S".to_owned(),
            epoch: 7,
            counter,
            nonce: nonce.to_owned(),
            role_id: "ops.dc.senior".to_owned(),
            level: 2,
            ticket_number: "tk-17".to_owned(),
            operator_id: "op-42".to_owned(),
            counter_note: "advanced".to_owned(),
            approver: None,
            reason: "work order 42".to_owned(),
            receipt: format!("receipt-{counter}.receipt"),
        }
    }

    #[test]
    fn a_ledger_that_does_not_exist_yet_is_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::open(&dir.path().join(LEDGER_FILENAME)).unwrap();
        assert!(ledger.is_fresh());
        assert_eq!(ledger.last_known(&fixtures::device_number()), None);
        assert_eq!(ledger.depth(&fixtures::device_number()), 0);
    }

    #[test]
    fn what_was_recorded_is_what_comes_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LEDGER_FILENAME);
        let mut ledger = Ledger::open(&path).unwrap();
        ledger
            .record(&entry(1, "0000014711"), ClaimedTime::new(10))
            .unwrap();
        ledger
            .record(&entry(2, "0000020815"), ClaimedTime::new(20))
            .unwrap();

        let reopened = Ledger::open(&path).unwrap();
        assert!(!reopened.is_fresh());
        let known = reopened.last_known(&fixtures::device_number()).unwrap();
        assert_eq!(known.counter, 2);
        assert_eq!(known.nonce, "0000020815");
        assert_eq!(reopened.depth(&fixtures::device_number()), 2);
    }

    #[test]
    fn another_device_has_a_history_of_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LEDGER_FILENAME);
        let mut ledger = Ledger::open(&path).unwrap();
        ledger
            .record(&entry(5, "0000054711"), ClaimedTime::new(10))
            .unwrap();

        assert_eq!(ledger.last_known(&fixtures::other_device_number()), None);
        assert_eq!(ledger.depth(&fixtures::other_device_number()), 0);
    }

    /// Removing history is what the ledger exists to catch: the receipts of a
    /// directory can be moved aside, its chain cannot.
    #[test]
    fn a_line_removed_from_the_middle_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LEDGER_FILENAME);
        let mut ledger = Ledger::open(&path).unwrap();
        for counter in 1..=3 {
            ledger
                .record(
                    &entry(counter, &format!("00000{counter}4711")),
                    ClaimedTime::new(counter),
                )
                .unwrap();
        }

        let text = std::fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text
            .lines()
            .filter(|line| !line.contains("\"counter\":2"))
            .collect();
        std::fs::write(&path, format!("{}\n", kept.join("\n"))).unwrap();

        assert!(matches!(
            Ledger::open(&path),
            Err(LedgerError::Broken { .. })
        ));
    }

    /// Editing a line the chain covers is caught; editing the newest one is
    /// not, and the module says so rather than leaving a reader to assume the
    /// chain covers everything.
    #[test]
    fn a_line_edited_in_place_breaks_the_chain_unless_it_is_the_newest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LEDGER_FILENAME);
        let mut ledger = Ledger::open(&path).unwrap();
        ledger
            .record(&entry(7, "0000074711"), ClaimedTime::new(10))
            .unwrap();
        ledger
            .record(&entry(8, "0000080815"), ClaimedTime::new(20))
            .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("\"counter\":7", "\"counter\":1")).unwrap();
        assert!(matches!(
            Ledger::open(&path),
            Err(LedgerError::Broken { .. })
        ));

        // The newest line carries nothing after it, so nothing covers it. What
        // covers it is the receipt of that same issuance — see the module.
        std::fs::write(&path, text.replace("\"counter\":8", "\"counter\":2")).unwrap();
        let reopened = Ledger::open(&path).unwrap();
        assert_eq!(
            reopened
                .last_known(&fixtures::device_number())
                .unwrap()
                .counter,
            7
        );
    }

    /// Обрезанный хвост цепочкой НЕ ловится — префикс валидной цепочки валиден.
    /// Имя теста говорит именно это: поиск по «truncated tail» должен приводить
    /// к правде, а не к зелёному тесту, внушающему обратное.
    #[test]
    fn a_truncated_tail_verifies_and_only_shortens_the_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LEDGER_FILENAME);
        let mut ledger = Ledger::open(&path).unwrap();
        for counter in 1..=3 {
            ledger
                .record(
                    &entry(counter, &format!("00000{counter}4711")),
                    ClaimedTime::new(counter),
                )
                .unwrap();
        }

        // Дропнутый хвост — самый дешёвый способ «отмотать» счётчик назад.
        let text = std::fs::read_to_string(&path).unwrap();
        let head: Vec<&str> = text.lines().take(1).collect();
        std::fs::write(&path, format!("{}\n", head.join("\n"))).unwrap();

        // A prefix of a valid chain verifies — this is the case the chain
        // cannot catch on its own, and the module documents what does: the
        // receipts of the same directory, and the depth recorded in them.
        let reopened = Ledger::open(&path).unwrap();
        assert_eq!(reopened.depth(&fixtures::device_number()), 1);
    }
}
