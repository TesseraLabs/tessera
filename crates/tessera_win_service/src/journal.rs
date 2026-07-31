//! The service journal: an append-only, hash-chained NDJSON record of what the
//! service decided.
//!
//! Every line carries a monotonic `seq`, the SHA-256 of the previous line
//! (`prev_hash`; the first line chains to a fixed genesis anchor), a timestamp
//! and an event. Altering, deleting or reordering a line breaks the chain, and
//! [`verify_lines`] reports the position of the first line that no longer fits.
//!
//! The chain is the same construction the issuance journal uses, with its own
//! genesis anchor so a line can never be moved between the two records. It is
//! deliberately re-stated here rather than shared: that journal's line format is
//! a catalogue of issuance operations, and a login record has no place in it.
//!
//! # Fail-closed
//!
//! An admission that cannot be journaled is not an admission. The journal is
//! wired into the verification flow as its monitor client
//! ([`JournalMonitor`]), which is the point where the flow already refuses a
//! session it could not register — so a full disk or a broken ACL denies the
//! login instead of opening an unrecorded one.
//!
//! No secret is ever written: not the PIN, not the technical account's
//! password, not the credential's key material.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// The fixed domain-separation preimage whose SHA-256 anchors an empty chain.
const GENESIS_PREIMAGE: &[u8] = b"tessera-engine-journal/v1/genesis";

/// Why a line could not be recorded.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// The backing file could not be opened, appended to, or read.
    #[error("journal storage unavailable: {0}")]
    Storage(#[from] std::io::Error),
    /// A record could not be serialized.
    #[error("journal record encoding failed: {0}")]
    Encoding(#[from] serde_json::Error),
}

/// What a journal line records.
///
/// Serialized flat next to the chain metadata, so one line is one JSON object
/// whose `event` field selects the variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// The service started and is listening.
    ServiceStarted {
        /// Build version of the service.
        version: String,
        /// Pipe the service listens on.
        pipe: String,
    },
    /// The service stopped on request from the service control manager.
    ServiceStopped,
    /// A credential was accepted and a session was opened for it.
    SessionOpened(SessionRecord),
    /// A session ended.
    SessionClosed {
        /// Correlation id from the matching [`Event::SessionOpened`].
        session_id: String,
        /// Why it ended.
        reason: String,
    },
    /// An attempt was refused. The coarse reason the client sees is derived
    /// from `error`; the full text is kept here and nowhere else.
    AttemptDenied {
        /// Correlation id of the refused attempt.
        session_id: String,
        /// Role the attempt was made for.
        role: String,
        /// The refusal, in full.
        error: String,
        /// The code the same failure returns on the PAM path.
        code: i32,
    },
}

/// The identity behind an opened session, as the flow established it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    /// Correlation id shared with the verdict returned to the client.
    pub session_id: String,
    /// Role the session was opened for.
    pub role: Option<String>,
    /// Resolved role slice version.
    pub role_version: Option<u32>,
    /// Common Name of the validated end-entity certificate.
    pub cert_cn: String,
    /// Hex serial of that certificate.
    pub cert_serial: String,
    /// Serial of the media the credential was read from, when known.
    pub usb_serial: Option<String>,
    /// Hex-encoded host id hash of this device.
    pub host_id_hash: String,
}

/// One journal line: chain metadata plus an event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    /// Monotonic position, from 0.
    seq: u64,
    /// Lowercase hex SHA-256 of the previous line; the genesis anchor at 0.
    prev_hash: String,
    /// Unix seconds.
    ts: u64,
    /// The recorded event.
    #[serde(flatten)]
    event: Event,
}

/// SHA-256 of `bytes`.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

/// The anchor a fresh chain's first `prev_hash` points at.
fn genesis_hash() -> [u8; 32] {
    sha256(GENESIS_PREIMAGE)
}

/// An append-only hash-chained journal over one file.
///
/// The file is opened for each append rather than held open: the service writes
/// a handful of lines per login, and a handle held for the life of a service
/// that runs for months is a handle that survives a log rotation nobody
/// notices.
#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    next_seq: u64,
    head: [u8; 32],
}

impl Journal {
    /// Opens the journal at `path`, resuming from its current tail.
    ///
    /// A missing file is an empty chain. New lines chain from the physical last
    /// line: if a stored line was tampered with, the break is reported by
    /// [`verify_lines`], not here — `open` only positions the append point.
    ///
    /// # Errors
    ///
    /// [`JournalError::Storage`] if an existing file cannot be read.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, JournalError> {
        let path = path.into();
        let lines = read_lines(&path)?;
        let next_seq = lines.len() as u64;
        let head = lines
            .last()
            .map_or_else(genesis_hash, |line| sha256(line.as_bytes()));
        Ok(Self {
            path,
            next_seq,
            head,
        })
    }

    /// The `seq` the next appended line will carry.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Appends `event`, stamped `now_unix`.
    ///
    /// Chain state advances only after the line is on disk, so a failed write
    /// leaves the journal exactly as it was.
    ///
    /// # Errors
    ///
    /// [`JournalError::Encoding`] if the event cannot be serialized,
    /// [`JournalError::Storage`] if the line cannot be written and flushed.
    pub fn append(&mut self, event: Event, now_unix: u64) -> Result<(), JournalError> {
        let entry = Entry {
            seq: self.next_seq,
            prev_hash: hex::encode(self.head),
            ts: now_unix,
            event,
        };
        let line = serde_json::to_string(&entry)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        // Without this the line is in a buffer the operating system may still
        // be holding when the machine goes down mid-login — which is exactly
        // the login worth having a record of.
        file.sync_data()?;
        self.head = sha256(line.as_bytes());
        self.next_seq = self.next_seq.saturating_add(1);
        Ok(())
    }

    /// Appends `event` stamped with the current wall clock.
    ///
    /// # Errors
    ///
    /// See [`Journal::append`].
    pub fn append_now(&mut self, event: Event) -> Result<(), JournalError> {
        self.append(event, now_unix())
    }

    /// The lines currently stored.
    ///
    /// # Errors
    ///
    /// [`JournalError::Storage`] if the file cannot be read.
    pub fn lines(&self) -> Result<Vec<String>, JournalError> {
        read_lines(&self.path)
    }
}

/// Unix seconds now; 0 if the clock is before the epoch, which is not a reason
/// to refuse a login.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Reads every line of `path`, in append order. A missing file has no lines.
fn read_lines(path: &Path) -> Result<Vec<String>, JournalError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text.lines().map(str::to_owned).collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(JournalError::Storage(e)),
    }
}

/// The outcome of verifying a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalStatus {
    /// Every line parses and chains to its predecessor.
    Intact {
        /// How many lines were examined.
        entries: u64,
    },
    /// The line at `position` is missing, reordered, or altered.
    Broken {
        /// Zero-based position of the first invalid line.
        position: u64,
    },
}

/// Verifies `lines` (in append order): recomputes the chain from genesis and
/// checks that `seq` is dense and monotonic from 0.
#[must_use]
pub fn verify_lines(lines: &[String]) -> JournalStatus {
    let mut expected_prev = genesis_hash();
    for (index, line) in lines.iter().enumerate() {
        let position = index as u64;
        let Ok(entry) = serde_json::from_str::<Entry>(line) else {
            return JournalStatus::Broken { position };
        };
        if entry.seq != position {
            return JournalStatus::Broken { position };
        }
        let Some(prev) = decode_hash(&entry.prev_hash) else {
            return JournalStatus::Broken { position };
        };
        if prev != expected_prev {
            return JournalStatus::Broken { position };
        }
        expected_prev = sha256(line.as_bytes());
    }
    JournalStatus::Intact {
        entries: lines.len() as u64,
    }
}

/// Decodes a lowercase-hex 32-byte hash; `None` on anything malformed.
fn decode_hash(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

/// The journal in its role as the verification flow's monitor client.
///
/// The flow notifies a monitor when a session opens and refuses the login if
/// that notification fails. On Linux the monitor is the daemon that enforces
/// continuous presence; this wave has no such enforcement on Windows, so the
/// same notification is spent on the one thing that does exist — the record.
/// Wiring the journal here rather than beside the flow is what makes an
/// unwritable journal deny the login instead of being noticed later.
#[derive(Debug)]
pub struct JournalMonitor {
    journal: Mutex<Journal>,
}

impl JournalMonitor {
    /// Wraps `journal` so the flow can write to it from any connection thread.
    #[must_use]
    pub fn new(journal: Journal) -> Self {
        Self {
            journal: Mutex::new(journal),
        }
    }

    /// Records `event` directly (service lifecycle, refusals).
    ///
    /// # Errors
    ///
    /// [`JournalError`] from the append, or [`JournalError::Storage`] with
    /// `Other` if the lock was poisoned by a panic in another thread — a
    /// poisoned journal is not one to keep writing to.
    pub fn record(&self, event: Event) -> Result<(), JournalError> {
        let mut journal = self.journal.lock().map_err(|_| {
            JournalError::Storage(std::io::Error::other(
                "journal lock poisoned by an earlier panic",
            ))
        })?;
        journal.append_now(event)
    }
}

impl tessera_core::ipc::MonitorClient for JournalMonitor {
    fn hello(&self) -> Result<(), tessera_core::error::IpcError> {
        Ok(())
    }

    fn open_session(
        &self,
        info: &tessera_core::ipc::OpenSessionInfo<'_>,
    ) -> Result<(), tessera_core::error::IpcError> {
        let record = SessionRecord {
            session_id: info.session_id.to_owned(),
            role: info.role.map(str::to_owned),
            role_version: info.role_version,
            cert_cn: info.cert_cn.to_owned(),
            cert_serial: info.cert_serial.to_owned(),
            usb_serial: info.usb_serial.map(str::to_owned),
            host_id_hash: info.host_id_hash.to_owned(),
        };
        self.record(Event::SessionOpened(record)).map_err(|e| {
            tracing::error!(
                target: "tessera.engine.journal",
                error = %e,
                "session could not be journaled; the admission is refused"
            );
            // The flow turns any error here into a denial. `Unavailable` is the
            // honest shape: the record this admission depends on is not there.
            tessera_core::error::IpcError::Unavailable
        })
    }

    fn close_session(
        &self,
        session_id: &str,
        reason: &str,
    ) -> Result<(), tessera_core::error::IpcError> {
        self.record(Event::SessionClosed {
            session_id: session_id.to_owned(),
            reason: reason.to_owned(),
        })
        .map_err(|_| tessera_core::error::IpcError::Unavailable)
    }

    fn ping(&self) -> Result<(), tessera_core::error::IpcError> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn sample_session(id: &str) -> Event {
        Event::SessionOpened(SessionRecord {
            session_id: id.to_owned(),
            role: Some("serv".to_owned()),
            role_version: Some(1),
            cert_cn: "alice".to_owned(),
            cert_serial: "2a".to_owned(),
            usb_serial: Some("USB-1".to_owned()),
            host_id_hash: "abcdef".to_owned(),
        })
    }

    #[test]
    fn empty_journal_verifies_and_starts_at_zero() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::open(dir.path().join("journal.ndjson")).unwrap();
        assert_eq!(journal.next_seq(), 0);
        assert_eq!(
            verify_lines(&journal.lines().unwrap()),
            JournalStatus::Intact { entries: 0 }
        );
    }

    #[test]
    fn appended_lines_chain_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.ndjson");
        let mut journal = Journal::open(&path).unwrap();
        journal
            .append(
                Event::ServiceStarted {
                    version: "0.5.0".to_owned(),
                    pipe: r"\\.\pipe\tessera-engine".to_owned(),
                },
                100,
            )
            .unwrap();
        journal.append(sample_session("s1"), 101).unwrap();
        journal
            .append(
                Event::SessionClosed {
                    session_id: "s1".to_owned(),
                    reason: "logoff".to_owned(),
                },
                102,
            )
            .unwrap();

        let lines = journal.lines().unwrap();
        assert_eq!(lines.len(), 3);
        assert_eq!(verify_lines(&lines), JournalStatus::Intact { entries: 3 });
    }

    /// Reopening must continue the chain rather than restart it — a service
    /// restart in the middle of a shift is the normal case, not the exception.
    #[test]
    fn reopening_resumes_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.ndjson");
        {
            let mut journal = Journal::open(&path).unwrap();
            journal.append(sample_session("s1"), 1).unwrap();
        }
        let mut journal = Journal::open(&path).unwrap();
        assert_eq!(journal.next_seq(), 1);
        journal.append(sample_session("s2"), 2).unwrap();
        assert_eq!(
            verify_lines(&journal.lines().unwrap()),
            JournalStatus::Intact { entries: 2 }
        );
    }

    /// Editing a line has to be visible, and at the line that was edited.
    #[test]
    fn tampering_breaks_the_chain_at_the_edited_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.ndjson");
        let mut journal = Journal::open(&path).unwrap();
        journal.append(sample_session("s1"), 1).unwrap();
        journal.append(sample_session("s2"), 2).unwrap();
        journal.append(sample_session("s3"), 3).unwrap();

        let mut lines = journal.lines().unwrap();
        lines[1] = lines[1].replace("\"alice\"", "\"mallory\"");
        assert_eq!(verify_lines(&lines), JournalStatus::Broken { position: 2 });

        // The edited line itself still parses and still chains to its own
        // predecessor; what it breaks is the successor's `prev_hash`. Dropping
        // a line instead is caught at the position of the dropped line.
        let mut lines = journal.lines().unwrap();
        lines.remove(1);
        assert_eq!(verify_lines(&lines), JournalStatus::Broken { position: 1 });
    }

    /// The monitor path is the one the flow uses; the record it writes has to
    /// verify like any other line.
    #[test]
    fn monitor_records_an_opened_session() {
        use tessera_core::ipc::MonitorClient as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.ndjson");
        let monitor = JournalMonitor::new(Journal::open(&path).unwrap());
        let info = tessera_core::ipc::OpenSessionInfo {
            session_id: "s1",
            pam_user: "serv",
            pam_service: "tessera-engine",
            host_id_hash: "abcdef",
            target: tessera_proto::SessionTarget::Unknown,
            usb_serial: Some("USB-1"),
            usb_vid_pid: None,
            usb_devnode: None,
            cert_cn: "alice",
            cert_serial: "2a",
            engineer_ski: "",
            engineer_cert_sha256: "",
            uid: 0,
            role: Some("serv"),
            role_version: Some(1),
            session_expiry: None,
        };
        monitor.open_session(&info).unwrap();

        let lines = read_lines(&path).unwrap();
        assert_eq!(verify_lines(&lines), JournalStatus::Intact { entries: 1 });
        assert!(lines[0].contains("session_opened"), "line: {}", lines[0]);
        assert!(lines[0].contains("alice"), "line: {}", lines[0]);
    }

    /// A journal that cannot be written denies the admission: the flow reads
    /// this error as "the session was not registered" and refuses.
    #[test]
    fn unwritable_journal_refuses_the_session() {
        use tessera_core::ipc::MonitorClient as _;

        let dir = tempfile::tempdir().unwrap();
        // A journal under a directory that does not exist: reading it is an
        // empty chain, appending to it fails on every platform, without the
        // test depending on a permission model.
        let path = dir.path().join("absent").join("journal.ndjson");
        let monitor = JournalMonitor::new(Journal::open(&path).unwrap());
        let info = tessera_core::ipc::OpenSessionInfo {
            session_id: "s1",
            pam_user: "serv",
            pam_service: "tessera-engine",
            host_id_hash: "abcdef",
            target: tessera_proto::SessionTarget::Unknown,
            usb_serial: None,
            usb_vid_pid: None,
            usb_devnode: None,
            cert_cn: "alice",
            cert_serial: "2a",
            engineer_ski: "",
            engineer_cert_sha256: "",
            uid: 0,
            role: Some("serv"),
            role_version: Some(1),
            session_expiry: None,
        };
        let err = monitor
            .open_session(&info)
            .expect_err("an unwritable journal must refuse");
        assert!(matches!(err, tessera_core::error::IpcError::Unavailable));
    }
}
