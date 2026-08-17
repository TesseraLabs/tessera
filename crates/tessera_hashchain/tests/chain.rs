//! The guarantees the shared chain owes every journal built on it.
//!
//! Each test is one sentence an auditor would want to be true: an edited line is
//! caught, a removed one is caught, two swapped ones are caught, the reported
//! position is the first line that stopped adding up, and a live journal whose
//! tail is not yet signed reads as intact rather than as broken.

#![expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
#![expect(
    clippy::indexing_slicing,
    reason = "a test that indexes past its own fixture should fail the test on the spot"
)]

use serde::{Deserialize, Serialize};

use tessera_hashchain::storage::{FailingStorage, MemoryStorage};
use tessera_hashchain::{
    sha256, verify_lines, Annotation, Chain, ChainPayload, ChainStatus, EntryKind, HeadSignature,
};

/// A payload standing in for a real journal's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op")]
enum TestPayload {
    #[serde(rename = "thing_happened")]
    ThingHappened { what: String },
    #[serde(rename = "head_signature")]
    HeadSignature(HeadSignature),
    #[serde(rename = "annotation")]
    Annotation(Annotation),
}

impl ChainPayload for TestPayload {
    const GENESIS_PREIMAGE: &'static [u8] = b"tessera-hashchain/test/genesis";

    fn kind(&self) -> EntryKind {
        match self {
            TestPayload::HeadSignature(_) => EntryKind::HeadSignature,
            _ => EntryKind::Record,
        }
    }

    fn is_structurally_valid(&self) -> bool {
        match self {
            TestPayload::Annotation(annotation) => annotation.is_structurally_valid(),
            _ => true,
        }
    }
}

/// The same payload under a different anchor — used to show that a line does
/// not travel between journals.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
struct OtherPayload(TestPayload);

impl ChainPayload for OtherPayload {
    const GENESIS_PREIMAGE: &'static [u8] = b"tessera-hashchain/other/genesis";

    fn kind(&self) -> EntryKind {
        self.0.kind()
    }

    fn is_structurally_valid(&self) -> bool {
        self.0.is_structurally_valid()
    }
}

pub(crate) fn event(what: &str) -> TestPayload {
    TestPayload::ThingHappened {
        what: what.to_owned(),
    }
}

fn chain_of(count: u64) -> Chain<MemoryStorage, TestPayload> {
    let mut chain = Chain::<MemoryStorage, TestPayload>::load(MemoryStorage::new()).unwrap();
    for index in 0..count {
        chain
            .append(&event(&format!("event {index}")), 1_700_000_000 + index)
            .unwrap();
    }
    chain
}

#[test]
fn an_untouched_chain_verifies_with_its_tail_unsigned() {
    let report = chain_of(3).verify().unwrap();
    assert_eq!(
        report.status,
        ChainStatus::IntactUnsignedTail {
            unsigned_from_seq: 0
        }
    );
    assert_eq!(report.entry_count, 3);
    assert_eq!(report.last_signed_seq, None);
}

#[test]
fn the_line_format_is_the_one_the_documentation_promises() {
    let chain = chain_of(1);
    let line = chain.storage().lines().first().unwrap().clone();
    let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();

    assert_eq!(parsed["seq"], 0);
    assert_eq!(parsed["ts"], 1_700_000_000_u64);
    assert_eq!(parsed["op"], "thing_happened");
    assert_eq!(parsed["what"], "event 0");
    // The first line points at the SHA-256 of the journal's genesis preimage.
    assert_eq!(
        parsed["prev_hash"],
        hex::encode(sha256(TestPayload::GENESIS_PREIMAGE))
    );
}

#[test]
fn a_signed_head_covers_everything_before_it() {
    let mut chain = chain_of(2);
    chain
        .append(
            &TestPayload::HeadSignature(HeadSignature {
                algorithm: "test-sig".to_owned(),
                signature: "bm90IHJlYWw=".to_owned(),
            }),
            1_700_000_100,
        )
        .unwrap();

    let report = chain.verify().unwrap();
    assert_eq!(report.status, ChainStatus::Intact);
    assert_eq!(report.last_signed_seq, Some(2));

    // …and stops covering as soon as the journal keeps living.
    chain.append(&event("after"), 1_700_000_200).unwrap();
    let report = chain.verify().unwrap();
    assert_eq!(
        report.status,
        ChainStatus::IntactUnsignedTail {
            unsigned_from_seq: 3
        }
    );
    assert_eq!(report.last_signed_seq, Some(2));
}

#[test]
fn an_edited_line_breaks_the_chain_at_the_line_after_it() {
    let chain = chain_of(4);
    let mut lines = chain.storage().lines();
    lines[1] = lines[1].replace("event 1", "event X");

    // The edited line still links to its own predecessor; what no longer holds
    // is the `prev_hash` of the line that followed it.
    assert_eq!(
        verify_lines::<TestPayload>(&lines).status,
        ChainStatus::Broken { position: 2 },
    );
}

#[test]
fn a_removed_line_breaks_the_chain_at_the_position_it_left_behind() {
    let chain = chain_of(4);
    let mut lines = chain.storage().lines();
    lines.remove(2);

    // Position 2 now holds what was line 3: its `seq` is 3 where 2 is due.
    assert_eq!(
        verify_lines::<TestPayload>(&lines).status,
        ChainStatus::Broken { position: 2 },
    );
}

#[test]
fn two_reordered_lines_break_the_chain() {
    let chain = chain_of(4);
    let mut lines = chain.storage().lines();
    lines.swap(1, 2);

    assert_eq!(
        verify_lines::<TestPayload>(&lines).status,
        ChainStatus::Broken { position: 1 },
    );
}

#[test]
fn a_line_does_not_travel_between_journals() {
    let lines = chain_of(2).storage().lines();

    // The same bytes read as another journal's: the anchor differs, so the very
    // first line fails to link.
    assert_eq!(
        verify_lines::<OtherPayload>(&lines).status,
        ChainStatus::Broken { position: 0 },
    );
}

#[test]
fn an_annotation_chains_like_anything_else() {
    let mut chain = chain_of(1);
    chain
        .append(
            &TestPayload::Annotation(Annotation {
                kind: "test.reconciliation".to_owned(),
                data: serde_json::json!({ "receipts": 3 }),
            }),
            1_700_000_050,
        )
        .unwrap();
    chain.append(&event("after"), 1_700_000_060).unwrap();

    assert!(matches!(
        chain.verify().unwrap().status,
        ChainStatus::IntactUnsignedTail { .. }
    ));

    // Removing it is exactly as visible as removing an event.
    let mut lines = chain.storage().lines();
    lines.remove(1);
    assert_eq!(
        verify_lines::<TestPayload>(&lines).status,
        ChainStatus::Broken { position: 1 },
    );
}

/// An annotation with no namespace tag, or with a bare value where the format
/// promises an object, parses as JSON and is still not a line the format admits.
#[test]
fn a_hand_written_annotation_that_the_format_does_not_admit_is_a_break() {
    for data in [serde_json::json!({}), serde_json::json!("bare")] {
        let kind = if data.is_object() { "" } else { "test.kind" };
        let mut chain = Chain::<MemoryStorage, TestPayload>::load(MemoryStorage::new()).unwrap();
        chain
            .append(
                &TestPayload::Annotation(Annotation {
                    kind: kind.to_owned(),
                    data,
                }),
                1,
            )
            .unwrap();

        assert_eq!(
            chain.verify().unwrap().status,
            ChainStatus::Broken { position: 0 },
        );
    }
}

/// A storage failure must leave the chain exactly where it was: the caller
/// refuses the action, and a refused action that left a record behind would be
/// worse than no record at all.
#[test]
fn a_failed_append_leaves_the_chain_untouched() {
    let mut chain = Chain::<FailingStorage, TestPayload>::load(FailingStorage).unwrap();
    let head_before = chain.head();
    assert!(chain.append(&event("never lands"), 1).is_err());
    assert_eq!(chain.head(), head_before);
    assert_eq!(chain.next_seq(), 0);
}

/// Two writers on one file at the same time.
///
/// `sshd` forks per connection, so two logins appending to one journal is the
/// ordinary case on a device, not a contrived one. Without a hold covering the
/// read-then-write, both writers see the same tail, both claim the same `seq`
/// and the same `prev_hash`, and the chain is broken from that position — for
/// good, because opening a broken chain is allowed on purpose and the journal
/// keeps growing past the break. Neither write fails, so nothing says so until
/// somebody reads the journal during an incident.
mod concurrency {
    use std::sync::{Arc, Barrier};

    use tessera_hashchain::storage::FileStorage;
    use tessera_hashchain::{verify_lines, Chain, ChainStatus};

    use super::{event, TestPayload};

    /// Writers, and records each of them appends.
    const WRITERS: usize = 8;
    const PER_WRITER: usize = 12;

    #[test]
    fn concurrent_appends_to_one_journal_leave_an_unbroken_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.ndjson");

        // Every writer opens its own chain over the same file, exactly as two
        // forked processes would, and they are released together so the writes
        // actually overlap.
        let barrier = Arc::new(Barrier::new(WRITERS));
        let mut writers = Vec::new();
        for writer in 0..WRITERS {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            writers.push(std::thread::spawn(move || {
                let mut chain =
                    Chain::<FileStorage, TestPayload>::load(FileStorage::new(&path)).unwrap();
                barrier.wait();
                for index in 0..PER_WRITER {
                    chain
                        .append(
                            &event(&format!("writer {writer} record {index}")),
                            1_700_000_000,
                        )
                        .unwrap();
                }
            }));
        }
        for writer in writers {
            writer.join().unwrap();
        }

        let lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(
            lines.len(),
            WRITERS * PER_WRITER,
            "records were lost or duplicated under concurrent appends",
        );

        let report = verify_lines::<TestPayload>(&lines);
        assert!(
            matches!(report.status, ChainStatus::IntactUnsignedTail { .. }),
            "concurrent appends broke the chain: {:?}",
            report.status,
        );
    }
}

/// The mode of the journal must not depend on who created it.
///
/// `open(2)` filters its mode argument through the process umask, so a daemon
/// started with a lax one would otherwise decide the permissions of the record.
/// A journal writable by group or other is not a weaker journal — it is a
/// decorative one: the chain is not keyed, so anyone allowed to write can
/// rewrite the history and recompute every link, and the edit that the chain
/// exists to make visible becomes invisible.
#[cfg(unix)]
mod permissions {
    use std::os::unix::fs::PermissionsExt as _;

    use tessera_hashchain::storage::FileStorage;
    use tessera_hashchain::{Chain, ChainStorage as _};

    use super::{event, TestPayload};

    /// Runs `body` under a deliberately wide-open umask.
    ///
    /// The umask is process-wide, so this is the one place in the crate that
    /// touches it and it puts the old value back immediately.
    fn with_permissive_umask<T>(body: impl FnOnce() -> T) -> T {
        use rustix::fs::Mode;
        use rustix::process::umask;

        let previous = umask(Mode::empty());
        let outcome = body();
        umask(previous);
        outcome
    }

    fn mode_of(path: &std::path::Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_journal_created_under_a_lax_umask_is_still_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.ndjson");

        with_permissive_umask(|| {
            let mut chain =
                Chain::<FileStorage, TestPayload>::load(FileStorage::new(&path)).unwrap();
            chain
                .append(&event("under a lax umask"), 1_700_000_000)
                .unwrap();
        });

        assert_eq!(
            mode_of(&path),
            0o600,
            "the journal took its permissions from the umask; anyone allowed to write it can \
             rewrite the history and recompute the chain over it",
        );
        // The lock beside it is held to the same rule: a file anyone may
        // replace is a lock anyone may take somewhere else.
        assert_eq!(mode_of(&dir.path().join("audit.ndjson.lock")), 0o600);
    }

    /// A journal that became group- or world-writable after it was created is
    /// narrowed back on the next append, not left as found.
    ///
    /// Pinning only at creation would defend a file for exactly as long as
    /// nobody touched it. Whoever may write this file may rewrite the history
    /// and recompute the chain over it, so a widened mode is not a lesser
    /// version of the guarantee — it is the absence of it.
    #[test]
    fn a_journal_that_was_widened_is_narrowed_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.ndjson");

        let mut chain = Chain::<FileStorage, TestPayload>::load(FileStorage::new(&path)).unwrap();
        chain.append(&event("first"), 1_700_000_000).unwrap();
        assert_eq!(mode_of(&path), 0o600);

        // Somebody opens it up — a careless `chmod`, a restore from an archive
        // that did not carry modes, an installer with its own ideas.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(mode_of(&path), 0o666);

        chain.append(&event("second"), 1_700_000_001).unwrap();
        assert_eq!(
            mode_of(&path),
            0o600,
            "a world-writable journal stayed world-writable",
        );
        assert_eq!(chain.storage().read_lines().unwrap().len(), 2);
    }
}
