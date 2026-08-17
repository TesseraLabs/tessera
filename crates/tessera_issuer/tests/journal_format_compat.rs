//! A journal written before the chain moved into `tessera_hashchain` must read
//! exactly as it did.
//!
//! The lines below are not produced by this build. They are the byte-for-byte
//! form the previous implementation wrote — `seq`, `prev_hash`, `ts` and the
//! flattened `op` payload, chained from the SHA-256 of
//! `tessera-issuance-journal/v1/genesis` — and they are frozen here as
//! literals precisely so that a future change to the serialization cannot pass
//! by being applied to the reader and the writer at once. A journal on an
//! operator's disk has no such symmetry: it was written once, by a build that
//! no longer exists, and it either still verifies or the history is gone.
//!
//! One line of each kind that matters: an issuance, the `codes.issue`
//! annotation the phone-channel ledger appends, and a head signature.

#![expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
#![expect(
    clippy::expect_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
#![expect(
    clippy::indexing_slicing,
    reason = "a test that indexes past its own frozen fixture should fail the test on the spot"
)]

use tessera_issuer::journal::{verify_lines, JournalStatus};

/// An issuance journal as an earlier build left it on disk.
fn journal_written_by_the_previous_build() -> Vec<String> {
    [
        r#"{"seq":0,"prev_hash":"cf9155d836062fbdff126663274d48ba5f2e79e0b6c7723e36c74bdc7a879694","ts":1700000000,"op":"issue_leaf","serial":"2a","parent":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","subject":"CN=shift,O=acme"}"#,
        r#"{"seq":1,"prev_hash":"d74f7164709e4fd77426cde580a21a18050dd35ce7d855882cb80d3cbfc30e46","ts":1700000100,"op":"annotation","kind":"codes.issue","data":{"device":"77000123S","epoch":7,"counter":1,"nonce":"0000014711","role":"ops.dc.senior","level":2,"ticket":"tk-17","operator":"op-42","counter_note":"advanced","approver":null,"reason":"work order 42","receipt":"receipt-1.receipt"}}"#,
        r#"{"seq":2,"prev_hash":"fe4adf323020a04f6461d5bfdd84489a70d12682258dd53fa23260a50da67860","ts":1700000200,"op":"head_signature","algorithm":"ecdsa-sha256","signature":"bm90IHJlYWw="}"#,
    ]
    .iter()
    .map(|line| (*line).to_owned())
    .collect()
}

#[test]
fn a_journal_from_before_the_shared_crate_still_verifies() {
    let report = verify_lines(&journal_written_by_the_previous_build());

    assert_eq!(
        report.status,
        JournalStatus::Intact,
        "a journal written by an earlier build no longer verifies: the on-disk \
         format changed, and every issuance journal in the field became unreadable"
    );
    assert_eq!(report.entry_count, 3);
    assert_eq!(report.last_signed_seq, Some(2));
}

/// The same bytes, with the middle line removed: the chain must still catch it.
/// Reading an old journal is half the guarantee; the other half is that reading
/// it still detects a tamper.
#[test]
fn a_tamper_in_an_old_journal_is_still_caught_at_its_position() {
    let mut lines = journal_written_by_the_previous_build();
    lines.remove(1);

    assert_eq!(
        verify_lines(&lines).status,
        JournalStatus::Broken { position: 1 }
    );
}

/// The line the phone-channel ledger writes is an annotation with `kind`
/// `codes.issue`. It has to keep round-tripping through the chain unchanged —
/// the ledger is the operator's only memory of which nonce counters have been
/// spoken aloud.
#[test]
fn the_ledger_annotation_is_read_back_as_it_was_written() {
    let lines = journal_written_by_the_previous_build();
    let parsed: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();

    assert_eq!(parsed["op"], "annotation");
    assert_eq!(parsed["kind"], "codes.issue");
    assert_eq!(parsed["data"]["counter"], 1);
    assert_eq!(parsed["data"]["nonce"], "0000014711");
    assert_eq!(parsed["data"]["receipt"], "receipt-1.receipt");
}

/// The other direction: what this build **writes** must still be those bytes.
///
/// The tests above check the reader. A reader alone is only half the guarantee
/// and the weaker half: a change that renames a field in both the writer and
/// the reader keeps every round-trip green while making every journal already on
/// disk unreadable by the new build — and making every journal the new build
/// writes unreadable by the old one. So this pins the writer against the same
/// frozen bytes.
#[test]
fn what_this_build_writes_is_still_the_frozen_format() {
    use tessera_hashchain::storage::MemoryStorage;
    use tessera_issuer::journal::{Journal, KeyOrigin};

    let mut journal = Journal::load(MemoryStorage::new()).unwrap();
    journal
        .record_leaf(
            &[0x2a],
            b"a certificate whose bytes do not matter here",
            "CN=shift,O=acme",
            KeyOrigin::Requester,
            1_700_000_000,
        )
        .unwrap();

    let written = journal.storage().lines();
    let first = written.first().expect("nothing was written");
    let parsed: serde_json::Value = serde_json::from_str(first).unwrap();

    // Field for field, against the shape frozen at the top of this file.
    assert_eq!(parsed["seq"], 0);
    assert_eq!(parsed["ts"], 1_700_000_000_u64);
    assert_eq!(parsed["op"], "issue_leaf");
    assert_eq!(parsed["serial"], "2a");
    assert_eq!(parsed["subject"], "CN=shift,O=acme");
    assert_eq!(
        parsed["prev_hash"], "cf9155d836062fbdff126663274d48ba5f2e79e0b6c7723e36c74bdc7a879694",
        "the genesis anchor of the issuance journal moved: every journal ever written \
         stops verifying",
    );
    // A requester key stays off the wire, which is what keeps these lines
    // byte-identical to the ones written before the field existed.
    assert!(
        parsed.get("key_origin").is_none(),
        "the default key origin reached the wire: old and new lines are no longer identical",
    );

    // And the line this build wrote verifies as part of the same chain as the
    // frozen ones — the two halves meeting.
    assert_eq!(
        verify_lines(&written).status,
        JournalStatus::IntactUnsignedTail {
            unsigned_from_seq: 0
        }
    );
}
