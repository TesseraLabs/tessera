//! What the device's audit journal promises, checked against a real file.
//!
//! The claims under test are the ones an auditor would lean on: a record that
//! was cut out of the file is found, and found *where*; a swapped pair is found;
//! an unattested tail is not mistaken for tampering; the ceiling is announced
//! rather than met in silence; and a rotation leaves a line saying what it
//! rotated away.

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
    reason = "a test that indexes past its own fixture should fail the test on the spot"
)]

use std::path::Path;

use tessera_core::audit::journal::{AuditError, HeadSigner};
use tessera_core::audit::{outcome, AuditJournal, AuditPolicy, AuditRecord, WhenFull};
use tessera_hashchain::ChainStatus;

/// A signer that signs nothing: the chain records the structure of an
/// attestation, and the cryptographic step belongs to the key store.
struct StubSigner;

impl HeadSigner for StubSigner {
    fn algorithm(&self) -> &'static str {
        "test-attestation"
    }

    fn sign(&self, head: &[u8; 32]) -> Result<Vec<u8>, String> {
        Ok(head.to_vec())
    }
}

/// A signer whose key store refuses.
struct RefusingSigner;

impl HeadSigner for RefusingSigner {
    fn algorithm(&self) -> &'static str {
        "test-attestation"
    }

    fn sign(&self, _head: &[u8; 32]) -> Result<Vec<u8>, String> {
        Err("the token is not present".to_owned())
    }
}

fn login(nonce: &str, outcome: &str) -> AuditRecord {
    AuditRecord::CodeLogin {
        nonce_ref: nonce.to_owned(),
        role_id: "ops.dc.senior".to_owned(),
        level: 1,
        epoch: 7,
        ticket_no: "tk-17".to_owned(),
        claimed_engineer_no: "eng-1".to_owned(),
        outcome: outcome.to_owned(),
        reason: None,
    }
}

fn lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn write_lines(path: &Path, lines: &[String]) {
    std::fs::write(path, format!("{}\n", lines.join("\n"))).unwrap();
}

#[test]
fn a_fresh_journal_is_intact_and_says_its_tail_is_unattested() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.ndjson");
    let mut journal = AuditJournal::open(AuditPolicy::new(&path)).unwrap();

    for index in 0..3_u64 {
        journal
            .record(
                &login(&format!("nonce-{index}"), outcome::SUCCESS),
                1_000 + index,
            )
            .unwrap();
    }

    let report = journal.verify().unwrap();
    assert_eq!(
        report.status,
        ChainStatus::IntactUnsignedTail {
            unsigned_from_seq: 0
        }
    );
    assert_eq!(report.entry_count, 3);
    assert_eq!(report.last_signed_seq, None);
}

/// The case the whole construction exists for: a line taken out of the file.
#[test]
fn a_record_cut_out_of_the_file_is_found_with_its_position() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.ndjson");
    let mut journal = AuditJournal::open(AuditPolicy::new(&path)).unwrap();
    for index in 0..4_u64 {
        journal
            .record(
                &login(&format!("nonce-{index}"), outcome::SUCCESS),
                1_000 + index,
            )
            .unwrap();
    }

    let mut kept = lines(&path);
    kept.remove(2);
    write_lines(&path, &kept);

    let reopened = AuditJournal::open(AuditPolicy::new(&path)).unwrap();
    assert_eq!(
        reopened.verify().unwrap().status,
        ChainStatus::Broken { position: 2 }
    );
}

#[test]
fn an_edited_record_and_a_reordered_pair_are_both_found() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.ndjson");
    let mut journal = AuditJournal::open(AuditPolicy::new(&path)).unwrap();
    for index in 0..4_u64 {
        journal
            .record(
                &login(&format!("nonce-{index}"), outcome::SUCCESS),
                1_000 + index,
            )
            .unwrap();
    }
    let original = lines(&path);

    let mut edited = original.clone();
    edited[1] = edited[1].replace("\"denied\"", "\"success\"");
    edited[1] = edited[1].replace("ops.dc.senior", "ops.dc.admin");
    write_lines(&path, &edited);
    assert_eq!(
        AuditJournal::open(AuditPolicy::new(&path))
            .unwrap()
            .verify()
            .unwrap()
            .status,
        ChainStatus::Broken { position: 2 }
    );

    let mut swapped = original;
    swapped.swap(1, 2);
    write_lines(&path, &swapped);
    assert_eq!(
        AuditJournal::open(AuditPolicy::new(&path))
            .unwrap()
            .verify()
            .unwrap()
            .status,
        ChainStatus::Broken { position: 1 }
    );
}

/// "Intact but not yet attested" and "broken" must never be reported as the
/// same thing: one is the ordinary state of a live device, the other is an
/// incident.
#[test]
fn an_attested_head_is_told_apart_from_a_broken_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.ndjson");
    let mut journal = AuditJournal::open(AuditPolicy::new(&path)).unwrap();
    journal
        .record(&login("nonce-0", outcome::SUCCESS), 1_000)
        .unwrap();
    journal.attest(&StubSigner, 1_001).unwrap();

    assert_eq!(journal.verify().unwrap().status, ChainStatus::Intact);
    assert_eq!(journal.last_attested_ts(), Some(1_001));

    journal
        .record(&login("nonce-1", outcome::DENIED), 1_002)
        .unwrap();
    assert_eq!(
        journal.verify().unwrap().status,
        ChainStatus::IntactUnsignedTail {
            unsigned_from_seq: 2
        }
    );

    // Reopening finds the attestation that is already in the file.
    let reopened = AuditJournal::open(AuditPolicy::new(&path)).unwrap();
    assert_eq!(reopened.last_attested_ts(), Some(1_001));
}

#[test]
fn attestation_on_the_schedule_waits_for_the_interval_and_a_refusing_key_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.ndjson");
    let mut policy = AuditPolicy::new(&path);
    policy.attest_interval_secs = 100;
    let mut journal = AuditJournal::open(policy).unwrap();

    // Never attested: always due.
    assert!(journal.attest_if_due(&StubSigner, 1_000).unwrap());
    assert!(!journal.attest_if_due(&StubSigner, 1_050).unwrap());
    assert!(journal.attest_if_due(&StubSigner, 1_100).unwrap());

    let mut refusing =
        AuditJournal::open(AuditPolicy::new(dir.path().join("other.ndjson"))).unwrap();
    assert!(matches!(
        refusing.attest(&RefusingSigner, 1_000),
        Err(AuditError::Attest(_))
    ));
}

/// A full journal must announce itself. The alternative — the operator working
/// out from an absence of lines that the ceiling was met a fortnight ago — is
/// exactly what the chain exists to make unnecessary.
#[test]
fn a_journal_at_its_ceiling_says_so_and_then_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.ndjson");
    let mut policy = AuditPolicy::new(&path);
    policy.ceiling_bytes = 400;
    policy.when_full = WhenFull::Refuse;
    let mut journal = AuditJournal::open(policy).unwrap();

    let mut refused = None;
    for index in 0..50_u64 {
        if let Err(error) = journal.record(
            &login(&format!("nonce-{index}"), outcome::DENIED),
            1_000 + index,
        ) {
            refused = Some(error);
            break;
        }
    }

    assert!(
        matches!(refused, Some(AuditError::Full { .. })),
        "the journal never refused"
    );

    let written = lines(&path);
    let notice = written
        .iter()
        .find(|line| line.contains("\"journal_full\""))
        .expect("the journal reached its ceiling without saying so");
    assert!(notice.contains("\"ceiling_bytes\":400"));

    // And the announcement is part of the chain, not a note beside it.
    assert!(matches!(
        journal.verify().unwrap().status,
        ChainStatus::IntactUnsignedTail { .. }
    ));
}

/// Rotation is allowed; silent rotation is not. The new chain's first line names
/// what was rotated away, so a shorter history is never mistaken for a shorter
/// past.
#[test]
fn rotation_leaves_a_record_of_the_break() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.ndjson");
    let mut policy = AuditPolicy::new(&path);
    policy.ceiling_bytes = 400;
    policy.when_full = WhenFull::Rotate;
    let mut journal = AuditJournal::open(policy).unwrap();

    let rotated = dir.path().join("audit.ndjson.1");
    // Stop at the first rotation: a second one is a separate guarantee, checked
    // by the test below.
    for index in 0..20_u64 {
        journal
            .record(
                &login(&format!("nonce-{index}"), outcome::DENIED),
                1_000 + index,
            )
            .unwrap();
        if rotated.exists() {
            break;
        }
    }

    assert!(rotated.is_file(), "the filled chain was not moved aside");

    let fresh = lines(&path);
    assert!(
        fresh[0].contains("\"chain_break\""),
        "the new chain does not open with the record of the break: {}",
        fresh[0]
    );
    assert!(fresh[0].contains("\"previous_entries\""));

    // The rotated-away chain is still a chain, and still verifies on its own.
    let old = lines(&rotated);
    assert!(old.iter().any(|line| line.contains("\"journal_full\"")));
    assert_eq!(
        tessera_hashchain::verify_lines::<AuditRecord>(&old).status,
        ChainStatus::IntactUnsignedTail {
            unsigned_from_seq: 0
        }
    );

    // …and so is the new one.
    assert!(matches!(
        journal.verify().unwrap().status,
        ChainStatus::IntactUnsignedTail { .. }
    ));
}

/// Rotating twice would put the second filled chain where the first one is,
/// destroying it at the exact moment a device is furthest behind on exporting
/// its audit. It is refused instead.
#[test]
fn a_second_rotation_refuses_rather_than_overwriting_the_first() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.ndjson");
    let mut policy = AuditPolicy::new(&path);
    policy.ceiling_bytes = 400;
    policy.when_full = WhenFull::Rotate;
    let mut journal = AuditJournal::open(policy).unwrap();

    let mut refusal = None;
    for index in 0..60_u64 {
        if let Err(error) = journal.record(
            &login(&format!("nonce-{index}"), outcome::DENIED),
            1_000 + index,
        ) {
            refusal = Some(error);
            break;
        }
    }
    assert!(
        matches!(refusal, Some(AuditError::Rotate(_))),
        "the journal rotated a second time over the first rotated chain"
    );

    // The first rotated chain is still whole.
    let rotated = lines(&dir.path().join("audit.ndjson.1"));
    assert_eq!(
        tessera_hashchain::verify_lines::<AuditRecord>(&rotated).status,
        ChainStatus::IntactUnsignedTail {
            unsigned_from_seq: 0
        }
    );
}

/// The annotation is how somebody else's data — a reconciliation projection —
/// gets the same protection as the device's own events.
#[test]
fn an_annotation_is_chained_and_its_removal_is_visible() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.ndjson");
    let mut journal = AuditJournal::open(AuditPolicy::new(&path)).unwrap();

    journal
        .record(&login("nonce-0", outcome::SUCCESS), 1_000)
        .unwrap();
    journal
        .annotate(
            "tessera.codes.reconciliation",
            serde_json::json!({ "operator": "op-42", "receipts": 3 }),
            1_001,
        )
        .unwrap();
    journal
        .record(&login("nonce-1", outcome::SUCCESS), 1_002)
        .unwrap();

    let mut without = lines(&path);
    without.remove(1);
    write_lines(&path, &without);

    assert_eq!(
        AuditJournal::open(AuditPolicy::new(&path))
            .unwrap()
            .verify()
            .unwrap()
            .status,
        ChainStatus::Broken { position: 1 }
    );
}

#[test]
fn an_annotation_carrying_a_secret_is_refused_before_it_reaches_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.ndjson");
    let mut journal = AuditJournal::open(AuditPolicy::new(&path)).unwrap();

    let refusal = journal.annotate(
        "tessera.codes.reconciliation",
        serde_json::json!({ "operator": "op-42", "calls": [{ "derived_key": "…" }] }),
        1_000,
    );
    assert!(
        matches!(refusal, Err(AuditError::SecretField { field }) if field == "calls[0].derived_key")
    );
    assert!(!path.exists(), "a refused record still touched the file");

    // A namespace tag is required, and the data must be an object.
    assert!(journal.annotate("", serde_json::json!({}), 1_000).is_err());
    assert!(journal
        .annotate("tessera.kind", serde_json::json!("bare"), 1_000)
        .is_err());
}

/// Rotation that cannot record the break is undone, not left half-done.
///
/// The disk fills exactly when a journal reaches its ceiling, which is exactly
/// when rotation runs. If the rename stood while the `chain_break` line failed
/// to land, the device would come back with a fresh chain starting at genesis
/// and nothing anywhere saying an older one exists — which is silent rotation,
/// the one thing task 3.3 declares impossible, and indistinguishable from a
/// journal somebody deleted.
#[test]
fn a_rotation_that_cannot_record_the_break_is_rolled_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.ndjson");
    let mut policy = AuditPolicy::new(&path);
    policy.ceiling_bytes = 400;
    policy.when_full = WhenFull::Rotate;
    let mut journal = AuditJournal::open(policy).unwrap();

    let rotated = dir.path().join("audit.ndjson.1");
    for index in 0..20_u64 {
        journal
            .record(
                &login(&format!("nonce-{index}"), outcome::DENIED),
                1_000 + index,
            )
            .unwrap();
        if rotated.exists() {
            break;
        }
    }
    let filled = lines(&rotated);
    assert!(!filled.is_empty(), "nothing was rotated away");

    // Take the first rotation away so a second one is admissible, then make the
    // new file impossible to write: a directory where a file is due is a write
    // that fails for a reason the journal cannot talk its way around.
    std::fs::remove_file(&rotated).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, filled.join("\n") + "\n").unwrap();
    let mut journal = {
        let mut policy = AuditPolicy::new(&path);
        policy.ceiling_bytes = 1;
        policy.when_full = WhenFull::Rotate;
        AuditJournal::open(policy).unwrap()
    };
    std::fs::create_dir(dir.path().join("blocker")).unwrap();

    // The rotated-away name is taken by a directory, so the rename itself
    // fails; whichever step fails, the filled journal must still be readable
    // where it was.
    std::fs::create_dir(&rotated).unwrap();
    let refusal = journal.record(&login("nonce-x", outcome::DENIED), 2_000);
    assert!(
        matches!(refusal, Err(AuditError::Rotate(_))),
        "a rotation that could not complete was not reported: {refusal:?}",
    );

    // The history is still there and still verifies: nothing was lost to a
    // rotation that did not happen.
    let survivors = lines(&path);
    assert!(
        survivors.len() >= filled.len(),
        "the filled journal lost records to a failed rotation",
    );
    assert!(matches!(
        tessera_hashchain::verify_lines::<AuditRecord>(&survivors).status,
        ChainStatus::IntactUnsignedTail { .. }
    ));
}

/// The one line allowed past the ceiling is the notice, and only the notice.
///
/// The ceiling is compared against the size the journal will have once a record
/// lands, not against the size it has now. Comparing the current size alone
/// makes the deliberate one-line exception unbounded, because the record about
/// to be written comes from outside this crate and can be any size at all.
#[test]
fn a_record_larger_than_the_headroom_does_not_slip_past_the_ceiling() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.ndjson");
    let mut policy = AuditPolicy::new(&path);
    policy.ceiling_bytes = 2_000;
    policy.when_full = WhenFull::Refuse;
    let mut journal = AuditJournal::open(policy).unwrap();

    // Well under the ceiling to begin with.
    journal
        .record(&login("nonce-0", outcome::DENIED), 1_000)
        .unwrap();
    let before = std::fs::metadata(&path).unwrap().len();
    assert!(before < 2_000);

    // One annotation far larger than the headroom that is left.
    let bulky = "x".repeat(64 * 1024);
    let refusal = journal.annotate("test.bulky", serde_json::json!({ "payload": bulky }), 1_001);
    assert!(
        matches!(refusal, Err(AuditError::Full { .. })),
        "a record far larger than the remaining headroom was accepted: {refusal:?}",
    );

    // The journal grew by the notice and by nothing else — certainly not by
    // sixty-four kilobytes.
    let after = std::fs::metadata(&path).unwrap().len();
    assert!(
        after < before + 1_024,
        "the journal grew by {} bytes past the ceiling",
        after - before,
    );
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(written.contains(r#""op":"journal_full""#));
    assert!(
        !written.contains("xxxxxxxxxx"),
        "the refused record was written anyway"
    );
}
