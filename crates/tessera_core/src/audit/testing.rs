//! Capturing what a body of code recorded, by reading the journal it wrote.
//!
//! # Why not a `tracing` subscriber
//!
//! Collecting events with a scoped subscriber is the obvious way to check what
//! some code emitted, and it is unsound for the thing tests most want to check.
//!
//! `tracing` caches `Interest` per callsite, **per process**. Once one thread
//! has evaluated a callsite against a subscriber that did not want it, another
//! thread's scoped subscriber can be handed nothing for that callsite at all. A
//! test that asserts an event *was* emitted then fails for a reason that has
//! nothing to do with the code — annoying, but visible.
//!
//! The dangerous direction is the other one. A test asserting an event was
//! **not** emitted passes trivially against a poisoned callsite: it sees no
//! events because the subscriber was never offered any, and it reports that as
//! the guarantee holding. Such a test checks nothing and says it checked
//! something, which is worse than not having it.
//!
//! So assertions about what was recorded read the journal instead. It is a file
//! this process wrote; reading it back is not subject to any cache, any thread,
//! or any ordering. What the journal holds is what happened.
//!
//! The `tracing` side is still checked — in `tests/audit_chain_targets.rs`,
//! which is a test binary of its own with a single test in it, so there is no
//! second thread to poison a callsite. That is the one place where a subscriber
//! is the right instrument, because there the *subject* is the subscriber's
//! view.

use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use super::journal::{AuditJournal, AuditPolicy};

/// Serialises the process-wide sink between capturing tests.
static SINK: OnceLock<Mutex<()>> = OnceLock::new();

/// Holds the sink for the length of one capture.
///
/// A poisoned lock is taken anyway: it means another test panicked while
/// holding it, and turning that into a failure in every test after it would
/// bury the first one.
fn hold() -> MutexGuard<'static, ()> {
    SINK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Runs `body` with a fresh audit journal installed, and returns every record
/// that reached it.
///
/// The journal is a real one in a temporary directory, opened through the
/// ordinary [`AuditJournal::open`], so what comes back is what the product
/// would have written to a device — not a rendering of it.
///
/// Any journal already installed is put back afterwards.
#[expect(
    clippy::expect_used,
    clippy::panic,
    reason = "a capture that cannot set up or read its own journal has nothing \
              to report, and should fail the test that asked for it on the spot"
)]
pub(crate) fn capture_records<F: FnOnce()>(body: F) -> Vec<serde_json::Value> {
    let _hold = hold();

    let dir = tempfile::tempdir().expect("a directory for the captured journal");
    let path = dir.path().join("audit.ndjson");
    let journal = AuditJournal::open(AuditPolicy::new(&path)).expect("a journal to capture into");
    let displaced = super::sink::install(journal);

    body();

    // Take our journal back, and check it is ours.
    //
    // The sink is process-wide, so "the capture came back empty" has two very
    // different causes: the body recorded nothing, which is a result, and
    // something else swapped the sink out from under it, which is a broken
    // test harness reporting a product guarantee. Left undistinguished the
    // second reads as the first, and an assertion about absence passes for the
    // wrong reason — the exact failure mode that moving off `tracing`
    // subscribers was supposed to end.
    //
    // The lock above is what prevents it; this is what makes a hole in that
    // lock announce itself instead of turning into `saw []`.
    let finished = super::sink::uninstall();
    let ours = finished
        .as_ref()
        .is_some_and(|journal| journal.policy().path == path);
    if let Some(displaced) = displaced {
        super::sink::install(displaced);
    }
    assert!(
        ours,
        "the audit sink was replaced while a capture held it: this capture cannot say what the \
         body recorded, and an empty result here would be indistinguishable from the body \
         recording nothing. Whatever installed a journal without taking          `audit::testing`'s lock is the defect.",
    );

    match std::fs::read_to_string(&path) {
        Ok(text) => text
            .lines()
            .map(|line| {
                serde_json::from_str(line).expect("the journal wrote a line it cannot read")
            })
            .collect(),
        // Nothing was recorded, which is a result and not a failure — it is
        // exactly what a "no event" assertion is looking for.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("the captured journal could not be read: {error}"),
    }
}

/// Every captured record whose `outcome` field is `outcome`.
///
/// The sink is process-wide, so a capture can also pick up records written by
/// whatever else the test runner is executing at that moment. That is harmless
/// for an assertion about absence — a foreign record cannot make one pass —
/// but an assertion about a specific record must narrow further than the
/// outcome, which is what [`matching`] is for.
pub(crate) fn with_outcome<'a>(
    records: &'a [serde_json::Value],
    outcome: &str,
) -> Vec<&'a serde_json::Value> {
    records
        .iter()
        .filter(|record| record.get("outcome").and_then(serde_json::Value::as_str) == Some(outcome))
        .collect()
}

/// The captured records whose named string fields all match.
///
/// Used to pick this test's own record out of a journal that other tests
/// running in parallel may also have written to.
pub(crate) fn matching<'a>(
    records: &'a [serde_json::Value],
    fields: &[(&str, &str)],
) -> Vec<&'a serde_json::Value> {
    records
        .iter()
        .filter(|record| {
            fields.iter().all(|(name, value)| {
                record.get(*name).and_then(serde_json::Value::as_str) == Some(*value)
            })
        })
        .collect()
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{capture_records, with_outcome};
    use crate::audit::{AuditJournal, AuditPolicy, AuditRecord};

    fn login(outcome: &str) -> AuditRecord {
        AuditRecord::CodeLogin {
            nonce_ref: "0000014711".to_owned(),
            role_id: "ops.dc.senior".to_owned(),
            level: 1,
            epoch: 7,
            ticket_no: "tk-17".to_owned(),
            outcome: outcome.to_owned(),
            reason: None,
        }
    }

    #[test]
    fn a_capture_returns_what_the_body_recorded() {
        let records = capture_records(|| {
            crate::audit::sink::mirror(&login("denied"));
        });
        assert_eq!(with_outcome(&records, "denied").len(), 1);
    }

    #[test]
    fn a_body_that_records_nothing_returns_nothing() {
        let records = capture_records(|| {});
        assert!(records.is_empty());
    }

    /// The guard that keeps a swapped sink from looking like an empty result.
    ///
    /// Driven deterministically rather than by racing threads: the body itself
    /// does what a neighbour taking no lock would do — installs a journal of its
    /// own — so the check is exercised on every run instead of on the runs where
    /// the scheduler happens to cooperate. A race reproduced only sometimes is a
    /// race whose fix is confirmed only sometimes.
    #[test]
    #[should_panic(expected = "the audit sink was replaced while a capture held it")]
    fn a_capture_whose_sink_was_swapped_says_so_instead_of_coming_back_empty() {
        let elsewhere = tempfile::tempdir().unwrap();
        let _records = capture_records(|| {
            let stolen = AuditJournal::open(AuditPolicy::new(
                elsewhere.path().join("somebody-elses.ndjson"),
            ))
            .unwrap();
            crate::audit::sink::install(stolen);
        });
    }
}
