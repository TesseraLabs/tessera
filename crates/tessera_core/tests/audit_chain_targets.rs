//! The chain is added beside the existing audit log, never in place of it.
//!
//! The `tracing` targets and the field names of the audit events are an API:
//! the `logging-audit` specification says the names are what operators grep, and
//! a consumer pinned to `codes.audit` has no way of knowing that a second
//! destination appeared. So this file checks the part that must not have moved —
//! the target, the event name, the fields — and checks it in both states the
//! device can be in: with a chain configured and without one.
//!
//! One test function on purpose. The audit sink is process-wide, and two tests
//! installing and removing it in parallel would be testing each other.

#![allow(clippy::panic)]
#![expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::subscriber::with_default;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt as _};
use tracing_subscriber::Registry;

use tessera_core::audit::{sink, AuditJournal, AuditPolicy};
use tessera_core::codes::audit as codes_audit;
use tessera_core::enrollment::audit as enrollment_audit;

/// One captured `tracing` event: what a consumer of the journal sees.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Captured {
    target: String,
    fields: BTreeMap<String, String>,
}

#[derive(Default)]
struct Collector {
    events: Arc<Mutex<Vec<Captured>>>,
}

struct FieldVisitor(BTreeMap<String, String>);

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }
}

impl<S: tracing::Subscriber> Layer<S> for Collector {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = FieldVisitor(BTreeMap::new());
        event.record(&mut visitor);
        self.events.lock().unwrap().push(Captured {
            target: event.metadata().target().to_owned(),
            fields: visitor.0,
        });
    }
}

/// Emits one of each audit event and returns what a `tracing` consumer saw.
fn emit_all() -> Vec<Captured> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let collector = Collector {
        events: Arc::clone(&events),
    };
    let subscriber = Registry::default().with(collector);

    with_default(subscriber, || {
        // The successful login is the one emitter that can refuse: the chains
        // installed here take the record, so it never does, and the tracing
        // event it emits first is what this file is checking either way.
        codes_audit::emit_success("0000014711", "ops.dc.senior", 1, 7, "tk-17").unwrap();
        codes_audit::emit_denied(
            Some("0000020815"),
            "ops.dc.senior",
            1,
            7,
            Some("tk-17"),
            codes_audit::REASON_CODE_MISMATCH,
        );
        codes_audit::emit_attempts_exhausted("0000031234", "ops.dc.senior", 1, 7, "tk-17");
        enrollment_audit::emit_device_enrolled(enrollment_audit::MODE_STANDALONE, 0);
        enrollment_audit::emit_enrollment_rejected(enrollment_audit::REASON_MANIFEST);
    });

    let captured = events.lock().unwrap().clone();
    captured
}

/// The events an operator's grep is pinned to, as they must keep looking.
fn expected() -> Vec<Captured> {
    let code_login = |nonce: &str, ticket: &str, outcome: &str, reason: Option<&str>| {
        let mut fields = BTreeMap::from([
            (
                "event".to_owned(),
                codes_audit::EVENT_QR_CODE_LOGIN.to_owned(),
            ),
            ("nonce_ref".to_owned(), nonce.to_owned()),
            ("role_id".to_owned(), "ops.dc.senior".to_owned()),
            ("level".to_owned(), "1".to_owned()),
            ("epoch".to_owned(), "7".to_owned()),
            ("outcome".to_owned(), outcome.to_owned()),
        ]);
        if !ticket.is_empty() {
            fields.insert("ticket_no".to_owned(), ticket.to_owned());
        }
        if let Some(reason) = reason {
            fields.insert("reason".to_owned(), reason.to_owned());
        }
        Captured {
            target: "codes.audit".to_owned(),
            fields,
        }
    };

    vec![
        code_login("0000014711", "tk-17", codes_audit::OUTCOME_SUCCESS, None),
        code_login(
            "0000020815",
            "tk-17",
            codes_audit::OUTCOME_DENIED,
            Some(codes_audit::REASON_CODE_MISMATCH),
        ),
        // The exhausted budget carries the ticket too. It did not always: the
        // field was added so the reconciliation can join this outcome to an
        // operator receipt on the same key as the other two, and this test is
        // what noticed the schema move.
        code_login(
            "0000031234",
            "tk-17",
            codes_audit::OUTCOME_ATTEMPTS_EXHAUSTED,
            None,
        ),
        Captured {
            target: "enrollment.audit".to_owned(),
            fields: BTreeMap::from([
                (
                    "event".to_owned(),
                    enrollment_audit::EVENT_DEVICE_ENROLLED.to_owned(),
                ),
                ("host_id".to_owned(), String::new()),
                ("serial".to_owned(), String::new()),
                (
                    "mode".to_owned(),
                    enrollment_audit::MODE_STANDALONE.to_owned(),
                ),
                ("bundle_version".to_owned(), "0".to_owned()),
            ]),
        },
        Captured {
            target: "enrollment.audit".to_owned(),
            fields: BTreeMap::from([
                (
                    "event".to_owned(),
                    enrollment_audit::EVENT_ENROLLMENT_REJECTED.to_owned(),
                ),
                ("host_id".to_owned(), String::new()),
                ("serial".to_owned(), String::new()),
                (
                    "reason".to_owned(),
                    enrollment_audit::REASON_MANIFEST.to_owned(),
                ),
            ]),
        },
    ]
}

#[test]
fn the_chain_changes_nothing_about_the_tracing_events() {
    // Without a chain: what the device emitted before this change existed.
    assert!(!sink::is_installed());
    let before = emit_all();
    assert_eq!(before, expected());

    // With a chain: the same five events, byte for byte the same fields.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.ndjson");
    sink::install(AuditJournal::open(AuditPolicy::new(&path)).unwrap());
    let with_chain = emit_all();
    assert_eq!(with_chain, expected());

    // …and the chain did receive them, or this test would be checking that
    // nothing happens at all.
    let journal = sink::uninstall().unwrap();
    assert_eq!(journal.verify().unwrap().entry_count, 5);

    // With the chain gone again, the events still go out.
    assert!(!sink::is_installed());
    assert_eq!(emit_all(), expected());
}
