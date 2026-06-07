#![allow(clippy::unwrap_used)]
#![allow(clippy::indexing_slicing)]

//! Verifies each MAC audit event emitter produces a tracing record with
//! the canonical `F_event` field and the expected level.  Captures
//! events through a custom `tracing_subscriber::Layer` so we don't need
//! `tracing-test` as a dev-dependency.

use std::sync::{Arc, Mutex};

use tessera_core::mac::audit::{
    self, EVENT_CERT_LACKS_EXT, EVENT_CERT_MAX_INT_CATS_ABOVE_32BIT, EVENT_HOMEDIR_LABEL_ABOVE,
    EVENT_INTEGRITY_APPLIED, EVENT_INTEGRITY_CAPPED, EVENT_MAC_APPLY_FAILED,
    EVENT_MAC_CAPS_MISSING, EVENT_MAC_FALLBACK_USED, EVENT_MAC_RUNTIME_REQUIRED, EVENT_MAC_SKIPPED,
    EVENT_MAC_USER_UNKNOWN,
};
use tessera_core::mac::IntegrityLabel;
use tessera_core::x509::CertIdent;
use tracing::field::{Field, Visit};
use tracing::Subscriber;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

#[derive(Default, Clone)]
struct Captured {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
}

#[derive(Debug, Clone)]
struct CapturedEvent {
    target: String,
    level: tracing::Level,
    fields: Vec<(String, String)>,
}

struct FieldCollector(Vec<(String, String)>);
impl Visit for FieldCollector {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .push((field.name().to_string(), format!("{value:?}")));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push((field.name().to_string(), value.to_string()));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.push((field.name().to_string(), value.to_string()));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.push((field.name().to_string(), value.to_string()));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.push((field.name().to_string(), value.to_string()));
    }
}

impl<S: Subscriber> Layer<S> for Captured {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut v = FieldCollector(Vec::new());
        event.record(&mut v);
        let meta = event.metadata();
        self.events.lock().unwrap().push(CapturedEvent {
            target: meta.target().to_string(),
            level: *meta.level(),
            fields: v.0,
        });
    }
}

fn run_capture<F: FnOnce()>(f: F) -> Vec<CapturedEvent> {
    let cap = Captured::default();
    let cap_clone = cap.clone();
    let subscriber = tracing_subscriber::registry().with(cap_clone);
    let _guard = tracing::subscriber::set_default(subscriber);
    f();
    let events = cap.events.lock().unwrap().clone();
    events
}

fn sample_ident() -> CertIdent {
    CertIdent {
        serial: "ABCD1234".into(),
        issuer: "CN=Issuer,O=Org".into(),
        cn: "alice@example.org".into(),
        fingerprint: "deadbeef".into(),
    }
}

fn assert_event(ev: &CapturedEvent, expected_event: &str) {
    assert_eq!(ev.target, "mac.audit", "target");
    let found = ev
        .fields
        .iter()
        .find(|(k, _)| k == "F_event")
        .map(|(_, v)| v.as_str());
    assert_eq!(found, Some(expected_event), "F_event mismatch in {ev:?}");
}

#[test]
fn emit_mac_skipped_emits_event() {
    let events = run_capture(|| audit::emit_mac_skipped("policy_ignore"));
    assert_eq!(events.len(), 1);
    assert_event(&events[0], EVENT_MAC_SKIPPED);
    assert_eq!(events[0].level, tracing::Level::INFO);
}

#[test]
fn emit_runtime_required_emits_event() {
    let events = run_capture(|| audit::emit_mac_runtime_required("Unavailable"));
    assert_eq!(events.len(), 1);
    assert_event(&events[0], EVENT_MAC_RUNTIME_REQUIRED);
    assert_eq!(events[0].level, tracing::Level::ERROR);
}

#[test]
fn emit_cert_lacks_ext_carries_all_cert_fields() {
    let ident = sample_ident();
    let events = run_capture(|| audit::emit_cert_lacks_ext(&ident, "alice", "login"));
    assert_eq!(events.len(), 1);
    assert_event(&events[0], EVENT_CERT_LACKS_EXT);
    let names: Vec<&str> = events[0].fields.iter().map(|(k, _)| k.as_str()).collect();
    for f in [
        "F_event",
        "F_pam_user",
        "F_pam_service",
        "F_cert_serial",
        "F_cert_issuer",
        "F_cert_cn",
        "F_cert_fingerprint",
    ] {
        assert!(names.contains(&f), "missing field {f} in {names:?}");
    }
}

#[test]
fn emit_integrity_applied_includes_label() {
    let ident = sample_ident();
    let label = IntegrityLabel {
        level: 3,
        categories: 0x0F,
    };
    let events = run_capture(|| audit::emit_integrity_applied(&ident, "alice", "login", label));
    assert_eq!(events.len(), 1);
    assert_event(&events[0], EVENT_INTEGRITY_APPLIED);
    let names: Vec<&str> = events[0].fields.iter().map(|(k, _)| k.as_str()).collect();
    assert!(names.contains(&"F_level"));
    assert!(names.contains(&"F_categories"));
}

#[test]
fn emit_integrity_capped_includes_user_and_effective_labels() {
    let ident = sample_ident();
    let eff = IntegrityLabel {
        level: 1,
        categories: 1,
    };
    let usr = IntegrityLabel {
        level: 5,
        categories: 0xFF,
    };
    let events = run_capture(|| audit::emit_integrity_capped(&ident, "alice", "login", eff, usr));
    assert_eq!(events.len(), 1);
    assert_event(&events[0], EVENT_INTEGRITY_CAPPED);
    assert_eq!(events[0].level, tracing::Level::WARN);
    let names: Vec<&str> = events[0].fields.iter().map(|(k, _)| k.as_str()).collect();
    for f in [
        "F_effective_level",
        "F_effective_categories",
        "F_user_level",
        "F_user_categories",
    ] {
        assert!(names.contains(&f), "missing {f}");
    }
}

#[test]
fn emit_homedir_label_above_includes_home_path() {
    let eff = IntegrityLabel {
        level: 1,
        categories: 0,
    };
    let home = IntegrityLabel {
        level: 5,
        categories: 0,
    };
    let events = run_capture(|| {
        audit::emit_homedir_label_above(
            "alice",
            "login",
            std::path::Path::new("/home/alice"),
            home,
            eff,
        );
    });
    assert_eq!(events.len(), 1);
    assert_event(&events[0], EVENT_HOMEDIR_LABEL_ABOVE);
    let names: Vec<&str> = events[0].fields.iter().map(|(k, _)| k.as_str()).collect();
    assert!(names.contains(&"F_home_dir"));
}

#[test]
fn emit_apply_failed_includes_detail() {
    let ident = sample_ident();
    let events = run_capture(|| audit::emit_apply_failed(&ident, "alice", "login", "parsec rc=-1"));
    assert_eq!(events.len(), 1);
    assert_event(&events[0], EVENT_MAC_APPLY_FAILED);
    let names: Vec<&str> = events[0].fields.iter().map(|(k, _)| k.as_str()).collect();
    assert!(names.contains(&"F_detail"));
}

#[test]
fn emit_caps_missing_uses_detail_field() {
    let events = run_capture(|| audit::emit_caps_missing("no PARSEC_CAP_CHMAC"));
    assert_eq!(events.len(), 1);
    assert_event(&events[0], EVENT_MAC_CAPS_MISSING);
    let names: Vec<&str> = events[0].fields.iter().map(|(k, _)| k.as_str()).collect();
    assert!(names.contains(&"F_detail"));
}

#[test]
fn emit_user_unknown_event() {
    let events = run_capture(|| audit::emit_user_unknown("alice", "login"));
    assert_eq!(events.len(), 1);
    assert_event(&events[0], EVENT_MAC_USER_UNKNOWN);
}

#[test]
fn emit_fallback_used_event() {
    let label = IntegrityLabel {
        level: 2,
        categories: 0,
    };
    let events = run_capture(|| audit::emit_fallback_used("alice", "login", label));
    assert_eq!(events.len(), 1);
    assert_event(&events[0], EVENT_MAC_FALLBACK_USED);
}

#[test]
fn emit_categories_above_32bit_event() {
    let events = run_capture(|| audit::emit_categories_above_32bit(0x1_0000_0001));
    assert_eq!(events.len(), 1);
    assert_event(&events[0], EVENT_CERT_MAX_INT_CATS_ABOVE_32BIT);
}
