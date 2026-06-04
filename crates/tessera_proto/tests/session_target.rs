#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]

use tessera_proto::SessionTarget;

#[test]
fn tty_serialization() {
    let t = SessionTarget::tty("/dev/tty1");
    let s = serde_json::to_string(&t).expect("encode");
    assert!(s.contains("\"tty\""), "json = {s}");
    assert!(s.contains("/dev/tty1"), "json = {s}");
}

#[test]
fn logind_id_helper_for_logind_session() {
    let t = SessionTarget::logind("c1");
    assert_eq!(t.logind_id(), Some("c1"));
}

#[test]
fn logind_id_helper_for_tty_returns_none() {
    let t = SessionTarget::tty("/dev/tty1");
    assert_eq!(t.logind_id(), None);
}

#[test]
fn unknown_roundtrip() {
    let t = SessionTarget::Unknown;
    let s = serde_json::to_string(&t).expect("encode");
    let back: SessionTarget = serde_json::from_str(&s).expect("decode");
    assert!(matches!(back, SessionTarget::Unknown));
}

#[test]
fn display_variant_roundtrip() {
    let t = SessionTarget::display(":0");
    let s = serde_json::to_string(&t).expect("encode");
    let back: SessionTarget = serde_json::from_str(&s).expect("decode");
    assert!(matches!(back, SessionTarget::Display { ref name } if name == ":0"));
}
