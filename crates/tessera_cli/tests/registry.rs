#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic,
    clippy::let_underscore_must_use
)]

use std::time::SystemTime;
use tessera_cli::registry::{ActiveSession, SessionRegistry};
use tessera_proto::SessionTarget;
use uuid::Uuid;

fn make(id: u128, serial: Option<&str>) -> ActiveSession {
    ActiveSession {
        session_id: Uuid::from_u128(id),
        pam_user: "u".into(),
        pam_service: "s".into(),
        target: SessionTarget::logind("c1"),
        usb_serial: serial.map(str::to_string),
        host_id_hash: "h".into(),
        opened_at: SystemTime::UNIX_EPOCH,
        cert_cn: "cn".into(),
        cert_serial: "01".into(),
        engineer_ski: String::new(),
        engineer_cert_sha256: String::new(),
        uid: 0,
    }
}

fn make_with_uid(id: u128, uid: u32, engineer_ski: &str) -> ActiveSession {
    ActiveSession {
        session_id: Uuid::from_u128(id),
        pam_user: "alice".into(),
        pam_service: "sshd".into(),
        target: SessionTarget::logind("c1"),
        usb_serial: None,
        host_id_hash: "h".into(),
        opened_at: SystemTime::UNIX_EPOCH,
        cert_cn: "Alice".into(),
        cert_serial: "01".into(),
        engineer_ski: engineer_ski.into(),
        engineer_cert_sha256: "1234".into(),
        uid,
    }
}

#[test]
fn add_then_find_by_id() {
    let r = SessionRegistry::new();
    let s = make(1, Some("AB"));
    r.add(s.clone());
    assert!(r.find_by_session_id(s.session_id).is_some());
}

#[test]
fn find_by_serial_returns_all_matching() {
    let r = SessionRegistry::new();
    r.add(make(1, Some("AB")));
    r.add(make(2, Some("AB")));
    r.add(make(3, Some("CD")));
    let found = r.find_by_serial("AB");
    assert_eq!(found.len(), 2);
}

#[test]
fn remove_returns_session() {
    let r = SessionRegistry::new();
    let s = make(1, Some("AB"));
    r.add(s.clone());
    let removed = r.remove(s.session_id).expect("present");
    assert_eq!(removed.session_id, s.session_id);
    assert!(r.find_by_session_id(s.session_id).is_none());
}

#[test]
fn lookup_by_uid_returns_engineer_ski() {
    let r = SessionRegistry::new();
    r.add(make_with_uid(1, 1000, "abcd"));
    let found = r.find_by_uid(1000).expect("session present");
    assert_eq!(found.engineer_ski, "abcd");
    assert_eq!(found.uid, 1000);
}

#[test]
fn lookup_by_uid_missing_returns_none() {
    let r = SessionRegistry::new();
    r.add(make_with_uid(1, 1000, "abcd"));
    assert!(r.find_by_uid(999).is_none());
}

#[test]
fn lookup_by_uid_zero_never_matches() {
    // uid=0 is the sentinel for "v1 client / unknown" — must not collide
    // with the wildcard scope; v1 sessions stay outside the index.
    let r = SessionRegistry::new();
    r.add(make(7, Some("AB")));
    assert!(r.find_by_uid(0).is_none());
}

#[test]
fn remove_clears_uid_index() {
    let r = SessionRegistry::new();
    let s = make_with_uid(1, 1000, "abcd");
    r.add(s.clone());
    r.remove(s.session_id);
    assert!(r.find_by_uid(1000).is_none());
}

#[test]
fn re_add_with_new_uid_evicts_old_index_entry() {
    let r = SessionRegistry::new();
    r.add(make_with_uid(1, 1000, "abcd"));
    // Same session id, different uid — old index entry must go.
    r.add(make_with_uid(1, 2000, "abcd"));
    assert!(r.find_by_uid(1000).is_none());
    assert!(r.find_by_uid(2000).is_some());
}

#[test]
fn from_snapshot_rebuilds_uid_index() {
    let r = SessionRegistry::from_snapshot(vec![make_with_uid(1, 1000, "abcd")]);
    assert!(r.find_by_uid(1000).is_some());
}

#[test]
fn update_target_swaps_target_in_place() {
    let r = SessionRegistry::new();
    let mut s = make(1, Some("AB"));
    s.target = SessionTarget::tty("/dev/tty1");
    r.add(s.clone());
    r.update_target(s.session_id, SessionTarget::logind("c7"))
        .expect("present");
    let got = r.find_by_session_id(s.session_id).expect("present");
    assert_eq!(got.target, SessionTarget::logind("c7"));
}

#[test]
fn update_target_unknown_id_is_err() {
    let r = SessionRegistry::new();
    assert!(r
        .update_target(Uuid::from_u128(42), SessionTarget::logind("c7"))
        .is_err());
}

#[test]
fn concurrent_add_remove_is_safe() {
    use std::sync::Arc;
    let r = Arc::new(SessionRegistry::new());
    let r1 = r.clone();
    let h = std::thread::spawn(move || {
        for i in 0..1000u128 {
            r1.add(make(i, Some("X")));
        }
    });
    let r2 = r.clone();
    let h2 = std::thread::spawn(move || {
        for i in 0..1000u128 {
            let _ = r2.remove(Uuid::from_u128(i));
        }
    });
    h.join().expect("h");
    h2.join().expect("h2");
    let _ = r.all();
}
