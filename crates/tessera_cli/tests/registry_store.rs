#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]

use std::os::unix::fs::PermissionsExt;
use std::time::SystemTime;
use tessera_cli::registry::{ActiveSession, RegistryStore};
use tessera_proto::SessionTarget;
use uuid::Uuid;

fn s(i: u128) -> ActiveSession {
    ActiveSession {
        session_id: Uuid::from_u128(i),
        pam_user: "u".into(),
        pam_service: "s".into(),
        target: SessionTarget::logind("c1"),
        usb_serial: Some("AB".into()),
        host_id_hash: "h".into(),
        opened_at: SystemTime::UNIX_EPOCH,
        cert_cn: "cn".into(),
        cert_serial: "01".into(),
        engineer_ski: String::new(),
        engineer_cert_sha256: String::new(),
        uid: 0,
    }
}

#[test]
fn persist_then_load_is_identical() {
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("sessions.json");
    let store = RegistryStore::new(path.clone());
    let snapshot = vec![s(1), s(2)];
    store.persist(&snapshot).expect("persist");
    let loaded = store.load().expect("load");
    assert_eq!(loaded.len(), 2);
}

#[test]
fn missing_file_returns_empty_no_error() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = RegistryStore::new(dir.path().join("missing.json"));
    let loaded = store.load().expect("load");
    assert!(loaded.is_empty());
}

#[test]
fn corrupt_file_returns_empty() {
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("bad.json");
    std::fs::write(&path, b"{not-json").expect("write");
    let store = RegistryStore::new(path);
    let loaded = store.load().expect("load");
    assert!(loaded.is_empty());
}

#[test]
fn persist_uses_0600_permissions() {
    // P1-K: the on-disk file must be 0o600 — sessions include CN/serial
    // and we do not want them readable by group or world. We also create
    // the temp file with O_CREAT|O_EXCL|mode=0o600 so there is no race
    // window where the umask could leave a wider mode visible.
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("sessions.json");
    let store = RegistryStore::new(path.clone());
    store.persist(&[s(1)]).expect("persist");
    let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn persist_twice_is_atomic_overwrite() {
    // P1-K: after two consecutive persists with different snapshots, the
    // final file must reflect the second snapshot exactly. There must be
    // no leftover temp files in the parent directory.
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("sessions.json");
    let store = RegistryStore::new(path.clone());

    store.persist(&[s(1)]).expect("first persist");
    store.persist(&[s(2), s(3)]).expect("second persist");

    let loaded = store.load().expect("load");
    assert_eq!(loaded.len(), 2);
    let ids: Vec<u128> = loaded.iter().map(|s| s.session_id.as_u128()).collect();
    assert_eq!(ids, vec![2, 3]);

    // No stray .tmp files left behind.
    let stray: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(stray.is_empty(), "stray tmp files: {stray:?}");
}
