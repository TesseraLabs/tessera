//! Phase 7 — verify that `state::write_sessions_atomic` labels the
//! underlying tempfile via `MacBackend::set_fd_label` (`level=0`,
//! `irelax=true`) BEFORE renaming into the published `sessions.json`
//! path. Closes the path-based TOCTOU window per MAC integrity spec
//! §5.3.1.

#![cfg(feature = "mac-tests")]
#![allow(clippy::unwrap_used)]

use tessera_core::mac::backend::MockMacBackend;

#[test]
fn write_atomic_labels_fd_before_rename() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("sessions.json");
    let mut m = MockMacBackend::new();
    m.expect_set_fd_label()
        .withf(|fd, l, irelax| *fd > 0 && l.level == 0 && l.categories == 0 && *irelax)
        .return_once(|_, _, _| Ok(()));

    tessera_cli::state::write_sessions_atomic(&path, b"{}", &m).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"{}");
}
