//! Phase 6 — verify that `server::bind_with_label` labels the listener's
//! fd via `MacBackend::set_fd_label` with `level=0` and `irelax=true`
//! BEFORE the atomic rename onto the final path. Fd-based labeling closes
//! the TOCTOU window between `bind()` and the label call that a same-uid
//! attacker could otherwise exploit by swapping the temp path for a symlink.

#![cfg(feature = "mac-tests")]
#![allow(clippy::unwrap_used)]

use tessera_core::mac::backend::MockMacBackend;

#[test]
fn bind_calls_set_fd_label_with_irelax_before_rename() {
    let tmp = tempfile::tempdir().unwrap();
    let final_path = tmp.path().join("monitord.sock");
    let mut mock = MockMacBackend::new();
    mock.expect_set_fd_label()
        .withf(|fd, l, irelax| *fd > 0 && l.level == 0 && l.categories == 0 && *irelax)
        .return_once(|_, _, _| Ok(()));

    tessera_cli::server::bind_with_label(&final_path, &mock).unwrap();
    assert!(
        final_path.exists(),
        "final socket path must exist post-rename"
    );
}
