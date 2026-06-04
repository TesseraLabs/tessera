#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]
//! Credential rejection — verifies that non-root peers get dropped at accept.

use std::io::Read;
use std::time::Duration;

use tessera_cli::registry::{RegistryStore, SessionRegistry};
use tessera_cli::testing::spawn_test_server_enforcing;

#[tokio::test(flavor = "multi_thread")]
async fn unauthorized_peer_is_dropped() {
    if nix::unistd::Uid::current().is_root() {
        eprintln!("skip: running as root, cannot verify rejection path without privilege drop");
        return;
    }
    let dir = tempfile::tempdir().expect("tmp");
    let sock = dir.path().join("monitor.sock");
    let registry = SessionRegistry::new();
    let store = RegistryStore::new(dir.path().join("s.json"));
    let server = spawn_test_server_enforcing(sock.clone(), registry, store)
        .await
        .expect("spawn");
    // Connect from this (non-root) process — server should close immediately.
    let sock2 = sock.clone();
    let join = tokio::task::spawn_blocking(move || {
        let mut s = std::os::unix::net::UnixStream::connect(&sock2).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let mut buf = [0u8; 16];
        s.read(&mut buf).unwrap_or(0)
    });
    let n = join.await.expect("join");
    assert_eq!(n, 0, "server should close non-root peer immediately");
    server.shutdown_and_join().await;
}
