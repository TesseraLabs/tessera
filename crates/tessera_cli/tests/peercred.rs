#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]

use tessera_cli::peercred::verify_peer_credentials;
use std::os::unix::net::UnixStream;
use tokio::net::UnixStream as TokioUnixStream;

#[tokio::test]
async fn rejects_non_root_peer_or_accepts_when_running_as_root() {
    let (a, _b) = UnixStream::pair().expect("pair");
    a.set_nonblocking(true).expect("nonblock");
    let tokio_a = TokioUnixStream::from_std(a).expect("tokio stream");
    let result = verify_peer_credentials(&tokio_a);
    let am_root = nix::unistd::Uid::current().is_root();
    if am_root {
        assert!(result.is_ok(), "root should be accepted: {result:?}");
    } else {
        let err = result.expect_err("non-root should be rejected");
        assert!(
            format!("{err}").to_lowercase().contains("unauthor"),
            "msg = {err}"
        );
    }
}
