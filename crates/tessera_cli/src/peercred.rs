//! `SO_PEERCRED` based peer-credentials check.
//!
//! On Linux the daemon enforces `uid == 0`. Implemented via tokio's portable
//! `peer_cred()` which delegates to `getsockopt(SO_PEERCRED)`.

use thiserror::Error;
use tokio::net::UnixStream;

/// Peer credentials returned by `peer_cred`.
#[derive(Debug, Clone, Copy)]
pub struct PeerCred {
    /// Effective UID.
    pub uid: u32,
    /// Effective GID.
    pub gid: u32,
    /// Peer PID, when available.
    pub pid: Option<i32>,
}

/// Errors from the peer-credentials check.
#[derive(Debug, Error)]
pub enum CredError {
    /// `peer_cred` returned an error.
    #[error("peer_cred failed: {0}")]
    Lookup(String),
    /// Peer's UID is not allowed.
    #[error("unauthorized peer uid={0}")]
    Unauthorized(u32),
}

/// Verify that the peer connected to `stream` is uid 0.
///
/// # Errors
///
/// Returns [`CredError::Unauthorized`] when the peer is non-root.
pub fn verify_peer_credentials(stream: &UnixStream) -> Result<PeerCred, CredError> {
    let cred = stream
        .peer_cred()
        .map_err(|e| CredError::Lookup(e.to_string()))?;
    let pc = PeerCred {
        uid: cred.uid(),
        gid: cred.gid(),
        pid: cred.pid(),
    };
    if pc.uid != 0 {
        return Err(CredError::Unauthorized(pc.uid));
    }
    Ok(pc)
}
