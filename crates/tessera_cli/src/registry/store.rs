//! Atomic JSON persistence for the session registry.
//!
//! The file is written through [`crate::state::write_sessions_atomic`]:
//! a same-filesystem tempfile receives the bytes (with an МКЦ irelax
//! `level=0` label applied to its fd BEFORE publication — see spec
//! §5.3.1), then `fsync(2)` + `rename(2)` make the new snapshot visible
//! at the final path. The parent directory is then `fsync`'d so the
//! rename survives power loss. Sessions include cert CN/serial which we
//! do not want exposed — the file therefore stays at `0600`.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use super::ActiveSession;

/// On-disk store for the session registry.
#[derive(Debug, Clone)]
pub struct RegistryStore {
    path: PathBuf,
}

impl RegistryStore {
    /// Construct a store rooted at `path`.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Path to the persisted file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load existing sessions from disk.
    ///
    /// A missing file or a corrupt JSON body is treated as "empty registry"
    /// and logged as WARN — we do not propagate the error so that the daemon
    /// can still start with a fresh registry after a crash.
    ///
    /// # Errors
    ///
    /// Returns the underlying `io::Error` only for non-`NotFound` IO failures.
    pub fn load(&self) -> io::Result<Vec<ActiveSession>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => match serde_json::from_slice::<Vec<ActiveSession>>(&bytes) {
                Ok(v) => Ok(v),
                Err(e) => {
                    tracing::warn!(
                        target: "tessera.monitord",
                        error = %e,
                        path = ?self.path,
                        "sessions.json corrupt, starting empty"
                    );
                    Ok(Vec::new())
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Atomically replace the on-disk file with a new snapshot.
    ///
    /// Delegates the tempfile + fd-label + fsync + rename sequence to
    /// [`crate::state::write_sessions_atomic`] so the МКЦ irelax label
    /// is set on the inode before it becomes visible at the published
    /// path (closes the path-based TOCTOU window per spec §5.3.1).
    /// After the rename the parent directory is `fsync`'d so the rename
    /// survives a power loss.
    ///
    /// This call is synchronous and may block; async callers should run it
    /// inside `tokio::task::spawn_blocking`.
    ///
    /// # Errors
    ///
    /// Returns the underlying `io::Error` for any failure during temp-file
    /// creation, write, rename, or directory fsync. Label failures are
    /// downgraded to a warning by `write_sessions_atomic`.
    pub fn persist(&self, snapshot: &[ActiveSession]) -> io::Result<()> {
        let parent = self.path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "registry path has no parent")
        })?;
        std::fs::create_dir_all(parent)?;

        let bytes = serde_json::to_vec_pretty(snapshot)?;

        #[cfg(feature = "astra-mac")]
        let backend = tessera_mac_parsec::ParsecBackend::new();
        #[cfg(not(feature = "astra-mac"))]
        let backend = tessera_core::mac::backend::StubBackend::new();

        crate::state::write_sessions_atomic(&self.path, &bytes, &backend)?;

        // fsync the parent directory so the rename is durable.
        let dir = File::open(parent)?;
        dir.sync_all()?;

        Ok(())
    }
}
