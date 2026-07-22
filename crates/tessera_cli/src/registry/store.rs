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

/// Failure loading the persisted session registry at startup.
///
/// A missing file is NOT an error (it deserialises to an empty registry —
/// a fresh host). Corruption and other I/O failures are surfaced so the
/// daemon can refuse to start rather than silently continue with an empty
/// registry: an empty registry drops every active session and its future
/// credential-removal action, which is exactly the fail-open outcome the
/// enforcement path exists to prevent.
#[derive(Debug, thiserror::Error)]
pub enum RegistryLoadError {
    /// The registry file exists but could not be read.
    #[error("read session registry {path}: {source}")]
    Read {
        /// Registry path that failed to read.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The registry file exists and was read, but its contents are not
    /// valid registry JSON. Treated as fail-closed rather than reset to
    /// empty so active sessions are not silently lost.
    #[error("session registry {path} is corrupt: {source}")]
    Corrupt {
        /// Registry path that failed to parse.
        path: PathBuf,
        /// Underlying deserialisation error.
        #[source]
        source: serde_json::Error,
    },
}

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
    /// A missing file deserialises to an empty registry (a fresh host).
    /// A present-but-corrupt file, or any other read failure, is reported so
    /// the caller can fail closed: silently resetting a corrupt registry to
    /// empty would drop every active session and its pending credential-
    /// removal action across a daemon restart.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryLoadError::Read`] for a non-`NotFound` I/O failure
    /// and [`RegistryLoadError::Corrupt`] when the file body is not valid
    /// registry JSON.
    pub fn load(&self) -> Result<Vec<ActiveSession>, RegistryLoadError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice::<Vec<ActiveSession>>(&bytes).map_err(|source| {
                RegistryLoadError::Corrupt {
                    path: self.path.clone(),
                    source,
                }
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(source) => Err(RegistryLoadError::Read {
                path: self.path.clone(),
                source,
            }),
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
