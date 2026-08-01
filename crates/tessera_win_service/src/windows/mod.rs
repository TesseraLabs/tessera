//! Everything that needs Win32, and nothing that does not.
//!
//! The split is deliberate: the modules under here are the ones that cannot be
//! exercised anywhere but on Windows, so keeping them thin is what keeps the
//! part of the service that *can* be tested large. Each one wraps one facility
//! — the security descriptor, the account database, DPAPI, the named pipe, the
//! service control manager — and hands back ordinary Rust values.

pub mod account;
pub mod dacl;
pub mod dpapi;
pub mod engine;
pub mod overlapped;
pub mod pipe;
pub mod prepare;
pub mod scm;
pub mod sys;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crate::journal::{Event, Journal, JournalMonitor};
use crate::paths::DataDir;

use engine::WindowsEngine;
use sys::WinError;

/// Why the service could not run.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// The journal could not be opened or its opening line could not be
    /// written. The service does not start without one: a device that cannot
    /// record admissions must not hand any out.
    #[error("journal: {0}")]
    Journal(#[from] crate::journal::JournalError),
    /// A Win32 call failed.
    #[error("{0}")]
    Win(#[from] WinError),
}

impl ServiceError {
    /// The code reported to the service control manager. Windows errors keep
    /// their own; everything else is a generic failure.
    #[must_use]
    pub fn code(&self) -> u32 {
        match self {
            Self::Win(e) => e.code,
            Self::Journal(_) => 1,
        }
    }
}

/// Opens the journal, builds the engine, and serves the pipe until stopped.
///
/// `on_running` is called once the pipe is listening. It exists so the service
/// control manager is told `RUNNING` at the point the service actually is —
/// not before the journal is open, and not after the first client has been
/// waited for.
///
/// # Errors
///
/// [`ServiceError`] when the journal cannot be opened or the pipe cannot be
/// created. Both are refusals to serve rather than degraded operation.
pub fn run_listener(
    data_dir: DataDir,
    account_name: String,
    pipe_name: String,
    stop: Arc<AtomicBool>,
    on_running: impl FnOnce(),
) -> Result<(), ServiceError> {
    let journal = Arc::new(JournalMonitor::new(Journal::open(data_dir.journal())?));
    journal.record(Event::ServiceStarted {
        version: crate::SERVICE_VERSION.to_owned(),
        pipe: pipe_name.clone(),
    })?;

    let engine = Arc::new(WindowsEngine::new(
        data_dir,
        account_name,
        Arc::clone(&journal),
    ));
    let mut listener = pipe::Listener::new(pipe_name, stop);
    on_running();
    let outcome = listener.run(&engine);

    // The stop is recorded whether the loop ended cleanly or not, so that a
    // journal read afterwards shows where the service went.
    if let Err(error) = journal.record(Event::ServiceStopped) {
        tracing::error!(
            target: "tessera.engine",
            error = %error,
            "service stop could not be journaled"
        );
    }
    outcome.map_err(ServiceError::Win)
}
