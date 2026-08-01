//! Where the provider's log goes.
//!
//! Inside `LogonUI` there is no console, no inherited journal and nobody to
//! read a message that goes nowhere. Without a sink of its own, every
//! diagnostic this crate emits is discarded, and a tile that misbehaves on a
//! stand has to be diagnosed by reading source instead of reading a log. So the
//! provider opens one file in the service's data directory and installs a
//! subscriber over it the first time `LogonUI` asks for a class object.
//!
//! # What is written, and what is not
//!
//! The log records what the provider *did*: which COM entry point was called,
//! which fail-closed path was taken, which error category came back, and the
//! `session_id` that ties a logon to the service's journal entry. It does not
//! record the PIN, the technical account's password, or any credential
//! material. That is a property of the call sites — the secret-bearing types
//! redact themselves in `Debug` and are never formatted with `Display` — and
//! not of a filter here, because a filter is something one forgets to update.
//!
//! # Where
//!
//! `C:\ProgramData\Tessera\logs\tessera_cp.log`. The root is taken by literal
//! rather than from `%ProgramData%`, matching the service: the environment is
//! an input from whoever started the process, and this process is started by
//! Windows.
//!
//! The root must already exist — `prepare` creates it with a descriptor that
//! admits only `SYSTEM` and administrators. This module creates the `logs`
//! subdirectory under it, which inherits that descriptor, and never creates the
//! root itself: a root created here would inherit `%ProgramData%`'s permissions
//! instead, and those let any user write into the tree.
//!
//! # When it cannot
//!
//! Every failure to set logging up is swallowed. There is nowhere to report it
//! to, and a provider that refuses to work because it cannot write a log file
//! would be a worse failure than a silent one.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Once};

use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

/// Root of the data directory the service prepares.
pub const DEFAULT_DATA_DIR: &str = r"C:\ProgramData\Tessera";

/// Subdirectory holding logs.
pub const LOG_DIR_NAME: &str = "logs";

/// The provider's log file.
pub const LOG_FILE_NAME: &str = "tessera_cp.log";

/// Environment variable that overrides the level.
pub const LEVEL_ENV: &str = "TESSERA_CP_LOG";

/// Level used when [`LEVEL_ENV`] says nothing.
///
/// Verbose on purpose while the Windows path is being brought up on a stand:
/// the first questions asked of this log are "was this entry point called at
/// all" and "in what order", and both are answered at `debug`. Turning it down
/// is setting `TESSERA_CP_LOG=info` machine-wide.
pub const DEFAULT_LEVEL: &str = "debug";

/// Size past which the log is rotated once, at open.
const MAX_LOG_BYTES: u64 = 8 * 1024 * 1024;

/// Why logging could not be set up.
#[derive(Debug, thiserror::Error)]
pub enum LogError {
    /// The data directory does not exist, so `prepare` has not run.
    #[error("the data directory {0} does not exist")]
    NoDataDir(PathBuf),
    /// The log directory or file could not be opened.
    #[error("log file io: {0}")]
    Io(#[from] io::Error),
    /// A subscriber was already installed.
    #[error("a global subscriber is already installed")]
    AlreadyInstalled,
}

/// Installs the file subscriber, once per process.
///
/// Safe to call from every entry point that might be the first one; subsequent
/// calls do nothing.
pub fn init() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        drop(init_in(Path::new(DEFAULT_DATA_DIR)));
    });
}

/// Installs the subscriber against an explicit data directory.
///
/// # Errors
///
/// [`LogError`] when the directory is missing, the file cannot be opened, or a
/// subscriber is already installed.
pub fn init_in(data_dir: &Path) -> Result<(), LogError> {
    let file = open_log_file(data_dir)?;
    let writer = SharedFile(Arc::new(Mutex::new(file)));

    let filter =
        EnvFilter::try_from_env(LEVEL_ENV).unwrap_or_else(|_| EnvFilter::new(DEFAULT_LEVEL));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_ansi(false)
        .with_target(true)
        .with_level(true)
        .try_init()
        .map_err(|_| LogError::AlreadyInstalled)
}

/// Opens the log file, rotating it first if it has grown past the cap.
///
/// # Errors
///
/// [`LogError::NoDataDir`] when the root is absent — that means `prepare` never
/// ran, and creating the root here would give it the wrong permissions.
/// [`LogError::Io`] for anything the filesystem refuses.
pub fn open_log_file(data_dir: &Path) -> Result<File, LogError> {
    if !data_dir.is_dir() {
        return Err(LogError::NoDataDir(data_dir.to_path_buf()));
    }

    let log_dir = data_dir.join(LOG_DIR_NAME);
    std::fs::create_dir_all(&log_dir)?;

    let path = log_dir.join(LOG_FILE_NAME);
    rotate_if_large(&path)?;

    Ok(OpenOptions::new().create(true).append(true).open(&path)?)
}

/// Moves an oversized log aside so the new one starts empty.
///
/// One generation is kept. A logon screen writes very little, so the cap exists
/// to bound a pathological loop rather than to archive history; keeping more
/// generations would mean deciding how much of a system directory this crate
/// may consume, which is not its decision to make.
fn rotate_if_large(path: &Path) -> Result<(), LogError> {
    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(());
    };
    if metadata.len() < MAX_LOG_BYTES {
        return Ok(());
    }

    let mut previous = path.as_os_str().to_owned();
    previous.push(".1");
    std::fs::rename(path, previous)?;
    Ok(())
}

/// A log file several threads may write to.
///
/// The provider's own worker threads log, so the sink is shared rather than
/// owned by one of them. A poisoned lock drops the line: a log that panics
/// inside `LogonUI` would be worse than a log with a hole in it.
#[derive(Clone)]
struct SharedFile(Arc<Mutex<File>>);

impl Write for SharedFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.0.lock() {
            Ok(mut file) => file.write(buf),
            Err(_poisoned) => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.0.lock() {
            Ok(mut file) => file.flush(),
            Err(_poisoned) => Ok(()),
        }
    }
}

impl<'writer> MakeWriter<'writer> for SharedFile {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_missing_data_directory_is_refused_rather_than_created() {
        let root = tempfile::tempdir().unwrap();
        let absent = root.path().join("never-prepared");

        let error = open_log_file(&absent).unwrap_err();
        assert!(matches!(error, LogError::NoDataDir(_)), "got {error:?}");
        assert!(
            !absent.exists(),
            "the root must not be created here: it would inherit the wrong permissions"
        );
    }

    #[test]
    fn the_log_directory_is_created_under_a_prepared_root() {
        let root = tempfile::tempdir().unwrap();

        let mut file = open_log_file(root.path()).unwrap();
        writeln!(file, "line").unwrap();

        let path = root.path().join(LOG_DIR_NAME).join(LOG_FILE_NAME);
        assert!(path.is_file());
        assert!(std::fs::read_to_string(&path).unwrap().contains("line"));
    }

    #[test]
    fn a_second_open_appends_rather_than_truncates() {
        let root = tempfile::tempdir().unwrap();
        writeln!(open_log_file(root.path()).unwrap(), "first").unwrap();
        writeln!(open_log_file(root.path()).unwrap(), "second").unwrap();

        let path = root.path().join(LOG_DIR_NAME).join(LOG_FILE_NAME);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("first") && content.contains("second"));
    }

    #[test]
    fn an_oversized_log_is_rotated_once() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(LOG_DIR_NAME).join(LOG_FILE_NAME);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            vec![b'x'; usize::try_from(MAX_LOG_BYTES).unwrap() + 1],
        )
        .unwrap();

        let mut file = open_log_file(root.path()).unwrap();
        writeln!(file, "fresh").unwrap();

        let mut rotated = path.as_os_str().to_owned();
        rotated.push(".1");
        assert!(Path::new(&rotated).is_file(), "the old log was kept");
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "fresh\n", "the new log starts empty");
    }

    #[test]
    fn a_log_within_the_cap_is_left_alone() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(LOG_DIR_NAME).join(LOG_FILE_NAME);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"small").unwrap();

        drop(open_log_file(root.path()).unwrap());

        let mut rotated = path.as_os_str().to_owned();
        rotated.push(".1");
        assert!(!Path::new(&rotated).exists());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "small");
    }
}
