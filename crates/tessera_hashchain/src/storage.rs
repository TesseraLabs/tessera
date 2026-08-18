//! Storage backends: a file, an in-memory vector, and one that always fails.

// Both are used only by backends that a feature turns on: with every feature
// off this module is the `ChainLock` trait and nothing else, and an
// unconditional import would warn — a warning that fails a build under a
// deny-warnings CI for a configuration that is otherwise perfectly valid.
#[cfg(any(test, feature = "file", feature = "testing"))]
use crate::chain::{ChainError, ChainStorage};

/// An exclusive hold on a chain for the length of one append transaction.
///
/// Carries nothing. What it is for is to exist until the transaction ends and
/// to release the underlying lock when it is dropped — including when the
/// process dies holding it, which is why the file backend expresses it as
/// `flock(2)` rather than as the existence of a lock file.
pub trait ChainLock {}

/// The hold taken by a storage that needs none: a `Vec` in one process, a
/// browser's own storage.
#[derive(Debug)]
pub struct NoLock;

impl ChainLock for NoLock {}

/// A file-backed storage: one NDJSON line per record.
///
/// Native only — a `wasm32` host supplies its own [`ChainStorage`] instead,
/// which is why this sits behind a feature.
///
/// # Why this backend locks, and over what
///
/// `pam_tessera` is a shared object in somebody else's process, and `sshd`
/// forks per connection. Two logins at once open the same journal. Without a
/// lock each of them reads the same tail, computes the same `seq` and the same
/// `prev_hash`, and appends — and the chain is broken from the next position
/// **for good**, because opening a broken chain is deliberately allowed and the
/// journal keeps growing past the break. Nothing reports it: both writes return
/// success, and the damage surfaces during an incident review, which is the one
/// moment the journal exists for.
///
/// So the lock covers the whole transaction — read the tail, then append — and
/// not the write alone. An atomic write was never the missing piece: neither
/// line is torn, they simply claim the same position.
///
/// # Why the write is one call and then synchronised
///
/// The [`ChainStorage`] contract says a line is persisted before `append`
/// returns, and a login is granted on the strength of that. Two `write_all`
/// calls could leave a line without its newline if the process dies between
/// them, gluing it to the next one and breaking the chain unrecoverably; and an
/// unsynchronised write can be a login granted against a record that a power
/// cut removes. One buffer, one write, then `sync_data`.
#[cfg(feature = "file")]
#[derive(Debug, Clone)]
pub struct FileStorage {
    path: std::path::PathBuf,
}

#[cfg(feature = "file")]
impl FileStorage {
    /// A file store at `path`, created on first append.
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The path the records live at.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// How many bytes the records occupy, counting the newline framing.
    ///
    /// A journal that has never been written occupies none. Callers with a
    /// ceiling ask this before appending — the size has to be known *before* the
    /// line lands, or the ceiling is a report of an overrun rather than a limit.
    ///
    /// # Errors
    ///
    /// [`ChainError::Storage`] if the file exists but cannot be inspected.
    pub fn byte_len(&self) -> Result<u64, ChainError> {
        match std::fs::metadata(&self.path) {
            Ok(meta) => Ok(meta.len()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(ChainError::Storage(e.to_string())),
        }
    }

    /// Creates `path` with [`OWNER_ONLY`], or opens it if it is already there.
    ///
    /// Returns whether the file had to be created, because the caller has
    /// durability work to do only in that case.
    fn open_for_append(&self) -> Result<(std::fs::File, bool), ChainError> {
        let existed = self.path.exists();
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(OWNER_ONLY);
        }
        let file = options
            .open(&self.path)
            .map_err(|e| ChainError::Storage(e.to_string()))?;

        // Two mechanisms, and they cover different holes — worth spelling out,
        // because either alone leaves one open.
        //
        // The `mode` above governs creation. Without it the request is `0o666`
        // and a process with a lax umask creates a world-writable journal;
        // with it the request is already `OWNER_ONLY`, and since the umask can
        // only ever *remove* bits, no umask can widen it.
        //
        // The pin below governs everything after that. `mode` says nothing
        // about a file that already exists, and a journal that became writable
        // by group or other at any point — a careless `chmod`, a restore from
        // an archive that did not carry modes, an installer with its own ideas
        // — is exactly as worthless as one created that way: whoever may write
        // it may rewrite the history and recompute the chain over it. There is
        // no legitimate reason for this file to be wider than its owner, so it
        // is narrowed back on every open rather than left as found and reported
        // somewhere an operator may never look. One `chmod` beside an `fsync`.
        pin_owner_only(&self.path)?;
        Ok((file, existed))
    }

    /// Path of the file the exclusive hold is taken on.
    ///
    /// A file of its own rather than the journal: the lock has to be takeable
    /// before the journal exists, and an advisory lock on a path that is later
    /// replaced would be a lock on a different inode.
    fn lock_path(&self) -> std::path::PathBuf {
        let mut name = self.path.as_os_str().to_os_string();
        name.push(".lock");
        std::path::PathBuf::from(name)
    }
}

/// Permissions the journal and its lock are created with: root alone.
///
/// The value of a hash chain is that an edit is visible. An edit made by
/// somebody the filesystem allows to write is not visible — the chain is not
/// keyed, so recomputing every link after a change is arithmetic anybody can do
/// (see `tessera_core::audit::attest`, where a forgery is built in a dozen
/// lines). A journal writable by group or other is therefore not a weaker
/// journal; it is a decorative one.
///
/// So the mode is pinned rather than left to `open(2)`, whose mode argument is
/// filtered through the umask of whichever process happens to create the file
/// first. A daemon started with a lax umask would otherwise decide the security
/// of the record.
#[cfg(all(feature = "file", unix))]
const OWNER_ONLY: u32 = 0o600;

/// Longest an append waits for another process to finish its transaction.
///
/// One transaction is a tail read and a write — sub-millisecond. Reaching this
/// bound means the holder is not making progress, and waiting longer would move
/// the failure from "refused" to "a login that hangs".
#[cfg(feature = "file")]
const LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long to sleep between attempts while waiting for the lock.
#[cfg(feature = "file")]
const LOCK_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

#[cfg(feature = "file")]
impl ChainStorage for FileStorage {
    fn append(&mut self, line: &str) -> Result<(), ChainError> {
        use std::io::Write as _;

        let (mut file, existed) = self.open_for_append()?;

        // One buffer, one write: a line that reached the file without its
        // newline would be glued to the next one, and no later read could tell
        // the two apart.
        let mut framed = String::with_capacity(line.len() + 1);
        framed.push_str(line);
        framed.push('\n');
        file.write_all(framed.as_bytes())
            .map_err(|e| ChainError::Storage(e.to_string()))?;

        // The caller grants a login on the strength of this record. An
        // unsynchronised write is a login granted against a record a power cut
        // takes away.
        file.sync_data()
            .map_err(|e| ChainError::Storage(e.to_string()))?;

        // The first record has to make its own directory entry durable too.
        // Synchronising the file guarantees its contents survive a power cut;
        // it says nothing about the *name*, and a journal whose name did not
        // survive is a journal that did not survive.
        //
        // So the outcome is propagated, not swallowed. Discarding it would
        // leave the caller believing a record is durable when the thing that
        // makes it findable may not be — which is the same failure the record
        // exists to prevent, one level down.
        if !existed {
            sync_parent_directory(&self.path)?;
        }
        Ok(())
    }

    fn read_lines(&self) -> Result<Vec<String>, ChainError> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => Ok(text.lines().map(str::to_owned).collect()),
            // A never-written journal has no lines yet.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(ChainError::Storage(e.to_string())),
        }
    }

    /// Reads the last line without reading the ones before it.
    ///
    /// The append path needs the tail and nothing else, and it runs on every
    /// login. Reading the whole journal to find its last line would put the
    /// entire history through a JSON parser on each authentication, and would
    /// do it worst on exactly the device whose journal has grown.
    fn tail(&self) -> Result<Option<String>, ChainError> {
        use std::io::{Read as _, Seek as _, SeekFrom};

        /// How much of the end to pull in at a time while looking backwards for
        /// the newline that starts the last line.
        const WINDOW: u64 = 4096;

        let mut file = match std::fs::File::open(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(ChainError::Storage(e.to_string())),
        };
        let len = file
            .metadata()
            .map_err(|e| ChainError::Storage(e.to_string()))?
            .len();
        if len == 0 {
            return Ok(None);
        }

        let mut end = len;
        let mut buffer: Vec<u8> = Vec::new();
        loop {
            let start = end.saturating_sub(WINDOW);
            let span = usize::try_from(end - start)
                .map_err(|_| ChainError::Storage("the journal tail is beyond this build".into()))?;
            let mut window = vec![0u8; span];
            file.seek(SeekFrom::Start(start))
                .map_err(|e| ChainError::Storage(e.to_string()))?;
            file.read_exact(&mut window)
                .map_err(|e| ChainError::Storage(e.to_string()))?;
            window.extend_from_slice(&buffer);
            buffer = window;

            let body = buffer.strip_suffix(b"\n").unwrap_or(&buffer);
            if let Some(position) = body.iter().rposition(|byte| *byte == b'\n') {
                let line = body.get(position + 1..).unwrap_or_default();
                return Ok(Some(String::from_utf8_lossy(line).into_owned()));
            }
            if start == 0 {
                return Ok(Some(String::from_utf8_lossy(body).into_owned()));
            }
            end = start;
        }
    }

    fn lock(&self) -> Result<Box<dyn ChainLock>, ChainError> {
        acquire(&self.lock_path())
    }
}

/// Pins `path` to [`OWNER_ONLY`], defeating the umask that `open(2)` applied.
#[cfg(all(feature = "file", unix))]
fn pin_owner_only(path: &std::path::Path) -> Result<(), ChainError> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(OWNER_ONLY)).map_err(|error| {
        ChainError::Storage(format!(
            "the permissions of {} could not be pinned to {OWNER_ONLY:o}, and a journal writable \
             by anyone but its owner is not evidence of anything: {error}",
            path.display()
        ))
    })
}

/// Where POSIX modes do not exist there is nothing to pin.
///
/// On Windows the journal takes the ACL it inherits from its directory, and
/// this crate does not narrow it. That is a real gap rather than a portability
/// footnote: the umask defence above has no Windows counterpart here, so a
/// journal in a directory an installer left permissive is writable by whoever
/// that directory admits — and whoever may write it may rewrite the history and
/// recompute the chain over it. Closing it properly means setting a DACL, which
/// belongs with the privileged-path machinery that already does DACL work, not
/// in the format crate. Named here so it is not mistaken for handled.
#[cfg(all(feature = "file", not(unix)))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the Result is not spurious: it is the signature the unix arm has, \
              and the shared call site reaches both with `?`. Narrowing this arm \
              to `()` would move the platform difference from one `cfg` here into \
              every place that pins a mode"
)]
fn pin_owner_only(path: &std::path::Path) -> Result<(), ChainError> {
    let _ = path;
    Ok(())
}

/// Makes the directory entry of a newly created journal durable.
///
/// Unix only, and not for portability handwaving: a directory is not openable
/// as a file on Windows at all, so there is nothing to synchronise and nothing
/// to report. On unix a failure is returned — see the call site for why it is
/// not swallowed.
#[cfg(all(feature = "file", unix))]
fn sync_parent_directory(path: &std::path::Path) -> Result<(), ChainError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    let dir = std::fs::File::open(parent).map_err(|error| {
        ChainError::Storage(format!(
            "the journal was written but its directory {} could not be opened to make the new \
             entry durable: {error}",
            parent.display()
        ))
    })?;
    dir.sync_all().map_err(|error| {
        ChainError::Storage(format!(
            "the journal was written but the directory entry naming it could not be made \
             durable: {error}"
        ))
    })
}

/// The same, where directories cannot be synchronised at all.
#[cfg(all(feature = "file", not(unix)))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the Result is not spurious: it is the signature the unix arm has, \
              and the shared call site reaches both with `?`. Narrowing this arm \
              to `()` would move the platform difference from one `cfg` here into \
              the append path"
)]
fn sync_parent_directory(path: &std::path::Path) -> Result<(), ChainError> {
    let _ = path;
    Ok(())
}

/// Takes the exclusive hold on the journal.
///
/// The hold itself — the system call, the non-blocking attempt, the retries and
/// the refusal — is [`crate::file_lock`], shared with the device code state,
/// which needs exactly the same thing for exactly the same reason. What stays
/// here is what belongs to the journal: where the file is, what mode it carries
/// and which error a failure becomes.
#[cfg(feature = "file")]
fn acquire(path: &std::path::Path) -> Result<Box<dyn ChainLock>, ChainError> {
    /// The hold, in the shape the chain expects.
    struct FileLock {
        /// Never read. Dropping it releases the hold — including when the
        /// process dies, which a lock expressed as "the path exists" could not
        /// promise inside a PAM module.
        _held: crate::file_lock::FileLock,
    }
    impl ChainLock for FileLock {}

    let file = open_lock_file(path)?;
    let held = crate::file_lock::lock_exclusive(file, LOCK_TIMEOUT, LOCK_RETRY_INTERVAL)
        .map_err(|e| ChainError::Storage(format!("the journal lock could not be taken: {e}")))?;
    Ok(Box::new(FileLock { _held: held }))
}

/// Opens the lock file with the mode the journal insists on.
#[cfg(all(feature = "file", unix))]
fn open_lock_file(path: &std::path::Path) -> Result<std::fs::File, ChainError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(OWNER_ONLY)
        .open(path)
        .map_err(|e| ChainError::Storage(format!("the journal lock could not be opened: {e}")))?;
    // The lock holds no data — only a hold on a descriptor — so a permissive
    // mode leaks nothing. It is pinned all the same: a file anyone may replace
    // is a lock anyone may take somewhere else, and the whole point of the hold
    // is that two writers contend for the same one.
    pin_owner_only(path)?;
    Ok(file)
}

/// The same, where the mode word does not exist.
///
/// Named rather than absorbed: off Unix the lock file carries whatever the
/// directory grants, so "a file anyone may replace is a lock anyone may take
/// somewhere else" is not closed here. Closing it means a DACL, which belongs
/// with the machinery that already does DACL work — see the note on
/// [`FileStorage`].
#[cfg(all(feature = "file", not(unix)))]
fn open_lock_file(path: &std::path::Path) -> Result<std::fs::File, ChainError> {
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|e| ChainError::Storage(format!("the journal lock could not be opened: {e}")))
}

/// A `Vec`-backed storage, for tests and for hosts that persist elsewhere.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Default, Clone)]
pub struct MemoryStorage {
    lines: std::cell::RefCell<Vec<String>>,
}

#[cfg(any(test, feature = "testing"))]
impl MemoryStorage {
    /// An empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The currently stored lines.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        self.lines.borrow().clone()
    }

    /// Replaces the stored lines, as a tamper would.
    ///
    /// It exists so a test can cut a line out, swap two, or edit one in place
    /// and then ask verification where the break is.
    pub fn set_lines(&self, lines: Vec<String>) {
        *self.lines.borrow_mut() = lines;
    }
}

#[cfg(any(test, feature = "testing"))]
impl ChainStorage for MemoryStorage {
    fn append(&mut self, line: &str) -> Result<(), ChainError> {
        self.lines.borrow_mut().push(line.to_owned());
        Ok(())
    }

    fn read_lines(&self) -> Result<Vec<String>, ChainError> {
        Ok(self.lines.borrow().clone())
    }
}

/// A storage whose `append` always fails, to drive the fail-closed path.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Default, Clone)]
pub struct FailingStorage;

#[cfg(any(test, feature = "testing"))]
impl ChainStorage for FailingStorage {
    fn append(&mut self, _line: &str) -> Result<(), ChainError> {
        Err(ChainError::Storage("append disabled for test".to_owned()))
    }

    fn read_lines(&self) -> Result<Vec<String>, ChainError> {
        Ok(Vec::new())
    }
}
