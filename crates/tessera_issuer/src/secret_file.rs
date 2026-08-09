//! The owner-only gate every file holding secret material passes through.
//!
//! Two inputs of the issuer are secret-bearing files: the file backend's PKCS#8
//! CA key and a secret file named on the command line (`--pin-file`,
//! `--key-passphrase-file`). Both are refused when the filesystem lets anyone
//! but the owner read them.
//!
//! The gate is applied to an *open descriptor*, never to a path: [`open`]
//! opens the file first and checks the metadata of that very handle, so the
//! answer cannot describe a different file than the one whose bytes are read.
//! Checking a path and then opening it leaves a window in which the path is
//! repointed — through a symlink or a rename — at a file the check never saw.
//! Opening does not read, so the requirement that an over-permissive file is
//! refused *before its content is read* still holds.
//!
//! The check lives here rather than beside either reader so the platform
//! difference has a single site: Unix has a permission model to enforce
//! (`mode & 0o077 == 0`, the precedent is `OpenSSH`), Windows does not express
//! access this way and its ACLs are not comparable bit for bit, so there the
//! gate passes and protection rests on the directory the file lives in. That
//! difference is announced rather than assumed — see [`GATE_ENFORCED`].
//!
//! The two readers are reached by different builds. Whole-file reading serves
//! the file backend's CA key and is there whenever that backend is; line
//! reading serves the command line's secret ladder — `--pin-file`,
//! `--key-passphrase-file`, `--pin-stdin` — and the announcement of an
//! unenforced gate is the ladder's to make, so both are built with the CLI. A
//! build with the file backend and no CLI has no caller for either.

// In a build with the file backend but no command line, the line-reading half —
// `read_line`, `read_first_line`, `ReadLineError`, its bound, and the gate's
// reach — has no caller left. It is kept whole rather than split by feature so
// the file and the gate stay described in one place; the readers themselves are
// unconditional, and adding the CLI feature back puts every one of them to work.
#![cfg_attr(not(feature = "cli"), allow(dead_code))]

use std::io::Read as _;
use std::path::Path;

use zeroize::Zeroizing;

/// Whether the owner-only permission gate is enforced on this target.
///
/// `false` means [`open`] admits any file the process can open at all. Callers
/// read this to tell the operator that the check did not run, so "no complaint"
/// is not mistaken for "the permissions were checked and are fine".
pub(crate) const GATE_ENFORCED: bool = cfg!(unix);

/// A file whose permission bits let group or others reach it.
///
/// Carries only the offending mode — never the path (the caller already has it)
/// and never any content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BeyondOwner {
    /// The file's permission bits (`st_mode & 0o7777`).
    pub(crate) mode: u32,
}

/// Why a secret-bearing file could not be opened for reading.
#[derive(Debug)]
pub(crate) enum OpenError {
    /// The file could not be opened or its metadata could not be read.
    Io(std::io::Error),
    /// The file is reachable beyond its owner.
    BeyondOwner(BeyondOwner),
}

/// The longest secret one line may carry, in bytes.
///
/// A PIN is a handful of characters and a passphrase a line of prose; four
/// kibibytes is far past either. The bound is what makes the read finite when
/// the source has no line terminator at all — a binary stream, `/dev/zero`, a
/// device that never ends — and it is reserved up front, so the buffer holding
/// the secret is never grown and never leaves a copy of what it held behind in
/// freed memory.
pub(crate) const MAX_SECRET_LEN: usize = 4096;

/// The largest buffer reserved from a file's declared size.
///
/// A PKCS#8 key is a few kibibytes; the clamp keeps a file that claims an
/// absurd length (a sparse file, a device, a corrupt entry) from demanding that
/// allocation up front, where `usize::MAX` would be an outright abort.
const MAX_RESERVE: usize = 1 << 20;

/// Why one line of a secret could not be read.
#[derive(Debug)]
pub(crate) enum ReadLineError {
    /// No line terminator arrived within [`MAX_SECRET_LEN`] bytes.
    TooLong,
    /// The underlying read failed.
    Io(std::io::Error),
}

/// A secret-bearing file that has passed the owner-only gate.
#[derive(Debug)]
pub(crate) struct SecretFile {
    /// The open handle the gate was applied to.
    file: std::fs::File,
    /// The file's size at the moment of the check, used to size the read buffer
    /// so the content is not copied between growing allocations.
    length: u64,
}

/// Open a secret-bearing file and refuse it if it is group- or world-accessible.
///
/// The gate runs on the metadata of the returned handle (`fstat`, not `stat`),
/// so a path swapped between the check and the read cannot smuggle in a file
/// that was never checked.
///
/// # Errors
///
/// [`OpenError::Io`] when the file cannot be opened or interrogated,
/// [`OpenError::BeyondOwner`] when any group or other permission bit is set. On
/// non-Unix targets the permission check always passes — see the module docs.
pub(crate) fn open(path: &Path) -> Result<SecretFile, OpenError> {
    let file = std::fs::File::open(path).map_err(OpenError::Io)?;
    let metadata = file.metadata().map_err(OpenError::Io)?;
    reject_beyond_owner(&metadata).map_err(OpenError::BeyondOwner)?;
    Ok(SecretFile {
        file,
        length: metadata.len(),
    })
}

impl SecretFile {
    /// Read the file's first line, and no more of it.
    ///
    /// Reading stops at the first line terminator, so nothing beyond the secret
    /// is consumed and a source that is still being written — a FIFO whose
    /// writer stays attached, a terminal device — answers as soon as the line
    /// arrives instead of waiting for an end that may never come. The declared
    /// size is not consulted at all: on a FIFO, a character device or anything
    /// else the filesystem sizes at zero it says nothing about the content.
    ///
    /// # Errors
    ///
    /// [`ReadLineError::TooLong`] when no terminator arrives within
    /// [`MAX_SECRET_LEN`] bytes, [`ReadLineError::Io`] on a read failure.
    pub(crate) fn read_first_line(mut self) -> Result<Zeroizing<Vec<u8>>, ReadLineError> {
        read_line(&mut self.file)
    }

    /// Read the whole file into a buffer that is wiped when it is dropped.
    ///
    /// For the one input that is whole-file by nature: the CA key. The buffer is
    /// reserved from the size seen at the gate (clamped by [`MAX_RESERVE`]), so
    /// the usual read completes without a reallocation — a grown `Vec` would
    /// leave the bytes it moved away from in freed memory, unwiped. A file that
    /// grew between the two moments still reads in full; only the no-copy
    /// property is lost.
    ///
    /// # Errors
    ///
    /// The underlying read error.
    pub(crate) fn read_all(mut self) -> std::io::Result<Zeroizing<Vec<u8>>> {
        let reserve = usize::try_from(self.length)
            .unwrap_or(MAX_RESERVE)
            .min(MAX_RESERVE);
        let mut buffer = Zeroizing::new(Vec::with_capacity(reserve.saturating_add(1)));
        self.file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }
}

/// Read one line into a buffer that is wiped when it is dropped, dropping a
/// single trailing line terminator (`\n`, optionally preceded by `\r`).
///
/// The read is byte at a time and unbuffered on purpose: a `BufReader` would
/// hold the rest of the stream — the secret's own tail among it — in an
/// allocation nobody wipes. Secrets are short, so the syscalls are few, and
/// nothing beyond the line is consumed.
///
/// The buffer is reserved to [`MAX_SECRET_LEN`] once and never grown, so no
/// intermediate allocation carrying part of the secret is ever freed unwiped.
///
/// Only the terminator goes: a secret's own trailing spaces are its content.
///
/// # Errors
///
/// [`ReadLineError::TooLong`] when no terminator arrives within
/// [`MAX_SECRET_LEN`] bytes, [`ReadLineError::Io`] on a read failure.
#[expect(
    clippy::unbuffered_bytes,
    reason = "a buffered read would keep the secret in an allocation that is never wiped; \
              a secret is a line long, so the syscalls it costs are a handful"
)]
pub(crate) fn read_line(
    source: &mut impl std::io::Read,
) -> Result<Zeroizing<Vec<u8>>, ReadLineError> {
    let mut buffer = Zeroizing::new(Vec::with_capacity(MAX_SECRET_LEN));
    for byte in source.bytes() {
        let byte = byte.map_err(ReadLineError::Io)?;
        if byte == b'\n' {
            break;
        }
        if buffer.len() == MAX_SECRET_LEN {
            return Err(ReadLineError::TooLong);
        }
        buffer.push(byte);
    }
    if buffer.last() == Some(&b'\r') {
        buffer.pop();
    }
    Ok(buffer)
}

/// Refuse a secret-bearing file that is group- or world-accessible.
///
/// `metadata` must belong to an already open handle — see [`open`], the only
/// caller.
///
/// # Errors
///
/// [`BeyondOwner`] with the file's permission bits when any group or other bit
/// is set. On non-Unix targets the check always passes — see the module docs.
fn reject_beyond_owner(metadata: &std::fs::Metadata) -> Result<(), BeyondOwner> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(BeyondOwner {
                mode: mode & 0o7777,
            });
        }
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::io::Read as _;

    use super::{open, read_line, OpenError, ReadLineError, GATE_ENFORCED, MAX_SECRET_LEN};

    /// The gate runs on the handle that is read, and an owner-only file passes
    /// with its content intact.
    #[test]
    fn an_owner_only_file_opens_and_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, b"s3cret\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let bytes = open(&path).unwrap().read_all().unwrap();
        assert_eq!(&*bytes, b"s3cret\n");
    }

    /// A file group or others can read is refused, and the error carries the
    /// mode rather than anything from the file.
    #[cfg(unix)]
    #[test]
    fn a_group_readable_file_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, b"s3cret\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        match open(&path) {
            Err(OpenError::BeyondOwner(e)) => assert_eq!(e.mode, 0o644),
            other => panic!("expected a permission refusal, got {other:?}"),
        }
    }

    /// The gate's platform reach is what the callers announce to the operator.
    #[test]
    fn the_gate_runs_where_the_platform_has_permissions() {
        assert_eq!(GATE_ENFORCED, cfg!(unix));
    }

    /// Reading stops at the first line and leaves the rest of the stream where
    /// it was: nothing beyond the secret is consumed.
    #[test]
    fn the_read_stops_at_the_first_line() {
        let mut stream = &b"s3cret\nnext\n"[..];
        assert_eq!(&**read_line(&mut stream).unwrap(), b"s3cret");
        assert_eq!(stream, b"next\n", "the rest of the stream was consumed");

        assert_eq!(&**read_line(&mut &b"pw\r\n"[..]).unwrap(), b"pw");
        assert_eq!(&**read_line(&mut &b"pw"[..]).unwrap(), b"pw");
        assert_eq!(&**read_line(&mut &b"a b \nnext"[..]).unwrap(), b"a b ");
        assert_eq!(&**read_line(&mut &b""[..]).unwrap(), b"");
    }

    /// A stream with no terminator at all ends at the bound instead of reading
    /// forever, and says which limit it hit.
    #[test]
    fn an_endless_stream_stops_at_the_bound() {
        let endless = std::io::repeat(b'x');
        let mut source = endless.take(u64::try_from(MAX_SECRET_LEN).unwrap() * 4);
        assert!(matches!(
            read_line(&mut source),
            Err(ReadLineError::TooLong)
        ));

        // Exactly the bound, terminated, is still a secret.
        let line = vec![b'x'; MAX_SECRET_LEN];
        let mut terminated = [line.as_slice(), b"\n"].concat();
        assert_eq!(
            read_line(&mut terminated.as_slice()).unwrap().len(),
            MAX_SECRET_LEN
        );
        terminated.clear();
    }

    /// A file the filesystem sizes at zero still yields its secret: the read
    /// follows the content, not the declared length.
    ///
    /// A FIFO is that case in its harshest form — the writer stays attached
    /// after the line, so a read that waited for end-of-file would never
    /// return. The writer holds the pipe open until the assertion is done.
    #[cfg(unix)]
    #[test]
    fn a_fifo_whose_writer_stays_attached_yields_its_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pin.fifo");
        let made = std::process::Command::new("mkfifo")
            .arg("-m")
            .arg("600")
            .arg(&path)
            .status()
            .expect("mkfifo must be available on a unix host");
        assert!(made.success(), "mkfifo failed: {made:?}");

        // The size the filesystem reports for a FIFO says nothing about what is
        // in it — the read must not be sized from it.
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);

        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let writer_path = path.clone();
        let writer = std::thread::spawn(move || {
            use std::io::Write as _;
            // Opening for writing unblocks the reader's open, and vice versa.
            let mut pipe = std::fs::OpenOptions::new()
                .write(true)
                .open(&writer_path)
                .unwrap();
            pipe.write_all(b"s3cret\n").unwrap();
            pipe.flush().unwrap();
            // Stay attached: this is what a read waiting for EOF would hang on.
            done_rx
                .recv()
                .expect("the test releases the writer when it is done");
        });

        let secret = open(&path).unwrap().read_first_line().unwrap();
        assert_eq!(&*secret, b"s3cret");

        done_tx
            .send(())
            .expect("the writer stays attached until released");
        writer.join().unwrap();
    }

    /// A missing file is an I/O error, distinguishable from a refusal.
    #[test]
    fn a_missing_file_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        match open(&dir.path().join("absent")) {
            Err(OpenError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
            other => panic!("expected an I/O error, got {other:?}"),
        }
    }
}
