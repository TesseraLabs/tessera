//! Parent-side pipe reader: streams hook child stdout/stderr line-by-line
//! to `tracing` (which routes to syslog in production).
//!
//! Each [`PipeReader`] wraps an owned read-end of a pipe. The expected
//! lifecycle:
//!
//! 1. Parent forks; child gets the write end, parent retains the read end.
//! 2. Parent constructs `PipeReader::new(read_fd, ..)` per pipe (stdout
//!    and stderr).
//! 3. Parent thread polls (`read_available()`) while the child is alive,
//!    then calls `drain()` once to capture remaining buffered data.
//! 4. Reader takes ownership of the FD and closes it when dropped.
//!
//! Lines longer than [`MAX_LINE_BYTES`] are truncated and appended with a
//! `… [truncated]` marker so a hook flooding the pipe can't blow up syslog.

use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use crate::hooks::stage::HookStage;

/// Maximum bytes of a single logical line forwarded to the sink. Anything
/// longer is truncated and tagged with `[truncated]`.
pub const MAX_LINE_BYTES: usize = 4096;

/// Maximum total bytes captured per pipe (stdout or stderr) before further
/// data is silently drained to `/dev/null`. P2-A: a runaway hook should
/// not be able to overwhelm the parent's logging budget. After this many
/// bytes the parent emits a single `tracing::warn!` and continues to read
/// (so the writer never blocks on a full pipe) but does not emit any
/// further log lines.
pub const MAX_CAPTURED_BYTES: usize = 1024 * 1024;

/// Stream variant — stdout vs stderr — for log routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeStream {
    /// Standard output stream.
    Stdout,
    /// Standard error stream.
    Stderr,
}

impl fmt::Display for PipeStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stdout => f.write_str("stdout"),
            Self::Stderr => f.write_str("stderr"),
        }
    }
}

/// Parent-side line reader.
pub struct PipeReader {
    inner: BufReader<File>,
    stage: HookStage,
    command_basename: String,
    stream: PipeStream,
    /// Carry-over buffer for partial lines (no trailing `\n` yet).
    partial: Vec<u8>,
    /// Total complete lines forwarded to sink so far.
    line_count: u64,
    /// Total bytes ingested from the pipe so far (regardless of whether
    /// they were emitted as log lines or dropped past the cap).
    bytes_ingested: usize,
    /// Whether we have crossed [`MAX_CAPTURED_BYTES`] and started silently
    /// draining further input.
    capped: bool,
}

impl PipeReader {
    /// Construct a [`PipeReader`] taking ownership of `read_fd`.
    ///
    /// The FD is wrapped into a `File` so dropping the reader closes it.
    /// The caller is responsible for setting `O_NONBLOCK` on the FD if
    /// desired (the executor does this before constructing the reader).
    ///
    /// # Safety
    ///
    /// `read_fd` must be a valid open file descriptor that nothing else
    /// owns; the [`PipeReader`] takes ownership.
    pub fn from_raw_fd(
        read_fd: RawFd,
        stage: HookStage,
        command_basename: String,
        stream: PipeStream,
    ) -> Self {
        // SAFETY: caller contract guarantees fd ownership transfer.
        #[allow(unsafe_code)]
        let f: File = unsafe { File::from_raw_fd(read_fd) };
        Self {
            inner: BufReader::new(f),
            stage,
            command_basename,
            stream,
            partial: Vec::with_capacity(256),
            line_count: 0,
            bytes_ingested: 0,
            capped: false,
        }
    }

    /// Construct from an owned FD.
    #[must_use]
    pub fn new(
        fd: OwnedFd,
        stage: HookStage,
        command_basename: String,
        stream: PipeStream,
    ) -> Self {
        let f: File = File::from(fd);
        Self {
            inner: BufReader::new(f),
            stage,
            command_basename,
            stream,
            partial: Vec::with_capacity(256),
            line_count: 0,
            bytes_ingested: 0,
            capped: false,
        }
    }

    /// How many complete lines this reader has forwarded so far.
    #[must_use]
    pub const fn line_count(&self) -> u64 {
        self.line_count
    }

    /// Read whatever is currently available on the pipe; emit one log
    /// event per complete line. Returns the number of bytes read.
    ///
    /// `WouldBlock` is treated as "nothing available right now" and
    /// returns `Ok(0)`. EOF (read returned 0) returns `Ok(0)` as well —
    /// callers should call [`Self::drain`] in that case.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] from the read. EOF and
    /// `WouldBlock` are not surfaced as errors.
    pub fn read_available(&mut self) -> io::Result<usize> {
        let mut buf = [0u8; 4096];
        match self.inner.get_mut().read(&mut buf) {
            Ok(0) => Ok(0),
            Ok(n) => {
                // `n` is the byte count returned by `read` into a 4096-byte
                // buffer, so `n <= buf.len()`; `.get(..n)` never fails here.
                if let Some(chunk) = buf.get(..n) {
                    self.process_chunk(chunk);
                }
                Ok(n)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e),
        }
    }

    /// Drain any remaining buffered data after the child has exited.
    /// Emits a final partial line (if any) tagged as such.
    ///
    /// On a blocking pipe (the production configuration in
    /// [`crate::hooks::fork_exec`]) `read_to_end` parks until the child
    /// closes its write end, then returns once EOF is observed. Any
    /// trailing bytes without a newline are flushed as a final line.
    ///
    /// Returns the total number of complete lines forwarded by this reader
    /// (including from previous `read_available` calls).
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] from the final read.
    pub fn drain(&mut self) -> io::Result<u64> {
        let mut buf = Vec::with_capacity(4096);
        self.inner.read_to_end(&mut buf)?;
        self.process_chunk(&buf);
        if !self.partial.is_empty() && !self.capped {
            self.flush_partial();
        }
        Ok(self.line_count)
    }

    fn process_chunk(&mut self, chunk: &[u8]) {
        // Track total bytes seen even when we drain silently — used for
        // diagnostics on the cap-warn line.
        self.bytes_ingested = self.bytes_ingested.saturating_add(chunk.len());

        // Determine how many of these bytes (if any) we can still emit
        // before crossing MAX_CAPTURED_BYTES. Past the cap we still drain
        // the pipe (so the writer never blocks) but do not emit further
        // log events.
        let already = self.bytes_ingested.saturating_sub(chunk.len());
        let remaining_budget = MAX_CAPTURED_BYTES.saturating_sub(already);
        let head_len = chunk.len().min(remaining_budget);
        // `head_len = chunk.len().min(..)` so `head_len <= chunk.len()`;
        // `.get(..head_len)` never fails. Empty slice on the impossible miss
        // preserves behavior (nothing to emit).
        let head = chunk.get(..head_len).unwrap_or(&[]);

        for byte in head {
            if *byte == b'\n' {
                let take = std::mem::take(&mut self.partial);
                self.emit_line(&take);
            } else {
                self.partial.push(*byte);
            }
        }

        if head_len < chunk.len() && !self.capped {
            // First time we crossed the cap: warn once and clear any
            // partial line we have so the final drain doesn't emit a
            // truncated tail. Further bytes (including the rest of this
            // chunk) are dropped on the floor.
            self.capped = true;
            self.partial.clear();
            tracing::warn!(
                target: "tessera.hook",
                stage = %self.stage,
                stream = %self.stream,
                command = %self.command_basename,
                cap_bytes = MAX_CAPTURED_BYTES,
                "hook output exceeded capture cap; further output silently drained"
            );
        }
    }

    fn flush_partial(&mut self) {
        let take = std::mem::take(&mut self.partial);
        self.emit_line(&take);
    }

    fn emit_line(&mut self, raw: &[u8]) {
        // Truncate if necessary.
        let truncated = raw.len() > MAX_LINE_BYTES;
        // When `truncated`, `raw.len() > MAX_LINE_BYTES`, so `.get(..MAX_LINE_BYTES)`
        // is in-bounds; fall back to the whole slice on the impossible miss.
        let slice: &[u8] = if truncated {
            raw.get(..MAX_LINE_BYTES).unwrap_or(raw)
        } else {
            raw
        };
        // Lossy decode is fine — hooks may emit non-UTF-8 bytes.
        let mut s = String::from_utf8_lossy(slice).into_owned();
        if truncated {
            s.push_str(" … [truncated]");
        }
        self.line_count += 1;
        match self.stream {
            PipeStream::Stdout => {
                tracing::info!(
                    target: "tessera.hook",
                    stage = %self.stage,
                    stream = %self.stream,
                    command = %self.command_basename,
                    "{}",
                    s,
                );
            }
            PipeStream::Stderr => {
                tracing::warn!(
                    target: "tessera.hook",
                    stage = %self.stage,
                    stream = %self.stream,
                    command = %self.command_basename,
                    "{}",
                    s,
                );
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_pipe() -> (RawFd, RawFd) {
        use std::os::fd::IntoRawFd;
        let (r, w) = nix::unistd::pipe().expect("pipe");
        (r.into_raw_fd(), w.into_raw_fd())
    }

    #[test]
    fn streams_two_complete_lines() {
        let (r_fd, w_fd) = make_pipe();
        let mut reader =
            PipeReader::from_raw_fd(r_fd, HookStage::PreAuth, "test".into(), PipeStream::Stdout);

        // Write three complete lines via a File that owns the write fd.
        // SAFETY: w_fd is a freshly created pipe write end with no other
        // owner.
        #[allow(unsafe_code)]
        let mut f: File = unsafe { File::from_raw_fd(w_fd) };
        f.write_all(b"hello\nworld\nthird\n").unwrap();
        drop(f);

        // Drain (EOF).
        let count = reader.drain().unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn partial_line_flushed_on_drain() {
        let (r_fd, w_fd) = make_pipe();
        let mut reader =
            PipeReader::from_raw_fd(r_fd, HookStage::PreAuth, "x".into(), PipeStream::Stderr);

        // SAFETY: w_fd is a freshly created pipe write end with no other
        // owner.
        #[allow(unsafe_code)]
        let mut f: File = unsafe { File::from_raw_fd(w_fd) };
        f.write_all(b"first line\nno-trailing-nl").unwrap();
        drop(f);

        let count = reader.drain().unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn long_line_is_truncated() {
        let (r_fd, w_fd) = make_pipe();
        let mut reader =
            PipeReader::from_raw_fd(r_fd, HookStage::PreAuth, "x".into(), PipeStream::Stdout);

        let big = vec![b'A'; MAX_LINE_BYTES + 2000];
        // SAFETY: w_fd is a freshly created pipe write end with no other
        // owner.
        #[allow(unsafe_code)]
        let mut f: File = unsafe { File::from_raw_fd(w_fd) };
        f.write_all(&big).unwrap();
        f.write_all(b"\n").unwrap();
        drop(f);

        let count = reader.drain().unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn pipe_stream_display() {
        assert_eq!(PipeStream::Stdout.to_string(), "stdout");
        assert_eq!(PipeStream::Stderr.to_string(), "stderr");
    }

    #[test]
    fn output_past_cap_is_silently_drained() {
        // P2-A: writing 2 MiB to the pipe should not produce log lines past
        // the 1 MiB cap. The reader must still drain the pipe (so the
        // writer doesn't block) and call drain() must succeed.
        //
        // Linux pipe capacity is 64 KiB by default — far smaller than the
        // 2 MiB payload — so the writer must run on a separate thread
        // while the reader drains, otherwise the producer would block.
        let (r_fd, w_fd) = make_pipe();
        let mut reader =
            PipeReader::from_raw_fd(r_fd, HookStage::PreAuth, "x".into(), PipeStream::Stdout);

        let writer = std::thread::spawn(move || {
            // SAFETY: w_fd is a freshly created pipe write end with no
            // other owner; the writer thread takes exclusive ownership.
            #[allow(unsafe_code)]
            let mut f: File = unsafe { File::from_raw_fd(w_fd) };
            // 2 MiB of newline-terminated 1 KiB lines (2048 lines).
            let line = vec![b'A'; 1023];
            for _ in 0..2048 {
                f.write_all(&line).unwrap();
                f.write_all(b"\n").unwrap();
            }
            drop(f);
        });

        let _ = reader.drain().unwrap();
        writer.join().unwrap();

        // Capacity is 1 MiB; emitted lines must be bounded.
        assert!(
            reader.line_count() <= 1024,
            "line count {} exceeds cap-window expectation",
            reader.line_count()
        );
        // We must have read all 2 MiB to keep the writer unblocked.
        assert!(reader.bytes_ingested >= 2 * 1024 * 1024);
        assert!(reader.capped);
    }

    #[test]
    fn read_available_handles_chunked_writes() {
        let (r_fd, w_fd) = make_pipe();
        let mut reader =
            PipeReader::from_raw_fd(r_fd, HookStage::PreAuth, "x".into(), PipeStream::Stdout);

        // SAFETY: w_fd is a freshly created pipe write end with no other
        // owner.
        #[allow(unsafe_code)]
        let mut f: File = unsafe { File::from_raw_fd(w_fd) };
        f.write_all(b"line one\nline two").unwrap();

        // Read what's available: should see 1 complete line + 1 buffered.
        let _ = reader.read_available().unwrap();
        assert_eq!(reader.line_count(), 1);

        f.write_all(b" continued\n").unwrap();
        drop(f);

        let _ = reader.drain().unwrap();
        assert_eq!(reader.line_count(), 2);
    }
}
