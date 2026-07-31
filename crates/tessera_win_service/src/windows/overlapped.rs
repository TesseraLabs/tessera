//! A pipe connection whose reads and writes have deadlines.
//!
//! The reason this exists rather than a [`std::fs::File`] over the same handle:
//! a synchronous `ReadFile` on a pipe has no deadline at all. A client that
//! connects and then says nothing — a credential provider that hung, or one
//! whose process was killed between the connect and the first frame — holds a
//! server thread and one of the few pipe instances for as long as the service
//! runs. Enough of those and the device stops accepting logins, with nobody
//! having attacked anything.
//!
//! Overlapped I/O is what gives the deadline: the operation is queued, we wait
//! on its event for a bounded time, and on expiry we cancel it and reap the
//! cancellation before returning. "Reap before returning" is the load-bearing
//! part — the `OVERLAPPED` block lives on the caller's stack, and returning
//! while the kernel may still write to it would be a use-after-free with no
//! `unsafe` in sight at the call site.
//!
//! # The cancel/complete race
//!
//! A cancellation can lose to a completion that was already in flight. When it
//! does, the operation really did transfer bytes, and reporting a timeout would
//! silently drop them out of the middle of a frame stream. The reap therefore
//! checks: if the operation completed with data, that data is returned and the
//! deadline is forgotten.
//!
//! # Unsafe
//!
//! Every raw call is wrapped alone. The invariants that matter are stated at
//! each block: the buffer and the `OVERLAPPED` outlive the operation, and no
//! operation is left in flight when a function returns.
#![allow(unsafe_code)]

use std::io::{Read, Write};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    DuplicateHandle, DUPLICATE_SAME_ACCESS, ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, ERROR_IO_PENDING,
    ERROR_NO_DATA, ERROR_OPERATION_ABORTED, ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, GENERIC_WRITE,
    HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
};
use windows_sys::Win32::System::Threading::{CreateEventW, GetCurrentProcess, ResetEvent};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use super::sys::{wide, Handle, WinError};

/// The largest wait the API accepts in one call, in milliseconds.
///
/// A budget longer than this is waited out in several passes rather than
/// silently clamped.
const MAX_WAIT_MS: u128 = u32::MAX as u128 - 1;

/// A manual-reset event used to wait for one overlapped operation at a time.
pub struct Event(Handle);

impl Event {
    /// Creates an unsignalled manual-reset event.
    ///
    /// # Errors
    ///
    /// [`WinError`] when the event cannot be created.
    pub fn new() -> Result<Self, WinError> {
        // SAFETY: no security attributes and no name are requested; the two
        // flags select a manual-reset event that starts unsignalled.
        let raw = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        Ok(Self(Handle::adopt(raw, "CreateEventW")?))
    }

    /// The event handle.
    #[must_use]
    pub fn raw(&self) -> HANDLE {
        self.0.raw()
    }

    /// Returns the event to its unsignalled state before queueing an operation.
    fn reset(&self) {
        // SAFETY: the handle is a live event this value owns.
        let _reset = unsafe { ResetEvent(self.0.raw()) };
    }
}

/// An `OVERLAPPED` block bound to an event, for one operation.
fn overlapped_for(event: &Event) -> OVERLAPPED {
    OVERLAPPED {
        hEvent: event.raw(),
        ..OVERLAPPED::default()
    }
}

/// Waits for `event` for at most `budget`.
///
/// Returns `true` when the event was signalled and `false` when the budget ran
/// out.
fn wait(event: &Event, budget: Duration) -> Result<bool, WinError> {
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    let mut left = budget.as_millis();
    loop {
        let slice = u32::try_from(left.min(MAX_WAIT_MS)).unwrap_or(u32::MAX - 1);
        // SAFETY: the handle is a live event and the timeout is a plain value.
        let outcome = unsafe { WaitForSingleObject(event.raw(), slice) };
        match outcome {
            WAIT_OBJECT_0 => return Ok(true),
            WAIT_TIMEOUT => {
                left = left.saturating_sub(u128::from(slice));
                if left == 0 {
                    return Ok(false);
                }
            }
            _ => return Err(WinError::last("WaitForSingleObject")),
        }
    }
}

/// A named-pipe endpoint with a deadline on every operation.
///
/// One instance owns one handle and one event, so a reader and a writer over
/// the same pipe are two of these ([`PipeConnection::try_clone`]) rather than
/// one shared between threads.
pub struct PipeConnection {
    handle: Handle,
    event: Event,
    read_budget: Duration,
    write_budget: Duration,
}

impl std::fmt::Debug for PipeConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeConnection")
            .field("read_budget", &self.read_budget)
            .field("write_budget", &self.write_budget)
            .finish_non_exhaustive()
    }
}

impl PipeConnection {
    /// Adopts a connected pipe handle that was created with
    /// `FILE_FLAG_OVERLAPPED`.
    ///
    /// Adopting a handle that is *not* overlapped would produce a connection
    /// whose deadlines never fire, so the flag is the caller's obligation and is
    /// stated here rather than checked: there is no way to ask a handle which
    /// flags it was opened with.
    ///
    /// # Errors
    ///
    /// [`WinError`] when the operation event cannot be created.
    pub fn adopt(
        handle: Handle,
        read_budget: Duration,
        write_budget: Duration,
    ) -> Result<Self, WinError> {
        Ok(Self {
            handle,
            event: Event::new()?,
            read_budget,
            write_budget,
        })
    }

    /// Opens a client connection to `name`.
    ///
    /// # Errors
    ///
    /// [`WinError`] when the pipe cannot be opened — the service is not
    /// running, or the caller is not `LocalSystem` and the descriptor refused
    /// it.
    pub fn connect(
        name: &str,
        read_budget: Duration,
        write_budget: Duration,
    ) -> Result<Self, WinError> {
        let wide_name = wide(name);
        // SAFETY: the name outlives the call; no security attributes, no
        // template, and no sharing are requested.
        let raw = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        Self::adopt(
            Handle::adopt(raw, "CreateFileW")?,
            read_budget,
            write_budget,
        )
    }

    /// A second endpoint on the same pipe, with its own event.
    ///
    /// The reader and the writer of one connection are separate values so that
    /// neither has to lock the other out of the handle mid-operation.
    ///
    /// # Errors
    ///
    /// [`WinError`] when the handle cannot be duplicated or the event cannot be
    /// created.
    pub fn try_clone(&self) -> Result<Self, WinError> {
        let mut duplicate: HANDLE = std::ptr::null_mut();
        // SAFETY: the call takes no arguments and returns a pseudo-handle that
        // is valid for the life of the process and needs no release.
        let process = unsafe { GetCurrentProcess() };
        // SAFETY: the source handle is live, both process handles are this
        // process's pseudo-handle, and `duplicate` is a live local the callee
        // writes on success.
        let ok = unsafe {
            DuplicateHandle(
                process,
                self.handle.raw(),
                process,
                &raw mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok == 0 {
            return Err(WinError::last("DuplicateHandle"));
        }
        Self::adopt(
            Handle::adopt(duplicate, "DuplicateHandle")?,
            self.read_budget,
            self.write_budget,
        )
    }

    /// Replaces the deadline on subsequent reads.
    pub fn set_read_budget(&mut self, budget: Duration) {
        self.read_budget = budget;
    }

    /// Cancels the operation described by `block` and waits for the kernel to
    /// finish with it.
    ///
    /// Returns the number of bytes the operation transferred anyway — a
    /// cancellation that lost the race to a completion.
    fn cancel_and_reap(&self, block: &OVERLAPPED) -> u32 {
        // SAFETY: the handle is live and `block` describes an operation queued
        // on it by this thread.
        let _cancelled = unsafe { CancelIoEx(self.handle.raw(), std::ptr::from_ref(block)) };
        let mut transferred: u32 = 0;
        // SAFETY: same handle and block; `bWait` is true, so this returns only
        // once the kernel has finished with the block, which is what makes it
        // safe for the block to go out of scope afterwards.
        let ok = unsafe {
            GetOverlappedResult(
                self.handle.raw(),
                std::ptr::from_ref(block),
                &raw mut transferred,
                1,
            )
        };
        if ok == 0 {
            0
        } else {
            transferred
        }
    }

    /// Collects the result of a completed operation.
    fn reap(&self, block: &OVERLAPPED) -> Result<u32, u32> {
        let mut transferred: u32 = 0;
        // SAFETY: the handle is live, `block` describes an operation queued on
        // it, and the event has already signalled, so no wait is needed.
        let ok = unsafe {
            GetOverlappedResult(
                self.handle.raw(),
                std::ptr::from_ref(block),
                &raw mut transferred,
                0,
            )
        };
        if ok == 0 {
            Err(super::sys::last_error())
        } else {
            Ok(transferred)
        }
    }
}

/// The errors that mean "the peer is gone", which is an end of stream rather
/// than a failure.
fn is_end_of_stream(code: u32) -> bool {
    matches!(
        code,
        ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED | ERROR_HANDLE_EOF | ERROR_NO_DATA
    )
}

/// The error a caller sees when a deadline expires.
fn timed_out(what: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, what)
}

/// A Win32 code as an I/O error.
fn io_error(operation: &'static str, code: u32) -> std::io::Error {
    std::io::Error::other(WinError::new(operation, code))
}

impl Read for PipeConnection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let wanted = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        self.event.reset();
        let mut block = overlapped_for(&self.event);
        // SAFETY: `buf` and `block` outlive every path out of this function —
        // each one either completes the operation or cancels and reaps it — and
        // the byte count matches the buffer.
        let started = unsafe {
            ReadFile(
                self.handle.raw(),
                buf.as_mut_ptr(),
                wanted,
                std::ptr::null_mut(),
                &raw mut block,
            )
        };
        if started == 0 {
            let code = super::sys::last_error();
            if is_end_of_stream(code) {
                return Ok(0);
            }
            if code != ERROR_IO_PENDING {
                return Err(io_error("ReadFile", code));
            }
            if !wait(&self.event, self.read_budget).map_err(std::io::Error::other)? {
                let salvaged = self.cancel_and_reap(&block);
                if salvaged > 0 {
                    return Ok(salvaged as usize);
                }
                return Err(timed_out("no frame arrived within the connection's budget"));
            }
        }
        match self.reap(&block) {
            Ok(read) => Ok(read as usize),
            Err(code) if is_end_of_stream(code) || code == ERROR_OPERATION_ABORTED => Ok(0),
            Err(code) => Err(io_error("ReadFile", code)),
        }
    }
}

impl Write for PipeConnection {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let wanted = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        self.event.reset();
        let mut block = overlapped_for(&self.event);
        // SAFETY: as in `read` — the buffer and the block outlive the
        // operation on every path.
        let started = unsafe {
            WriteFile(
                self.handle.raw(),
                buf.as_ptr(),
                wanted,
                std::ptr::null_mut(),
                &raw mut block,
            )
        };
        if started == 0 {
            let code = super::sys::last_error();
            if is_end_of_stream(code) {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            if code != ERROR_IO_PENDING {
                return Err(io_error("WriteFile", code));
            }
            if !wait(&self.event, self.write_budget).map_err(std::io::Error::other)? {
                let salvaged = self.cancel_and_reap(&block);
                if salvaged > 0 {
                    // A partial write leaves the frame stream broken; the
                    // caller's only correct move is to drop the connection,
                    // which is what this error makes it do.
                    return Err(timed_out("the peer stopped reading mid-frame"));
                }
                return Err(timed_out("the peer did not read within the write budget"));
            }
        }
        match self.reap(&block) {
            Ok(written) => Ok(written as usize),
            Err(code) if is_end_of_stream(code) => {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            Err(code) => Err(io_error("WriteFile", code)),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // Nothing is buffered on this side: `write` returns only once the
        // kernel has taken the bytes. Flushing the pipe itself
        // (`FlushFileBuffers`) is deliberately not done — it blocks until the
        // client has read everything, which is exactly the unbounded wait this
        // module exists to remove.
        Ok(())
    }
}

impl crate::protocol::FrameTimeout for PipeConnection {
    fn set_frame_timeout(&mut self, budget: Duration) -> std::io::Result<()> {
        self.set_read_budget(budget);
        Ok(())
    }
}

impl crate::protocol::FrameTimeout for std::io::BufReader<PipeConnection> {
    fn set_frame_timeout(&mut self, budget: Duration) -> std::io::Result<()> {
        self.get_mut().set_read_budget(budget);
        Ok(())
    }
}
