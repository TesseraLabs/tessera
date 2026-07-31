//! The named-pipe listener.
//!
//! Synchronous from the caller's point of view, one thread per connection.
//! There is no async runtime here on purpose: the service handles one login at
//! a time on a machine where a login is a rare event, and a runtime would be a
//! large dependency in a process that runs as `LocalSystem`.
//!
//! Every instance is created with the descriptor from [`super::dacl`], so the
//! access check happens in the kernel before the first byte: a process that is
//! not `LocalSystem` never reaches the framing layer.
//!
//! # Why the handles are overlapped
//!
//! Two waits here would otherwise be unbounded, and each of them holds
//! something scarce:
//!
//! * the wait for a *client* holds the accept loop, which is what made stopping
//!   the service require connecting to its own pipe to wake it up;
//! * the wait for a *frame* holds a connection thread and one of the few pipe
//!   instances, so a credential provider that hangs after connecting takes a
//!   slot away from the next login. No attacker is needed for that — a crashed
//!   client does it by accident, and enough of them stop the device being
//!   logged into at all.
//!
//! Overlapped handles give both waits a deadline. The accept loop polls its
//! stop flag between waits, and the per-frame deadline lives in
//! [`super::overlapped::PipeConnection`]. The self-connect wake-up is gone
//! along with the wait that needed it.
//!
//! # Unsafe
//!
//! Four calls: creating an instance, waiting for a client, reaping that wait,
//! and disconnecting. Each is wrapped alone, and the connect operation is
//! always reaped before its `OVERLAPPED` goes out of scope.
#![allow(unsafe_code)]

use std::io::{BufReader, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::WaitForSingleObject;
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use crate::engine::AuthEngine;
use crate::protocol::{serve, Budgets, Session};

use super::dacl;
use super::overlapped::{Event, PipeConnection};
use super::sys::{last_error, wide, Handle, WinError};

/// How many instances of the pipe may exist at once.
///
/// A credential provider needs one. The rest of the budget covers a client that
/// reconnects before the previous connection has been torn down, and caps what
/// a misbehaving SYSTEM process can hold. With a deadline on every read this is
/// no longer the only thing between a hung client and a device nobody can log
/// into, but it is still the first.
const MAX_INSTANCES: u32 = 8;

/// Buffer sizes suggested to the kernel, in bytes. One protocol frame fits
/// several times over.
const BUFFER_BYTES: u32 = 64 * 1024;

/// Default timeout the API requires, in milliseconds. It applies to clients
/// that wait for a free instance, not to any read of ours.
const DEFAULT_TIMEOUT_MS: u32 = 5_000;

/// How often the accept loop looks at its stop flag while waiting for a client.
///
/// This is the service's stop latency, and nothing else depends on it.
const ACCEPT_POLL: Duration = Duration::from_millis(250);

/// How long a reply may take to reach a peer before the connection is written
/// off. A client that has stopped reading is not one to keep a thread for.
const WRITE_BUDGET: Duration = Duration::from_secs(10);

/// A listener on one pipe name.
pub struct Listener {
    name: String,
    stop: Arc<AtomicBool>,
    budgets: Budgets,
    first_instance_created: bool,
}

impl Listener {
    /// A listener for `name`, e.g. `\\.\pipe\tessera-engine`, with the default
    /// frame budgets.
    #[must_use]
    pub fn new(name: impl Into<String>, stop: Arc<AtomicBool>) -> Self {
        Self {
            name: name.into(),
            stop,
            budgets: Budgets::default(),
            first_instance_created: false,
        }
    }

    /// The same listener with different frame budgets.
    #[must_use]
    pub fn with_budgets(mut self, budgets: Budgets) -> Self {
        self.budgets = budgets;
        self
    }

    /// The pipe name this listener serves.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Accepts connections until the stop flag is set.
    ///
    /// Each connection is served on its own thread. A connection that fails is
    /// logged and dropped; the listener keeps accepting, because one broken
    /// client must not take the device's only way in with it.
    ///
    /// The next instance is created after the current one has a client, so a
    /// second client arriving in that gap is told the pipe is busy. Windows
    /// clients wait for a free instance (`WaitNamedPipe`), and the caller here
    /// is a single credential provider, so the gap costs a retry at worst.
    ///
    /// # Errors
    ///
    /// [`WinError`] when an instance cannot be created — the name is taken by
    /// another process, or the descriptor was refused. Both mean the service
    /// cannot listen at all.
    pub fn run<E: AuthEngine + 'static>(&mut self, engine: &Arc<E>) -> Result<(), WinError> {
        while !self.stop.load(Ordering::SeqCst) {
            let instance = self.create_instance()?;
            let connected = match wait_for_client(&instance, &self.stop) {
                Ok(connected) => connected,
                Err(error) => {
                    tracing::warn!(
                        target: "tessera.engine.pipe",
                        error = %error,
                        "waiting for a client failed"
                    );
                    continue;
                }
            };
            if !connected {
                // The stop flag was set while waiting; this instance never had
                // a client.
                disconnect(&instance);
                break;
            }

            let connection = match PipeConnection::adopt(instance, self.budgets.idle, WRITE_BUDGET)
            {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::error!(
                        target: "tessera.engine.pipe",
                        error = %error,
                        "connection could not be prepared; the client is dropped"
                    );
                    continue;
                }
            };
            let engine = Arc::clone(engine);
            let budgets = self.budgets;
            let spawned = std::thread::Builder::new()
                .name("tessera-engine-conn".to_owned())
                .spawn(move || serve_connection(connection, &*engine, budgets));
            if let Err(error) = spawned {
                tracing::error!(
                    target: "tessera.engine.pipe",
                    error = %error,
                    "connection thread could not be started; the client is dropped"
                );
            }
        }
        Ok(())
    }

    /// Creates one instance of the pipe.
    ///
    /// The first instance carries `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a name
    /// already owned by another process is a failure to start rather than a
    /// second listener quietly sharing it — which is how a client ends up
    /// talking to something that is not this service.
    fn create_instance(&mut self) -> Result<Handle, WinError> {
        let descriptor = dacl::pipe_descriptor()?;
        let attributes = descriptor.attributes();
        let name = wide(&self.name);
        let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if !self.first_instance_created {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        // SAFETY: `name` is a NUL-terminated pipe name and `attributes` borrows
        // a descriptor that outlives the call.
        let raw = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                MAX_INSTANCES,
                BUFFER_BYTES,
                BUFFER_BYTES,
                DEFAULT_TIMEOUT_MS,
                &raw const attributes,
            )
        };
        let handle = Handle::adopt(raw, "CreateNamedPipeW")?;
        self.first_instance_created = true;
        Ok(handle)
    }
}

/// Waits for a client, giving up when `stop` is set.
///
/// Returns `true` when a client connected and `false` when the wait was
/// abandoned because the service is stopping.
fn wait_for_client(instance: &Handle, stop: &AtomicBool) -> Result<bool, WinError> {
    let event = Event::new()?;
    let mut block = OVERLAPPED {
        hEvent: event.raw(),
        ..OVERLAPPED::default()
    };
    // SAFETY: the handle is a live overlapped pipe instance, and `block`
    // outlives every path below — each one either sees the operation complete
    // or cancels and reaps it before returning.
    let started = unsafe { ConnectNamedPipe(instance.raw(), &raw mut block) };
    if started != 0 {
        return Ok(true);
    }
    let code = last_error();
    // A client that connected between creation and this call is a connected
    // client, not an error, and nothing was queued on its behalf.
    if code == ERROR_PIPE_CONNECTED {
        return Ok(true);
    }
    if code != ERROR_IO_PENDING {
        return Err(WinError::new("ConnectNamedPipe", code));
    }

    loop {
        if stop.load(Ordering::SeqCst) {
            cancel_and_reap(instance, &block);
            return Ok(false);
        }
        let slice = u32::try_from(ACCEPT_POLL.as_millis()).unwrap_or(u32::MAX - 1);
        // SAFETY: the event is live and owned by this frame.
        let outcome = unsafe { WaitForSingleObject(event.raw(), slice) };
        match outcome {
            WAIT_OBJECT_0 => {
                let mut transferred: u32 = 0;
                // SAFETY: the handle and the block are the pair the operation
                // was queued with, and the event has already signalled, so no
                // wait is requested.
                let ok = unsafe {
                    GetOverlappedResult(
                        instance.raw(),
                        std::ptr::from_ref(&block),
                        &raw mut transferred,
                        0,
                    )
                };
                if ok == 0 {
                    return Err(WinError::last("ConnectNamedPipe"));
                }
                return Ok(true);
            }
            WAIT_TIMEOUT => {}
            _ => {
                let error = WinError::last("WaitForSingleObject");
                cancel_and_reap(instance, &block);
                return Err(error);
            }
        }
    }
}

/// Cancels a queued operation and waits for the kernel to finish with its
/// block, so that the block may go out of scope.
fn cancel_and_reap(instance: &Handle, block: &OVERLAPPED) {
    // SAFETY: the handle is live and `block` describes an operation queued on
    // it by this thread.
    let _cancelled = unsafe { CancelIoEx(instance.raw(), std::ptr::from_ref(block)) };
    let mut transferred: u32 = 0;
    // SAFETY: the same pair; `bWait` is true, so this returns only once the
    // kernel has finished with the block.
    let _reaped = unsafe {
        GetOverlappedResult(
            instance.raw(),
            std::ptr::from_ref(block),
            &raw mut transferred,
            1,
        )
    };
}

/// Disconnects a client without serving it.
fn disconnect(instance: &Handle) {
    // SAFETY: the handle is a live pipe instance; disconnecting an instance
    // with no client is harmless.
    let _disconnected = unsafe { DisconnectNamedPipe(instance.raw()) };
}

/// Serves one connection and closes it.
fn serve_connection<E: AuthEngine>(connection: PipeConnection, engine: &E, budgets: Budgets) {
    let writer = match connection.try_clone() {
        Ok(writer) => writer,
        Err(error) => {
            tracing::error!(
                target: "tessera.engine.pipe",
                error = %error,
                "connection handle could not be duplicated; dropping the client"
            );
            return;
        }
    };
    let mut reader = BufReader::new(connection);
    let mut writer = writer;
    let mut session = Session::new(engine, crate::SERVICE_VERSION);
    if let Err(error) = serve(&mut reader, &mut writer, &mut session, budgets) {
        tracing::warn!(
            target: "tessera.engine.pipe",
            error = %error,
            "connection ended with an error"
        );
    }
    let _flushed = writer.flush();
}
