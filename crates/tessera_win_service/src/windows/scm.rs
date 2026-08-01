//! Service control manager: registration, lifecycle, and the service's own
//! main.
//!
//! The service runs as `LocalSystem`. Not for convenience: the pipe admits only
//! SYSTEM, the data directory admits only SYSTEM and administrators, and the
//! account operations `prepare` performs need the same authority. Running as
//! anything else would mean widening one of those.
//!
//! # Stopping
//!
//! The control handler sets a flag and connects to the pipe once, which
//! unblocks the accepting thread. Connections already being served finish on
//! their own threads; a login in flight is not cut off by a stop request, and
//! the process exits when the accept loop returns.
//!
//! # Unsafe
//!
//! This is an FFI boundary in both directions: we call into `advapi32`, and it
//! calls back into two `extern "system"` functions. Both callbacks catch panics
//! before they can unwind into the service control manager, where unwinding is
//! undefined behaviour.
#![allow(unsafe_code)]

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::{Arc, OnceLock};

use windows_sys::Win32::Foundation::{ERROR_SERVICE_DOES_NOT_EXIST, NO_ERROR};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, RegisterServiceCtrlHandlerExW, SetServiceStatus,
    StartServiceCtrlDispatcherW, StartServiceW, SC_HANDLE, SC_MANAGER_ALL_ACCESS,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_ALL_ACCESS, SERVICE_AUTO_START,
    SERVICE_CONFIG_DESCRIPTION, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
    SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

use crate::paths::{
    DataDir, DEFAULT_ACCOUNT_NAME, DEFAULT_PIPE_NAME, SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME,
    SERVICE_NAME,
};

use super::sys::{wide, WinError};

/// The argument that tells the binary it was started by the service control
/// manager rather than by a person.
pub const SERVICE_ARGUMENT: &str = "service";

/// The status handle, as an integer because a pointer is not `Sync`. Zero until
/// the handler is registered.
static STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);

/// Set once the service has been asked to stop.
static STOP: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// The pipe the service listens on, resolved once.
static PIPE_NAME: OnceLock<String> = OnceLock::new();

/// The shared stop flag.
fn stop_flag() -> Arc<AtomicBool> {
    Arc::clone(STOP.get_or_init(|| Arc::new(AtomicBool::new(false))))
}

/// A service-control-manager handle closed when dropped.
struct ScHandle(SC_HANDLE);

impl ScHandle {
    /// Adopts `raw`, refusing null.
    fn adopt(raw: SC_HANDLE, operation: &'static str) -> Result<Self, WinError> {
        if raw.is_null() {
            return Err(WinError::last(operation));
        }
        Ok(Self(raw))
    }
}

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: the handle was checked at construction and this is the only
        // place it is released.
        let _closed = unsafe { CloseServiceHandle(self.0) };
    }
}

/// Opens the service control manager with full access.
fn manager() -> Result<ScHandle, WinError> {
    // SAFETY: both name parameters are null, which selects the local machine
    // and the active database.
    let raw = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS) };
    ScHandle::adopt(raw, "OpenSCManagerW")
}

/// Opens the service, or reports that it is not registered.
fn service(manager: &ScHandle, access: u32) -> Result<Option<ScHandle>, WinError> {
    let name = wide(SERVICE_NAME);
    // SAFETY: the manager handle is live and `name` is a NUL-terminated string
    // that outlives the call.
    let raw = unsafe { OpenServiceW(manager.0, name.as_ptr(), access) };
    if raw.is_null() {
        let error = WinError::last("OpenServiceW");
        if error.code == ERROR_SERVICE_DOES_NOT_EXIST {
            return Ok(None);
        }
        return Err(error);
    }
    Ok(Some(ScHandle(raw)))
}

/// Registers the service, pointed at `exe`.
///
/// The registered command line carries [`SERVICE_ARGUMENT`], which is how the
/// same binary knows it is being started by the control manager and not by a
/// person at a console.
///
/// # Errors
///
/// [`WinError`] when the manager cannot be opened or the service cannot be
/// created — including when a service of this name already exists, which the
/// caller reports rather than papering over.
pub fn install(exe: &Path) -> Result<(), WinError> {
    let manager = manager()?;
    let name = wide(SERVICE_NAME);
    let display = wide(SERVICE_DISPLAY_NAME);
    // Quoted, because an unquoted path with a space in it is the classic
    // unquoted-service-path weakness: the control manager would try every
    // prefix as an executable.
    let command = wide(&format!("\"{}\" {SERVICE_ARGUMENT}", exe.display()));
    // SAFETY: every string parameter is a NUL-terminated buffer that outlives
    // the call; the unused group, tag, dependency, account and password
    // parameters are null, which selects `LocalSystem` with no dependencies.
    let raw = unsafe {
        CreateServiceW(
            manager.0,
            name.as_ptr(),
            display.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    let handle = ScHandle::adopt(raw, "CreateServiceW")?;
    set_description(&handle);
    Ok(())
}

/// Attaches the description shown in the services console. Best-effort: a
/// service without a description works, and refusing to install over a missing
/// caption would be the wrong trade.
fn set_description(service: &ScHandle) {
    let mut text = wide(SERVICE_DESCRIPTION);
    let description = SERVICE_DESCRIPTIONW {
        lpDescription: text.as_mut_ptr(),
    };
    // SAFETY: the handle is live, the info level matches the structure passed,
    // and the buffer the structure points at outlives the call.
    let ok = unsafe {
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_DESCRIPTION,
            std::ptr::from_ref(&description).cast(),
        )
    };
    if ok == 0 {
        tracing::warn!(
            target: "tessera.engine.scm",
            error = %WinError::last("ChangeServiceConfig2W"),
            "service description could not be set"
        );
    }
}

/// Removes the registration. Reports whether there was one.
///
/// # Errors
///
/// [`WinError`] when the manager cannot be opened or the deletion is refused.
pub fn uninstall() -> Result<bool, WinError> {
    let manager = manager()?;
    let Some(handle) = service(&manager, SERVICE_ALL_ACCESS)? else {
        return Ok(false);
    };
    // SAFETY: the handle is live and opened with delete access.
    let ok = unsafe { DeleteService(handle.0) };
    if ok == 0 {
        return Err(WinError::last("DeleteService"));
    }
    Ok(true)
}

/// Starts the registered service. Reports whether there was one to start.
///
/// # Errors
///
/// [`WinError`] when the start is refused.
pub fn start() -> Result<bool, WinError> {
    let manager = manager()?;
    let Some(handle) = service(&manager, SERVICE_ALL_ACCESS)? else {
        return Ok(false);
    };
    // SAFETY: the handle is live; no start arguments are passed.
    let ok = unsafe { StartServiceW(handle.0, 0, std::ptr::null()) };
    if ok == 0 {
        return Err(WinError::last("StartServiceW"));
    }
    Ok(true)
}

/// Asks the registered service to stop. Reports whether there was one.
///
/// # Errors
///
/// [`WinError`] when the control is refused.
pub fn stop() -> Result<bool, WinError> {
    let manager = manager()?;
    let Some(handle) = service(&manager, SERVICE_ALL_ACCESS)? else {
        return Ok(false);
    };
    let mut status = empty_status();
    // SAFETY: the handle is live and `status` is a live local the callee writes.
    let ok = unsafe { ControlService(handle.0, SERVICE_CONTROL_STOP, &raw mut status) };
    if ok == 0 {
        return Err(WinError::last("ControlService"));
    }
    Ok(true)
}

/// A zeroed status of the right service type.
fn empty_status() -> SERVICE_STATUS {
    SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_STOPPED,
        dwControlsAccepted: 0,
        dwWin32ExitCode: NO_ERROR,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    }
}

/// Reports `state` to the control manager.
fn report(state: u32, accepts_control: bool, exit_code: u32) {
    let raw = STATUS_HANDLE.load(Ordering::SeqCst);
    if raw == 0 {
        return;
    }
    let mut status = empty_status();
    status.dwCurrentState = state;
    status.dwControlsAccepted = if accepts_control {
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
    } else {
        0
    };
    status.dwWin32ExitCode = exit_code;
    // A start that takes longer than this hint makes the control manager warn;
    // the service opens a pipe and reads two files, so it is generous.
    status.dwWaitHint = 10_000;
    let handle = raw as SERVICE_STATUS_HANDLE;
    // SAFETY: the handle came from `RegisterServiceCtrlHandlerExW` and stays
    // valid for the life of the process; `status` is a live local.
    let ok = unsafe { SetServiceStatus(handle, &raw const status) };
    if ok == 0 {
        tracing::warn!(
            target: "tessera.engine.scm",
            error = %WinError::last("SetServiceStatus"),
            state,
            "service status could not be reported"
        );
    }
}

/// The control handler.
///
/// Called by the control manager on its own thread. It does the least it can:
/// set the flag, report the pending state, and poke the pipe so the accept loop
/// notices.
extern "system" fn handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut std::ffi::c_void,
    _context: *mut std::ffi::c_void,
) -> u32 {
    // A panic crossing this boundary would unwind into the control manager,
    // which is undefined behaviour; the guard turns it into a service that
    // keeps running instead.
    let outcome = std::panic::catch_unwind(|| {
        if control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN {
            // Setting the flag is the whole of it: the accept loop waits on an
            // overlapped connect and looks at this flag between waits, so it
            // notices within its poll interval without being poked.
            stop_flag().store(true, Ordering::SeqCst);
            report(SERVICE_STOP_PENDING, false, NO_ERROR);
        }
    });
    if outcome.is_err() {
        tracing::error!(
            target: "tessera.engine.scm",
            "the control handler panicked; the service keeps running"
        );
    }
    NO_ERROR
}

/// The service's entry point, as the control manager calls it.
extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    // Same reasoning as the control handler: nothing may unwind out of here.
    let outcome = std::panic::catch_unwind(run_service);
    match outcome {
        Ok(Ok(())) => report(SERVICE_STOPPED, false, NO_ERROR),
        Ok(Err(error)) => {
            tracing::error!(target: "tessera.engine.scm", error = %error, "service stopped on error");
            // A non-zero exit code is how the control manager is told this was
            // a failure rather than a requested stop.
            report(SERVICE_STOPPED, false, error.code());
        }
        Err(_) => {
            tracing::error!(target: "tessera.engine.scm", "service panicked");
            report(SERVICE_STOPPED, false, 1);
        }
    }
}

/// Everything the service does between `START_PENDING` and `STOPPED`.
fn run_service() -> Result<(), super::ServiceError> {
    let name = wide(SERVICE_NAME);
    // SAFETY: `name` is a NUL-terminated service name that outlives the call
    // and `handler` is an `extern "system"` function of the required shape; no
    // context pointer is passed.
    let handle =
        unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(handler), std::ptr::null()) };
    if handle.is_null() {
        return Err(WinError::last("RegisterServiceCtrlHandlerExW").into());
    }
    STATUS_HANDLE.store(handle as isize, Ordering::SeqCst);
    report(SERVICE_START_PENDING, false, NO_ERROR);

    super::run_listener(
        DataDir::default_location(),
        DEFAULT_ACCOUNT_NAME.to_owned(),
        pipe_name(),
        stop_flag(),
        || report(SERVICE_RUNNING, true, NO_ERROR),
    )
}

/// The pipe the service listens on.
///
/// Fixed for now: the configuration names a socket path whose Windows meaning
/// is a pipe, but the service has to listen before it can read a configuration
/// it is expected to serve, so the name cannot come from there without a
/// bootstrap of its own.
fn pipe_name() -> String {
    PIPE_NAME
        .get_or_init(|| DEFAULT_PIPE_NAME.to_owned())
        .clone()
}

/// Hands the process to the control manager.
///
/// Returns when the service has stopped.
///
/// # Errors
///
/// [`WinError`] when the process was not started as a service — which is what
/// `StartServiceCtrlDispatcherW` reports, and is the expected outcome of
/// running the service argument by hand.
pub fn dispatch() -> Result<(), WinError> {
    let mut name = wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: the table is NUL-terminated by its second, zeroed entry, and both
    // it and the name buffer outlive the call, which blocks until the service
    // stops.
    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if ok == 0 {
        return Err(WinError::last("StartServiceCtrlDispatcherW"));
    }
    Ok(())
}

/// The path of the running executable, for `install`.
///
/// # Errors
///
/// [`WinError`] when the path cannot be determined.
pub fn current_exe() -> Result<std::path::PathBuf, WinError> {
    std::env::current_exe().map_err(|e| {
        WinError::new(
            "GetModuleFileNameW",
            u32::try_from(e.raw_os_error().unwrap_or(0)).unwrap_or(0),
        )
    })
}
