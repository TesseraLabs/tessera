//! Signed plugin discovery, loading, and `MacBackend` bridge.

#![allow(unsafe_code)]

use std::ffi::{c_void, CStr};
use std::mem::ManuallyDrop;
use std::path::{Path, PathBuf};
use std::ptr;

use libloading::Library;
use sha2::{Digest, Sha256};

use crate::mac::{IntegrityLabel, MacBackend, MacError, MacRuntime, MrdState};

use super::audit;
use super::header::{
    EnforcementBackendVTable, PluginIntegrityLabel, TesseraPluginHeader, PLUGIN_CAP_MISSING,
    PLUGIN_INVALID_INPUT, PLUGIN_OK, PLUGIN_PANIC, PLUGIN_UNAVAILABLE, PLUGIN_USER_UNKNOWN,
    TESSERA_ENFORCEMENT_BACKEND_KIND, TESSERA_PLUGIN_ABI_VERSION,
};
use super::verify::verify_detached_signature;

type PluginEntry = unsafe extern "C" fn() -> *const TesseraPluginHeader;

/// Default directory for installed plugins.
pub const DEFAULT_PLUGIN_DIR: &str = "/usr/lib/tessera/plugins";

/// A runtime plugin load failure.
#[derive(Debug, thiserror::Error)]
pub enum PluginLoadError {
    /// Selected plugin file does not exist.
    #[error("selected plugin is missing: {0}")]
    Missing(PathBuf),
    /// Detached signature verification failed.
    #[error("plugin signature rejected: {0}")]
    Signature(String),
    /// The dynamic loader rejected the shared library.
    #[error("dlopen failed: {0}")]
    Dlopen(String),
    /// Required entry export is missing.
    #[error("plugin entry export missing")]
    Entry,
    /// Plugin returned a null or malformed header.
    #[error("plugin header is malformed")]
    Header,
    /// ABI version mismatch.
    #[error("plugin ABI mismatch: expected {expected}, got {actual}")]
    Abi {
        /// Host ABI.
        expected: u32,
        /// Plugin ABI.
        actual: u32,
    },
    /// Plugin kind is not supported by this loader.
    #[error("unsupported plugin kind: {0}")]
    Kind(u32),
    /// Header name differs from the explicitly selected name.
    #[error("selected plugin name mismatch")]
    Name,
    /// Plugin initialisation failed.
    #[error("plugin init failed with status {0}")]
    Init(i32),
}

impl PluginLoadError {
    fn reason(&self) -> &'static str {
        match self {
            Self::Missing(_) => "missing",
            Self::Signature(_) => "signature",
            Self::Dlopen(_) => "dlopen",
            Self::Entry | Self::Header | Self::Name => "header",
            Self::Abi { .. } => "abi",
            Self::Kind(_) => "kind",
            Self::Init(_) => "init",
        }
    }
}

/// Loaded enforcement plugin bridged onto [`MacBackend`].
pub struct PluginBackend {
    name: String,
    version: String,
    context: usize,
    vtable: EnforcementBackendVTable,
    _library: ManuallyDrop<Library>,
}

// SAFETY: the ABI contract requires plugin contexts and all callbacks to be
// thread-safe. A plugin violating this contract is invalid; the host never
// mutates the vtable and forwards only shared calls.
unsafe impl Send for PluginBackend {}
// SAFETY: same contract as the `Send` implementation above.
unsafe impl Sync for PluginBackend {}

impl std::fmt::Debug for PluginBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginBackend")
            .field("name", &self.name)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

fn plugin_filename(name: &str) -> String {
    #[cfg(target_os = "linux")]
    {
        format!("tessera_backend_{name}.so")
    }
    #[cfg(not(target_os = "linux"))]
    {
        format!(
            "{}tessera_backend_{name}.{}",
            std::env::consts::DLL_PREFIX,
            std::env::consts::DLL_EXTENSION
        )
    }
}

fn signature_path(plugin: &Path) -> PathBuf {
    let mut name = plugin.as_os_str().to_owned();
    name.push(".sig");
    PathBuf::from(name)
}

fn emit_inactive_plugins(dir: &Path, selected: Option<&Path>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if Some(path.as_path()) != selected
            && path.extension().and_then(|value| value.to_str())
                == Some(std::env::consts::DLL_EXTENSION)
        {
            audit::inactive(&path);
        }
    }
}

/// Load the selected enforcement plugin from [`DEFAULT_PLUGIN_DIR`].
///
/// Missing or rejected plugins degrade to [`crate::mac::StubBackend`]. The
/// caller's runtime and role policy remains responsible for failing closed
/// when enforcement is required.
#[must_use]
pub fn load_enforcement_backend(name: Option<&str>, config: &str) -> Box<dyn MacBackend> {
    load_enforcement_backend_from_dir(Path::new(DEFAULT_PLUGIN_DIR), name, config)
}

/// Load the selected enforcement plugin from an explicit directory.
///
/// This variant exists for tests and package smoke checks.
#[must_use]
pub fn load_enforcement_backend_from_dir(
    dir: &Path,
    name: Option<&str>,
    config: &str,
) -> Box<dyn MacBackend> {
    let Some(name) = name else {
        emit_inactive_plugins(dir, None);
        return Box::new(crate::mac::StubBackend::new());
    };
    let path = dir.join(plugin_filename(name));
    emit_inactive_plugins(dir, Some(&path));
    match load_path(&path, name, config) {
        Ok(backend) => Box::new(backend),
        Err(error) => {
            audit::rejected(&path, error.reason());
            Box::new(crate::mac::StubBackend::new())
        }
    }
}

fn open_library(path: &Path) -> Result<Library, libloading::Error> {
    #[cfg(unix)]
    {
        use libloading::os::unix::{Library as UnixLibrary, RTLD_LOCAL, RTLD_NOW};

        // SAFETY: the caller verifies the detached signature before reaching
        // this function. RTLD_NOW rejects unresolved symbols immediately and
        // RTLD_LOCAL prevents plugin symbols from leaking into the process
        // global namespace.
        let library = unsafe { UnixLibrary::open(Some(path), RTLD_NOW | RTLD_LOCAL) }?;
        Ok(library.into())
    }
    #[cfg(not(unix))]
    {
        // SAFETY: the caller verifies the detached signature before reaching
        // this function. The platform loader owns symbol resolution policy.
        unsafe { Library::new(path) }
    }
}

fn load_path(
    path: &Path,
    selected_name: &str,
    config: &str,
) -> Result<PluginBackend, PluginLoadError> {
    if !path.is_file() {
        return Err(PluginLoadError::Missing(path.to_path_buf()));
    }
    if !cfg!(debug_assertions) {
        verify_detached_signature(path, &signature_path(path))
            .map_err(|error| PluginLoadError::Signature(error.to_string()))?;
    }
    let bytes = std::fs::read(path).map_err(|error| PluginLoadError::Dlopen(error.to_string()))?;
    let sha256 = hex::encode(Sha256::digest(bytes));

    // SAFETY: signature verification has completed before this point. The
    // library remains loaded for the rest of the process through
    // `ManuallyDrop`, so all obtained symbols and vtable pointers stay valid.
    let library = open_library(path).map_err(|error| PluginLoadError::Dlopen(error.to_string()))?;
    // SAFETY: the symbol name and function type are the public plugin ABI.
    let entry = unsafe { library.get::<PluginEntry>(b"tessera_plugin_entry\0") }
        .map_err(|_| PluginLoadError::Entry)?;
    // SAFETY: invocation follows the function signature exported by the
    // plugin. Null and all header fields are validated before use.
    let header_ptr = unsafe { entry() };
    if header_ptr.is_null() {
        return Err(PluginLoadError::Header);
    }
    // SAFETY: non-null pointer returned by the entry function is required to
    // reference a process-lifetime static header.
    let header = unsafe { &*header_ptr };
    if header.abi_version != TESSERA_PLUGIN_ABI_VERSION {
        return Err(PluginLoadError::Abi {
            expected: TESSERA_PLUGIN_ABI_VERSION,
            actual: header.abi_version,
        });
    }
    if header.kind != TESSERA_ENFORCEMENT_BACKEND_KIND {
        return Err(PluginLoadError::Kind(header.kind));
    }
    if header.name.is_null() || header.plugin_version.is_null() || header.vtable.is_null() {
        return Err(PluginLoadError::Header);
    }
    // SAFETY: validated non-null pointers are required to address
    // NUL-terminated process-lifetime strings.
    let name = unsafe { CStr::from_ptr(header.name) }
        .to_str()
        .map_err(|_| PluginLoadError::Header)?;
    // SAFETY: same invariant as the plugin name above.
    let version = unsafe { CStr::from_ptr(header.plugin_version) }
        .to_str()
        .map_err(|_| PluginLoadError::Header)?;
    if name != selected_name {
        return Err(PluginLoadError::Name);
    }
    // SAFETY: kind=backend.enforcement defines the vtable pointer type.
    let vtable = unsafe { *(header.vtable.cast::<EnforcementBackendVTable>()) };
    let init = vtable.init.ok_or(PluginLoadError::Header)?;
    let mut context = ptr::null_mut::<c_void>();
    // SAFETY: callback and its arguments follow the validated vtable ABI. The
    // plugin contract requires panic to be caught before crossing the C ABI.
    let status = unsafe { init(config.as_ptr(), config.len(), &raw mut context) };
    if status == PLUGIN_PANIC {
        audit::panic(name, "init");
    }
    if status != PLUGIN_OK || context.is_null() {
        return Err(PluginLoadError::Init(status));
    }
    audit::loaded(name, version, &sha256);
    Ok(PluginBackend {
        name: name.to_owned(),
        version: version.to_owned(),
        context: context as usize,
        vtable,
        _library: ManuallyDrop::new(library),
    })
}

impl PluginBackend {
    fn context(&self) -> *mut c_void {
        self.context as *mut c_void
    }

    fn map_status(&self, operation: &'static str, status: i32) -> Result<(), MacError> {
        match status {
            PLUGIN_OK => Ok(()),
            PLUGIN_USER_UNKNOWN => Err(MacError::UserUnknown {
                user: operation.to_owned(),
            }),
            PLUGIN_UNAVAILABLE => Err(MacError::Unavailable),
            PLUGIN_CAP_MISSING => Err(MacError::CapMissing),
            PLUGIN_INVALID_INPUT => Err(MacError::TextFormat(operation.to_owned())),
            PLUGIN_PANIC => {
                audit::panic(&self.name, operation);
                Err(MacError::Unavailable)
            }
            rc => Err(MacError::Parsec { op: operation, rc }),
        }
    }

    fn guarded_status(
        &self,
        operation: &'static str,
        call: impl FnOnce() -> i32,
    ) -> Result<(), MacError> {
        self.map_status(operation, call())
    }
}

impl MacBackend for PluginBackend {
    fn probe(&self) -> MacRuntime {
        let Some(probe) = self.vtable.probe else {
            return MacRuntime::Unavailable;
        };
        // SAFETY: callback comes from a validated, process-lifetime vtable and
        // must contain its own panic boundary.
        let status = unsafe { probe(self.context()) };
        match status {
            1 => MacRuntime::Active,
            2 => MacRuntime::Disabled,
            PLUGIN_PANIC => {
                audit::panic(&self.name, "probe");
                MacRuntime::Unavailable
            }
            _ => MacRuntime::Unavailable,
        }
    }

    fn probe_mrd(&self) -> MrdState {
        let Some(probe) = self.vtable.probe_mrd else {
            return MrdState::Unknown;
        };
        // SAFETY: callback comes from a validated, process-lifetime vtable and
        // must contain its own panic boundary.
        match unsafe { probe(self.context()) } {
            1 => MrdState::Active,
            2 => MrdState::Inactive,
            PLUGIN_PANIC => {
                audit::panic(&self.name, "probe_mrd");
                MrdState::Unknown
            }
            _ => MrdState::Unknown,
        }
    }

    fn check_write_capability(&self) -> Result<(), MacError> {
        let callback = self
            .vtable
            .check_write_capability
            .ok_or(MacError::Unavailable)?;
        self.guarded_status("check_write_capability", || {
            // SAFETY: callback comes from a validated, process-lifetime
            // vtable and must contain its own panic boundary.
            unsafe { callback(self.context()) }
        })
    }

    fn get_user_mnkc(&self, user: &str) -> Result<IntegrityLabel, MacError> {
        let callback = self.vtable.get_user_mnkc.ok_or(MacError::Unavailable)?;
        let mut label = PluginIntegrityLabel {
            level: 0,
            reserved: [0; 7],
            categories: 0,
        };
        let result = self.guarded_status("get_user_mnkc", || {
            // SAFETY: callback comes from a validated vtable; buffers remain
            // live and correctly sized for the duration of the call.
            unsafe { callback(self.context(), user.as_ptr(), user.len(), &raw mut label) }
        });
        match result {
            Err(MacError::UserUnknown { .. }) => {
                return Err(MacError::UserUnknown {
                    user: user.to_owned(),
                });
            }
            other => other?,
        }
        Ok(label.into())
    }

    fn apply_session(&self, label: IntegrityLabel) -> Result<(), MacError> {
        let callback = self.vtable.apply_session.ok_or(MacError::Unavailable)?;
        self.guarded_status("apply_session", || {
            // SAFETY: callback comes from a validated vtable.
            unsafe { callback(self.context(), label.into()) }
        })
    }

    fn get_file_label(&self, path: &Path) -> Result<IntegrityLabel, MacError> {
        let callback = self.vtable.get_file_label.ok_or(MacError::Unavailable)?;
        let path = path.to_string_lossy();
        let mut label = PluginIntegrityLabel {
            level: 0,
            reserved: [0; 7],
            categories: 0,
        };
        self.guarded_status("get_file_label", || {
            // SAFETY: callback comes from a validated vtable; buffers remain
            // live and correctly sized for the duration of the call.
            unsafe { callback(self.context(), path.as_ptr(), path.len(), &raw mut label) }
        })?;
        Ok(label.into())
    }

    fn set_file_label(
        &self,
        path: &Path,
        label: IntegrityLabel,
        irelax: bool,
    ) -> Result<(), MacError> {
        let callback = self.vtable.set_file_label.ok_or(MacError::Unavailable)?;
        let path = path.to_string_lossy();
        self.guarded_status("set_file_label", || {
            // SAFETY: callback comes from a validated vtable; the path buffer
            // remains live for the duration of the call.
            unsafe {
                callback(
                    self.context(),
                    path.as_ptr(),
                    path.len(),
                    label.into(),
                    irelax,
                )
            }
        })
    }

    fn set_fd_label(
        &self,
        fd: std::os::unix::io::RawFd,
        label: IntegrityLabel,
        irelax: bool,
    ) -> Result<(), MacError> {
        let callback = self.vtable.set_fd_label.ok_or(MacError::Unavailable)?;
        self.guarded_status("set_fd_label", || {
            // SAFETY: callback comes from a validated vtable.
            unsafe { callback(self.context(), fd, label.into(), irelax) }
        })
    }
}

impl Drop for PluginBackend {
    fn drop(&mut self) {
        if let Some(teardown) = self.vtable.teardown {
            // SAFETY: callback comes from the same validated vtable, receives
            // the context returned by init exactly once, and must swallow any
            // panic before crossing the C ABI.
            unsafe { teardown(self.context()) };
        }
        // `_library` is intentionally ManuallyDrop: plugins are never
        // dlclosed from PAM or daemon processes.
    }
}

impl From<IntegrityLabel> for PluginIntegrityLabel {
    fn from(value: IntegrityLabel) -> Self {
        Self {
            level: value.level,
            reserved: [0; 7],
            categories: value.categories,
        }
    }
}

impl From<PluginIntegrityLabel> for IntegrityLabel {
    fn from(value: PluginIntegrityLabel) -> Self {
        Self {
            level: value.level,
            categories: value.categories,
        }
    }
}
