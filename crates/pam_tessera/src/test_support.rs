//! Path fixtures shared by this crate's tests.
//!
//! The unit tests reach this module as part of the crate; the integration
//! tests pull the same file in through `#[path]` from `tests/common`, so both
//! sides agree on one definition.
//!
//! Config validation insists that a number of paths be absolute, and what
//! counts as absolute depends on the platform: `/run/tessera/monitord.sock`
//! has no drive letter or UNC prefix, so Windows reads it as relative and the
//! validator refuses it. Tests must therefore hand the validator a value that
//! is genuinely absolute on the host they run on.
//!
//! These values exist to satisfy validation, not to state what the product
//! should use on a given platform — the Windows transport is a named pipe and
//! how that maps onto the configuration schema is decided elsewhere.
//!
//! The second platform trap is TOML: a Windows path embedded verbatim in a
//! basic string turns `\U`, `\t` and friends into escape sequences, so every
//! path that reaches a config fixture goes through [`toml_path`].

use std::path::Path;

/// Absolute monitord socket path accepted by config validation on this
/// platform.
#[cfg(windows)]
pub const MONITOR_SOCKET_PATH: &str = r"C:\ProgramData\tessera\monitord.sock";
/// Absolute monitord socket path accepted by config validation on this
/// platform.
#[cfg(not(windows))]
pub const MONITOR_SOCKET_PATH: &str = "/run/tessera/monitord.sock";

/// Absolute monitord state-file path accepted by config validation on this
/// platform.
#[cfg(windows)]
pub const MONITOR_STATE_FILE_PATH: &str = r"C:\ProgramData\tessera\sessions.json";
/// Absolute monitord state-file path accepted by config validation on this
/// platform.
#[cfg(not(windows))]
pub const MONITOR_STATE_FILE_PATH: &str = "/run/tessera/sessions.json";

/// Absolute path to an existing system file, standing in for a PKCS#11 module
/// wherever a fixture only needs the path to pass validation.
#[cfg(windows)]
pub const PKCS11_MODULE_PATH: &str = r"C:\Windows\System32\cmd.exe";
/// Absolute path to an existing system file, standing in for a PKCS#11 module
/// wherever a fixture only needs the path to pass validation.
#[cfg(not(windows))]
pub const PKCS11_MODULE_PATH: &str = "/bin/sh";

/// Absolute path that no PKCS#11 module occupies, for fixtures that need the
/// load of the module to fail.
#[cfg(windows)]
pub const MISSING_PKCS11_MODULE_PATH: &str = r"C:\nonexistent\dummy.dll";
/// Absolute path that no PKCS#11 module occupies, for fixtures that need the
/// load of the module to fail.
#[cfg(not(windows))]
pub const MISSING_PKCS11_MODULE_PATH: &str = "/nonexistent/dummy.so";

/// A `[monitor]` section carrying platform-absolute paths, ready to be spliced
/// into a config fixture.
///
/// Only the two path fields are set: every other knob keeps falling back to
/// the top-level legacy fields, so adding this section to a fixture does not
/// change what the fixture asserts.
pub fn monitor_section_toml() -> String {
    format!(
        "[monitor]\nsocket_path = {}\nstate_file_path = {}\n",
        toml_path(Path::new(MONITOR_SOCKET_PATH)),
        toml_path(Path::new(MONITOR_STATE_FILE_PATH)),
    )
}

/// Render `path` as a quoted TOML basic string with backslashes escaped.
///
/// A Windows path pasted into TOML unescaped is a parse error rather than a
/// path: `C:\Users\...` starts a `\U` unicode escape.
pub fn toml_path(path: &Path) -> String {
    format!("{:?}", path.to_string_lossy())
}
