//! Path fixtures shared by this crate's tests.
//!
//! Config validation insists that many paths be absolute, and what counts as
//! absolute depends on the platform: `/run/tessera/monitord.sock` carries no
//! drive letter, so Windows reads it as relative and the validator refuses it.
//! A test that means to exercise something else entirely — role TTLs, hook
//! `run_as`, the GOST engine probe — must therefore hand the validator paths
//! that are absolute on the host it runs on.
//!
//! The values here exist to satisfy validation. They are not a statement about
//! what the product should use on a given platform; the Windows engine brings
//! its own transport and its own paths.
//!
//! The second platform trap is TOML: a Windows path pasted verbatim into a
//! basic string turns `\U`, `\t` and friends into escape sequences, so every
//! path that reaches a config fixture goes through [`toml_path`].
//!
//! The unit tests reach this module as part of the crate; the integration
//! tests pull the same file in through `#[path]` from `tests/common`, so both
//! sides agree on one definition.

use std::path::{Path, PathBuf};

/// Environment variable naming the `gost-engine` shared library to test with.
///
/// Set it when the engine is not where `openssl version -e` says engines live
/// — a self-built engine, or a host with several OpenSSL installations.
// Reached only from the GOST tests, which are feature-gated, so the crate's
// own unit-test build sees this as unused. `expect` is wrong here: it would
// itself go unfulfilled in the builds where the item *is* used.
#[allow(dead_code)]
pub const GOST_ENGINE_PATH_ENV: &str = "TESSERA_TEST_GOST_ENGINE_PATH";

/// Locate the `gost-engine` shared library on this host, if it has one.
///
/// Every GOST code path now requires the caller to name the engine's file —
/// there is no lookup by id left anywhere — so a test that wants to exercise
/// one has to produce that path itself. Returns `None` when no engine can be
/// found, which callers treat as "skip", not as a failure: developer hosts
/// and CI runners outside Astra have none.
///
/// [`GOST_ENGINE_PATH_ENV`] wins when it points at a real file; otherwise the
/// engine directory reported by `openssl version -e` is probed for `gost.so`.
// Unused in the builds that leave the GOST tests out; see the note on
// `GOST_ENGINE_PATH_ENV`.
#[allow(dead_code)]
#[must_use]
pub fn gost_engine_path() -> Option<PathBuf> {
    if let Some(configured) = std::env::var_os(GOST_ENGINE_PATH_ENV) {
        let configured = PathBuf::from(configured);
        return configured.is_file().then_some(configured);
    }
    let out = std::process::Command::new("openssl")
        .args(["version", "-e"])
        .output()
        .ok()?;
    // `ENGINESDIR: "/usr/lib/x86_64-linux-gnu/engines-1.1"`
    let text = String::from_utf8(out.stdout).ok()?;
    let dir = text.split('"').nth(1)?;
    let candidate = PathBuf::from(dir).join("gost.so");
    candidate.is_file().then_some(candidate)
}

/// Absolute path to an existing system executable, standing in for a shell,
/// a PKCS#11 module or a hook command wherever a fixture only needs a path
/// that exists and is absolute.
#[cfg(windows)]
pub const SHELL_PATH: &str = r"C:\Windows\System32\cmd.exe";
/// Absolute path to an existing system executable, standing in for a shell,
/// a PKCS#11 module or a hook command wherever a fixture only needs a path
/// that exists and is absolute.
#[cfg(not(windows))]
pub const SHELL_PATH: &str = "/bin/sh";

/// Re-root a POSIX-style absolute test path so it is absolute on this
/// platform: on Windows the same path lands on the `C:` drive.
///
/// Only the shape matters — nothing is created at the returned location.
#[cfg(windows)]
pub fn absolute(posix: &str) -> String {
    format!("C:{}", posix.replace('/', "\\"))
}

/// Re-root a POSIX-style absolute test path so it is absolute on this
/// platform: on Windows the same path lands on the `C:` drive.
///
/// Only the shape matters — nothing is created at the returned location.
#[cfg(not(windows))]
pub fn absolute(posix: &str) -> String {
    posix.to_owned()
}

/// Render `path` as a quoted TOML basic string with backslashes escaped.
///
/// A Windows path pasted into TOML unescaped is a parse error rather than a
/// path: `C:\Users\...` starts a `\U` unicode escape.
pub fn toml_path(path: impl AsRef<Path>) -> String {
    format!("{:?}", path.as_ref().to_string_lossy())
}

/// A `[monitor]` section carrying platform-absolute paths, ready to be spliced
/// into a config fixture.
///
/// Only the two path fields are set: every other knob keeps falling back to
/// the top-level legacy fields, so adding this section to a fixture does not
/// change what the fixture asserts. Both fields are needed because their
/// defaults are POSIX paths that Windows rejects.
pub fn monitor_section_toml() -> String {
    format!(
        "\n[monitor]\nsocket_path = {}\nstate_file_path = {}\n",
        toml_path(absolute("/run/tessera/monitord.sock")),
        toml_path(absolute("/run/tessera/sessions.json")),
    )
}

/// Rewrite the `/bin/sh` stand-in a POSIX-written fixture uses for the PKCS#11
/// module and for every hook command — both are checked for absoluteness.
///
/// Callers that splice in their own `anchors` do so before calling this, while
/// the `anchors = ["/bin/sh"]` line still reads as the fixture wrote it.
///
/// Use this instead of [`platform_config_toml`] when the caller goes on to
/// append a `[monitor]` section of its own; a second table of that name would
/// not parse.
pub fn platform_paths(src: &str) -> String {
    src.replace("\"/bin/sh\"", &toml_path(SHELL_PATH))
}

/// Make a config fixture written in POSIX terms loadable on this platform:
/// [`platform_paths`] plus the `[monitor]` section whose defaults cannot be
/// supplied off Unix.
pub fn platform_config_toml(src: &str) -> String {
    let body = platform_paths(src);
    if body.contains("[monitor]") {
        body
    } else {
        body + &monitor_section_toml()
    }
}
