//! The service's data directory and the names inside it.
//!
//! One place decides where the configuration, the journal and the account
//! secret live, because `prepare` creates that layout and the service reads it;
//! two answers would mean a service that starts against a directory nobody
//! prepared.
//!
//! The names are plain constants and the layout is a plain struct, so a test on
//! any platform can point the service at a temporary directory.

use std::path::{Path, PathBuf};

/// Default root of the service's data directory.
///
/// `%ProgramData%` is resolved by literal, not by environment variable: the
/// service runs as `LocalSystem` and an environment variable is an input from
/// whoever started the process.
pub const DEFAULT_DATA_DIR: &str = r"C:\ProgramData\Tessera";

/// Configuration file name inside the data directory.
pub const CONFIG_FILE_NAME: &str = "tessera.toml";

/// Journal file name inside the data directory.
pub const JOURNAL_FILE_NAME: &str = "journal.ndjson";

/// Name of the DPAPI-protected blob holding the technical account's password.
pub const ACCOUNT_SECRET_FILE_NAME: &str = "account.dpapi";

/// The pipe the service listens on when the configuration names none.
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\tessera-engine";

/// The local account a successful login is opened under.
///
/// One shared account: the engineer's identity is the credential, and the role
/// is what the journal records. Fifteen characters or fewer, because the
/// pre-Windows-2000 account name is capped there and a longer name would be
/// silently truncated somewhere downstream.
pub const DEFAULT_ACCOUNT_NAME: &str = "tessera-logon";

/// Service name registered with the service control manager.
pub const SERVICE_NAME: &str = "TesseraEngine";

/// Service display name shown in the services console.
pub const SERVICE_DISPLAY_NAME: &str = "Tessera Engine";

/// Service description shown in the services console.
pub const SERVICE_DESCRIPTION: &str =
    "Проверяет удостоверения на съёмных носителях и выдаёт вердикт входа.";

/// The service name recorded in the journal for attempts it handles.
pub const AUDIT_SERVICE_NAME: &str = "tessera-engine";

/// The layout of one data directory.
#[derive(Debug, Clone)]
pub struct DataDir {
    root: PathBuf,
}

impl DataDir {
    /// The layout rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The default layout, under [`DEFAULT_DATA_DIR`].
    #[must_use]
    pub fn default_location() -> Self {
        Self::new(DEFAULT_DATA_DIR)
    }

    /// The root itself.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where the configuration is read from.
    #[must_use]
    pub fn config(&self) -> PathBuf {
        self.root.join(CONFIG_FILE_NAME)
    }

    /// Where the journal is appended to.
    #[must_use]
    pub fn journal(&self) -> PathBuf {
        self.root.join(JOURNAL_FILE_NAME)
    }

    /// Where the technical account's password is kept.
    #[must_use]
    pub fn account_secret(&self) -> PathBuf {
        self.root.join(ACCOUNT_SECRET_FILE_NAME)
    }
}

impl Default for DataDir {
    fn default() -> Self {
        Self::default_location()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The account name has to fit the pre-Windows-2000 cap; nothing in the
    /// code path checks it at runtime, so it is checked here.
    #[test]
    fn the_account_name_fits_the_sam_limit() {
        assert!(
            DEFAULT_ACCOUNT_NAME.len() <= 20,
            "account name is {} characters",
            DEFAULT_ACCOUNT_NAME.len()
        );
        assert!(DEFAULT_ACCOUNT_NAME
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    }

    #[test]
    fn the_layout_hangs_off_one_root() {
        let dir = DataDir::new(r"C:\tmp\tessera");
        assert!(dir.config().starts_with(dir.root()));
        assert!(dir.journal().starts_with(dir.root()));
        assert!(dir.account_secret().starts_with(dir.root()));
    }
}
