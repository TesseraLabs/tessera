//! `prepare`: everything that must exist on a device before the service can
//! start.
//!
//! It creates the data directory with an ACL of its own, creates the local
//! account a session runs under, generates that account's password, and stores
//! the password where only `LocalSystem` can read it.
//!
//! # Idempotence
//!
//! Running it twice must not cost a device its logins, so the rules are:
//!
//! * The directory is created if absent and its ACL is applied every time —
//!   applying it again is how a directory whose permissions drifted is brought
//!   back, and it is the one step that is safe to repeat unconditionally.
//! * The account is created if absent and left alone if present.
//! * The password is generated only when there is no stored one to lose. A
//!   stored secret is never overwritten while its account exists, because the
//!   copy on disk is the only copy: replacing it would strand every credential
//!   provider that already holds the old one and, worse, leave the account and
//!   the file disagreeing if the second step failed.
//! * The one case where the password *is* replaced is an account that exists
//!   without a stored secret. There is nothing to lose there, and the
//!   alternative — leaving the pair broken — is a device that fails every login
//!   with no way back short of deleting the account by hand.

use std::path::Path;

use zeroize::Zeroizing;

use crate::paths::{DataDir, DEFAULT_ACCOUNT_NAME};

use super::sys::WinError;
use super::{account, dacl, dpapi};

/// Why a device could not be prepared.
#[derive(Debug, thiserror::Error)]
pub enum PrepareError {
    /// A directory or file could not be created or written.
    #[error("{path}: {source}")]
    Io {
        /// What was being created.
        path: String,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// A Win32 call failed.
    #[error("{0}")]
    Win(#[from] WinError),
    /// A password could not be generated.
    #[error("password generation: {0}")]
    Password(#[from] crate::password::PasswordError),
    /// The stored secret could not be read back through the trust walk.
    #[error("stored account secret: {0}")]
    Secret(String),
}

/// What one run of `prepare` did to the account and its password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountOutcome {
    /// The account did not exist; it and its password were created.
    Created,
    /// Both halves were already in place and were left alone.
    AlreadyPrepared,
    /// The account existed without a stored password, so a new one was set.
    PasswordReset,
}

/// What one run of `prepare` did.
///
/// The directory's ACL is not reported: it is applied on every run, so a
/// successful run always means it is what this build says it should be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// The data directory did not exist and was created.
    pub directory_created: bool,
    /// What happened to the account.
    pub account: AccountOutcome,
}

/// Creates or repairs everything the service needs on this device.
///
/// # Errors
///
/// [`PrepareError`] at the first step that fails. Nothing is rolled back: a
/// half-prepared device is left as it is, because every step is one a re-run
/// resumes, and undoing an account that may already have been used would be a
/// worse outcome than leaving it.
pub fn run(dir: &DataDir, account_name: &str) -> Result<Report, PrepareError> {
    let directory_created = !dir.root().exists();
    create_dir(dir.root())?;
    // Two subdirectories the configuration refers to. They are created here so
    // they inherit the protected ACL from the start, rather than being made
    // later by hand under whatever permissions happen to apply then.
    create_dir(&dir.root().join("roles"))?;
    create_dir(&dir.root().join("ca"))?;
    dacl::protect_data_dir(dir.root())?;

    let account_exists = account::exists(account_name)?;
    let secret_exists = dir.account_secret().exists();

    let account = match (account_exists, secret_exists) {
        // Nothing here yet: create the account with a fresh password.
        (false, _) => {
            let password = crate::password::generate()?;
            account::create(account_name, &password, ACCOUNT_COMMENT)?;
            store_password(dir, &password)?;
            AccountOutcome::Created
        }
        // Both halves are present and agree as far as this command can tell.
        (true, true) => AccountOutcome::AlreadyPrepared,
        // The account is there but its password is not: reset it, because the
        // pair is unusable as it stands.
        (true, false) => {
            let password = crate::password::generate()?;
            account::set_password(account_name, &password)?;
            store_password(dir, &password)?;
            AccountOutcome::PasswordReset
        }
    };

    Ok(Report {
        directory_created,
        account,
    })
}

/// Comment recorded on the account, so that whoever finds it in the account
/// list knows what created it.
const ACCOUNT_COMMENT: &str =
    "Tessera: учётная запись входа по удостоверению. Пароль хранит служба Tessera Engine.";

/// The default account name, exposed so the command line and the service agree
/// without either importing the other.
#[must_use]
pub fn default_account_name() -> &'static str {
    DEFAULT_ACCOUNT_NAME
}

/// Creates `path` if it does not exist.
fn create_dir(path: &Path) -> Result<(), PrepareError> {
    std::fs::create_dir_all(path).map_err(|source| PrepareError::Io {
        path: path.display().to_string(),
        source,
    })
}

/// Seals `password` and writes it, then narrows the file's ACL.
///
/// The file exists for a moment with the directory's inherited permissions
/// (`LocalSystem` and administrators) before its own are applied. That window
/// is inside a directory those two already own exclusively, so it widens
/// nothing; closing it properly means creating the file with a descriptor
/// attached, which is worth doing when this file stops being written once per
/// device lifetime.
fn store_password(dir: &DataDir, password: &str) -> Result<(), PrepareError> {
    let sealed = dpapi::protect(password.as_bytes())?;
    let path = dir.account_secret();
    std::fs::write(&path, &sealed).map_err(|source| PrepareError::Io {
        path: path.display().to_string(),
        source,
    })?;
    dacl::protect_account_secret(&path)?;
    Ok(())
}

/// Reads back the stored password.
///
/// The file is read through the same trust walk the configuration and the role
/// store go through: a secret file whose permissions have been widened is not
/// read at all. A service that cannot read it cannot admit anyone, which is the
/// intended failure — an admission whose password came from somewhere else is
/// not an admission worth having.
///
/// # Errors
///
/// [`PrepareError::Secret`] when the file is missing, untrusted, undecryptable,
/// or not UTF-8.
pub fn stored_password(dir: &DataDir) -> Result<Zeroizing<String>, PrepareError> {
    use tessera_core::privileged_path::{read_file, ExecTrust};

    let path = dir.account_secret();
    let sealed = read_file(&path, ExecTrust::Root)
        .map_err(|e| PrepareError::Secret(format!("{}: {e}", path.display())))?;
    let plain = dpapi::unprotect(&sealed)?;
    let text = std::str::from_utf8(&plain)
        .map_err(|_| PrepareError::Secret("stored password is not UTF-8".to_owned()))?;
    Ok(Zeroizing::new(text.to_owned()))
}
