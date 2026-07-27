//! The boundary between system accounts and accounts that may act as roles.
//!
//! A role name is a login account name (`ssh serv@device`), so the role
//! namespace and the Unix account namespace are the same namespace. `root`,
//! `daemon`, `bin`, `sys`, `mail` and `nobody` all satisfy the role-id grammar
//! `^[a-z][a-z0-9-]{0,15}$`, which makes a stray `root.toml` in the role store
//! — a provisioning typo, or a copied sample — enough to turn `ssh root@device`
//! into an ordinary role login.
//!
//! The rejection is keyed on the **uid the account has on this device**, not on
//! a list of reserved names: the danger is not the name but the fact that an
//! account with somebody else's privileges already exists under it. A name list
//! would encode a guess about which names those are, drift from the
//! distribution, and reject legitimate roles (`mail` is a system account on
//! Debian and a sensible role name at the same time).
//!
//! Two call sites share this module: the PAM login path (refuse the login) and
//! the role-store loader (refuse the slice, so the operator sees the
//! provisioning mistake before an engineer trips over it).

/// Lowest uid a regular account can have; anything below it belongs to the
/// system.
///
/// 1000 is `UID_MIN` from `/etc/login.defs` on Debian, Ubuntu and Astra Linux,
/// the distributions this product targets: accounts a distribution or a package
/// creates for its own use land below it, accounts created for people or for
/// Tessera roles land at or above it. Census provisions role accounts from a
/// declared `uid_range` outside the system range, so the boundary does not cut
/// off correctly provisioned roles.
///
/// The value is compiled in rather than parsed from `/etc/login.defs` at
/// authentication time: a login-time dependency on that file would let a local
/// edit of `UID_MIN` widen the gate, and would put a file parser on the
/// authentication path for a number that has not moved on any supported
/// distribution.
pub const FIRST_REGULAR_UID: u32 = 1000;

/// What the passwd database says about a login name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswdLookup {
    /// The account exists and carries this uid.
    Uid(u32),
    /// The passwd database has no entry for the name.
    NoEntry,
    /// The passwd database could not be consulted (NSS failure, unusable
    /// name). The account's class stays unknown.
    Unavailable,
}

/// Why an account name cannot be used as a role.
///
/// The message never mentions the role store: whether a slice with this name
/// exists is exactly the fact the login path must not leak (an early
/// store-existence check was rejected for being such an oracle). The account
/// name and its uid are public through `getent passwd`, so naming them tells an
/// attacker nothing they could not read themselves.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SystemAccountError {
    /// The account exists on this device with a uid below
    /// [`FIRST_REGULAR_UID`].
    #[error(
        "account `{account}` is a system account on this device \
         (uid {uid}, below the first regular uid {boundary}) and cannot be a role"
    )]
    SystemAccount {
        /// The login account name.
        account: String,
        /// The uid the account carries on this device.
        uid: u32,
        /// The boundary that was applied ([`FIRST_REGULAR_UID`]).
        boundary: u32,
    },

    /// The passwd database could not be consulted, so the account could not be
    /// cleared. Fail-closed: an unknown class is refused, not assumed regular.
    #[error("cannot establish whether `{account}` is a system account: passwd lookup failed")]
    LookupFailed {
        /// The login account name.
        account: String,
    },
}

/// This device's passwd view, used to tell system accounts from accounts that
/// may act as roles.
///
/// Holds the lookup as a plain function pointer so the type stays `Copy`, has
/// no lifetime, and can be threaded through the store loader and the flow
/// without a wrapper type in any public signature. [`SystemAccounts::passwd`]
/// is the production view; the other constructors exist for callers that have
/// no device passwd database to consult (offline linting) and for tests, which
/// must not depend on the passwd file of the machine running them.
#[derive(Debug, Clone, Copy)]
pub struct SystemAccounts {
    /// Resolves a login name to its uid.
    lookup: fn(&str) -> PasswdLookup,
}

impl Default for SystemAccounts {
    fn default() -> Self {
        Self::passwd()
    }
}

impl SystemAccounts {
    /// The device's real passwd database (`getpwnam`).
    #[must_use]
    pub const fn passwd() -> Self {
        Self {
            lookup: passwd_lookup,
        }
    }

    /// A view in which no account exists.
    ///
    /// For contexts with no device passwd database to consult — linting a role
    /// base for another device, and tests.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            lookup: no_such_account,
        }
    }

    /// A view backed by `lookup`.
    #[must_use]
    pub const fn with_lookup(lookup: fn(&str) -> PasswdLookup) -> Self {
        Self { lookup }
    }

    /// Decide whether `account` may be used as a role name on this device.
    ///
    /// An account with no passwd entry is *not* a system account: it is simply
    /// absent, and the caller's own path (role resolution, login) rejects it
    /// on its own terms. Turning absence into a refusal here would change
    /// observable behaviour where nothing was promised.
    ///
    /// # Errors
    ///
    /// [`SystemAccountError::SystemAccount`] when the account exists below
    /// [`FIRST_REGULAR_UID`], [`SystemAccountError::LookupFailed`] when the
    /// passwd database could not be consulted.
    pub fn check(&self, account: &str) -> Result<(), SystemAccountError> {
        match (self.lookup)(account) {
            PasswdLookup::Uid(uid) if uid < FIRST_REGULAR_UID => {
                Err(SystemAccountError::SystemAccount {
                    account: account.to_owned(),
                    uid,
                    boundary: FIRST_REGULAR_UID,
                })
            }
            PasswdLookup::Uid(_) | PasswdLookup::NoEntry => Ok(()),
            PasswdLookup::Unavailable => Err(SystemAccountError::LookupFailed {
                account: account.to_owned(),
            }),
        }
    }
}

/// `getpwnam`-backed lookup used by [`SystemAccounts::passwd`].
fn passwd_lookup(account: &str) -> PasswdLookup {
    match nix::unistd::User::from_name(account) {
        Ok(Some(user)) => PasswdLookup::Uid(user.uid.as_raw()),
        Ok(None) => PasswdLookup::NoEntry,
        Err(errno) => {
            tracing::warn!(
                target: "tessera.role",
                account,
                errno = errno as i32,
                "passwd lookup failed; the account cannot be cleared as non-system"
            );
            PasswdLookup::Unavailable
        }
    }
}

/// Lookup used by [`SystemAccounts::empty`].
fn no_such_account(_account: &str) -> PasswdLookup {
    PasswdLookup::NoEntry
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::missing_docs_in_private_items)]

    use super::*;

    /// A passwd view with the accounts a Debian-family device would have:
    /// `root` at 0, a packaged system account just under the boundary, and a
    /// provisioned role account above it.
    fn fixture() -> SystemAccounts {
        SystemAccounts::with_lookup(|account| match account {
            "root" => PasswdLookup::Uid(0),
            "mail" => PasswdLookup::Uid(8),
            "edge" => PasswdLookup::Uid(FIRST_REGULAR_UID - 1),
            "serv" => PasswdLookup::Uid(4000),
            "broken" => PasswdLookup::Unavailable,
            _ => PasswdLookup::NoEntry,
        })
    }

    #[test]
    fn root_is_a_system_account() {
        let err = fixture().check("root").expect_err("root must be refused");
        assert!(matches!(
            err,
            SystemAccountError::SystemAccount { uid: 0, .. }
        ));
    }

    #[test]
    fn packaged_system_account_is_refused_even_with_a_role_like_name() {
        // `mail` is a valid role id and a Debian system account at once — the
        // case a static name list would get wrong in both directions.
        assert!(fixture().check("mail").is_err());
    }

    #[test]
    fn account_just_below_the_boundary_is_system() {
        assert!(fixture().check("edge").is_err());
    }

    #[test]
    fn provisioned_role_account_passes() {
        fixture().check("serv").expect("a role account must pass");
    }

    #[test]
    fn absent_account_is_not_a_system_account() {
        // Absence is not a refusal reason: the caller's own path rejects an
        // unknown account, and inventing a new refusal here would change
        // observable behaviour.
        fixture()
            .check("ghost")
            .expect("an absent account must not be refused here");
    }

    #[test]
    fn unavailable_passwd_fails_closed() {
        let err = fixture()
            .check("broken")
            .expect_err("an unusable passwd database must fail closed");
        assert!(matches!(err, SystemAccountError::LookupFailed { .. }));
    }

    #[test]
    fn empty_view_clears_every_name() {
        SystemAccounts::empty()
            .check("root")
            .expect("an empty passwd view knows no accounts");
    }

    #[test]
    fn message_says_nothing_about_the_role_store() {
        let message = fixture()
            .check("root")
            .expect_err("root must be refused")
            .to_string();
        assert!(!message.contains("slice"), "{message}");
        assert!(!message.contains("store"), "{message}");
    }
}
