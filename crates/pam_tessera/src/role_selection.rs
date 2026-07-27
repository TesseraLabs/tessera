//! Role selection: the requested role IS the login account name.
//!
//! An engineer logs into a role account whose name is the role (`ssh
//! oper@device`), so `PAM_USER` is the only source of the requested role.
//! This module turns that name into a [`RoleId`] and nothing else — it never
//! rewrites `PAM_USER`, and there is no second source (no name suffix, no PAM
//! prompt, no environment variable). Multiple sources are what create a window
//! in which the name read by the stack differs from the name the module acts
//! on, and a difference between "before" and "after" is an escalation (the
//! polkit CVE-2021-3560 class).
//!
//! An account name that cannot be a `role_id` at all (`Admin`, `svc_backup`,
//! anything over 16 characters) is rejected here — before any credential
//! material is touched. A name that is syntactically a `role_id` but names no
//! role in the on-device store (`ivanov`, `root`) is rejected later, by the
//! store resolve stage that runs after the certificate is verified: answering
//! "does role X exist on this device" before authentication would hand an
//! attacker at the console a role-existence oracle, and role names are
//! deliberately not disclosed pre-authentication.
//!
//! The conversion is pure and unit-tested against the accepted/rejected name
//! table from the role-selection spec.

use tessera_core::role::RoleId;

/// Errors from deriving the requested role from the login account name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SelectionError {
    /// PAM handed us an empty user name.
    #[error("empty account name")]
    EmptyAccount,
    /// The account name is not a valid `role_id`
    /// (`^[a-z][a-z0-9-]{0,15}$`), so it is not a role account.
    #[error("account name is not a role: {0}")]
    NotARole(String),
}

/// Derive the requested role from the login account name.
///
/// Rules (role-selection spec):
/// - `oper` → `RoleId("oper")`
/// - `read-only` → `RoleId("read-only")`
/// - `Admin`, `1serv`, `svc_backup`, `ivanov+serv`, a 17-char name →
///   [`SelectionError::NotARole`]
/// - empty string → [`SelectionError::EmptyAccount`]
///
/// The name is validated through [`RoleId`] so the same
/// `^[a-z][a-z0-9-]{0,15}$` contract applies everywhere. This function only
/// answers "could this name be a role at all"; whether the device actually
/// carries such a role is decided by the store resolve stage after the
/// certificate is verified.
///
/// # Errors
///
/// See [`SelectionError`].
pub fn role_from_account(account: &str) -> Result<RoleId, SelectionError> {
    if account.is_empty() {
        return Err(SelectionError::EmptyAccount);
    }
    RoleId::new(account).map_err(|_| SelectionError::NotARole(account.to_owned()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn role_account_name_is_the_role() {
        assert_eq!(role_from_account("oper").unwrap().as_str(), "oper");
    }

    #[test]
    fn hyphenated_role_account_ok() {
        assert_eq!(
            role_from_account("read-only").unwrap().as_str(),
            "read-only"
        );
    }

    #[test]
    fn sixteen_char_name_is_the_boundary() {
        let name = format!("a{}", "a".repeat(15));
        assert_eq!(role_from_account(&name).unwrap().as_str(), name);
        let too_long = format!("a{}", "a".repeat(16));
        assert!(matches!(
            role_from_account(&too_long),
            Err(SelectionError::NotARole(_))
        ));
    }

    #[test]
    fn empty_account_rejected() {
        assert_eq!(role_from_account(""), Err(SelectionError::EmptyAccount));
    }

    #[test]
    fn names_that_cannot_be_a_role_id_are_rejected() {
        // Legal Unix account names that no role can ever be called.
        for name in ["Admin", "1serv", "svc_backup", "_oper", "oper.serv", "OPER"] {
            assert!(
                matches!(role_from_account(name), Err(SelectionError::NotARole(_))),
                "{name} must not be accepted as a role account",
            );
        }
    }

    #[test]
    fn personal_account_names_pass_syntax_and_are_denied_by_the_store() {
        // `ivanov` and `root` satisfy the role_id pattern, so this stage
        // cannot reject them; they are denied by the store resolve stage
        // (`role_deny reason=not_found`) after the certificate is verified.
        // Answering "does this role exist" earlier would be a pre-auth oracle.
        assert!(role_from_account("ivanov").is_ok());
        assert!(role_from_account("root").is_ok());
    }

    #[test]
    fn plus_in_the_name_is_not_a_role_selector() {
        // The `<user>+<role>` login form is gone: `+` is simply an illegal
        // character in a role id, so the whole name is rejected rather than
        // split.
        assert_eq!(
            role_from_account("ivanov+serv"),
            Err(SelectionError::NotARole("ivanov+serv".to_owned()))
        );
    }
}
