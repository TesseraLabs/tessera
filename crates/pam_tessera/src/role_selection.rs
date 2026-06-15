//! Login-string role selection: parse the `<user>+<role>` suffix and
//! canonicalise `PAM_USER`.
//!
//! This is the first thing `pam_sm_authenticate` does with the PAM user name
//! (design Decision 6): split off the optional `+<role>` suffix, validate it,
//! and rewrite `PAM_USER` to the canonical account name *before* any other
//! work or any other module in the stack reads the user (polkit
//! CVE-2021-3560 lesson — no swap window). The `+` character is therefore
//! forbidden in canonical account names (enforced at provisioning).
//!
//! Parsing is pure and unit-tested against the full edge table from the
//! role-selection delta spec.

use tessera_core::role::RoleId;

/// Errors from parsing a `<user>+<role>` login string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SelectionError {
    /// The login string was empty, or the canonical user part was empty
    /// (e.g. `+serv`).
    #[error("empty user name in login string")]
    EmptyUser,
    /// The suffix was present but empty (`ivanov+`).
    #[error("empty role suffix in login string")]
    EmptyRole,
    /// More than one `+` separator (`ivanov+a+b`).
    #[error("multiple '+' separators in login string")]
    MultipleSeparators,
    /// The role part is not a valid `role_id` (`^[a-z][a-z0-9-]{0,15}$`).
    #[error("invalid role_id in login string: {0}")]
    InvalidRoleId(String),
}

/// Parse a raw login string into `(canonical_user, optional_role)`.
///
/// Rules (role-selection delta spec edge table):
/// - `ivanov` → `("ivanov", None)`
/// - `ivanov+serv` → `("ivanov", Some(serv))`
/// - `ivanov+` → [`SelectionError::EmptyRole`]
/// - `ivanov+a+b` → [`SelectionError::MultipleSeparators`]
/// - `+serv` (empty user) → [`SelectionError::EmptyUser`]
/// - empty string → [`SelectionError::EmptyUser`]
/// - `ivanov+Bad` (bad `role_id`) → [`SelectionError::InvalidRoleId`]
///
/// The role part is validated through [`RoleId`] so the same
/// `^[a-z][a-z0-9-]{0,15}$` contract applies everywhere.
///
/// # Errors
///
/// See [`SelectionError`].
pub fn parse_user_role(raw: &str) -> Result<(String, Option<RoleId>), SelectionError> {
    if raw.is_empty() {
        return Err(SelectionError::EmptyUser);
    }
    let mut parts = raw.split('+');
    // `split` always yields at least one element.
    let user = parts.next().unwrap_or("");
    let role_part = parts.next();
    // Any further element means a second separator was present.
    if parts.next().is_some() {
        return Err(SelectionError::MultipleSeparators);
    }
    if user.is_empty() {
        return Err(SelectionError::EmptyUser);
    }
    match role_part {
        None => Ok((user.to_owned(), None)),
        Some("") => Err(SelectionError::EmptyRole),
        Some(role) => {
            let role_id =
                RoleId::new(role).map_err(|_| SelectionError::InvalidRoleId(role.to_owned()))?;
            Ok((user.to_owned(), Some(role_id)))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn plain_user_no_role() {
        let (user, role) = parse_user_role("ivanov").unwrap();
        assert_eq!(user, "ivanov");
        assert_eq!(role, None);
    }

    #[test]
    fn user_with_role() {
        let (user, role) = parse_user_role("ivanov+serv").unwrap();
        assert_eq!(user, "ivanov");
        assert_eq!(role.unwrap().as_str(), "serv");
    }

    #[test]
    fn trailing_plus_is_empty_role() {
        assert_eq!(parse_user_role("ivanov+"), Err(SelectionError::EmptyRole));
    }

    #[test]
    fn double_suffix_rejected() {
        assert_eq!(
            parse_user_role("ivanov+a+b"),
            Err(SelectionError::MultipleSeparators)
        );
    }

    #[test]
    fn empty_string_is_empty_user() {
        assert_eq!(parse_user_role(""), Err(SelectionError::EmptyUser));
    }

    #[test]
    fn leading_plus_is_empty_user() {
        assert_eq!(parse_user_role("+serv"), Err(SelectionError::EmptyUser));
    }

    #[test]
    fn bad_role_id_rejected() {
        // Uppercase is not a valid role_id.
        assert!(matches!(
            parse_user_role("ivanov+Serv"),
            Err(SelectionError::InvalidRoleId(_))
        ));
        // Leading digit.
        assert!(matches!(
            parse_user_role("ivanov+1serv"),
            Err(SelectionError::InvalidRoleId(_))
        ));
        // Too long (>16 chars).
        let long = format!("ivanov+{}", "a".repeat(17));
        assert!(matches!(
            parse_user_role(&long),
            Err(SelectionError::InvalidRoleId(_))
        ));
    }

    #[test]
    fn role_id_boundary_lengths() {
        // 16-char role_id is accepted.
        let role = format!("a{}", "a".repeat(15));
        let s = format!("ivanov+{role}");
        let (_user, parsed) = parse_user_role(&s).unwrap();
        assert_eq!(parsed.unwrap().as_str(), role);
    }

    #[test]
    fn hyphenated_role_id_ok() {
        let (_u, role) = parse_user_role("ivanov+read-only").unwrap();
        assert_eq!(role.unwrap().as_str(), "read-only");
    }
}
