//! The name the session phase is allowed to act under.
//!
//! `pam_sm_authenticate` and `pam_sm_open_session` are separate PAM callbacks.
//! Nothing in PAM guarantees that `PAM_USER` still holds the value the module
//! authenticated: the application, or another module in the stack, may set it
//! between the two phases. The module no longer rewrites `PAM_USER` itself, so
//! it cannot rely on owning it either.
//!
//! The name that was actually authorised is the resolved role: an engineer
//! logs into a role account whose name *is* the role, and the role in
//! [`AuthContext`] was resolved from `PAM_USER` and checked against the
//! certificate's `allowed_roles` in one uninterrupted step. That snapshot is
//! therefore the only trustworthy source in the session phase, and the live
//! `PAM_USER` is treated as an untrusted claim that must match it.
//!
//! A mismatch is refused rather than reconciled: applying a MAC label or
//! running privileged `session_open` hooks for an account the certificate was
//! never checked against is exactly the escalation the atomic resolve stage
//! exists to prevent (the polkit CVE-2021-3560 class).

use tessera_core::pam_data::AuthContext;

/// Why the session phase must not proceed under the observed `PAM_USER`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionIdentityError {
    /// The stored context carries no role, so there is no authorised name to
    /// compare against. Every login resolves a role, so this can only be a
    /// context written by an older module or a corrupted frame — either way
    /// there is nothing to authorise the session against.
    #[error("authentication context carries no resolved role")]
    NoAuthorizedAccount,
    /// `PAM_USER` no longer names the account the certificate admitted.
    #[error("PAM_USER changed after authentication: authorized {authorized}, observed {observed}")]
    AccountChanged {
        /// The account name fixed at authenticate time.
        authorized: String,
        /// The name read off the handle in the session phase.
        observed: String,
    },
}

/// The account name this context was authorised for, if any.
///
/// The role id and the login account name are the same string by
/// construction, so the resolved role is the authorised account.
#[must_use]
pub fn authorized_account(ctx: &AuthContext) -> Option<&str> {
    ctx.role.as_ref().map(|role| role.role.as_str())
}

/// Check the live `PAM_USER` against the account fixed at authenticate time.
///
/// Returns the authorised name — deliberately the one from the context, not
/// the caller's string, so downstream code cannot accidentally keep using the
/// unverified value.
///
/// # Errors
///
/// See [`SessionIdentityError`]. Both variants are fail-closed: callers in the
/// session phase must refuse rather than fall back to any other name.
pub fn verify_session_account<'ctx>(
    ctx: &'ctx AuthContext,
    observed_pam_user: &str,
) -> Result<&'ctx str, SessionIdentityError> {
    let authorized = authorized_account(ctx).ok_or(SessionIdentityError::NoAuthorizedAccount)?;
    if authorized == observed_pam_user {
        Ok(authorized)
    } else {
        Err(SessionIdentityError::AccountChanged {
            authorized: authorized.to_owned(),
            observed: observed_pam_user.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::time::Duration;

    use tessera_core::role::{RoleId, SessionRolePayload};

    use super::*;

    fn ctx_with_role(role: Option<&str>) -> AuthContext {
        let mut ctx = AuthContext::new("sess-test".to_owned(), "ssh".to_owned());
        ctx.cert_cn = Some("service-engineer".to_owned());
        ctx.role = role.map(|r| SessionRolePayload {
            role: RoleId::new(r).unwrap(),
            role_version: 1,
            ttl: Duration::from_mins(1),
            mac_mask: None,
        });
        ctx
    }

    #[test]
    fn matching_pam_user_yields_the_authorized_account() {
        let ctx = ctx_with_role(Some("oper"));
        assert_eq!(verify_session_account(&ctx, "oper").unwrap(), "oper");
    }

    #[test]
    fn account_swapped_between_phases_is_refused() {
        let ctx = ctx_with_role(Some("oper"));
        assert_eq!(
            verify_session_account(&ctx, "serv"),
            Err(SessionIdentityError::AccountChanged {
                authorized: "oper".to_owned(),
                observed: "serv".to_owned(),
            })
        );
    }

    #[test]
    fn certificate_cn_is_not_an_authorized_account() {
        // The CN identifies the engineer, not the role account. It must never
        // stand in for the name the session acts under.
        let ctx = ctx_with_role(Some("oper"));
        assert!(verify_session_account(&ctx, "service-engineer").is_err());
    }

    #[test]
    fn context_without_a_role_authorizes_nothing() {
        let ctx = ctx_with_role(None);
        assert_eq!(authorized_account(&ctx), None);
        assert_eq!(
            verify_session_account(&ctx, "oper"),
            Err(SessionIdentityError::NoAuthorizedAccount)
        );
    }
}
