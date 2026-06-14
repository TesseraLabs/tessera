//! Role selection: the atomic resolve + coverage stage and the session
//! payload snapshot.
//!
//! This module is the security-critical core of the role-format login path
//! (design.md Decision 6, polkit CVE-2021-3560 lesson). The PAM module
//! parses the `user+role` suffix early and rewrites `PAM_USER`; once the
//! certificate is verified the requested role MUST be resolved from the
//! [`RoleStore`] and checked for coverage **in one uninterrupted step**,
//! with no window in which the role can be swapped before the session is
//! fixed.
//!
//! Two responsibilities live here, both pure (no PAM, no I/O beyond the
//! already-loaded store) so they can be unit-tested in isolation:
//!
//! - [`resolve_and_cover`] — resolve the requested [`RoleId`] from the store
//!   and verify membership in the certificate's `allowed_roles` list, gated
//!   by the [`RoleEnforce`] mode.
//! - [`SessionRolePayload::fix`] — snapshot the resolved slice's payload at
//!   session-open time (so a later store edit cannot affect a live session),
//!   compute the bounded TTL, and refuse roles whose payload needs an
//!   enforcement backend absent from this build.

use std::time::Duration;

use super::audit;
use super::schema::{RoleId, RoleSlice};
use super::store::RoleStore;

/// Migration / enforcement mode for the `[roles]` config section.
///
/// Mirrors `[roles].enforce` (`false` | `warn` | `require`); kept in
/// `tessera_core` so the resolve/coverage logic is testable without the
/// validated-config type. The PAM module maps its config enum onto this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleEnforce {
    /// Roles are not checked at all — pre-role behaviour (v0.3.19).
    Disabled,
    /// Resolve + coverage are checked and logged, but never deny.
    Warn,
    /// Full enforcement: any resolve / coverage failure denies the login.
    Require,
}

/// Reason a role login was denied. Matches the `role_deny` audit dictionary
/// (logging-audit spec): `not_found` / `not_covered` / `backend_unavailable`
/// / `mask_exceeds_ceiling` / `syntax`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleDenyReason {
    /// The requested role is not present in the on-device store, or the
    /// store is empty / unconfigured under `require`.
    NotFound,
    /// The requested role is not a member of the certificate's
    /// `allowed_roles` list.
    NotCovered,
    /// The resolved role payload needs an enforcement backend that this
    /// build does not provide (open build: `mac_mask` without `ParsecBackend`,
    /// `selinux` without the `SELinux` adapter).
    BackendUnavailable,
    /// The role's MAC mask exceeds the certificate's integrity ceiling
    /// (reserved for the mac-integrity intersection in task 5.1).
    MaskExceedsCeiling,
    /// The login string was syntactically invalid, or no role was supplied
    /// where one is required.
    Syntax,
}

impl RoleDenyReason {
    /// Stable wire string used in the `role_deny` audit event `reason` field.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RoleDenyReason::NotFound => "not_found",
            RoleDenyReason::NotCovered => "not_covered",
            RoleDenyReason::BackendUnavailable => "backend_unavailable",
            RoleDenyReason::MaskExceedsCeiling => "mask_exceeds_ceiling",
            RoleDenyReason::Syntax => "syntax",
        }
    }
}

impl std::fmt::Display for RoleDenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How the engineer's identity proved coverage of the requested role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageMethod {
    /// X.509 certificate `allowed_roles` extension (membership).
    Cert,
    /// Tessera Code MAC entry (`role_id` in the code) — commercial, future.
    Code,
}

impl CoverageMethod {
    /// Stable wire string for the `role_session_open` audit `method` field.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CoverageMethod::Cert => "cert",
            CoverageMethod::Code => "code",
        }
    }
}

/// Outcome of [`resolve_and_cover`].
///
/// `Allowed` carries the resolved slice (cloned out of the store) so the
/// caller can immediately fix the session payload without re-reading the
/// store — closing the swap window (CVE-2021-3560).
#[derive(Debug, Clone)]
pub enum Resolution {
    /// Role resolved and covered. Carries the resolved slice and the method.
    Allowed {
        /// The resolved role slice (a copy taken atomically with coverage).
        /// Boxed to keep the enum small (the `RoleSlice` is large relative to
        /// the other variants).
        slice: Box<RoleSlice>,
        /// How coverage was proven.
        method: CoverageMethod,
    },
    /// Enforcement is disabled — no role is selected; behave as v0.3.19.
    Skipped,
    /// Resolve or coverage failed. The caller decides (per [`RoleEnforce`])
    /// whether to deny; an audit `role_deny` has already been emitted.
    Denied {
        /// Why it failed.
        reason: RoleDenyReason,
    },
}

/// Atomically resolve `requested` from `store` and verify it is covered by
/// `allowed_roles`, gated by `enforce`. **No swap window**: the slice is
/// cloned out of the store in the same call that checks coverage.
///
/// Coverage is *membership only* (design Decision 3): the requested role
/// must appear in `allowed_roles`; there is no level comparison
/// ("admin covers oper" must be expressed by listing both).
///
/// `allowed_roles` is the parsed `pam_cert_allowed_roles` extension:
/// - `Some(list)` — the cert carries the extension (possibly empty).
/// - `None` — the cert has no extension; under cert-method coverage this
///   means the cert grants no roles, so any requested role is `NotCovered`.
///
/// Behaviour by mode:
/// - [`RoleEnforce::Disabled`] — returns [`Resolution::Skipped`] without
///   touching the store (pre-role behaviour).
/// - [`RoleEnforce::Warn`] — performs the checks and logs, but a failure
///   still returns [`Resolution::Allowed`] when the role resolved, or
///   [`Resolution::Skipped`] when it did not (never denies). A `role_deny`
///   audit is emitted on failure for visibility, but the login proceeds.
/// - [`RoleEnforce::Require`] — a failure returns [`Resolution::Denied`].
///
/// `requested` is the role id parsed from the login suffix / prompt. When
/// `None`, the caller already decided a role was not supplied; under
/// `Require` that is a [`RoleDenyReason::Syntax`] deny, under `Warn` /
/// `Disabled` it is a skip.
#[must_use]
pub fn resolve_and_cover(
    store: &RoleStore,
    requested: Option<&RoleId>,
    allowed_roles: Option<&[RoleId]>,
    enforce: RoleEnforce,
    user: &str,
) -> Resolution {
    if enforce == RoleEnforce::Disabled {
        return Resolution::Skipped;
    }

    let Some(role_id) = requested else {
        // No role supplied where one may be needed.
        return deny_or_skip(enforce, RoleDenyReason::Syntax, user, "");
    };

    // Resolve from the store (one read; the slice is cloned out below so no
    // later store mutation can affect this decision).
    let Some(slice) = store.get(role_id) else {
        return deny_or_skip(enforce, RoleDenyReason::NotFound, user, role_id.as_str());
    };

    // Coverage: membership in the cert's allowed_roles. A cert without the
    // extension grants no roles (fail-closed).
    let covered = allowed_roles.is_some_and(|roles| roles.iter().any(|r| r == role_id));
    if !covered {
        // Clone the slice anyway so warn-mode can still fix the session.
        return match enforce {
            RoleEnforce::Require => {
                audit::emit_role_deny(user, role_id.as_str(), RoleDenyReason::NotCovered.as_str());
                Resolution::Denied {
                    reason: RoleDenyReason::NotCovered,
                }
            }
            RoleEnforce::Warn => {
                audit::emit_role_deny(user, role_id.as_str(), RoleDenyReason::NotCovered.as_str());
                Resolution::Allowed {
                    slice: Box::new(slice.clone()),
                    method: CoverageMethod::Cert,
                }
            }
            // Unreachable: Disabled handled above.
            RoleEnforce::Disabled => Resolution::Skipped,
        };
    }

    Resolution::Allowed {
        slice: Box::new(slice.clone()),
        method: CoverageMethod::Cert,
    }
}

/// Map a resolve/coverage failure to a [`Resolution`] honouring `enforce`,
/// emitting the `role_deny` audit event in every non-disabled mode.
fn deny_or_skip(
    enforce: RoleEnforce,
    reason: RoleDenyReason,
    user: &str,
    requested_role: &str,
) -> Resolution {
    match enforce {
        RoleEnforce::Require => {
            audit::emit_role_deny(user, requested_role, reason.as_str());
            Resolution::Denied { reason }
        }
        RoleEnforce::Warn => {
            audit::emit_role_deny(user, requested_role, reason.as_str());
            Resolution::Skipped
        }
        RoleEnforce::Disabled => Resolution::Skipped,
    }
}

/// A snapshot of a resolved role's session-relevant payload, taken at
/// session-open time. Holding a copy (not a store reference) is the design
/// guarantee that editing or deleting the role mid-session does not affect
/// the live session (it lives out its TTL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRolePayload {
    /// The role id this session was opened with.
    pub role: RoleId,
    /// The role slice version recorded for audit.
    pub role_version: u32,
    /// Bounded session TTL — never unbounded (design Decision 8).
    pub ttl: Duration,
    /// Astra МКЦ `mac_mask` requested by the role, parsed to a raw category
    /// bitmask (role-format). `None` when the role declares no `mac_mask`.
    /// Snapshotted here so the session-open MAC orchestrator can use it as the
    /// requested label without re-reading the store.
    pub mac_mask: Option<u64>,
}

/// Errors from fixing a session payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionFixError {
    /// The role payload needs an enforcement backend not present in this
    /// build (open build: `mac_mask` / `selinux`). Explicit deny — never a
    /// silent privilege narrowing (spec «не молчаливое сужение прав»).
    #[error("role payload needs an enforcement backend absent from this build")]
    BackendUnavailable,
}

impl SessionFixError {
    /// The audit deny reason this fix-error maps to.
    #[must_use]
    pub fn deny_reason(self) -> RoleDenyReason {
        match self {
            SessionFixError::BackendUnavailable => RoleDenyReason::BackendUnavailable,
        }
    }
}

/// Compute the bounded session TTL.
///
/// `TTL = min(cert TTL, role.session.max_ttl, global default)`, ignoring
/// the absent bounds. The global default is always present, so the result is
/// never unbounded (design Decision 8).
#[must_use]
pub fn bounded_ttl(
    cert_ttl: Option<Duration>,
    role_max_ttl: Option<Duration>,
    global_default: Duration,
) -> Duration {
    let mut ttl = global_default;
    if let Some(c) = cert_ttl {
        ttl = ttl.min(c);
    }
    if let Some(r) = role_max_ttl {
        ttl = ttl.min(r);
    }
    ttl
}

/// Whether this build can enforce the slice's payload.
///
/// Open build (no `astra-mac` feature, no `SELinux` adapter) cannot enforce a
/// `mac_mask` or a `selinux` context. Such a role MUST be denied explicitly
/// rather than have its privileges silently narrowed. A role whose payload
/// is fully covered by available backends (groups / sudo / limits) works in
/// the open build.
///
/// The `astra-mac` feature gates `mac_mask`. `SELinux` has no compile-time
/// feature in the open build, so `selinux` is always unavailable here; when
/// the commercial adapter lands it will relax this with its own gate.
#[must_use]
pub fn payload_backend_available(slice: &RoleSlice) -> bool {
    let Some(payload) = slice.payload.as_ref() else {
        return true;
    };
    if payload.mac_mask.is_some() && !cfg!(feature = "astra-mac") {
        return false;
    }
    if payload.selinux.is_some() {
        // SELinux enforcement is a commercial adapter; the open build parses
        // the section but cannot apply it. No compile-time feature exists in
        // open-core, so it is always unavailable here.
        return false;
    }
    true
}

impl SessionRolePayload {
    /// Snapshot the resolved slice into a session payload, computing the
    /// bounded TTL and refusing payloads that need an absent backend.
    ///
    /// # Errors
    ///
    /// [`SessionFixError::BackendUnavailable`] when the slice payload needs
    /// an enforcement backend this build does not provide.
    pub fn fix(
        slice: &RoleSlice,
        cert_ttl: Option<Duration>,
        global_default: Duration,
    ) -> Result<Self, SessionFixError> {
        if !payload_backend_available(slice) {
            return Err(SessionFixError::BackendUnavailable);
        }
        let role_max_ttl = slice.session.as_ref().and_then(super::schema::SessionLimits::max_ttl);
        let ttl = bounded_ttl(cert_ttl, role_max_ttl, global_default);
        // Snapshot the role's mac_mask as a raw bitmask. The slice has already
        // passed `validate_payload_for_os` (mac_mask only valid on astra and
        // parsed there), so `parse_mac_mask` cannot fail here; map any
        // defensive error to no mask rather than panicking.
        let mac_mask = slice
            .payload
            .as_ref()
            .and_then(|p| p.mac_mask.as_deref())
            .and_then(|s| super::schema::parse_mac_mask(s).ok());
        Ok(Self {
            role: slice.role.clone(),
            role_version: slice.version,
            ttl,
            mac_mask,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::missing_panics_doc,
        clippy::missing_docs_in_private_items,
        clippy::duration_suboptimal_units
    )]

    use super::*;
    use crate::role::schema::{parse_slice, RoleOs};
    use crate::role::store::TrustMode;
    use std::fs;
    use tempfile::TempDir;

    fn rid(s: &str) -> RoleId {
        RoleId::new(s).unwrap()
    }

    fn write(dir: &TempDir, role: &str, body: &str) {
        fs::write(dir.path().join(format!("{role}.toml")), body.as_bytes()).unwrap();
    }

    fn linux_groups_slice(role: &str) -> String {
        format!(
            "role = \"{role}\"\nversion = 4\nos = \"linux\"\nname = \"{role}\"\nlevel = 1\n\
             [payload]\ngroups = [\"wheel\"]\n"
        )
    }

    fn store_with(role: &str, body: &str) -> (TempDir, RoleStore) {
        let dir = tempfile::tempdir().unwrap();
        write(&dir, role, body);
        let store = RoleStore::load(dir.path(), RoleOs::Linux, TrustMode::Standalone).unwrap();
        (dir, store)
    }

    // ---- resolve_and_cover -------------------------------------------------

    #[test]
    fn disabled_always_skips_without_touching_store() {
        let store = RoleStore::default();
        let r = resolve_and_cover(&store, Some(&rid("serv")), None, RoleEnforce::Disabled, "ivanov");
        assert!(matches!(r, Resolution::Skipped));
    }

    #[test]
    fn require_resolved_and_covered_is_allowed() {
        let (_d, store) = store_with("serv", &linux_groups_slice("serv"));
        let allowed = vec![rid("oper"), rid("serv")];
        let r = resolve_and_cover(
            &store,
            Some(&rid("serv")),
            Some(&allowed),
            RoleEnforce::Require,
            "ivanov",
        );
        match r {
            Resolution::Allowed { slice, method } => {
                assert_eq!(slice.role.as_str(), "serv");
                assert_eq!(method, CoverageMethod::Cert);
            }
            other => panic!("expected Allowed, got {other:?}"),
        }
    }

    #[test]
    fn require_not_in_store_denies_not_found() {
        let (_d, store) = store_with("serv", &linux_groups_slice("serv"));
        let allowed = vec![rid("admin")];
        let r = resolve_and_cover(
            &store,
            Some(&rid("admin")),
            Some(&allowed),
            RoleEnforce::Require,
            "ivanov",
        );
        assert!(matches!(
            r,
            Resolution::Denied {
                reason: RoleDenyReason::NotFound
            }
        ));
    }

    #[test]
    fn require_not_covered_denies_not_covered() {
        // admin exists in store but cert allows only [oper, serv].
        let (_d, store) = store_with("admin", &linux_groups_slice("admin"));
        let allowed = vec![rid("oper"), rid("serv")];
        let r = resolve_and_cover(
            &store,
            Some(&rid("admin")),
            Some(&allowed),
            RoleEnforce::Require,
            "ivanov",
        );
        assert!(matches!(
            r,
            Resolution::Denied {
                reason: RoleDenyReason::NotCovered
            }
        ));
    }

    #[test]
    fn require_no_extension_is_not_covered() {
        let (_d, store) = store_with("serv", &linux_groups_slice("serv"));
        let r = resolve_and_cover(
            &store,
            Some(&rid("serv")),
            None,
            RoleEnforce::Require,
            "ivanov",
        );
        assert!(matches!(
            r,
            Resolution::Denied {
                reason: RoleDenyReason::NotCovered
            }
        ));
    }

    #[test]
    fn require_no_role_supplied_denies_syntax() {
        let store = RoleStore::default();
        let r = resolve_and_cover(&store, None, None, RoleEnforce::Require, "ivanov");
        assert!(matches!(
            r,
            Resolution::Denied {
                reason: RoleDenyReason::Syntax
            }
        ));
    }

    #[test]
    fn warn_not_covered_allows_but_resolves() {
        let (_d, store) = store_with("admin", &linux_groups_slice("admin"));
        let allowed = vec![rid("oper")];
        let r = resolve_and_cover(
            &store,
            Some(&rid("admin")),
            Some(&allowed),
            RoleEnforce::Warn,
            "ivanov",
        );
        // warn never denies: covered=false still yields Allowed with the slice.
        assert!(matches!(r, Resolution::Allowed { .. }));
    }

    #[test]
    fn warn_not_found_skips() {
        let store = RoleStore::default();
        let r = resolve_and_cover(
            &store,
            Some(&rid("ghost")),
            Some(&[]),
            RoleEnforce::Warn,
            "ivanov",
        );
        assert!(matches!(r, Resolution::Skipped));
    }

    // ---- bounded_ttl -------------------------------------------------------

    #[test]
    fn bounded_ttl_picks_minimum() {
        let g = Duration::from_secs(43200);
        // cert shortest
        assert_eq!(
            bounded_ttl(Some(Duration::from_secs(100)), Some(Duration::from_secs(200)), g),
            Duration::from_secs(100)
        );
        // role shortest
        assert_eq!(
            bounded_ttl(Some(Duration::from_secs(500)), Some(Duration::from_secs(200)), g),
            Duration::from_secs(200)
        );
        // global shortest
        assert_eq!(
            bounded_ttl(
                Some(Duration::from_secs(99999)),
                Some(Duration::from_secs(88888)),
                g
            ),
            g
        );
    }

    #[test]
    fn bounded_ttl_never_unbounded_without_cert_or_role() {
        let g = Duration::from_secs(43200);
        // No cert TTL, no role max_ttl → falls back to the global default.
        assert_eq!(bounded_ttl(None, None, g), g);
    }

    // ---- SessionRolePayload::fix ------------------------------------------

    #[test]
    fn fix_groups_only_role_ok_in_open_build() {
        let slice = parse_slice(
            linux_groups_slice("oper").as_bytes(),
            "oper",
            RoleOs::Linux,
        )
        .unwrap();
        let fixed = SessionRolePayload::fix(&slice, None, Duration::from_secs(43200)).unwrap();
        assert_eq!(fixed.role.as_str(), "oper");
        assert_eq!(fixed.role_version, 4);
        assert_eq!(fixed.ttl, Duration::from_secs(43200));
    }

    #[test]
    fn fix_mac_mask_role_denies_backend_unavailable_on_stub() {
        // mac_mask is an astra payload; open (stub) build cannot enforce it.
        let doc = "role = \"hi\"\nversion = 1\nos = \"astra\"\nname = \"hi\"\nlevel = 5\n\
                   [payload]\nmac_mask = \"0xff\"\n";
        let slice = parse_slice(doc.as_bytes(), "hi", RoleOs::Astra).unwrap();
        let res = SessionRolePayload::fix(&slice, None, Duration::from_secs(43200));
        // In the open build (no astra-mac feature) this denies; with the
        // feature it succeeds. Assert per build so the test holds either way.
        if cfg!(feature = "astra-mac") {
            let fixed = res.unwrap();
            assert_eq!(fixed.mac_mask, Some(0xff));
        } else {
            assert_eq!(res.unwrap_err(), SessionFixError::BackendUnavailable);
            assert_eq!(
                SessionFixError::BackendUnavailable.deny_reason(),
                RoleDenyReason::BackendUnavailable
            );
        }
    }

    #[test]
    fn fix_selinux_role_denies_backend_unavailable() {
        let doc = "role = \"se\"\nversion = 2\nos = \"linux\"\nname = \"se\"\nlevel = 1\n\
                   [payload.selinux]\nuser = \"staff_u\"\n";
        let slice = parse_slice(doc.as_bytes(), "se", RoleOs::Linux).unwrap();
        let res = SessionRolePayload::fix(&slice, None, Duration::from_secs(43200));
        assert_eq!(res.unwrap_err(), SessionFixError::BackendUnavailable);
    }

    #[test]
    fn fix_uses_role_max_ttl_when_shorter() {
        let doc = "role = \"oper\"\nversion = 1\nos = \"linux\"\nname = \"oper\"\nlevel = 1\n\
                   [session]\nmax_ttl_seconds = 600\n";
        let slice = parse_slice(doc.as_bytes(), "oper", RoleOs::Linux).unwrap();
        let fixed = SessionRolePayload::fix(
            &slice,
            Some(Duration::from_secs(5000)),
            Duration::from_secs(43200),
        )
        .unwrap();
        assert_eq!(fixed.ttl, Duration::from_secs(600));
    }

    #[test]
    fn deny_reason_wire_strings() {
        assert_eq!(RoleDenyReason::NotFound.as_str(), "not_found");
        assert_eq!(RoleDenyReason::NotCovered.as_str(), "not_covered");
        assert_eq!(RoleDenyReason::BackendUnavailable.as_str(), "backend_unavailable");
        assert_eq!(RoleDenyReason::MaskExceedsCeiling.as_str(), "mask_exceeds_ceiling");
        assert_eq!(RoleDenyReason::Syntax.as_str(), "syntax");
        assert_eq!(CoverageMethod::Cert.as_str(), "cert");
        assert_eq!(CoverageMethod::Code.as_str(), "code");
    }
}
