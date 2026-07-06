//! `libpam_tessera.so` PAM service module.
#![deny(missing_docs)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod di;
pub mod entry;
pub mod flow;
pub mod logging;
pub mod pam_args;
pub mod panic_guard;
pub mod role_selection;
pub mod session;
pub mod xdg_capture;

#[cfg(target_os = "linux")]
pub mod data_handle;

#[cfg(target_os = "linux")]
pub mod pam_conv;

#[cfg(target_os = "linux")]
pub mod pam_helpers;

pub use host_identity::resolve_host_identity;

mod host_identity {
    //! Resolve the active host identity from a validated config.
    //!
    //! Wraps [`tessera_core::host_identity::HostIdentityResolver`] so
    //! the cdylib entry can pull the resolved tuple in one call.

    use std::fmt::Write as _;
    use std::path::PathBuf;

    use sha2::{Digest, Sha256};
    use tessera_core::config::ValidatedConfig;
    use tessera_core::error::HostIdentityError;
    use tessera_core::host_identity::{HostIdSourceKind, HostIdentityResolver};

    /// Resolved host identity tuple consumed by the auth flow:
    /// `(source kind, raw value, hex-encoded sha256 hash)`.
    pub type ResolvedTuple = (HostIdSourceKind, String, String);

    /// Resolve the active host identity from a validated config.
    ///
    /// Honours the configured `override` value first (when the config
    /// includes `Override` in its sources) so test/dev hosts can pin a
    /// deterministic value.  Otherwise delegates to
    /// [`HostIdentityResolver`].
    ///
    /// # Errors
    ///
    /// Returns [`HostIdentityError`] when every configured source fails
    /// and the configured fallback is `Deny`.
    pub fn resolve_host_identity(
        cfg: &ValidatedConfig,
    ) -> Result<ResolvedTuple, HostIdentityError> {
        if cfg
            .host_identity
            .sources
            .contains(&HostIdSourceKind::Override)
        {
            if let Some(raw) = cfg.host_identity.override_value.clone() {
                return Ok(hash_tuple(HostIdSourceKind::Override, raw));
            }
        }
        let chain = HostIdentityResolver::from_validated(&cfg.host_identity, PathBuf::from("/"));
        // Probe every configured source first and emit one INFO line per
        // source so the syslog has the full picture of which sources
        // answered and which failed. This is what admins eyeball on the
        // device to register a fresh box into the registry, instead of
        // running `sha256sum /etc/machine-id` by hand. `probe_all` does
        // NOT influence selection — `resolve()` still keeps its
        // first-working-wins policy.
        for probe in chain.probe_all() {
            match &probe.outcome {
                Ok(r) => tracing::info!(
                    target: "tessera.host_identity",
                    source = ?probe.source,
                    raw = %r.raw,
                    host_id_hash_prefix = %r.hash_prefix(),
                    host_id_hash = %r.hash_hex,
                    "host_identity: probe ok"
                ),
                Err(reason) => tracing::info!(
                    target: "tessera.host_identity",
                    source = ?probe.source,
                    error = %reason,
                    "host_identity: probe error"
                ),
            }
        }
        let id = chain.resolve()?;
        tracing::info!(
            target: "tessera.host_identity",
            source = ?id.source_kind,
            host_id_hash_prefix = %id.hash_prefix(),
            "host_identity: probe selected (first successful)"
        );
        Ok((id.source_kind, id.raw, id.hash_hex))
    }

    fn hash_tuple(kind: HostIdSourceKind, raw: String) -> ResolvedTuple {
        let normalized: String = tessera_core::host_identity::normalize_host_id(&raw);
        let hash = Sha256::digest(normalized.as_bytes());
        let mut hex = String::with_capacity(64);
        for byte in hash {
            // Запись в `String` инфаллибельна; результат намеренно игнорируем.
            let _write = write!(hex, "{byte:02x}");
        }
        (kind, raw, hex)
    }
}

use std::time::{Duration, SystemTime};
use tessera_core::pam_data::AuthContext;

/// PAM `pam_sm_acct_mgmt` core, decoupled from the PAM handle for testing.
///
/// Returns:
///
/// - `PAM_ACCT_EXPIRED` (`13`) if the certificate's `notAfter` (captured at
///   `pam_sm_authenticate` time and stored in [`AuthContext::cert_not_after`])
///   plus the `[trust].clock_skew_seconds` tolerance (captured at the same
///   moment in [`AuthContext::clock_skew_seconds`]) is before `now`.
/// - `PAM_SUCCESS` (`0`) otherwise.
#[must_use]
pub fn acct_mgmt_core(ctx: &AuthContext, now: SystemTime) -> i32 {
    if let Some(na) = ctx.cert_not_after {
        let skew = Duration::from_secs(ctx.clock_skew_seconds);
        // `notAfter` near the upper bound of `SystemTime` can overflow on
        // `+ skew` (which panics); a deadline past that bound is infinitely
        // far in the future, so overflow means "not expired".
        match na.checked_add(skew) {
            Some(deadline) if now > deadline => return PAM_ACCT_EXPIRED,
            _ => {}
        }
    }
    panic_guard::PAM_SUCCESS
}

/// `PAM_ACCT_EXPIRED` literal — kept here so we don't pull `pam-sys` into the
/// non-Linux build.
pub const PAM_ACCT_EXPIRED: i32 = 13;

/// `PAM_AUTHINFO_UNAVAIL` re-export.
pub const PAM_AUTHINFO_UNAVAIL: i32 = panic_guard::PAM_AUTHINFO_UNAVAIL;

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::duration_suboptimal_units
)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tessera_core::host_identity::HostIdSourceKind;

    fn ctx_with_not_after(not_after: Option<SystemTime>) -> AuthContext {
        ctx_with_skew(not_after, 0)
    }

    fn ctx_with_skew(not_after: Option<SystemTime>, clock_skew_seconds: u64) -> AuthContext {
        AuthContext {
            session_id: "sess-acct".to_string(),
            cert_cn: Some("alice".into()),
            cert_serial: Some("01".into()),
            usb_serial: None,
            usb_vid_pid: None,
            pam_service: "ssh".into(),
            host_id: "h".into(),
            host_id_source: HostIdSourceKind::Override,
            authenticated_at: SystemTime::UNIX_EPOCH,
            cert_not_after: not_after,
            clock_skew_seconds,
            cert_max_integrity: None,
            cert_ident: None,
            home_dir: None,
            role: None,
        }
    }

    #[test]
    fn acct_mgmt_returns_success_when_not_after_is_in_future() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let ctx = ctx_with_not_after(Some(now + Duration::from_secs(60)));
        assert_eq!(acct_mgmt_core(&ctx, now), panic_guard::PAM_SUCCESS);
    }

    #[test]
    fn acct_mgmt_returns_expired_when_not_after_is_in_past() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let ctx = ctx_with_not_after(Some(now - Duration::from_secs(60)));
        assert_eq!(acct_mgmt_core(&ctx, now), PAM_ACCT_EXPIRED);
    }

    #[test]
    fn acct_mgmt_returns_success_when_not_after_unset() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let ctx = ctx_with_not_after(None);
        assert_eq!(acct_mgmt_core(&ctx, now), panic_guard::PAM_SUCCESS);
    }

    #[test]
    fn acct_mgmt_returns_success_when_expired_within_clock_skew() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        // Expired 30s ago, but the 60s skew tolerance still covers it.
        let ctx = ctx_with_skew(Some(now - Duration::from_secs(30)), 60);
        assert_eq!(acct_mgmt_core(&ctx, now), panic_guard::PAM_SUCCESS);
    }

    #[test]
    fn acct_mgmt_returns_expired_when_past_clock_skew() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        // Expired 61s ago — one second beyond the 60s skew tolerance.
        let ctx = ctx_with_skew(Some(now - Duration::from_secs(61)), 60);
        assert_eq!(acct_mgmt_core(&ctx, now), PAM_ACCT_EXPIRED);
    }
}
