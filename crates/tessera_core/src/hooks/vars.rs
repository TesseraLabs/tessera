//! Resolved hook variables.
//!
//! A [`HookVars`] is the runtime counterpart of [`crate::hooks::PlaceholderVar`]:
//! it carries the values that the parent process will substitute into hook
//! command-line and environment templates **before** `fork`. Each field is an
//! `Option` because at `pre_auth` stage some values (certificate / USB / session)
//! are not yet known.
//!
//! Cert binding (which user on which host) is verified separately via the
//! cert's `pam_cert_user_binding` / `pam_cert_host_binding` extensions and
//! is not surfaced as a hook variable.

use crate::hooks::placeholder::PlaceholderVar;
use crate::hooks::stage::HookStage;
use crate::pam_data::AuthContext;

/// Runtime values for hook placeholder substitution.
///
/// Construct with [`HookVars::empty`] then chain `with_*` builders, or
/// build directly with the public fields.
#[derive(Debug, Clone, Default)]
pub struct HookVars {
    /// Hook stage that the executor is about to run.
    pub stage: HookStage,
    /// `PAM_USER` value.
    pub pam_user: Option<String>,
    /// `PAM_SERVICE` value.
    pub pam_service: Option<String>,
    /// Resolved host identity.
    pub host_id: Option<String>,
    /// Hex SHA-256 of `host_id`.
    pub host_id_hash: Option<String>,
    /// Source kind name for the host identity (e.g. `dmi:product_uuid`).
    pub host_id_source: Option<String>,
    /// Verified certificate Common Name.
    pub cert_cn: Option<String>,
    /// Verified certificate serial (hex).
    pub cert_serial: Option<String>,
    /// USB token serial number.
    pub usb_serial: Option<String>,
    /// USB VID/PID string in `vvvv:pppp` form.
    pub usb_vid_pid: Option<String>,
    /// Per-auth session id.
    pub session_id: Option<String>,
}

impl HookVars {
    /// Empty `HookVars` with all fields `None`. Stage defaults to `PreAuth`.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Set the hook stage.
    #[must_use]
    pub fn with_stage(mut self, stage: HookStage) -> Self {
        self.stage = stage;
        self
    }

    /// Set the PAM user.
    #[must_use]
    pub fn with_pam_user(mut self, value: impl Into<String>) -> Self {
        self.pam_user = Some(value.into());
        self
    }

    /// Set the PAM service.
    #[must_use]
    pub fn with_pam_service(mut self, value: impl Into<String>) -> Self {
        self.pam_service = Some(value.into());
        self
    }

    /// Set the host identity.
    #[must_use]
    pub fn with_host_id(mut self, value: impl Into<String>) -> Self {
        self.host_id = Some(value.into());
        self
    }

    /// Set the host identity hash.
    #[must_use]
    pub fn with_host_id_hash(mut self, value: impl Into<String>) -> Self {
        self.host_id_hash = Some(value.into());
        self
    }

    /// Set the host identity source label.
    #[must_use]
    pub fn with_host_id_source(mut self, value: impl Into<String>) -> Self {
        self.host_id_source = Some(value.into());
        self
    }

    /// Set the certificate CN.
    #[must_use]
    pub fn with_cert_cn(mut self, value: impl Into<String>) -> Self {
        self.cert_cn = Some(value.into());
        self
    }

    /// Set the certificate serial.
    #[must_use]
    pub fn with_cert_serial(mut self, value: impl Into<String>) -> Self {
        self.cert_serial = Some(value.into());
        self
    }

    /// Set the USB serial.
    #[must_use]
    pub fn with_usb_serial(mut self, value: impl Into<String>) -> Self {
        self.usb_serial = Some(value.into());
        self
    }

    /// Set the USB VID/PID.
    #[must_use]
    pub fn with_usb_vid_pid(mut self, value: impl Into<String>) -> Self {
        self.usb_vid_pid = Some(value.into());
        self
    }

    /// Set the session id.
    #[must_use]
    pub fn with_session_id(mut self, value: impl Into<String>) -> Self {
        self.session_id = Some(value.into());
        self
    }

    /// Builder for `pre_auth` stage: only PAM identity + host identity are
    /// known yet; cert / USB / session fields stay `None`.
    #[must_use]
    pub fn for_pre_auth(
        pam_user: &str,
        pam_service: &str,
        host_id: &str,
        host_id_hash: &str,
        host_id_source: impl Into<String>,
    ) -> Self {
        Self::empty()
            .with_stage(HookStage::PreAuth)
            .with_pam_user(pam_user)
            .with_pam_service(pam_service)
            .with_host_id(host_id)
            .with_host_id_hash(host_id_hash)
            .with_host_id_source(host_id_source)
    }

    /// Builder for `post_auth_success` stage: every field except `usb_*` /
    /// `cert_*` may be populated by the caller; pass through everything from
    /// the `AuthContext` we'd otherwise build right after.
    #[must_use]
    pub fn for_post_auth_success(pam_user: &str, ctx: &AuthContext) -> Self {
        Self::for_session_like(HookStage::PostAuthSuccess, pam_user, ctx)
    }

    /// Builder for `session_open` stage. Pulls everything from the stored
    /// [`AuthContext`].
    #[must_use]
    pub fn for_session_open(pam_user: &str, ctx: &AuthContext) -> Self {
        Self::for_session_like(HookStage::SessionOpen, pam_user, ctx)
    }

    /// Builder for `session_close` stage. Pulls everything from the stored
    /// [`AuthContext`].
    #[must_use]
    pub fn for_session_close(pam_user: &str, ctx: &AuthContext) -> Self {
        Self::for_session_like(HookStage::SessionClose, pam_user, ctx)
    }

    fn for_session_like(stage: HookStage, pam_user: &str, ctx: &AuthContext) -> Self {
        let mut v = Self::empty()
            .with_stage(stage)
            .with_pam_user(pam_user)
            .with_pam_service(&ctx.pam_service)
            .with_host_id(&ctx.host_id)
            .with_host_id_hash(&ctx.host_id)
            .with_host_id_source(ctx.host_id_source.to_string())
            .with_session_id(&ctx.session_id);
        if let Some(cn) = ctx.cert_cn.as_deref() {
            v = v.with_cert_cn(cn);
        }
        if let Some(s) = ctx.cert_serial.as_deref() {
            v = v.with_cert_serial(s);
        }
        if let Some(s) = ctx.usb_serial.as_deref() {
            v = v.with_usb_serial(s);
        }
        if let Some(s) = ctx.usb_vid_pid.as_deref() {
            v = v.with_usb_vid_pid(s);
        }
        v
    }

    /// Resolve a [`PlaceholderVar`] to the matching field.
    ///
    /// Returns `Some(&str)` when the field has been populated and `None`
    /// otherwise. Stage-time validity (whether the placeholder is allowed at
    /// the hook's stage) is enforced earlier in
    /// [`crate::hooks::validator::validate_hook`]; runtime `None` simply means
    /// the PAM caller did not supply the value, and the executor must surface
    /// it as a hook setup error rather than silently substituting an empty
    /// string.
    #[must_use]
    pub fn resolve(&self, var: PlaceholderVar) -> Option<&str> {
        match var {
            PlaceholderVar::PamUser => self.pam_user.as_deref(),
            PlaceholderVar::PamService => self.pam_service.as_deref(),
            PlaceholderVar::HostId => self.host_id.as_deref(),
            PlaceholderVar::HostIdHash => self.host_id_hash.as_deref(),
            PlaceholderVar::HostIdSource => self.host_id_source.as_deref(),
            PlaceholderVar::CertCn => self.cert_cn.as_deref(),
            PlaceholderVar::CertSerial => self.cert_serial.as_deref(),
            PlaceholderVar::UsbSerial => self.usb_serial.as_deref(),
            PlaceholderVar::UsbVidPid => self.usb_vid_pid.as_deref(),
            PlaceholderVar::SessionId => self.session_id.as_deref(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn empty_has_all_none() {
        let v = HookVars::empty();
        assert_eq!(v.stage, HookStage::PreAuth);
        assert!(v.pam_user.is_none());
        assert!(v.pam_service.is_none());
        assert!(v.host_id.is_none());
        assert!(v.host_id_hash.is_none());
        assert!(v.host_id_source.is_none());
        assert!(v.cert_cn.is_none());
        assert!(v.cert_serial.is_none());
        assert!(v.usb_serial.is_none());
        assert!(v.usb_vid_pid.is_none());
        assert!(v.session_id.is_none());
    }

    #[test]
    fn builder_sets_fields() {
        let v = HookVars::empty()
            .with_stage(HookStage::PostAuthSuccess)
            .with_pam_user("alice")
            .with_pam_service("login")
            .with_host_id("hid")
            .with_host_id_hash("hidhash")
            .with_host_id_source("dmi")
            .with_cert_cn("Alice CN")
            .with_cert_serial("0xDEAD")
            .with_usb_serial("USB-123")
            .with_usb_vid_pid("0951:1666")
            .with_session_id("sid-1");
        assert_eq!(v.stage, HookStage::PostAuthSuccess);
        assert_eq!(v.pam_user.as_deref(), Some("alice"));
        assert_eq!(v.pam_service.as_deref(), Some("login"));
        assert_eq!(v.host_id.as_deref(), Some("hid"));
        assert_eq!(v.host_id_hash.as_deref(), Some("hidhash"));
        assert_eq!(v.host_id_source.as_deref(), Some("dmi"));
        assert_eq!(v.cert_cn.as_deref(), Some("Alice CN"));
        assert_eq!(v.cert_serial.as_deref(), Some("0xDEAD"));
        assert_eq!(v.usb_serial.as_deref(), Some("USB-123"));
        assert_eq!(v.usb_vid_pid.as_deref(), Some("0951:1666"));
        assert_eq!(v.session_id.as_deref(), Some("sid-1"));
    }

    #[test]
    fn resolve_returns_correct_field_for_every_variant() {
        let v = HookVars::empty()
            .with_pam_user("u")
            .with_pam_service("s")
            .with_host_id("hid")
            .with_host_id_hash("hh")
            .with_host_id_source("hs")
            .with_cert_cn("cn")
            .with_cert_serial("ser")
            .with_usb_serial("us")
            .with_usb_vid_pid("v:p")
            .with_session_id("sid");

        assert_eq!(v.resolve(PlaceholderVar::PamUser), Some("u"));
        assert_eq!(v.resolve(PlaceholderVar::PamService), Some("s"));
        assert_eq!(v.resolve(PlaceholderVar::HostId), Some("hid"));
        assert_eq!(v.resolve(PlaceholderVar::HostIdHash), Some("hh"));
        assert_eq!(v.resolve(PlaceholderVar::HostIdSource), Some("hs"));
        assert_eq!(v.resolve(PlaceholderVar::CertCn), Some("cn"));
        assert_eq!(v.resolve(PlaceholderVar::CertSerial), Some("ser"));
        assert_eq!(v.resolve(PlaceholderVar::UsbSerial), Some("us"));
        assert_eq!(v.resolve(PlaceholderVar::UsbVidPid), Some("v:p"));
        assert_eq!(v.resolve(PlaceholderVar::SessionId), Some("sid"));
    }

    #[test]
    fn for_pre_auth_sets_stage_and_pam_host_fields_only() {
        let v = HookVars::for_pre_auth("alice", "ssh", "host-id", "hidhash", "override");
        assert_eq!(v.stage, HookStage::PreAuth);
        assert_eq!(v.pam_user.as_deref(), Some("alice"));
        assert_eq!(v.pam_service.as_deref(), Some("ssh"));
        assert_eq!(v.host_id.as_deref(), Some("host-id"));
        assert_eq!(v.host_id_hash.as_deref(), Some("hidhash"));
        assert_eq!(v.host_id_source.as_deref(), Some("override"));
        assert!(v.cert_cn.is_none());
        assert!(v.usb_serial.is_none());
        assert!(v.session_id.is_none());
    }

    #[test]
    fn for_session_open_pulls_full_context() {
        use crate::host_identity::HostIdSourceKind;
        use crate::pam_data::AuthContext;
        let ctx = AuthContext {
            session_id: "sid-1".into(),
            cert_cn: Some("alice".into()),
            cert_serial: Some("01ab".into()),
            usb_serial: Some("USB-9".into()),
            usb_vid_pid: Some("0951:1666".into()),
            pam_service: "ssh".into(),
            host_id: "h-id".into(),
            host_id_source: HostIdSourceKind::Override,
            authenticated_at: std::time::SystemTime::UNIX_EPOCH,
            cert_not_after: None,
            clock_skew_seconds: 0,
            cert_max_integrity: None,
            cert_ident: None,
            home_dir: None,
        };
        let v = HookVars::for_session_open("alice", &ctx);
        assert_eq!(v.stage, HookStage::SessionOpen);
        assert_eq!(v.pam_user.as_deref(), Some("alice"));
        assert_eq!(v.pam_service.as_deref(), Some("ssh"));
        assert_eq!(v.session_id.as_deref(), Some("sid-1"));
        assert_eq!(v.cert_cn.as_deref(), Some("alice"));
        assert_eq!(v.usb_serial.as_deref(), Some("USB-9"));
        assert_eq!(v.usb_vid_pid.as_deref(), Some("0951:1666"));
        assert_eq!(v.host_id_source.as_deref(), Some("override"));
    }

    #[test]
    fn for_session_close_uses_session_close_stage() {
        use crate::host_identity::HostIdSourceKind;
        use crate::pam_data::AuthContext;
        let ctx = AuthContext::new("sid".into(), "ssh".into());
        let _ = HostIdSourceKind::Override; // explicit dep
        let v = HookVars::for_session_close("bob", &ctx);
        assert_eq!(v.stage, HookStage::SessionClose);
        assert_eq!(v.pam_user.as_deref(), Some("bob"));
    }

    #[test]
    fn for_post_auth_success_uses_post_stage() {
        use crate::pam_data::AuthContext;
        let ctx = AuthContext::new("sid".into(), "ssh".into());
        let v = HookVars::for_post_auth_success("carol", &ctx);
        assert_eq!(v.stage, HookStage::PostAuthSuccess);
        assert_eq!(v.pam_user.as_deref(), Some("carol"));
    }

    #[test]
    fn resolve_returns_none_when_field_absent() {
        // pre_auth stage has no cert_cn yet — runtime resolution is None
        // even though the validator wouldn't allow a pre_auth template that
        // references cert_cn in the first place.
        let v = HookVars::empty().with_pam_user("u");
        assert!(v.resolve(PlaceholderVar::CertCn).is_none());
        assert!(v.resolve(PlaceholderVar::SessionId).is_none());
    }
}
