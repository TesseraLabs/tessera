//! PAM auth context stored by the cdylib.

use std::path::PathBuf;
use std::time::SystemTime;

use crate::host_identity::HostIdSourceKind;
use crate::mac::IntegrityLabel;
use crate::x509::CertIdent;

/// Authentication context stored in PAM data.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Session id.
    pub session_id: String,
    /// Certificate CN.
    pub cert_cn: Option<String>,
    /// Certificate serial.
    pub cert_serial: Option<String>,
    /// USB serial.
    pub usb_serial: Option<String>,
    /// USB VID/PID.
    pub usb_vid_pid: Option<String>,
    /// PAM service.
    pub pam_service: String,
    /// Host id.
    pub host_id: String,
    /// Host id source.
    pub host_id_source: HostIdSourceKind,
    /// Authentication timestamp.
    pub authenticated_at: SystemTime,
    /// Certificate `notAfter`, captured at authenticate time so that
    /// [`pam_sm_acct_mgmt`] can re-check expiry without re-loading the cert.
    pub cert_not_after: Option<SystemTime>,
    /// `MAX_INTEGRITY` extension parsed from the leaf, or `None` if the
    /// cert carries no such extension.  Consumed by the MAC orchestrator
    /// at session-open time.
    pub cert_max_integrity: Option<IntegrityLabel>,
    /// Cert identifiers (serial, issuer, CN, fingerprint) captured at
    /// authenticate time so audit events in `pam_sm_open_session` do
    /// not need to re-parse the leaf.
    pub cert_ident: Option<CertIdent>,
    /// Resolved `$HOME` of the PAM user at authenticate time, used by
    /// the MAC orchestrator's home-label advisory.  Optional because
    /// some PAM services run without a recognised passwd entry.
    pub home_dir: Option<PathBuf>,
}

impl AuthContext {
    /// Create a Stage 1 default context.
    pub fn new(session_id: String, pam_service: String) -> Self {
        Self {
            session_id,
            cert_cn: None,
            cert_serial: None,
            usb_serial: None,
            usb_vid_pid: None,
            pam_service,
            host_id: String::new(),
            host_id_source: HostIdSourceKind::Override,
            authenticated_at: SystemTime::now(),
            cert_not_after: None,
            cert_max_integrity: None,
            cert_ident: None,
            home_dir: None,
        }
    }
}
