//! What the protocol layer is allowed to ask of the verification core.
//!
//! The trait exists so the connection handling can be driven — and tested —
//! without a volume, a credential, or Windows. The production implementation
//! lives in [`crate::windows::engine`]; it is the only thing in this crate that
//! touches the verification path, and it does so by calling the same
//! `authenticate_pkcs12` a Linux login goes through.

use tessera_proto::{Admission, Denial, DenialReason, RoleSummary, WireSecret};

/// Why the service could not produce an answer at all.
///
/// Distinct from a refusal: a refusal is an answer.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// Configuration could not be read or validated.
    #[error("configuration: {0}")]
    Config(String),
    /// The role store could not be loaded.
    #[error("role store: {0}")]
    RoleStore(String),
    /// Trust material named by the configuration could not be read or parsed.
    #[error("trust material: {0}")]
    Trust(String),
    /// The device's own identity could not be resolved.
    #[error("host identity: {0}")]
    HostIdentity(String),
    /// The journal could not be opened or written.
    #[error("journal: {0}")]
    Journal(String),
}

/// One authentication request as it arrives from a client.
///
/// The credential itself is absent by design: the client names a role and
/// supplies a PIN, and the service finds the media and reads the credential.
pub struct AuthRequest<'a> {
    /// Requested role id.
    pub role: &'a str,
    /// PIN protecting the credential on the media.
    pub pin: &'a WireSecret,
}

/// The verification core, as the protocol layer sees it.
pub trait AuthEngine: Send + Sync {
    /// The roles this device offers, ordered for display, without a default.
    ///
    /// # Errors
    ///
    /// [`EngineError`] when the store cannot be read — the client is told the
    /// service failed rather than shown an empty, and therefore misleading,
    /// list.
    fn list_roles(&self) -> Result<Vec<RoleSummary>, EngineError>;

    /// Reaches a verdict on the credential currently on removable media.
    ///
    /// # Errors
    ///
    /// [`Denial`] for every outcome that is not an admission, including the
    /// ones caused by the service's own state: a device that cannot verify
    /// refuses.
    fn authenticate(&self, request: &AuthRequest<'_>) -> Result<Admission, Denial>;
}

/// The coarse category a client is told, derived from the flow's own error.
///
/// The mapping is stated once, here, because it is the boundary between what
/// the journal records in full and what a person standing at the tile learns.
/// Anything that is not clearly about the media or about the role is reported
/// as a credential refusal: that is the arm that says the least.
#[must_use]
pub fn classify(error: &pam_tessera::flow::FlowError) -> DenialReason {
    use pam_tessera::flow::FlowError;

    match error {
        // No media, no credential on it, or media that vanished mid-read.
        FlowError::Usb(_) | FlowError::Discovery(_) | FlowError::Mount(_) => DenialReason::Media,
        // The credential is fine as far as the chain goes; what it is not is
        // authorised for this role.
        FlowError::RoleDenied(_) | FlowError::DelegationDenied(_) => DenialReason::Role,
        // The device could not carry out the check, or could not record the
        // result. Both are the service's fault and neither is a statement
        // about the credential.
        FlowError::Internal(_) | FlowError::MonitorRegistration(_) => DenialReason::Internal,
        _ => DenialReason::Credential,
    }
}

/// Builds the refusal sent to the client from the flow's error.
#[must_use]
pub fn denial_for(error: &pam_tessera::flow::FlowError) -> Denial {
    Denial {
        reason: classify(error),
        code: error.pam_code(),
    }
}

/// The refusal used when the service could not even start the check.
#[must_use]
pub fn internal_denial() -> Denial {
    Denial {
        reason: DenialReason::Internal,
        // PAM_SYSTEM_ERR: a broken internal invariant, which is what a service
        // that cannot read its own configuration is.
        code: 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pam_tessera::flow::FlowError;

    #[test]
    fn media_failures_are_reported_as_media() {
        let err = FlowError::Usb(tessera_core::usb::UsbError::Timeout);
        assert_eq!(classify(&err), DenialReason::Media);
        assert_eq!(denial_for(&err).code, 9);
    }

    #[test]
    fn role_failures_are_reported_as_role() {
        let err = FlowError::RoleDenied(tessera_core::role::RoleDenyReason::NotCovered);
        assert_eq!(classify(&err), DenialReason::Role);
        assert_eq!(denial_for(&err).code, 6);
    }

    /// An unrecorded session is the service's failure, and it must not read as
    /// a statement about the credential — the credential may well have been
    /// valid.
    #[test]
    fn an_unwritable_journal_is_reported_as_internal() {
        let err = FlowError::MonitorRegistration(tessera_core::error::IpcError::Unavailable);
        assert_eq!(classify(&err), DenialReason::Internal);
    }

    #[test]
    fn everything_else_is_reported_as_credential() {
        let err = FlowError::MaxTries;
        assert_eq!(classify(&err), DenialReason::Credential);
        assert_eq!(denial_for(&err).code, 11);
    }
}
