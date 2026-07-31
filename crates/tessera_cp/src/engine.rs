//! The engine service as the tile sees it.
//!
//! Everything the provider knows about the device comes through this trait: the
//! list of roles and the verdict on an authentication attempt. Verification
//! itself — the chain, the challenge, revocation, whether the role covers the
//! credential — happens on the other side, under `LocalSystem`, and the tile
//! learns only the outcome.
//!
//! The trait exists so that the tile's behaviour can be tested against scripted
//! answers; the implementation that talks to the real service over the named
//! pipe is [`crate::service::ServiceEngine`].

use zeroize::Zeroizing;

use crate::kerb::LogonTarget;
use crate::role::RoleChoice;

/// Why the tile could not get an answer out of the service.
///
/// Every variant leads to the same place — no serialization and a status line —
/// but they are distinguished so the log says which fail-closed path was taken.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum EngineError {
    /// The pipe could not be opened: the service is not running, or the caller
    /// is not allowed to talk to it.
    #[error("the engine service is unavailable")]
    Unavailable,
    /// The service speaks a protocol version this provider does not.
    #[error("the engine service speaks an incompatible protocol version")]
    ProtocolMismatch,
    /// The connection dropped part-way through an exchange.
    #[error("the connection to the engine service was lost")]
    Disconnected,
    /// A reply arrived that this provider cannot make sense of.
    #[error("the engine service sent a malformed reply")]
    Malformed,
    /// The service answered, and what it answered was an error.
    #[error("the engine service reported error {code}")]
    Service {
        /// Numeric code from the protocol's shared table.
        code: u32,
    },
    /// The service did not answer within the deadline.
    ///
    /// Separate from [`Self::Unavailable`] because the two are different
    /// operational failures: nothing listening, versus something listening and
    /// stuck. Both are fail-closed, and neither depends on the credential, so
    /// telling them apart on screen reveals nothing about it.
    #[error("the engine service did not answer in time")]
    Timeout,
}

/// What the tile sends the service to be authenticated.
///
/// The PIN is [`Zeroizing`] so that dropping the request wipes it; the request
/// is deliberately consumed by [`EngineClient::authenticate`] so that the drop
/// happens as soon as the exchange is over.
#[derive(Debug)]
pub struct AuthRequest {
    /// Identifier of the role the engineer picked.
    pub role_id: String,
    /// PIN of the credential on the removable medium.
    pub pin: Zeroizing<String>,
}

/// Why the service refused.
///
/// These are the wire's categories, not finer ones: the service coarsens the
/// cause before it leaves the trusted half of the machine. The tile coarsens
/// further still and shows one message for all of them — an engineer at the
/// console who can tell "wrong PIN" from "certificate revoked" from "role not
/// covered" has been handed an oracle. The distinction survives only into the
/// log, so that this side's record agrees with the service's journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenialCode {
    /// No usable medium appeared, or none carried a credential.
    Media,
    /// A credential was found and did not pass verification.
    Credential,
    /// The credential does not cover the requested role, or the device does not
    /// offer that role.
    Role,
    /// The service could not reach a verdict at all — fail-closed.
    Internal,
}

/// A grant, with everything the tile needs to serialise a logon and nothing
/// else.
///
/// The secret is the technical account's password. It lives for exactly as long
/// as the serialization takes: `Zeroizing` wipes it on drop, and the state
/// machine drops it as soon as the block is packed.
#[derive(Debug)]
pub struct Grant {
    /// Account the serialized credentials name.
    pub account: LogonTarget,
    /// The account's password, handed over for this logon only.
    pub secret: Zeroizing<String>,
    /// Correlation id of the service's journal entry for this admission.
    ///
    /// Carried so that a logon seen at the tile can be matched with the record
    /// the service wrote. It is not a secret and never reaches the screen.
    pub session_id: String,
}

/// The service's answer to an authentication request.
#[derive(Debug)]
pub enum Verdict {
    /// Access granted.
    Granted(Grant),
    /// Access refused.
    Denied(DenialCode),
}

/// The engine service, as far as the credential provider is concerned.
pub trait EngineClient {
    /// Asks for the roles this device offers.
    ///
    /// # Errors
    ///
    /// Any failure to reach or understand the service; the tile treats them all
    /// as "no roles", which leaves the combo box disabled.
    fn list_roles(&self) -> Result<Vec<RoleChoice>, EngineError>;

    /// Submits an authentication attempt and waits for the verdict.
    ///
    /// # Errors
    ///
    /// Any failure to reach or understand the service. A refusal is *not* an
    /// error — it is [`Verdict::Denied`], because the exchange succeeded.
    fn authenticate(&self, request: AuthRequest) -> Result<Verdict, EngineError>;
}

/// A borrowed client is a client.
///
/// Lets a caller keep the client — to inspect what it was asked, or to share
/// one connection between tiles — while the tile still owns "an engine".
impl<T: EngineClient + ?Sized> EngineClient for &T {
    fn list_roles(&self) -> Result<Vec<RoleChoice>, EngineError> {
        (**self).list_roles()
    }

    fn authenticate(&self, request: AuthRequest) -> Result<Verdict, EngineError> {
        (**self).authenticate(request)
    }
}
