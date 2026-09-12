//! Login by a one-time code dictated over the telephone (mode 0).
//!
//! The engineer stands at a device nobody can reach over a network. The device
//! prints a challenge, the engineer reads it to an operator, the operator
//! computes a code in their cabinet and reads it back, the device checks it
//! locally. This module is the PAM half of that conversation: it decides which
//! level is being asked for, drives the prompts, and turns the verdict of
//! [`tessera_core::codes`] into a PAM return code.
//!
//! # What lives here and what does not
//!
//! Nothing cryptographic. The nonce, the ticket checks, the key agreement, the
//! code itself and the one-time state all belong to [`tessera_core::codes`],
//! which in turn computes nothing of its own — every byte both sides agree on
//! comes from `tessera_codes_contract`. What is decided here is the order of
//! the prompts, the bounds on what a person may type, the МКЦ level, the
//! ceiling the session label is computed against, and the mapping onto the
//! codes an application waiting on PAM will act on.
//!
//! # The order of the conversation
//!
//! 1. The integrity level of the session is established from the source the OS
//!    adapter names: the label of the running process where a mandatory
//!    mechanism is declared, the base level where none is. A level that cannot
//!    be established ends the attempt — see [`crate::codes_level`].
//! 2. The login account is checked for being a role account at all, before any
//!    artefact is touched.
//! 3. The operator is named and the challenge is printed. Nothing is asked
//!    about the key container: the device opens its own key.
//! 4. The code is asked for, and asked for again after a wrong one, up to the
//!    attempt budget the fleet parameters set for one nonce.
//! 5. The level is read a **second** time and compared with the level the code
//!    was computed over. A session that changed level while the two sides were
//!    on the telephone is refused; see [`toctou`](self#the-second-read).
//!
//! # The second read
//!
//! The level enters the challenge, so the code proves that an operator holding
//! an admitting ticket authorised *that* level. Between printing the challenge
//! and returning success there is a window in which the label of the process
//! can change, and a success returned after it would apply a code granted for
//! one level to a session running at another. The second read closes it: the
//! two readings must agree, or the login fails.

use std::time::{Duration, SystemTime};

use secrecy::SecretString;

use tessera_codes_contract::canon::Level;
use tessera_codes_contract::time::ClaimedTime;
use tessera_core::audit::AuditError;
use tessera_core::codes::boot::BootMarkers;
use tessera_core::codes::{
    audit, Accepted, AttemptRequest, CodeLoginError, CodeMethod, CodesConfig, LocalRoles,
};
use tessera_core::error::IpcError;
use tessera_core::host_identity::HostIdSourceKind;
use tessera_core::ipc::{MonitorClient, MonitorFailMode, OpenSessionInfo};
use tessera_core::mac::IntegrityLabel;
use tessera_core::pam_conv::PamConvError;
use tessera_core::pam_data::AuthContext;
use tessera_core::role::{AccountCheck, RoleDenyReason, RoleStore, SessionRolePayload};

use crate::codes_level::{LevelError, LevelSource};

/// Longest identifier of an issuing side a person may type, in BYTES.
///
/// Taken from the contract rather than chosen here: it is the width the payload
/// budget reserves for this field, and a prompt that accepted more would take a
/// value the challenge then refuses — or, before the contract enforced it, draw
/// a QR nobody can scan. Counted in bytes for the same reason the contract
/// counts them: sixty-four Cyrillic letters are a hundred and twenty-eight
/// bytes.
const MAX_SERVER_ID_LEN: usize = tessera_codes_contract::challenge::MAX_SERVER_ID_BYTES;

/// Longest personal number of an engineer a person may type, in bytes.
const MAX_ENGINEER_ID_LEN: usize = tessera_codes_contract::challenge::MAX_ENGINEER_ID_BYTES;

/// Longest code a person may type.
///
/// The contract caps a code well below this; the bound is here so that a
/// conversation driver which does not bound its own answers cannot hand the
/// verification an arbitrarily long string.
const MAX_CODE_LEN: usize = 64;

/// Refusal detail: the integrity level of the session could not be read.
const REASON_LEVEL_UNREADABLE: &str = "level_unreadable";

/// Refusal detail: the level changed between the challenge and the verdict.
const REASON_LEVEL_CHANGED: &str = "level_changed";

/// Refusal detail: the login account is not a role account of this device.
const REASON_ROLE_ACCOUNT: &str = "role_account";

/// Refusal detail: the boot markers of the device could not be read.
const REASON_BOOT_MARKERS: &str = "boot_markers";

/// Refusal detail: an answer to a prompt was empty or over the bound.
const REASON_INPUT: &str = "input";

/// Refusal detail: the payload does not fit a symbol a camera can read.
///
/// A fleet reaches this by publishing an address long enough to push the URL
/// past the budget of the payload, and the answer is a refusal at the device
/// rather than a QR nobody can scan.
const REASON_QR: &str = "qr_payload_too_long";

/// Refusal detail: the personal number is not one.
///
/// Kept apart from the general input refusal because the two are acted on
/// differently by whoever reads the journal: one says a value was too long or
/// carried a separator of the wire form, this one says a number did not meet
/// its own check character, and only the second points at a person retyping
/// something off a note.
const REASON_ENGINEER_NUMBER: &str = "engineer_number_malformed";

/// How many times an empty answer to a visible prompt of THIS branch is asked
/// for again.
///
/// The prompts this governs are the issuing side and the personal number.
/// The account name is not among them and never asks twice: the second visible
/// prompt of the greeter's channel receives its password field, and a name
/// asked for again would be that password — see `entry::resolve_login_account`.
/// These two are different: they are not identity, they are checked against the
/// contract of the channel before anything is done with them, and a value that
/// is merely wrong is refused rather than recorded.
///
/// One, and both halves of that are deliberate.
///
/// Asking again at all: the standard greeter of the target fleet answers the
/// second prompt of a conversation with the contents of its password field,
/// which on this method nobody fills — so the answer to the first visible
/// prompt arrives empty through no fault of the person at the device. From the
/// third prompt onwards the greeter draws the module's own text, and the
/// repeat reaches them.
///
/// Not asking forever: a channel that returns an empty string for every prompt
/// exists too, and a login that keeps asking holds the attempt lock open with
/// nothing to show for it. A non-empty answer that is wrong is refused as
/// before — this is about an answer nobody gave, not about a bad one.
pub(crate) const EMPTY_ANSWER_RETRIES: usize = 1;

/// Prompt naming the issuing side this attempt is addressed to.
const SERVER_PROMPT: &str = "Сервер выдачи: ";

/// Prompt naming the engineer standing at the device.
const ENGINEER_PROMPT: &str = "Личный номер: ";

/// Prompt for the code the engineer brings back.
const CODE_PROMPT: &str = "Код: ";

/// Line above the QR, telling the engineer what the symbol is for.
const QR_CAPTION: &str = "Отсканируйте телефоном:";

/// Line under the QR, carrying the payload as text.
///
/// Not a courtesy. A console where the half-block glyphs do not render, a
/// session logged to a file, a camera that will not focus — in every one of
/// them the text is the only way the challenge reaches the engineer's side, and
/// it is the same bytes the symbol carries.
const QR_FALLBACK_CAPTION: &str = "Или введите вручную:";

/// What the engineer is shown when a code did not meet and another may be tried.
const RETRY_MESSAGE: &str = "Код не принят. Попробуйте ещё раз.";

/// Assembles what is shown above the code prompt: the QR and the payload.
///
/// A payload that cannot be drawn refuses the attempt instead of being shown
/// smaller: a symbol above the version a telephone resolves is drawn, looks
/// right to a person, and does not read — which costs an engineer a trip rather
/// than a message.
fn shown_challenge(
    payload: &str,
    pam_user: &str,
    level: Level,
    epoch: u32,
) -> Result<String, CodeFlowError> {
    let symbol = tessera_core::codes::qr::unicode_blocks(payload).map_err(|_| {
        audit::emit_denied(&audit::Denial {
            nonce: None,
            role_id: pam_user,
            level: level.get(),
            epoch,
            ticket_number: None,
            claimed_engineer_no: None,
            reason: REASON_QR,
        });
        CodeFlowError::Denied
    })?;
    Ok(format!(
        "{QR_CAPTION}\n{symbol}{QR_FALLBACK_CAPTION}\n{payload}\n"
    ))
}

/// What goes above the code prompt when the symbol is already on a screen.
///
/// One line of text and the payload, and neither is decoration. The overlay
/// draws the SYMBOL and nothing else: a camera that will not focus, glare on a
/// screen, a room where telephones with cameras are not allowed — in every one
/// of them the address typed by hand is the only way the challenge reaches the
/// engineer's side, and there is nowhere else on a graphical login to read it
/// from.
///
/// What is left out is the half-block drawing: it is forty lines, the greeter
/// of the target fleet renders the module's text in a one-line inline panel,
/// and the symbol it would duplicate is already on the screen behind it.
fn typed_challenge(payload: &str) -> String {
    format!("{QR_FALLBACK_CAPTION}\n{payload}\n")
}

/// The conversation with the person at the device.
///
/// Production drives the live `pam_conv`; tests script the answers, which is
/// the only way the order of the prompts and the retry budget can be checked
/// without a PAM stack.
pub trait CodeConversation {
    /// Show a message that expects no answer.
    ///
    /// Best-effort by contract: a message the application drops MUST NOT
    /// change the verdict, so this returns nothing to act on.
    fn show_info(&mut self, message: &str);

    /// Ask for a value that is meant to be visible while it is typed.
    ///
    /// # Errors
    ///
    /// [`PamConvError`] when the conversation cannot be driven or the answer
    /// is not text.
    fn prompt_visible(&mut self, prompt: &str) -> Result<String, PamConvError>;

    /// Ask for a value that must not be echoed.
    ///
    /// # Errors
    ///
    /// [`PamConvError`], as [`CodeConversation::prompt_visible`].
    fn prompt_secret(&mut self, prompt: &str) -> Result<SecretString, PamConvError>;
}

/// Shows the challenge on the screen of a graphical login.
///
/// On a text console the challenge travels in the prompt and there is nothing
/// to do. On a graphical login the greeter owns the screen, and the QR has to
/// be put on top of it by a separate, unprivileged process — which this branch
/// starts and stops around the attempt.
///
/// # The whole contract is that it cannot fail the login
///
/// Every method here is best effort, and that is not politeness: the text path
/// is the base one and the overlay is the better case on top of it. A device
/// with no display manager, a greeter that is not running, a socket that could
/// not be created, an overlay binary that is not installed — each of them must
/// leave the login exactly as it would have been, same prompts, same verdict.
/// That is why [`OverlayPresenter::present`] returns an option and not a
/// result: there is no error for a caller to act on, because there is no action
/// a caller is allowed to take.
///
/// It is also why the symbol is taken down by dropping the handle rather than
/// by a call the flow has to remember: every exit path of an attempt — accepted,
/// refused, a conversation that failed halfway — drops it, and a QR left on the
/// screen of a machine anybody can walk up to is the failure that matters here.
pub trait OverlayPresenter {
    /// Put the payload on the screen for the length of the attempt.
    ///
    /// [`None`] when there is no screen to put it on, which is the ordinary
    /// case on a text login and not a failure of anything.
    fn present(&self, payload: &str) -> Option<Box<dyn OverlayHandle>>;
}

/// The symbol that is currently on the screen.
///
/// Carries no methods on purpose. What a caller does with it is hold it for the
/// length of the attempt and let it go: the implementation takes the symbol
/// down when the value is dropped, and a handle that also had a `dismiss` would
/// be two ways of doing one thing, of which a caller can forget one.
pub trait OverlayHandle {}

/// An overlay for a device that has no graphical login.
///
/// The production default. It is a type rather than an `Option` in the
/// dependencies because "there is no overlay" and "the overlay did not come up"
/// have to behave identically, and the surest way to make two paths behave
/// identically is for there to be one path.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOverlay;

impl OverlayPresenter for NoOverlay {
    fn present(&self, _payload: &str) -> Option<Box<dyn OverlayHandle>> {
        None
    }
}

/// The two things about the running system this branch cannot make up.
///
/// Both are files the kernel writes. They are behind a trait because a test
/// cannot reboot a machine or relabel its own process, and because the level
/// has to be read twice with something able to change in between.
pub trait DeviceProbe {
    /// The integrity level of the running process.
    ///
    /// # Errors
    ///
    /// [`LevelError`] when the label is missing, empty, or not in a shape the
    /// module accepts. Every one of them is a refusal — no level is guessed.
    fn integrity_level(&self) -> Result<Level, LevelError>;

    /// The boot identifier and the time since boot.
    ///
    /// # Errors
    ///
    /// The underlying read failure. A device that cannot state them gets no
    /// code login: the lifetime of a pending attempt would otherwise be
    /// measured against a clock the engineer owns.
    fn boot_markers(&self) -> Result<BootMarkers, std::io::Error>;
}

/// The device half of the code method, as this branch uses it.
///
/// [`CodeMethod`] is the only production implementation. The trait exists so
/// the branch can be driven through every refusal the method can produce —
/// an exhausted counter, a rolled-back state, a spent attempt budget — none of
/// which can be staged against real artefacts without corrupting them first.
pub trait CodeMethodApi {
    /// An attempt this method started.
    type Attempt;

    /// The key epoch this method is running under.
    ///
    /// Read from the method rather than from the configuration because the two
    /// can differ: a persisted epoch ahead of the configured one wins, and the
    /// method is the only party that knows the result.
    fn epoch(&self) -> u32;

    /// Start an attempt and produce the challenge to print.
    ///
    /// # Errors
    ///
    /// [`CodeLoginError`] — see [`CodeMethod::begin_with_markers`].
    fn begin(
        &self,
        request: &AttemptRequest<'_>,
        markers: &BootMarkers,
    ) -> Result<Self::Attempt, CodeLoginError>;

    /// The challenge in the form it travels in: one line of the contract's
    /// wire form, signature included.
    fn payload(&self, attempt: &Self::Attempt) -> String;

    /// Verify the code that was read back.
    ///
    /// # Errors
    ///
    /// [`CodeLoginError`] — see [`CodeMethod::verify_with_markers`].
    fn verify(
        &self,
        attempt: &mut Self::Attempt,
        presented: &str,
        markers: &BootMarkers,
    ) -> Result<Accepted, CodeLoginError>;
}

impl CodeMethodApi for CodeMethod {
    type Attempt = tessera_core::codes::StartedAttempt;

    fn epoch(&self) -> u32 {
        Self::epoch(self).get()
    }

    fn begin(
        &self,
        request: &AttemptRequest<'_>,
        markers: &BootMarkers,
    ) -> Result<Self::Attempt, CodeLoginError> {
        self.begin_with_markers(request, markers)
    }

    fn payload(&self, attempt: &Self::Attempt) -> String {
        attempt.payload(Self::page_url(self))
    }

    fn verify(
        &self,
        attempt: &mut Self::Attempt,
        presented: &str,
        markers: &BootMarkers,
    ) -> Result<Accepted, CodeLoginError> {
        self.verify_with_markers(attempt, presented, markers)
    }
}

/// Refusal of a code login, as the PAM branch sees it.
///
/// The variants are grouped by what an application waiting on PAM should do
/// about them, which is what [`CodeFlowError::pam_code`] states. The detail of
/// *why* an attempt was refused stays in the audit journal — see
/// [`tessera_core::codes::audit`] — and never travels to a caller who could
/// turn it into a probe.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CodeFlowError {
    /// This device does not offer the code method.
    ///
    /// Not a failure of the login: a device that was never given a key
    /// container and a ticket set simply has no method here, and the PAM stack
    /// moves on to whatever follows it.
    #[error("the code login method is not provisioned on this device")]
    Unavailable,

    /// The platform cannot provide what the method rests on.
    ///
    /// Reported like an unprovisioned device — the stack steps over the method
    /// and goes on — because for a stack the two are the same instruction. What
    /// they are not is a fault: see
    /// [`CodeLoginError::UnsupportedPlatform`] for why the method cannot exist
    /// where file permissions cannot be checked.
    #[error("the code login method is not available on this platform")]
    UnsupportedPlatform,

    /// The attempt was refused. The reason is in the audit journal.
    #[error("the code login attempt was refused")]
    Denied,

    /// The attempt budget of this nonce is spent.
    #[error("the attempt budget of this code is exhausted")]
    AttemptsExhausted,

    /// The login account is not a role account of this device.
    #[error("the login account is not a role account: {0}")]
    RoleDenied(RoleDenyReason),

    /// The integrity level of the session could not be established.
    #[error("the integrity level of this session could not be read: {0}")]
    Level(#[source] LevelError),

    /// The level changed between the challenge and the verdict.
    #[error("the integrity level changed from {granted} to {observed} during the attempt")]
    LevelChanged {
        /// The level the code was computed over.
        granted: u32,
        /// The level the second read found.
        observed: u32,
    },

    /// The answer to a prompt was empty, or longer than the branch accepts.
    #[error("an answer to a prompt was empty or longer than {limit} characters")]
    Input {
        /// The bound the answer had to fit.
        limit: usize,
    },

    /// The PAM conversation could not be driven.
    #[error("pam conversation: {0}")]
    Conv(#[from] PamConvError),

    /// The session could not be registered with the daemon, and the strict
    /// fail mode does not open a session the daemon never learned about.
    ///
    /// The certificate path refuses the same failure for a neighbouring
    /// reason — a session monitord never recorded cannot have the removal of
    /// its carrier enforced. There is no carrier here, but the daemon is also
    /// the party that ends a session when its term runs out, so an
    /// unregistered code session is an unbounded one.
    #[error("the session could not be registered with the daemon: {0}")]
    MonitorRegistration(#[source] IpcError),

    /// The deadline of the session could not be computed.
    ///
    /// A role whose term cannot be added to the moment of authentication
    /// describes a session with no end. Refused rather than opened: an
    /// unbounded session is exactly what the term exists to prevent, and there
    /// is no fail mode under which one is acceptable.
    #[error("the deadline of this session could not be computed; refusing to open it unbounded")]
    SessionUnbounded,

    /// The login could not be recorded on the device's audit chain, and a
    /// session that cannot be accounted for is not opened.
    ///
    /// The neighbour of [`CodeFlowError::MonitorRegistration`], and refused for
    /// the same shape of reason: there the daemon never learned about the
    /// session and so could not end it; here the journal never learned about it
    /// and so cannot attest that it happened. The control over an operator of
    /// the telephone channel *is* the reconciliation between the logins a fleet
    /// saw and the issuances its server recorded — a login the journal missed is
    /// an issuance that reads as unpaired, or worse, an entry into a system that
    /// left no trace at all.
    ///
    /// Only reachable on a device that has an audit chain. One without a chain
    /// configured is not refused: the chain is opt-in, and its absence has
    /// never been what authorises a login.
    #[error("the login could not be recorded on the audit chain: {0}")]
    Unaccountable(#[source] AuditError),

    /// The device is refusing for now and will stop on its own.
    ///
    /// Two limits produce it: the budget of challenges the device issues in a
    /// window, which is what keeps a stream of requests from spending the nonce
    /// counter to exhaustion, and the lock a run of failed attempts puts on one
    /// role. Neither needs an administrator, and saying so to the engineer is
    /// the point of keeping it apart from `Denied` — at a machine in a vestibule
    /// "wait two minutes" and "this will never work" are different instructions.
    #[error("the code method is refusing for another {} second(s)", retry_after.as_secs())]
    TemporarilyLocked {
        /// How long the engineer has to wait.
        retry_after: Duration,
    },

    /// The device is in a state that no login can proceed from until an
    /// administrator acts: an exhausted nonce counter, a state that moved
    /// backwards, an unreadable state, unreadable boot markers, or a system
    /// random generator that will not answer.
    ///
    /// Kept as one variant on purpose. They differ in what has to be done —
    /// and the journal says which one it was — but not in what the login can
    /// do about it, which is nothing.
    #[error("the device cannot run the code method: {0}")]
    DeviceState(#[source] CodeLoginError),
}

impl CodeFlowError {
    /// Map a refusal to its PAM return code.
    ///
    /// The numbers are the ones in `<security/_pam_types.h>`:
    ///
    /// | Variant                                | Code                       |
    /// | -------------------------------------- | -------------------------- |
    /// | `Unavailable` / `UnsupportedPlatform`  | `PAM_AUTHINFO_UNAVAIL` (9) |
    /// | `AttemptsExhausted` / `TemporarilyLocked` | `PAM_MAXTRIES` (11)     |
    /// | `Denied` / `Conv` / `Input`            | `PAM_AUTH_ERR` (7)         |
    /// | `RoleDenied` / `Level` / `LevelChanged`| `PAM_PERM_DENIED` (6)      |
    /// | `MonitorRegistration` / `SessionUnbounded` | `PAM_PERM_DENIED` (6)  |
    /// | `Unaccountable`                        | `PAM_PERM_DENIED` (6)      |
    /// | `DeviceState`                          | `PAM_SYSTEM_ERR` (4)       |
    ///
    /// `PAM_AUTHINFO_UNAVAIL` is the only code a stack can be configured to
    /// step over (`authinfo_unavail=ignore`), and the two variants that carry
    /// it are deliberate and few: a device that was never given the artefacts,
    /// and a platform where the method cannot exist. Both say nothing about the
    /// attempt, and both leave a stack free to try the certificate path.
    ///
    /// Nothing else may join them. A state that moved backwards, a store that
    /// cannot be read, a lock that could not be taken — those are faults of a
    /// device that *does* run this method, and a stack stepping over a fault
    /// would be stepping over the refusal that fault produced. They stay
    /// `DeviceState`, which is `PAM_SYSTEM_ERR`, and a test below pins that.
    ///
    /// `AttemptsExhausted` is `PAM_MAXTRIES` — 11. Not 8, which is
    /// `PAM_CRED_INSUFFICIENT` and tells the application a different story
    /// ("the authentication data cannot be reached" instead of "stop asking,
    /// the budget is spent").
    ///
    /// # How the exhausted budget is reached
    ///
    /// Worth spelling out, because the path is easy to read as dead. The
    /// budget belongs to one nonce, and a nonce lives for one conversation:
    /// the next `pam_sm_authenticate` raises a fresh challenge with a fresh
    /// budget, so an exhausted budget is only ever observable **inside** the
    /// retry loop of [`authenticate_by_code`].
    ///
    /// It is observable there because the method reports the exhaustion on the
    /// last attempt it allowed, not on a call after it — the wrong code that
    /// spends the final attempt comes back as
    /// [`CodeLoginError::AttemptsExhausted`] rather than
    /// [`CodeLoginError::Denied`]. The branch passes that verdict through
    /// untouched, and must keep doing so: a refusal that costs the nonce
    /// nothing — a key container that will not open, a ticket that stopped
    /// admitting the request — is also a `Denied`, and the method is the only
    /// party that can tell the two apart, because it is the party holding the
    /// counter.
    #[must_use]
    pub const fn pam_code(&self) -> i32 {
        match self {
            Self::Unavailable | Self::UnsupportedPlatform => PAM_AUTHINFO_UNAVAIL,
            Self::AttemptsExhausted | Self::TemporarilyLocked { .. } => PAM_MAXTRIES,
            Self::Denied | Self::Conv(_) | Self::Input { .. } => PAM_AUTH_ERR,
            // `MonitorRegistration` shares the code the certificate path
            // returns for the same refusal, so one fault reads the same way
            // whichever method met it.
            Self::RoleDenied(_)
            | Self::Level(_)
            | Self::LevelChanged { .. }
            | Self::MonitorRegistration(_)
            | Self::Unaccountable(_)
            | Self::SessionUnbounded => PAM_PERM_DENIED,
            Self::DeviceState(_) => PAM_SYSTEM_ERR,
        }
    }
}

/// `PAM_SYSTEM_ERR` — the device itself is in no state to answer.
const PAM_SYSTEM_ERR: i32 = 4;
/// `PAM_PERM_DENIED` — the credential does not authorise this.
const PAM_PERM_DENIED: i32 = 6;
/// `PAM_AUTH_ERR` — the generic "authentication did not succeed" code.
const PAM_AUTH_ERR: i32 = 7;
/// `PAM_AUTHINFO_UNAVAIL` — the method has nothing to authenticate with.
const PAM_AUTHINFO_UNAVAIL: i32 = 9;
/// `PAM_MAXTRIES` — the attempt budget is spent; asking again is pointless.
const PAM_MAXTRIES: i32 = 11;

/// Everything the branch needs beside the conversation and the device.
pub struct CodeDeps<'a> {
    /// The configured method, as `config.toml` names it.
    ///
    /// The attempt budget of one nonce is read from here, and nothing else is.
    /// In particular **not** the key epoch: the method may be running under a
    /// persisted epoch ahead of this one, and only the method knows which won
    /// — see [`CodeMethodApi::epoch`]. Reading the epoch from here wrote one
    /// value into the journal beside another for the same login.
    pub config: &'a CodesConfig,
    /// The on-device role store.
    pub store: &'a RoleStore,
    /// How this device decides whether a name is an account it already owns.
    pub accounts: AccountCheck<'a>,
    /// Global default session TTL from `[roles].default_session_ttl`.
    pub default_session_ttl: Duration,
    /// Resolved host id hash, recorded into the [`AuthContext`].
    pub host_id_hash: &'a str,
    /// Source kind that produced the host id.
    pub host_id_source: HostIdSourceKind,
    /// The daemon, which is what ends a session when its term runs out.
    ///
    /// Deliberately **not** wrapped in a
    /// [`tessera_core::ipc::FailModeWrapper`], unlike the client the
    /// certificate path is handed. The wrapper turns a permissive-mode failure
    /// into `Ok(())` before the caller sees it, and this path has something to
    /// say about that case which the wrapper cannot: that the term of the
    /// session will not be applied. The policy is applied here instead, by
    /// [`register_code_session`], and it is the same policy.
    pub monitor: &'a dyn MonitorClient,
    /// What to do when the daemon cannot be reached.
    pub monitor_fail_mode: MonitorFailMode,
    /// Where the session lives, so the daemon can end it when its term runs
    /// out. Derived from `PAM_TTY` by the caller.
    pub pam_target: tessera_proto::SessionTarget,
    /// What puts the QR on the screen of a graphical login.
    ///
    /// [`NoOverlay`] on a device that has none, which is every device that logs
    /// in over ssh or on a text console. Nothing this value does can change the
    /// verdict of an attempt — see [`OverlayPresenter`].
    pub overlay: &'a dyn OverlayPresenter,
}

/// The login being attempted.
pub struct CodeLogin<'a> {
    /// The login account, which is also the role being asked for.
    pub pam_user: &'a str,
    /// The PAM service that drove the stack.
    pub pam_service: &'a str,
    /// Identifier minted for this session.
    pub session_id: String,
    /// The wall clock of the device.
    ///
    /// Used for the term of the operator ticket and for nothing else: an
    /// offline device's clock is set by whoever stands in front of it, so the
    /// lifetime of a challenge and the invalidation of pending attempts are
    /// measured against the boot markers [`DeviceProbe`] supplies instead.
    pub now: SystemTime,
}

/// Open the configured method against the artefacts of this device.
///
/// Separate from [`authenticate_by_code`] so the caller owns the
/// [`CodeMethod`] for the length of the attempt while the flow itself stays
/// generic over the trait — and so a device without artefacts is answered
/// before a single prompt is shown.
///
/// The artefacts are opened through
/// [`CodeMethod::open_privileged`]: their ownership and mode are the whole of
/// what the method trusts — the container holds the key every code is derived
/// from — so a device where one of them became writable by somebody else does
/// not offer the method at all.
///
/// # Errors
///
/// [`CodeFlowError::Unavailable`] when the method is not configured or the
/// device carries no artefacts of it, and [`CodeFlowError::DeviceState`] when
/// the artefacts are there but unusable — a path whose permissions were
/// weakened among them.
pub fn open_method(
    config: Option<&CodesConfig>,
    store: &RoleStore,
) -> Result<CodeMethod, CodeFlowError> {
    let config = config.ok_or(CodeFlowError::Unavailable)?;
    CodeMethod::open_privileged(config.clone(), LocalRoles::from_store(store)).map_err(|error| {
        match error {
            CodeLoginError::Unavailable => CodeFlowError::Unavailable,
            CodeLoginError::UnsupportedPlatform => CodeFlowError::UnsupportedPlatform,
            other => CodeFlowError::DeviceState(other),
        }
    })
}

/// Drive one code login attempt and produce the context of the session.
///
/// # Errors
///
/// Every variant of [`CodeFlowError`]; see [`CodeFlowError::pam_code`] for
/// what each one tells the PAM stack.
pub fn authenticate_by_code<M, C, P>(
    deps: &CodeDeps<'_>,
    login: CodeLogin<'_>,
    method: &M,
    conv: &mut C,
    probe: &P,
) -> Result<CodeLoginOutcome, CodeFlowError>
where
    M: CodeMethodApi,
    C: CodeConversation,
    P: DeviceProbe,
{
    // Taken field by field rather than destructured: the identifier of the
    // session is moved into the context at the very end, and everything up to
    // there reads the login where it stands.
    let pam_user = login.pam_user;
    // From the method, not from `deps.config`: the two disagree whenever a
    // persisted epoch is ahead of the configured one, and then every event
    // this branch emits would name a different epoch than the events the
    // method emits for the same login.
    let epoch = method.epoch();

    // The level first: it is part of the challenge, so an attempt that cannot
    // say which level it is for must not start. Where a mandatory mechanism is
    // declared, a device that answers nothing is refused rather than read as
    // the base level; where none is, the base level is the answer and no
    // reading is attempted — see `codes_level`.
    let level = probe.integrity_level().map_err(|error| {
        tracing::warn!(
            target: "tessera.codes",
            error = %error,
            pam_user = %pam_user,
            "the integrity level of this session could not be read; refusing the code login",
        );
        // Before the engineer has been asked for anything: there is no number
        // to record, and the journal says it does not know rather than
        // inventing one.
        audit::emit_denied(&audit::Denial {
            nonce: None,
            role_id: pam_user,
            level: 0,
            epoch,
            ticket_number: None,
            claimed_engineer_no: None,
            reason: REASON_LEVEL_UNREADABLE,
        });
        CodeFlowError::Level(error)
    })?;

    // The login account IS the role, so a name that cannot be a role at all —
    // or an account the distribution created for its own use — is refused
    // before any artefact, prompt or key container is touched.
    let role_id = requested_role(pam_user, level, epoch)?;
    ensure_role_account(pam_user, deps.accounts, level, epoch)?;

    let (server_id, engineer_id) = ask_who_is_asking(conv, pam_user, level, epoch)?;
    let request = AttemptRequest {
        role_id: role_id.as_str(),
        level,
        server_id: &server_id,
        engineer_id: &engineer_id,
        now: claimed_time(login.now),
    };

    let markers = read_markers(probe, pam_user, level, epoch)?;
    let mut attempt = method
        .begin(&request, &markers)
        .map_err(|error| flow_error(error, epoch))?;

    // The challenge travels in the TEXT OF THE PROMPT and not through
    // `PAM_TEXT_INFO`. On fly-modern an info message becomes a modal warning
    // box and the QR never reaches the login screen at all (design of
    // 2026-07-03, §6.1, checked on a live 1.8.4). A method that shows nothing on
    // the fleet it was built for is a method nobody can use, so the one channel
    // that does reach every front end is the prompt.
    let payload = method.payload(&attempt);
    let shown = shown_challenge(&payload, pam_user, level, epoch)?;
    // Held, not acted on: the handle IS the overlay being on the screen, and it
    // comes down when this binding goes out of scope at the end of the attempt.
    // Named rather than `_`, which would drop it here and take the symbol down
    // before the engineer had seen it.
    let overlay = raise_overlay(deps, &payload, pam_user, epoch);
    // Whether the symbol is already on a screen. The text form goes into the
    // prompt only when it is not: on a graphical login the person is looking at
    // the overlay, and the greeter of the target fleet draws the module's text
    // in a one-line inline panel, where forty lines of half-block glyphs are
    // not a fallback but a prompt nobody can read the code request out of.
    //
    // Asked of the overlay rather than of the items PAM set: the items say a
    // display was NAMED, the handle says a symbol is SHOWN. An overlay that
    // did not come up on a named display leaves the challenge in the prompt,
    // where it was going anyway.
    let symbol_on_screen = overlay.is_some();

    // Nothing is asked for the key container, and nothing holds a password for
    // it either: the key of the device is stored without one, guarded by the
    // ownership and mode of the store. An engineer does not know a secret for
    // it and must not, and a device that had to be told one could not come back
    // from a power cut on its own. See
    // `tessera_core::codes::store::load_device_key`.
    //
    // One pass per attempt the nonce is allowed. The budget itself is kept by
    // the method against persisted state, so the loop cannot hand out more
    // than it; the bound here only stops the branch spinning on a refusal that
    // costs no attempt, such as a ticket that stopped admitting the request.
    //
    // The verdict of the method is passed through exactly as given, and the
    // last pass is not special-cased. The wrong code that spends the final
    // attempt already comes back as `AttemptsExhausted`, so `PAM_MAXTRIES`
    // leaves this loop on its own; deciding exhaustion here instead — by
    // counting prompts — would report a spent budget for the refusals that
    // spend nothing, which only the method can distinguish because only the
    // method holds the counter.
    let mut accepted: Option<Accepted> = None;
    let mut first_prompt = true;
    for remaining in (0..deps.config.params.attempts_per_nonce()).rev() {
        // The symbol goes up once, with the first prompt. Drawing it again on
        // every retry would scroll the screen and leave the engineer scanning a
        // half-erased QR — and they are looking at the code they mistyped, not
        // at the challenge, which has not changed.
        let prompt = match (first_prompt, symbol_on_screen) {
            (true, false) => format!("{shown}{CODE_PROMPT}"),
            (true, true) => format!("{}{CODE_PROMPT}", typed_challenge(&payload)),
            (false, _) => CODE_PROMPT.to_owned(),
        };
        first_prompt = false;
        let typed = bounded_answer(
            &conv.prompt_visible(&prompt)?,
            MAX_CODE_LEN,
            pam_user,
            level,
            epoch,
        )?;
        let code = normalise_code(&typed);
        // Markers are read afresh for every verification: an attempt that did
        // not survive a reboot must be refused by the reboot, not by whatever
        // the branch remembered from before it.
        let markers = read_markers(probe, pam_user, level, epoch)?;
        match method.verify(&mut attempt, &code, &markers) {
            Ok(value) => {
                accepted = Some(value);
                break;
            }
            Err(CodeLoginError::Denied) if remaining > 0 => {
                conv.show_info(RETRY_MESSAGE);
            }
            Err(error) => return Err(flow_error(error, epoch)),
        }
    }
    let Some(accepted) = accepted else {
        return Err(CodeFlowError::Denied);
    };

    confirm_level_unchanged(probe, pam_user, epoch, &accepted)?;

    let role = fix_role_payload(deps, pam_user, &accepted)?;
    let auth_ctx = auth_context(deps, login, role, &accepted);

    // Able to refuse: the daemon is what ends this session when its term runs
    // out, so a session it never learned about is an unbounded one.
    let registration = register_code_session(deps, &auth_ctx, pam_user)?;

    // Only now. Everything above could still have refused — the second reading
    // of the level, the role payload, the registration under a strict fail
    // mode — and an event written earlier would record a login that ended in a
    // PAM refusal. The reconciliation this event exists for is between the
    // logins a fleet saw and the issuances its server recorded, and a success
    // that did not happen makes an unpaired issuance look paired.
    //
    // And this one can refuse. It is the last step before the session exists,
    // which is the only place the refusal is worth anything: the device has a
    // hash-chained journal, the journal will not take the record, and a session
    // nothing can account for is exactly the session an operator with the
    // telephone would want.
    //
    // "The device has a journal" is not an assumption made here — it is what
    // `sink::install_from_config` established in `entry.rs` before any of this
    // ran, from the `[audit]` section. Without that call every device looks
    // like one that keeps no journal, this step returns `Ok` for that reason,
    // and the refusal below never fires on any hardware. A device that really
    // keeps no journal returns `Ok` too, and the login proceeds as it always
    // did — that case is a configuration, not a failure.
    record_success_or_withdraw(deps, &auth_ctx, pam_user, registration, || {
        audit::emit_success(
            &accepted.nonce_ref,
            &accepted.role_id,
            accepted.level.get(),
            epoch,
            &accepted.ticket_number,
            &accepted.claimed_engineer_no,
        )
    })?;

    Ok(CodeLoginOutcome {
        auth_ctx,
        registration,
    })
}

/// Asks a visible prompt, and asks it again when the answer comes back empty.
///
/// The last answer is returned whatever it is: what an empty or unusable value
/// costs is decided by [`bounded_answer`], in one place, for every prompt. This
/// only decides how many times the question is put — see
/// [`EMPTY_ANSWER_RETRIES`] for why it is put more than once and why not
/// indefinitely.
///
/// # Errors
///
/// [`CodeFlowError::Conv`] when the conversation cannot be driven at all.
fn ask_visible<C: CodeConversation>(conv: &mut C, prompt: &str) -> Result<String, CodeFlowError> {
    let mut answer = conv.prompt_visible(prompt)?;
    for _ in 0..EMPTY_ANSWER_RETRIES {
        if !answer.trim().is_empty() {
            break;
        }
        answer = conv.prompt_visible(prompt)?;
    }
    Ok(answer)
}

/// Asks which side is expected to issue, and who is standing at the device.
///
/// Two prompts and no more, in that order. The second answer is checked as a
/// number rather than only bounded: it goes into the code, so a code cut for
/// one engineer is useless to the next person to walk up to this device — and
/// it is what the journal of this device names, which is otherwise a role
/// account and nothing else.
///
/// # Errors
///
/// [`CodeFlowError::Conv`] when the conversation cannot be driven, and
/// [`CodeFlowError::Input`] for an answer the channel cannot carry.
fn ask_who_is_asking<C: CodeConversation>(
    conv: &mut C,
    pam_user: &str,
    level: Level,
    epoch: u32,
) -> Result<(String, String), CodeFlowError> {
    let server_id = bounded_answer(
        &ask_visible(conv, SERVER_PROMPT)?,
        MAX_SERVER_ID_LEN,
        pam_user,
        level,
        epoch,
    )?;
    let typed = bounded_answer(
        &ask_visible(conv, ENGINEER_PROMPT)?,
        MAX_ENGINEER_ID_LEN,
        pam_user,
        level,
        epoch,
    )?;
    let engineer_id = checked_engineer_number(&typed, pam_user, level, epoch)?;
    Ok((server_id, engineer_id))
}

/// Puts the same payload on the screen of a graphical login, if there is one.
///
/// The value it returns is held, not acted on: the handle takes the symbol down
/// when it is dropped, which happens on every way out of an attempt — the
/// accepted code, the spent budget, a conversation that failed at the first
/// prompt.
///
/// Nothing is checked about the result and nothing can be. An overlay that did
/// not come up leaves the challenge in the prompt, where it was going anyway,
/// and the login proceeds exactly as it would have on a device with no screen.
fn raise_overlay(
    deps: &CodeDeps<'_>,
    payload: &str,
    pam_user: &str,
    epoch: u32,
) -> Option<Box<dyn OverlayHandle>> {
    let overlay = deps.overlay.present(payload);
    if overlay.is_none() {
        tracing::debug!(
            target: "tessera.codes",
            user = pam_user,
            epoch,
            "the challenge is shown in the prompt only: no overlay on this device"
        );
    }
    overlay
}

/// Read the level a second time and refuse a session that changed level.
///
/// Between printing the challenge and returning success there is a window in
/// which the label of the process can change — the two sides are on the
/// telephone for that whole time. A success returned after it would apply a
/// code granted for one level to a session running at another, so the two
/// readings have to agree.
///
/// A level that became unreadable is the same refusal as one that changed: an
/// unknown level is not the level the operator authorised.
fn confirm_level_unchanged<P: DeviceProbe>(
    probe: &P,
    pam_user: &str,
    epoch: u32,
    accepted: &Accepted,
) -> Result<(), CodeFlowError> {
    let granted = accepted.level.get();
    let observed = probe.integrity_level().map_err(|error| {
        tracing::error!(
            target: "tessera.codes",
            error = %error,
            pam_user = %pam_user,
            "the integrity level became unreadable after a code was accepted",
        );
        audit::emit_denied(&audit::Denial {
            nonce: None,
            role_id: pam_user,
            level: granted,
            epoch,
            ticket_number: Some(&accepted.ticket_number),
            claimed_engineer_no: Some(&accepted.claimed_engineer_no),
            reason: REASON_LEVEL_UNREADABLE,
        });
        CodeFlowError::Level(error)
    })?;
    if observed.get() == granted {
        return Ok(());
    }

    tracing::error!(
        target: "tessera.codes",
        pam_user = %pam_user,
        granted,
        observed = observed.get(),
        "the integrity level changed during the attempt; refusing the code login",
    );
    audit::emit_denied(&audit::Denial {
        nonce: None,
        role_id: pam_user,
        level: granted,
        epoch,
        ticket_number: Some(&accepted.ticket_number),
        claimed_engineer_no: Some(&accepted.claimed_engineer_no),
        reason: REASON_LEVEL_CHANGED,
    });
    Err(CodeFlowError::LevelChanged {
        granted,
        observed: observed.get(),
    })
}

/// Strip the separators a person types when reading a code back.
///
/// The operator dictates the code in groups, so an engineer writes down
/// `1234 5678` and types what they wrote down. The contract alphabet has no
/// space in it, so the code would be refused — and refused at the cost of one
/// of five attempts, for a habit the printed challenge itself encourages by
/// grouping what it shows.
///
/// Only spaces and hyphens go. Everything else reaches the verification
/// unchanged: a character that is not in the alphabet is a wrong code, and
/// quietly deleting it would turn one wrong code into a different wrong code.
fn normalise_code(typed: &str) -> String {
    typed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect()
}

/// Refuse an answer that is empty, longer than the branch accepts, or carries
/// what a document of the channel cannot.
///
/// The bound is counted in characters rather than bytes: what the engineer
/// typed is what is being bounded, and a Cyrillic name is not twice as long
/// for having been written in Cyrillic.
///
/// The set of characters is asked of the contract rather than spelled out here,
/// and it is asked *now* rather than when the challenge is assembled. A value
/// carrying `;` or `=` — a number typed as `TN=4471`, a paste with a tail —
/// would otherwise fail inside `Challenge::new` and arrive as a state no login
/// proceeds from until an administrator acts. It is the engineer's input, they
/// are standing at the device, and what they need is to be asked again.
fn bounded_answer(
    answer: &str,
    limit: usize,
    pam_user: &str,
    level: Level,
    epoch: u32,
) -> Result<String, CodeFlowError> {
    let trimmed = answer.trim();
    // Bytes, not characters: the bound belongs to the payload budget, which is
    // spent in bytes. Counting characters let a value in Cyrillic pass a prompt
    // and then be refused by the document, which reads to an engineer as the
    // device breaking rather than as a value being too long.
    if trimmed.is_empty()
        || trimmed.len() > limit
        || !tessera_codes_contract::wire::is_usable_in_a_document(trimmed)
    {
        audit::emit_denied(&audit::Denial {
            nonce: None,
            role_id: pam_user,
            level: level.get(),
            epoch,
            ticket_number: None,
            claimed_engineer_no: None,
            reason: REASON_INPUT,
        });
        return Err(CodeFlowError::Input { limit });
    }
    Ok(trimmed.to_owned())
}

/// Refuse a personal number whose check character does not meet.
///
/// The number carries an organisation segment, a serial part and a check
/// character over both, and the device checks it before it starts an attempt.
/// The alternative is worse than it looks: a mistyped number produces a code
/// that ALMOST met, and the person debugging that stands at a machine on a site
/// comparing arithmetic, when the answer was a character somebody typed wrong.
///
/// Checked here rather than inside the challenge for the same reason the
/// character set is: this is the engineer's input, they are at the keyboard,
/// and what they need is to be asked again — not a login that stops until an
/// administrator looks at it.
///
/// The refusal names no more than the others do. Which of the two numbers was
/// wrong, and how, goes to the journal.
fn checked_engineer_number(
    typed: &str,
    pam_user: &str,
    level: Level,
    epoch: u32,
) -> Result<String, CodeFlowError> {
    match tessera_codes_contract::engineer_number::EngineerNumber::parse(typed) {
        // The number as it was TYPED travels on, not the folded form: it is
        // what the engineer will read back off their own screen, and it is what
        // the issuing side is about to be shown.
        Ok(_) => Ok(typed.to_owned()),
        Err(error) => {
            tracing::info!(
                target: "tessera.codes",
                user = pam_user,
                epoch,
                error = %error,
                "the personal number was refused before an attempt was started"
            );
            // What goes into the journal is the string as it was TYPED, and
            // that is the point rather than an oversight. A refused number is
            // the only trace an attempt under an unknown identity leaves — the
            // attempt never starts, so there is no nonce and no challenge to
            // record — and a journal that stored the folded form, or nothing at
            // all, would answer "somebody typed something" to the one question
            // an investigator has. It is bounded before it gets here
            // (`bounded_answer` at MAX_ENGINEER_ID_LEN), and the journal writes
            // JSON, so a hostile string is data in a field rather than a line
            // of its own.
            audit::emit_denied(&audit::Denial {
                nonce: None,
                role_id: pam_user,
                level: level.get(),
                epoch,
                ticket_number: None,
                claimed_engineer_no: Some(typed),
                reason: REASON_ENGINEER_NUMBER,
            });
            Err(CodeFlowError::Input {
                limit: MAX_ENGINEER_ID_LEN,
            })
        }
    }
}

/// Read the boot markers, refusing the login when they cannot be had.
fn read_markers<P: DeviceProbe>(
    probe: &P,
    pam_user: &str,
    level: Level,
    epoch: u32,
) -> Result<BootMarkers, CodeFlowError> {
    probe.boot_markers().map_err(|error| {
        tracing::error!(
            target: "tessera.codes",
            error = %error,
            pam_user = %pam_user,
            "the boot markers of this device are unreadable; refusing the code login",
        );
        audit::emit_denied(&audit::Denial {
            nonce: None,
            role_id: pam_user,
            level: level.get(),
            epoch,
            ticket_number: None,
            claimed_engineer_no: None,
            reason: REASON_BOOT_MARKERS,
        });
        CodeFlowError::DeviceState(CodeLoginError::BootMarkers {
            reason: error.to_string(),
        })
    })
}

/// Turn a refusal of the method into the branch's own, keeping the ones a
/// caller must act on apart from the single denial everything else collapses
/// into.
///
/// The device-state refusals are logged here rather than swallowed: they are
/// the ones an administrator has to see, and by the time the error reaches PAM
/// only a number is left of it.
fn flow_error(error: CodeLoginError, epoch: u32) -> CodeFlowError {
    match error {
        CodeLoginError::Unavailable => CodeFlowError::Unavailable,
        CodeLoginError::UnsupportedPlatform => CodeFlowError::UnsupportedPlatform,
        CodeLoginError::Denied => CodeFlowError::Denied,
        CodeLoginError::AttemptsExhausted => CodeFlowError::AttemptsExhausted,
        CodeLoginError::TemporarilyLocked { retry_after } => {
            CodeFlowError::TemporarilyLocked { retry_after }
        }
        other => {
            tracing::error!(
                target: "tessera.codes",
                error = %other,
                epoch,
                "the code method cannot run on this device until an administrator acts",
            );
            CodeFlowError::DeviceState(other)
        }
    }
}

/// The moment the device claims, for the term of the operator ticket.
///
/// A clock reading before the Unix epoch yields zero rather than a panic.
///
/// Zero is **accepted** by the ticket, not refused by it: the term is checked
/// as `not_after`, and no moment is smaller than a `not_after` that has not
/// passed. So a device whose clock has been wound back far enough presents
/// every ticket it holds as current, expired ones included.
///
/// That is not a defect of this function, and moving the refusal here would
/// not close it — a clock set to last week does the same thing and reads as
/// perfectly ordinary. The wall clock of a device an engineer stands in front
/// of is theirs to set, and this method is built not to need it: what a code
/// costs an attacker is bounded by the one-time nonce, the attempt budget and
/// the ticket revocation list, none of which asks the clock anything. The term
/// of a ticket is a coarse limit checked against an untrusted reading, and
/// this comment exists so the next reader does not mistake it for an enforced
/// one.
fn claimed_time(now: SystemTime) -> ClaimedTime {
    ClaimedTime::new(
        now.duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs()),
    )
}

/// Derive the role id from the login account name.
fn requested_role(
    pam_user: &str,
    level: Level,
    epoch: u32,
) -> Result<tessera_core::role::RoleId, CodeFlowError> {
    crate::role_selection::role_from_account(pam_user).map_err(|error| {
        tracing::warn!(
            target: "tessera.codes",
            error = %error,
            pam_user = %pam_user,
            "login account name is not a role; refused before any artefact is touched",
        );
        tessera_core::role::audit::emit_role_deny(
            pam_user,
            pam_user,
            RoleDenyReason::Syntax.as_str(),
        );
        audit::emit_denied(&audit::Denial {
            nonce: None,
            role_id: pam_user,
            level: level.get(),
            epoch,
            ticket_number: None,
            claimed_engineer_no: None,
            reason: REASON_ROLE_ACCOUNT,
        });
        CodeFlowError::RoleDenied(RoleDenyReason::Syntax)
    })
}

/// Refuse a login into an account that belongs to the system rather than to a
/// role.
fn ensure_role_account(
    pam_user: &str,
    accounts: AccountCheck<'_>,
    level: Level,
    epoch: u32,
) -> Result<(), CodeFlowError> {
    use tessera_core::role::SystemAccountError;

    accounts.check(pam_user).map_err(|error| {
        let reason = match error {
            SystemAccountError::SystemAccount { .. }
            | SystemAccountError::SystemPrincipal { .. } => RoleDenyReason::SystemAccount,
            _ => RoleDenyReason::BackendUnavailable,
        };
        tracing::warn!(
            target: "tessera.codes",
            error = %error,
            pam_user = %pam_user,
            reason = %reason,
            "login account is not a role account; refused before any artefact is touched",
        );
        tessera_core::role::audit::emit_role_deny(pam_user, pam_user, reason.as_str());
        audit::emit_denied(&audit::Denial {
            nonce: None,
            role_id: pam_user,
            level: level.get(),
            epoch,
            ticket_number: None,
            claimed_engineer_no: None,
            reason: REASON_ROLE_ACCOUNT,
        });
        CodeFlowError::RoleDenied(reason)
    })
}

/// Snapshot the role the accepted code granted.
///
/// The code proved that an operator holding an admitting ticket authorised
/// this role, and [`tessera_core::codes`] has already checked that this device
/// still defines it. What is left is to fix the payload the session will live
/// under — the МКЦ categories among it — so a later edit of the store cannot
/// reach a session that is already open.
fn fix_role_payload(
    deps: &CodeDeps<'_>,
    pam_user: &str,
    accepted: &Accepted,
) -> Result<SessionRolePayload, CodeFlowError> {
    let role_id = crate::role_selection::role_from_account(&accepted.role_id).map_err(|_| {
        tessera_core::role::audit::emit_role_deny(
            pam_user,
            &accepted.role_id,
            RoleDenyReason::Syntax.as_str(),
        );
        CodeFlowError::RoleDenied(RoleDenyReason::Syntax)
    })?;
    let Some(slice) = deps.store.get(&role_id) else {
        tessera_core::role::audit::emit_role_deny(
            pam_user,
            role_id.as_str(),
            RoleDenyReason::NotFound.as_str(),
        );
        return Err(CodeFlowError::RoleDenied(RoleDenyReason::NotFound));
    };

    // No certificate means no certificate TTL: the session is bounded by the
    // role, or by the global default when the role names none. It is never
    // unbounded.
    let payload =
        SessionRolePayload::fix(slice, None, deps.default_session_ttl).map_err(|fix_error| {
            let reason = fix_error.deny_reason();
            tessera_core::role::audit::emit_role_deny(pam_user, role_id.as_str(), reason.as_str());
            CodeFlowError::RoleDenied(reason)
        })?;

    tessera_core::role::audit::emit_role_session_open(
        pam_user,
        payload.role.as_str(),
        payload.role_version,
        tessera_core::role::CoverageMethod::Code.as_str(),
        payload.ttl.as_secs(),
    );
    Ok(payload)
}

/// Audit event: the session was opened, and its term will not be applied.
const EVENT_EXPIRY_UNENFORCED: &str = "code_session_expiry_unenforced";

/// The absolute moment a code session must end.
///
/// The term of the role and nothing else. The certificate path takes the
/// earlier of the role deadline and the `notAfter` of the leaf; there is no
/// leaf here and therefore no second bound — which is worth stating, so the
/// next reader does not go looking for the clamp that is missing.
///
/// Anchored at the moment of authentication rather than shipped as a relative
/// term the daemon re-anchors at its own clock, for the same reason the
/// certificate path does it: the deadline the daemon enforces is then the one
/// this device computed, whatever the two clocks disagree about.
///
/// `None` only when the addition overflows the clock, which describes a
/// session with no end — the caller refuses it rather than opening one.
fn code_session_expiry(
    role: &SessionRolePayload,
    authenticated_at: SystemTime,
) -> Option<SystemTime> {
    authenticated_at.checked_add(role.ttl)
}

/// Register the freshly opened session with the daemon.
///
/// The daemon is what applies the term: it schedules the end of the session
/// against the absolute instant this function sends it. A session it never
/// learned about runs until its owner logs out, which is the unbounded session
/// the term exists to prevent — so a failure to register is not a bookkeeping
/// problem here, it is the loss of the guarantee.
///
/// The fail mode decides what to do about that, exactly as it does on the
/// certificate path:
///
/// * **strict** — the login is refused. A session whose end nobody will
///   enforce is not opened.
/// * **permissive** — the login proceeds, and the journal says specifically
///   that the term will not be applied. The generic "monitord call failed"
///   line the fail-mode wrapper writes does not carry that consequence, which
///   is why this path applies the policy itself rather than delegating it.
///
/// [`IpcError::Unauthorized`] is refused under either mode: a daemon that
/// rejects the registration has not failed to answer, it has answered no.
///
/// # Errors
///
/// [`CodeFlowError::SessionUnbounded`] when no deadline can be computed, and
/// [`CodeFlowError::MonitorRegistration`] when the registration failed and the
/// mode does not tolerate it.
fn register_code_session(
    deps: &CodeDeps<'_>,
    auth_ctx: &AuthContext,
    pam_user: &str,
) -> Result<Registration, CodeFlowError> {
    let Some(role) = auth_ctx.role.as_ref() else {
        // Unreachable: a code login that resolves no role never reaches here.
        // Refused rather than registered without a term.
        tracing::error!(
            target: "tessera.codes",
            pam_user = %pam_user,
            "a code session reached registration without a role; refusing to open it unbounded",
        );
        return Err(CodeFlowError::SessionUnbounded);
    };
    let Some(expiry) = code_session_expiry(role, auth_ctx.authenticated_at) else {
        tracing::error!(
            target: "tessera.codes",
            pam_user = %pam_user,
            ttl_secs = role.ttl.as_secs(),
            "the deadline of this session does not fit the clock; refusing to open it unbounded",
        );
        return Err(CodeFlowError::SessionUnbounded);
    };

    let info = OpenSessionInfo {
        session_id: &auth_ctx.session_id,
        pam_user,
        pam_service: &auth_ctx.pam_service,
        host_id_hash: &auth_ctx.host_id,
        target: deps.pam_target.clone(),
        // No carrier: this login was proved by a code read down a telephone,
        // and there is no device whose removal could end the session. The
        // daemon skips every carrier check for a session without a serial, so
        // nothing here asks it to watch for something that was never plugged
        // in. `carrier` only names the namespace a serial belongs to, and with
        // no serial it names the namespace of nothing.
        usb_serial: None,
        usb_vid_pid: None,
        usb_devnode: None,
        carrier: tessera_proto::CarrierKind::UsbPartition,
        // No certificate, so nothing that identifies one. Writing a value into
        // any of these would put an issuer's name on a login no issuer signed.
        cert_cn: "",
        cert_serial: "",
        engineer_ski: "",
        engineer_cert_sha256: "",
        uid: crate::flow::resolve_uid(pam_user),
        role: Some(role.role.as_str()),
        role_version: Some(role.role_version),
        session_expiry: Some(expiry),
    };

    match deps.monitor.open_session(&info) {
        Ok(()) => Ok(Registration::Recorded),
        Err(error)
            if deps.monitor_fail_mode == MonitorFailMode::Strict
                || matches!(error, IpcError::Unauthorized) =>
        {
            tracing::error!(
                target: "tessera.codes",
                error = %error,
                pam_user = %pam_user,
                "the session could not be registered with the daemon; refusing the code login",
            );
            Err(CodeFlowError::MonitorRegistration(error))
        }
        Err(error) => {
            // The login proceeds, and the journal carries the consequence
            // rather than the transport failure: what an auditor needs to know
            // is that this session has no enforced end, not which socket
            // refused to answer.
            tracing::error!(
                target: "codes.audit",
                event = EVENT_EXPIRY_UNENFORCED,
                pam_user = %pam_user,
                role_id = %role.role.as_str(),
                session_id = %auth_ctx.session_id,
                ttl_secs = role.ttl.as_secs(),
                error = %error,
                "the session was opened but its term will not be applied: the daemon did not \
                 record it, and the permissive fail mode admits the login anyway",
            );
            Ok(Registration::NotRecorded)
        }
    }
}

/// Whether the daemon took the registration.
///
/// Public because the refusals that can still happen are not all inside this
/// module: the caller stores the context into PAM data after the flow returns,
/// and that can fail too. Whoever can refuse after the session exists has to
/// be able to ask whether there is a registration to give back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registration {
    /// The daemon recorded the session and will end it at its term.
    Recorded,
    /// The daemon did not, and the permissive fail mode let the login through.
    NotRecorded,
}

/// A code login that succeeded, and what the daemon knows about it.
///
/// The registration travels out with the context because the login is not over
/// when this value is produced: the caller still has to store the context, and
/// a session the daemon holds for a login that then fails is a phantom on the
/// side of the ledger the code channel is reconciled by.
pub struct CodeLoginOutcome {
    /// The context of the session, for the caller to store.
    pub auth_ctx: AuthContext,
    /// Whether the daemon recorded the session.
    pub registration: Registration,
}

/// Reason given to the daemon when a session is withdrawn because the journal
/// would not account for it.
pub const CLOSE_REASON_UNACCOUNTABLE: &str = "audit_unaccountable";

/// Reason given when the context of an authenticated session could not be
/// handed to PAM, so no session phase will ever run for it.
pub const CLOSE_REASON_CONTEXT_LOST: &str = "context_not_stored";

/// Record the success in the hash-chained journal, or give the registration
/// back if the journal will not take it.
///
/// The emission is a closure so that this decision can be tested without
/// installing a journal into the process-global sink: what is worth pinning
/// here is not how a record is written but what happens to the session when
/// writing fails.
///
/// # Errors
///
/// [`CodeFlowError::Unaccountable`] when the journal refused the record. The
/// registration is withdrawn first, so the refusal leaves nothing behind.
fn record_success_or_withdraw<E>(
    deps: &CodeDeps<'_>,
    auth_ctx: &AuthContext,
    pam_user: &str,
    registration: Registration,
    emit: E,
) -> Result<(), CodeFlowError>
where
    E: FnOnce() -> Result<(), AuditError>,
{
    let Err(error) = emit() else {
        return Ok(());
    };
    // The registration has to be given back. This login is about to be
    // refused, and a session the daemon still holds would be carried to the
    // end of its term and handed to an auditor as a login that never happened
    // — on the very side of the ledger the code channel is reconciled by.
    if registration == Registration::Recorded {
        withdraw_code_session(
            deps.monitor,
            &auth_ctx.session_id,
            pam_user,
            CLOSE_REASON_UNACCOUNTABLE,
        );
    }
    Err(CodeFlowError::Unaccountable(error))
}

/// Withdraw a registration the login is no longer going to justify.
///
/// The window this closes is small and entirely real: the session is
/// registered, then the journal refuses the record, then the login is refused
/// — and the daemon is left holding a session that never existed. It would
/// carry that session to the end of its term and hand an auditor a phantom on
/// the side of the ledger where a phantom is worst: reconciliation is exactly
/// what the code channel is audited by.
///
/// Best-effort by necessity. If the daemon will not take the withdrawal there
/// is nothing further this side can do, and the login is refused either way —
/// so the failure is logged loudly rather than turned into a second verdict.
pub fn withdraw_code_session(
    monitor: &dyn MonitorClient,
    session_id: &str,
    pam_user: &str,
    reason: &str,
) {
    if let Err(error) = monitor.close_session(session_id, reason) {
        tracing::error!(
            target: "tessera.codes",
            error = %error,
            pam_user = %pam_user,
            session_id = %session_id,
            reason,
            "the login was refused after the session was registered, and the registration \
             could not be withdrawn: the daemon holds a session that does not exist",
        );
    }
}

/// The integrity ceiling of a session opened by a code.
///
/// In the certificate path the ceiling is the `MAX_INTEGRITY` extension of the
/// leaf. There is no certificate here, and the operator ticket plays that part:
/// it is the document that bounds how high a level the operator may hand out,
/// and it was checked against the level of this attempt before the code was
/// verified.
///
/// The two coordinates come from different places on purpose.
///
/// * The **linear level** is the ceiling of the ticket, clamped to what a label
///   can hold. Nothing on the device states a linear bound: a role slice
///   carries a mask of categories, and reading it as a set of levels is exactly
///   the mistake this function exists to keep out of the session label.
/// * The **categories** are every bit. A ticket bounds the level and says
///   nothing at all about categories, and `IntegrityLabel::covers` treats a
///   ceiling of no categories as granting none — a ceiling written that way
///   would refuse every role that asks for one. All bits leave the intersection
///   with the user's МНКЦ exactly as it was, which is what "the ticket narrows
///   no category" has to mean here.
fn ticket_ceiling(level_ceiling: Level) -> IntegrityLabel {
    IntegrityLabel {
        // A ticket written for a level no label can express is capped rather
        // than wrapped: the widest ceiling a label can hold still bounds
        // nothing the МКЦ contour would not have bounded anyway.
        level: i8::try_from(level_ceiling.get()).unwrap_or(IntegrityLabel::MAX_LEVEL),
        categories: u64::MAX,
    }
}

/// Assemble the context the session phases read.
///
/// Every certificate-shaped field is empty, because there is no certificate:
/// the credential of this login is a code, and describing it as a certificate
/// would put a value in the audit trail that no issuer ever wrote.
///
/// `cert_max_integrity` is the exception, and it is not a claim about a
/// certificate: it is the ceiling the session label is computed against, and in
/// this path the operator ticket states it — see [`ticket_ceiling`]. Leaving it
/// empty made `[mac] cert_integrity = "required"` refuse every code login for
/// want of an extension no code login can carry, and left the session running
/// at whatever level the МНКЦ of the account allowed rather than at the one the
/// operator authorised.
fn auth_context(
    deps: &CodeDeps<'_>,
    login: CodeLogin<'_>,
    role: SessionRolePayload,
    accepted: &Accepted,
) -> AuthContext {
    AuthContext {
        session_id: login.session_id,
        cert_cn: None,
        cert_serial: None,
        usb_serial: None,
        usb_vid_pid: None,
        pam_service: login.pam_service.to_owned(),
        host_id: deps.host_id_hash.to_owned(),
        host_id_source: deps.host_id_source,
        authenticated_at: login.now,
        cert_not_after: None,
        clock_skew_seconds: 0,
        cert_max_integrity: Some(ticket_ceiling(accepted.level_ceiling)),
        cert_ident: None,
        home_dir: resolve_home_dir(login.pam_user),
        role: Some(role),
    }
}

/// Resolve the login account's home directory for the MAC advisory.
#[cfg(unix)]
fn resolve_home_dir(pam_user: &str) -> Option<std::path::PathBuf> {
    match nix::unistd::User::from_name(pam_user) {
        Ok(Some(user)) => Some(user.dir),
        _ => None,
    }
}

/// Resolve the login account's home directory — there is no passwd database
/// off Unix, so the caller gets what a failed lookup yields.
#[cfg(not(unix))]
fn resolve_home_dir(_pam_user: &str) -> Option<std::path::PathBuf> {
    None
}

/// The probe of the running system.
///
/// Carries the level source of the OS adapter this device runs under: a device
/// with no mandatory mechanism has no label to read, and both readings — the
/// one that goes into the challenge and the one that confirms it — have to come
/// from the same source, or the second would refuse what the first allowed.
pub struct SystemProbe {
    /// Where the level of a session comes from on this device.
    level_source: LevelSource,
}

impl SystemProbe {
    /// Binds the probe to the level source of the configured OS adapter.
    #[must_use]
    pub const fn new(level_source: LevelSource) -> Self {
        Self { level_source }
    }
}

impl DeviceProbe for SystemProbe {
    fn integrity_level(&self) -> Result<Level, LevelError> {
        self.level_source.read()
    }

    fn boot_markers(&self) -> Result<BootMarkers, std::io::Error> {
        BootMarkers::read()
    }
}

/// The conversation driven against a live PAM handle.
///
/// The handle is held as a raw pointer, so an instance must not outlive the
/// `pam_sm_*` frame that owns it — the same contract
/// [`crate::pam_conv::closure_from_pamh`] carries.
#[cfg(target_os = "linux")]
pub struct PamCodeConversation {
    /// The live PAM handle of the enclosing callback.
    pamh: *mut pam_sys::pam_handle_t,
}

#[cfg(target_os = "linux")]
impl PamCodeConversation {
    /// Bind the conversation to a live PAM handle.
    ///
    /// # Safety
    ///
    /// `pamh` must be the live handle of the current `pam_sm_*` callback, and
    /// the returned value must not outlive that frame.
    #[must_use]
    pub const unsafe fn new(pamh: *mut pam_sys::pam_handle_t) -> Self {
        Self { pamh }
    }
}

#[cfg(target_os = "linux")]
impl CodeConversation for PamCodeConversation {
    fn show_info(&mut self, message: &str) {
        // SAFETY: `self.pamh` is the live PAM handle of the enclosing frame
        // (the contract of `PamCodeConversation::new`).
        if let Err(error) = unsafe { crate::pam_conv::show_info(self.pamh, message) } {
            // A message the application refuses is not a verdict: the login
            // continues, and the journal keeps what the engineer did not see.
            tracing::warn!(
                target: "tessera.codes",
                error = %error,
                "PAM_TEXT_INFO was not delivered",
            );
        }
    }

    fn prompt_visible(&mut self, prompt: &str) -> Result<String, PamConvError> {
        // SAFETY: `self.pamh` is the live PAM handle of the enclosing frame.
        unsafe { crate::pam_conv::prompt_visible(self.pamh, prompt) }
    }

    fn prompt_secret(&mut self, prompt: &str) -> Result<SecretString, PamConvError> {
        // SAFETY: `self.pamh` is the live PAM handle of the enclosing frame.
        unsafe { crate::pam_conv::prompt_pin(self.pamh, prompt) }
    }
}

/// Serialisation of the process-wide audit sink for the tests of this branch.
///
/// The sink is one handle per process, by design — the `emit_*` helpers on the
/// auth path have nowhere to thread one through. That makes it shared mutable
/// state between test threads: a test that installs a journal which refuses
/// records would make every other test that expects a successful login refuse
/// too, and the failure would move around with the scheduler.
///
/// So every path into [`authenticate_by_code`] in the tests takes this lock,
/// and only the two funnels take it — no test holds it itself.
#[cfg(test)]
mod test_sink {
    use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

    /// The lock itself.
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    /// Holds the sink for the duration of one driven attempt.
    ///
    /// A poisoned lock is taken anyway: it means some other test panicked while
    /// holding it, and turning that into a second failure in every test after
    /// it would bury the first one.
    pub(super) fn hold() -> MutexGuard<'static, ()> {
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod live_tests;

#[cfg(test)]
mod tests;
