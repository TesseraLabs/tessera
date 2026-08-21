//! Login by a one-time code read out over the telephone.
//!
//! The engineer stands at an offline device. The device prints a challenge, the
//! engineer reads it to an operator, the operator computes a code in their
//! cabinet and reads it back, the device checks it locally. Nothing in that
//! sequence needs a network, a site or a clock anybody trusts — which is the
//! point, because the device this method exists for is the one nobody can reach
//! any other way.
//!
//! # What this module is, and is not
//!
//! It is the device half of the method: assembling the challenge, holding the
//! one live attempt, checking the operator ticket, deriving the key and
//! verifying the code. It is not the PAM branch — it prompts for
//! nothing, prints nothing and returns no PAM code — and it is not the formula:
//! every byte that both sides have to agree on comes from
//! [`tessera_codes_contract`], and no serialisation, truncation or key
//! derivation is written a second time here.
//!
//! # The two calls
//!
//! The surface is deliberately two functions, so that the PAM branch built on
//! it is thin:
//!
//! - [`CodeMethod::begin`] starts an attempt and hands back the challenge to
//!   print;
//! - [`CodeMethod::verify`] takes the code that was read back and either
//!   accepts it or refuses.
//!
//! # Order of the checks
//!
//! The ticket is checked before any key is derived — signature, term,
//! revocation, then the scope over this device, the role and the level — and
//! whether the device still defines the role is checked after it. Every
//! refusal on that path is one [`CodeLoginError::Denied`]; which step failed
//! goes to the audit journal and not to the caller. The refusals that are *not*
//! denials are the ones an engineer has to act on: an unprovisioned device, a
//! spent attempt budget, a state directory the device cannot read, write or
//! lock.
//!
//! # Where the level ceiling comes from
//!
//! From the operator ticket, and from nowhere else. The ticket bounds the
//! linear level the same way the `MAX_INTEGRITY` extension of a certificate
//! does in the certificate path; a role slice states no such bound, so nothing
//! on the device is read as one. [`Accepted::level_ceiling`] carries it out to
//! the caller, which assembles the session label from it and from the
//! categories the role asks for.
//!
//! # What holds the one-time property
//!
//! One attempt, in memory, for as long as the device holds the lock of its
//! state directory. The nonce is a long random value drawn per attempt, and the
//! attempt — that nonce, the ephemeral private key, the wrong codes it has
//! taken — lives in [`StartedAttempt`] and nowhere else. A code presented for
//! anything but the attempt in hand meets nothing, because there is nothing
//! else to meet: no file remembers a nonce, so no file can be rolled back to
//! make one live again. A reboot, a crash or a snapshot without memory ends the
//! attempt by ending the process that held it.
//!
//! There used to be a persisted counter and a set of spent nonces instead. They
//! were what a snapshot rollback restored — together with the counter that was
//! supposed to detect the rollback, which is why that check compared two values
//! that moved as one. See [`state`], which now persists only the throttle.

pub mod agreement;
pub mod artefacts;
pub mod audit;
pub mod boot;
pub mod draw;
pub mod epoch;
pub mod error;
pub mod lock;
pub mod roles;
pub mod state;
pub mod store;
pub mod throttle;
pub mod tickets;

use std::path::PathBuf;
use std::time::Duration;

use tessera_codes_contract::canon::Level;
use tessera_codes_contract::challenge::{Challenge, ChallengeFields, SignedChallenge};
use tessera_codes_contract::code::verify_code;
use tessera_codes_contract::device_number::CheckedDeviceNumber;
use tessera_codes_contract::key::{
    derive_key, EphemeralKeyAgreement as _, Epoch, KeyAgreement as _, KeyContext,
};
use tessera_codes_contract::nonce::Nonce;
use tessera_codes_contract::params::FleetParams;
use tessera_codes_contract::signature::Signature;
use tessera_codes_contract::ticket::SignedTicket;
use tessera_codes_contract::time::ClaimedTime;

use self::agreement::EphemeralAgreement;
use self::boot::BootMarkers;
use self::lock::StateLock;
use self::state::CodeState;
use self::tickets::{TicketAnchor, TicketRejection, TicketStore};

pub use self::artefacts::{ArtefactError, CodesDelivery, DeliveredKey};
pub use self::error::CodeLoginError;
pub use self::roles::LocalRoles;
pub use self::store::CodesPaths;
pub use self::tickets::DeviceScope;

/// Default local lifetime of a printed challenge.
///
/// The value is a fleet parameter and is not part of the MAC: the two sides
/// agree on a code, not on how long the device is willing to wait for it. It is
/// bounded from both ends by the contract — see
/// [`tessera_codes_contract::params::MAX_ATTEMPT_TTL_SECS`] — and measured
/// against the monotonic markers of the running system, never against the wall
/// clock an engineer can set.
pub const DEFAULT_CODE_TTL: Duration =
    Duration::from_secs(tessera_codes_contract::params::DEFAULT_ATTEMPT_TTL_SECS);

/// Everything the method reads from the configuration of a fleet.
#[derive(Debug, Clone)]
pub struct CodesConfig {
    /// Where the artefacts and the state live.
    pub paths: CodesPaths,
    /// Parameters shared with the operator cabinet.
    pub params: FleetParams,
    /// Number of this device, with its check character.
    pub device_number: CheckedDeviceNumber,
    /// Key epoch of this device.
    pub epoch: Epoch,
    /// The scope of this device, matched against the scope of a ticket.
    pub device_scope: DeviceScope,
    /// Local lifetime of a printed challenge.
    pub code_ttl: Duration,
    /// Path to the GOST engine, forwarded to the key container.
    pub gost_engine_path: Option<PathBuf>,
}

/// What the engineer is asking for.
#[derive(Debug, Clone, Copy)]
pub struct AttemptRequest<'a> {
    /// Role account the engineer is logging into.
    pub role_id: &'a str,
    /// Integrity level being asked for.
    pub level: Level,
    /// Operator on the telephone, as they named themselves.
    pub server_id: &'a str,
    /// Personal number of the engineer at the device, as they gave it.
    ///
    /// It goes into the MAC input, so a code cut for one engineer does not meet
    /// when another presents it. The device checks nothing about the value
    /// itself — there is no register of people on an offline device — and it
    /// does not have to: what the two sides have to agree on is the bytes, and
    /// a number nobody can vouch for still names who was at the keyboard in the
    /// journal of this device.
    pub engineer_id: &'a str,
    /// The moment the device claims, for the term of the ticket.
    pub now: ClaimedTime,
}

/// The one attempt a device holds open.
///
/// Everything about the attempt is here and nowhere else: the challenge, the
/// ephemeral pair its code is derived from, how many wrong codes it has taken,
/// and the exclusive hold on the state directory that keeps a second login from
/// starting a second attempt while this one lives. Nothing is written to disk,
/// so nothing can be brought back after this value is dropped — which is what
/// makes a nonce one-time now that no file remembers one.
///
/// The value is deliberately neither cloneable nor storable, and the lock it
/// carries is released when it is dropped, however the process ends. That it
/// cannot be cloned is checked by the compiler rather than asserted at run
/// time:
///
/// ```compile_fail
/// use tessera_core::codes::{CodeMethod, StartedAttempt};
///
/// fn duplicate(attempt: &StartedAttempt) -> StartedAttempt {
///     // `StartedAttempt` implements no `Clone`: the ephemeral private key and
///     // the lock of the device would be duplicated with it.
///     attempt.clone()
/// }
/// ```
#[derive(Debug)]
pub struct StartedAttempt {
    signed: SignedChallenge,
    ticket_number: String,
    claimed_at: ClaimedTime,
    /// The pair this attempt agreed on; see [`EphemeralAgreement`].
    agreement: EphemeralAgreement,
    /// Whole seconds since boot at the moment the challenge was printed.
    started_since_boot: u64,
    /// Boot the attempt was started under.
    ///
    /// The process cannot outlive its own boot, so this can only differ from
    /// the markers of the moment when something is feeding the method markers
    /// it did not read from the running system. That is refused rather than
    /// reasoned about.
    boot_id: String,
    /// Wrong codes this attempt has already taken.
    attempts_used: u8,
    /// Whether the attempt is over — its code was accepted, or its budget ran
    /// out. A spent attempt answers nothing further.
    spent: bool,
    /// The exclusive hold on the state directory, released with the attempt.
    _lock: StateLock,
}

impl StartedAttempt {
    /// Returns the challenge, for the caller to print.
    #[must_use]
    pub const fn challenge(&self) -> &Challenge {
        self.signed.challenge()
    }

    /// Returns the challenge together with the signature of this device.
    ///
    /// This is what travels to the issuing side: the challenge alone is a set
    /// of values anybody can type, and the issuing side has no way to tell it
    /// from one a device stated.
    #[must_use]
    pub const fn signed_challenge(&self) -> &SignedChallenge {
        &self.signed
    }

    /// Returns the challenge in the grouped form it is read aloud in.
    #[must_use]
    pub fn spoken_form(&self) -> String {
        self.signed.spoken_form()
    }

    /// Returns the number of the ticket the operator is working under.
    #[must_use]
    pub fn ticket_number(&self) -> &str {
        &self.ticket_number
    }

    /// Returns the request this attempt was started for.
    ///
    /// Rebuilt from the challenge rather than taken from a caller a second
    /// time: what the code was computed over is what the challenge says, and a
    /// role or a level supplied again could disagree with it. The moment is the
    /// one the attempt was admitted at, so that a call outliving the term of a
    /// ticket is refused by the term of the ticket rather than by a second
    /// reading of a clock the device does not trust.
    fn request(&self) -> AttemptRequest<'_> {
        AttemptRequest {
            role_id: self.challenge().role_id(),
            level: self.challenge().level(),
            server_id: self.challenge().server_id(),
            engineer_id: self.challenge().engineer_id(),
            now: self.claimed_at,
        }
    }
}

/// A code that was accepted.
///
/// # Why no success event is emitted here
///
/// A code that meets is not yet a login. After this value is returned the
/// caller still re-reads the integrity level and compares it with the
/// challenge, fixes the role payload, and registers the session with the
/// daemon — any of which can refuse, and the strict monitoring mode does. An
/// event written here would record a successful login for an attempt that ends
/// in a PAM refusal, and the reconciliation an auditor performs is precisely
/// between the logins a fleet saw and the receipts its operators wrote: a
/// success that never happened makes an operator receipt look paired when it
/// is not.
///
/// So the success event is the caller's to emit, once nothing is left that can
/// refuse — see [`audit::emit_success`], which takes exactly the fields this
/// value carries. Refusals stay here, because a refusal *is* the end of the
/// attempt at the point it is discovered.
#[derive(Debug, Clone)]
pub struct Accepted {
    /// Role account the code granted.
    pub role_id: String,
    /// Level the code granted.
    pub level: Level,
    /// Highest linear level the admitting ticket reaches.
    ///
    /// The ceiling of the ticket, not the level of this login: it is what the
    /// operator was authorised to hand out, and it plays in this path the part
    /// the `MAX_INTEGRITY` extension of a certificate plays in the other one.
    /// The caller builds the ceiling of the session label out of it — nothing
    /// on the device states a linear bound of its own.
    pub level_ceiling: Level,
    /// Number of the ticket the operator worked under.
    pub ticket_number: String,
    /// The nonce the code was computed over.
    ///
    /// Carried out so the caller can name it in the audit event it emits when
    /// the login has fully succeeded — see [`Accepted`]'s note on why this
    /// module does not emit that event itself.
    pub nonce_ref: String,
    /// Personal number of the engineer, as they gave it.
    ///
    /// Carried out for the same reason as the nonce, and named "claimed" for
    /// the reason stated on
    /// [`AttemptRequest::engineer_id`]: the device checks nothing about it and
    /// the journal must not imply otherwise.
    pub claimed_engineer_no: String,
}

/// The code login method on one device.
pub struct CodeMethod {
    config: CodesConfig,
    roles: LocalRoles,
    tickets: TicketStore,
    anchor: TicketAnchor,
}

impl CodeMethod {
    /// Opens the method against the artefacts of the device.
    ///
    /// The ticket set, its revocation list and the trust anchor are read here,
    /// once per attempt, so a revocation list delivered between two logins
    /// takes effect at the next one — the same order a certificate revocation
    /// list is applied in.
    ///
    /// # Errors
    ///
    /// [`CodeLoginError::Unavailable`] when the device carries no artefacts of
    /// the method or no ticket, and [`CodeLoginError::State`] when the
    /// artefacts are present but unreadable.
    pub fn open(config: CodesConfig, roles: LocalRoles) -> Result<Self, CodeLoginError> {
        Self::open_inner(config, roles, false)
    }

    /// Opens the method, first checking that nothing an attacker could have
    /// weakened is in the path of its artefacts.
    ///
    /// This is the entry a live device uses. Every artefact and the state
    /// directory are walked with the same ownership policy the role store is
    /// loaded under: each component owned by root (or by the account the
    /// process is running as), and no group- or other-write bit anywhere. A
    /// device whose key container became group-writable does not offer the
    /// method — the artefacts are the whole of what the method trusts, so
    /// permissions that would let somebody else rewrite them are not a warning.
    ///
    /// [`CodeMethod::open`] skips the walk and exists for tests, which run out
    /// of a temporary directory that no ownership policy would accept. That
    /// split is the same one [`crate::role::RoleStore::load`] and
    /// `load_privileged` already draw.
    ///
    /// # Errors
    ///
    /// [`CodeLoginError::Unavailable`] as [`CodeMethod::open`], and
    /// [`CodeLoginError::State`] when a path does not satisfy the policy.
    pub fn open_privileged(config: CodesConfig, roles: LocalRoles) -> Result<Self, CodeLoginError> {
        Self::open_inner(config, roles, true)
    }

    /// Shared body of the two entries.
    fn open_inner(
        mut config: CodesConfig,
        roles: LocalRoles,
        privileged: bool,
    ) -> Result<Self, CodeLoginError> {
        // Answered before a single artefact is read, because it is decided by
        // the platform rather than by anything on disk. The store walk would
        // refuse a moment later anyway — `fs_mode` cannot pin a mode here — but
        // it would refuse as a device in a broken state, and this device is not
        // broken: the method does not exist on this platform. A stack can step
        // over "no method here" and reach the certificate path; it cannot step
        // over "this device is faulty".
        platform_offers_the_method()?;

        if !config.paths.artefacts_present() {
            return Err(CodeLoginError::Unavailable);
        }
        // The state directory is created before anything is asked of an
        // engineer. Leaving it to the first write meant the method announced
        // itself, printed a challenge, took an operator's name and only then
        // failed on a directory that was never there.
        if let Err(error) = std::fs::create_dir_all(&config.paths.state_dir) {
            audit::emit_denied(&artefact_refusal(config.epoch));
            return Err(CodeLoginError::State {
                reason: format!(
                    "the code state directory {} could not be created: {error}",
                    config.paths.state_dir.display()
                ),
            });
        }
        // Which key the store holds is a fact of the store, not of the
        // configuration: an import that rotated the key moved the persisted
        // epoch forward and never touched `config.toml`. See
        // [`epoch::effective`] for why the store wins and why the reverse
        // ordering refuses instead.
        let persisted_epoch = epoch::read(&config.paths.state_dir).map_err(|error| {
            audit::emit_denied(&artefact_refusal(config.epoch));
            CodeLoginError::State {
                reason: format!("the persisted key epoch could not be read: {error}"),
            }
        })?;
        config.epoch = epoch::effective(config.epoch, persisted_epoch).map_err(|error| {
            audit::emit_denied(&artefact_refusal(config.epoch));
            CodeLoginError::State {
                reason: error.to_string(),
            }
        })?;
        if privileged {
            config.paths.check_trusted().map_err(|reason| {
                audit::emit_denied(&artefact_refusal(config.epoch));
                CodeLoginError::State { reason }
            })?;
        }
        let tickets = TicketStore::load(&config.paths.tickets, &config.paths.ticket_revocations)
            .map_err(|error| {
                audit::emit_denied(&artefact_refusal(config.epoch));
                CodeLoginError::State {
                    reason: error.to_string(),
                }
            })?;
        if tickets.is_empty() {
            return Err(CodeLoginError::Unavailable);
        }
        let anchor = TicketAnchor::load(&config.paths.ticket_authority).map_err(|error| {
            audit::emit_denied(&artefact_refusal(config.epoch));
            CodeLoginError::State {
                reason: error.to_string(),
            }
        })?;

        Ok(Self {
            config,
            roles,
            tickets,
            anchor,
        })
    }

    /// The key epoch this method is actually running under.
    ///
    /// **Not** necessarily the one `config.toml` names. When the persisted
    /// epoch of the store is ahead — an import rotated the key and never
    /// touched the configuration — [`epoch::effective`] picks the store's, and
    /// that is the epoch every code is derived under.
    ///
    /// It is exposed because the caller emits audit events of its own, and a
    /// caller reading the configured value would write one epoch into the
    /// journal while this module wrote another, for the same login, in exactly
    /// the situation the effective-epoch selection exists to handle. The
    /// journal of one login has to agree with itself.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.config.epoch
    }

    /// Starts an attempt and returns the challenge to read out.
    ///
    /// # Errors
    ///
    /// See [`CodeMethod::begin_with_markers`]; this call additionally returns
    /// [`CodeLoginError::BootMarkers`] when the markers of the running system
    /// cannot be read.
    pub fn begin(&self, request: &AttemptRequest<'_>) -> Result<StartedAttempt, CodeLoginError> {
        self.begin_with_markers(request, &read_markers()?)
    }

    /// Starts an attempt against explicit boot markers.
    ///
    /// # Errors
    ///
    /// [`CodeLoginError::Denied`] when the ticket or the local role definition
    /// does not admit the request, [`CodeLoginError::Rng`] when the system
    /// generator refuses, [`CodeLoginError::TemporarilyLocked`] when the
    /// issuance budget of this device is spent, and [`CodeLoginError::State`]
    /// when the state cannot be read or written — which includes another login
    /// already holding an attempt open on this device.
    pub fn begin_with_markers(
        &self,
        request: &AttemptRequest<'_>,
        markers: &BootMarkers,
    ) -> Result<StartedAttempt, CodeLoginError> {
        let ticket = self.admit(request)?;
        let ticket_number = ticket.ticket().number().as_str().to_owned();

        // The key of the device is what a challenge is stated by: it is the
        // device's own identity in this channel, and the artefact policy makes
        // it mandatory. It no longer derives the code — that is the ephemeral
        // pair below — it signs the challenge, and the issuing side answers
        // nothing it cannot attribute to a registered device. Opened here, at
        // the top: a container that will not open costs the engineer a refusal
        // now instead of one after the whole conversation.
        let device_key = self.device_key()?;

        // Taken here and handed to the attempt: the hold lives as long as the
        // attempt does, so a device carries one live attempt and not eight. A
        // console login and an SSH session arriving together is the normal case
        // on a device reachable both ways, and the second of them is refused
        // while the first is being answered rather than given an attempt of its
        // own. See [`lock`].
        let held = self.lock()?;
        let mut state = self.load_state(markers)?;

        // Before anything is drawn or printed. The challenge leaves the device
        // before any code comes back, so every call reaching this point costs
        // the device an ephemeral pair and the only attempt slot it has; a
        // limit applied afterwards would be no limit at all.
        if let Some(retry_after) = state
            .throttle()
            .check_issue(request.role_id, markers.since_boot_secs())
            .wait()
        {
            return Err(self.throttled(
                request,
                Some(&ticket_number),
                retry_after,
                audit::REASON_ISSUANCE_THROTTLED,
            ));
        }

        // Drawn, never counted. The value is the whole of what separates this
        // attempt from every other, so a generator that will not answer stops
        // the attempt here rather than yielding something predictable.
        let drawn = draw::draw_nonce(&self.config.params).map_err(|error| match error {
            draw::DrawError::Rng { reason } => CodeLoginError::Rng { reason },
            draw::DrawError::Exhausted => CodeLoginError::Rng {
                reason: error.to_string(),
            },
        })?;
        let nonce =
            Nonce::parse(&drawn, &self.config.params).map_err(|error| CodeLoginError::State {
                reason: format!("the drawn nonce does not fit the fleet parameters: {error}"),
            })?;

        // Generated for this attempt and no other. The public half goes into
        // the challenge, so the issuing side agrees against the pair of the
        // attempt in front of it; the private half stays in this process and
        // dies with the login.
        let agreement =
            EphemeralAgreement::generate(self.config.params.profile()).map_err(|error| {
                CodeLoginError::State {
                    reason: format!("the ephemeral pair of the attempt could not be made: {error}"),
                }
            })?;

        let challenge = Challenge::new(ChallengeFields {
            device_number: self.config.device_number.clone(),
            epoch: self.config.epoch,
            nonce,
            role_id: request.role_id,
            level: request.level,
            server_id: request.server_id,
            engineer_id: request.engineer_id,
            ephemeral_point: agreement.public_point().clone(),
        })
        .map_err(|error| CodeLoginError::State {
            reason: error.to_string(),
        })?;

        // Signed by the key the registry holds for this device, over the
        // challenge as a whole. The signature says nothing about who is
        // standing at the device and does not stand between anyone and a code
        // — see `SignedChallenge` — it says only that these values were stated
        // by this device and not composed by a caller.
        let signature = sign_challenge(&device_key, &challenge)?;

        // Counted once the challenge exists: a request refused for any other
        // reason cost the device nothing, and charging it would let a stranger
        // naming an operator nobody holds keep an engineer waiting.
        state.throttle_mut().note_issued(markers.since_boot_secs());
        state
            .save(&self.config.paths.state_dir)
            .map_err(|error| CodeLoginError::State {
                reason: error.to_string(),
            })?;

        Ok(StartedAttempt {
            signed: SignedChallenge::new(challenge, signature),
            ticket_number,
            claimed_at: request.now,
            agreement,
            started_since_boot: markers.since_boot_secs(),
            boot_id: markers.boot_id().to_owned(),
            attempts_used: 0,
            spent: false,
            _lock: held,
        })
    }

    /// Verifies the code that was read back.
    ///
    /// # Errors
    ///
    /// See [`CodeMethod::verify_with_markers`]; this call additionally returns
    /// [`CodeLoginError::BootMarkers`] when the markers of the running system
    /// cannot be read.
    pub fn verify(
        &self,
        attempt: &mut StartedAttempt,
        presented: &str,
    ) -> Result<Accepted, CodeLoginError> {
        self.verify_with_markers(attempt, presented, &read_markers()?)
    }

    /// Verifies the code against explicit boot markers.
    ///
    /// The attempt is taken by exclusive reference because verifying spends
    /// something of it: the budget of wrong codes it has left, and — on the
    /// last of them or on success — the attempt itself. Nothing about it is
    /// written down, so the value in hand is the only record there is.
    ///
    /// # Errors
    ///
    /// [`CodeLoginError::Denied`] when the code does not meet, the attempt is
    /// no longer open, its local lifetime has passed, or the ticket stopped
    /// admitting the request; [`CodeLoginError::AttemptsExhausted`] when the
    /// budget of the attempt is spent; [`CodeLoginError::State`] for the
    /// persisted throttle.
    pub fn verify_with_markers(
        &self,
        attempt: &mut StartedAttempt,
        presented: &str,
        markers: &BootMarkers,
    ) -> Result<Accepted, CodeLoginError> {
        // Copied out of the attempt rather than borrowed from it: the attempt is
        // charged below, and a borrow of the challenge would hold it still.
        let nonce = attempt.challenge().nonce().as_str().to_owned();
        let ticket_number = attempt.ticket_number.clone();
        let role_id = attempt.challenge().role_id().to_owned();
        let server_id = attempt.challenge().server_id().to_owned();
        let engineer_id = attempt.challenge().engineer_id().to_owned();
        let request = AttemptRequest {
            role_id: &role_id,
            level: attempt.challenge().level(),
            server_id: &server_id,
            engineer_id: &engineer_id,
            now: attempt.claimed_at,
        };

        // The lock of the state directory is already held — the attempt owns it
        // — so what is loaded here is the throttle, and the writes below are
        // covered by the same hold.
        let mut state = self.load_state(markers)?;
        if let Some(retry_after) = state
            .throttle()
            .check_verify(request.role_id, markers.since_boot_secs())
            .wait()
        {
            return Err(self.throttled(
                &request,
                Some(&ticket_number),
                retry_after,
                audit::REASON_ROLE_LOCKED,
            ));
        }
        self.refuse_unless_live(&mut state, attempt, markers)?;
        // The ticket is checked again before anything is derived: a code is
        // computed only under a ticket that admits the request, and the check
        // that happened when the challenge was printed is not the check that
        // guards the computation.
        let ticket = self.admit(&request)?;

        let level_ceiling = ticket.ticket().scope().max_level();

        // The attempt is charged BEFORE the code is looked at. Charging
        // afterwards would make the budget depend on this process living long
        // enough to record what it just learned — and here the record is the
        // process, so a caller that cuts it off between the comparison and the
        // charge would get the guess for free.
        attempt.attempts_used = attempt.attempts_used.saturating_add(1);
        let used = attempt.attempts_used;

        let accepted = self.code_meets(ticket, attempt, presented);
        match accepted {
            Ok(true) => {
                // The attempt is over: a code that was accepted is not offered
                // to a second verification, and the value carrying the attempt
                // is what says so.
                attempt.spent = true;
                state.throttle_mut().note_success(request.role_id);
                self.save_state(&state)?;
                // No success event here: the login is not over. See the note
                // on `Accepted` — the caller emits it once nothing is left
                // that can still refuse.
                Ok(Accepted {
                    role_id: request.role_id.to_owned(),
                    level: request.level,
                    level_ceiling,
                    ticket_number: ticket_number.clone(),
                    nonce_ref: nonce.clone(),
                    claimed_engineer_no: engineer_id.clone(),
                })
            }
            Ok(false) => {
                // A wrong code inside the budget is not a failed attempt: the
                // budget is what bounds it, and arming the role lock here would
                // take the remaining tries away from the engineer the fleet
                // parameters granted them to. The attempt is counted where it
                // ends — in `exhaust`.
                if used >= self.config.params.attempts_per_nonce() {
                    return Err(self.exhaust(&mut state, attempt, markers.since_boot_secs()));
                }
                // The run of failures this wrong code just extended has to
                // reach the disk. What the throttle learned from the answer is
                // written here, and a lock that lives only in this process
                // locks nothing.
                self.save_state(&state)?;
                Err(self.deny(
                    &request,
                    Some(&nonce),
                    Some(&ticket_number),
                    audit::REASON_CODE_MISMATCH,
                ))
            }
            // A key that could not be assembled is not a wrong code: it costs
            // the engineer no attempt, and it is the device's failure to state.
            // The charge above is given back here rather than skipped there —
            // an attempt is charged before anybody knows what it will turn out
            // to be, and the direction to fail in is the one that costs an
            // attempt rather than the one that hands out a free guess.
            Err(reason) => {
                attempt.attempts_used = attempt.attempts_used.saturating_sub(1);
                Err(self.deny(&request, Some(&nonce), Some(&ticket_number), reason))
            }
        }
    }

    /// Refuses unless the attempt in hand is still open.
    ///
    /// Everything here refuses before a key is derived, and every one of these
    /// refusals is about the attempt rather than about the code: an attempt
    /// whose code was already accepted or whose budget ran out, and a challenge
    /// older than the device is willing to wait for.
    ///
    /// There is no check for "a nonce nobody is holding open" any more, and its
    /// absence is the point: the only way to reach this function is to hold the
    /// attempt, so a nonce nobody holds cannot be presented at all.
    fn refuse_unless_live(
        &self,
        state: &mut CodeState,
        attempt: &StartedAttempt,
        markers: &BootMarkers,
    ) -> Result<(), CodeLoginError> {
        let request = attempt.request();
        let nonce = attempt.challenge().nonce().as_str().to_owned();

        if attempt.spent {
            return Err(self.deny(
                &request,
                Some(&nonce),
                Some(&attempt.ticket_number),
                audit::REASON_ATTEMPT_SPENT,
            ));
        }
        if attempt.attempts_used >= self.config.params.attempts_per_nonce() {
            return Err(self.exhaust(state, attempt, markers.since_boot_secs()));
        }
        // A different boot means these markers were not read from the system
        // this attempt was started on: the attempt lives in the memory of one
        // process, and a process does not outlive its own boot. The device
        // whose monotonic clock was dragged backwards lands here too, as an
        // attempt that claims to have started after the present moment.
        let stale_markers = attempt.boot_id != markers.boot_id()
            || attempt.started_since_boot > markers.since_boot_secs();
        let age = markers
            .since_boot_secs()
            .saturating_sub(attempt.started_since_boot);
        if stale_markers || age > self.config.code_ttl.as_secs() {
            return Err(self.deny(
                &request,
                Some(&nonce),
                Some(&attempt.ticket_number),
                audit::REASON_TTL,
            ));
        }

        Ok(())
    }

    /// Checks the ticket and then the local role base, in that order.
    ///
    /// The ticket answers both the role and the level; the device answers only
    /// whether it still defines the role, which is the residual bound a role
    /// base narrowed after the code was cut would otherwise slip past.
    fn admit(&self, request: &AttemptRequest<'_>) -> Result<&SignedTicket, CodeLoginError> {
        // Looked up before the check so that a refusal can name it: which
        // ticket was rejected is the field the journal is reconciled by, and
        // `admit` reports only that something failed.
        let number = self
            .tickets
            .ticket_number_of(request.server_id)
            .map(str::to_owned);
        let ticket = self
            .tickets
            .admit(request, &self.config.device_scope, &self.anchor)
            .map_err(|rejection: TicketRejection| {
                self.deny(request, None, number.as_deref(), rejection.audit_reason())
            })?;

        if !self.roles.holds(request.role_id) {
            return Err(self.deny(request, None, number.as_deref(), audit::REASON_ROLE_UNKNOWN));
        }
        Ok(ticket)
    }

    /// Refuses unless the key container of this device still opens.
    ///
    /// Nothing a person typed opens this container, and nothing the
    /// configuration holds either: the stored key carries no password, and what
    /// guards it is the mode and ownership the method has already checked — see
    /// `store::load_device_key`.
    fn device_key(&self) -> Result<openssl::pkey::PKey<openssl::pkey::Private>, CodeLoginError> {
        store::load_device_key(
            &self.config.paths.device_key_container,
            self.config.gost_engine_path.as_deref(),
        )
        .map_err(|error| {
            tracing::warn!(
                target: "codes.audit",
                error = %error,
                "the device key container did not open"
            );
            CodeLoginError::State {
                reason: format!("the device key container did not open: {error}"),
            }
        })
    }

    /// Recomputes the code and reports whether the presented one meets it.
    ///
    /// The exchange goes on the ephemeral pair the attempt was started with and
    /// the key of the ticket. The long-lived key of this device takes no part:
    /// a code that could be derived from it could be derived by whoever holds a
    /// copy of the disk, and then the issuing side is not in the loop at all.
    ///
    /// The error side names the audit reason of a device-side failure — a peer
    /// point the profile rejects, a ticket that will not encode — which is
    /// never a wrong code and never costs an attempt.
    fn code_meets(
        &self,
        ticket: &SignedTicket,
        attempt: &StartedAttempt,
        presented: &str,
    ) -> Result<bool, &'static str> {
        let secret = attempt
            .agreement
            .agree(ticket.ticket().public_key().as_bytes())
            .map_err(|error| {
                tracing::warn!(
                    target: "codes.audit",
                    error = %error,
                    "the key agreement with the ticket key failed"
                );
                audit::REASON_KEY_MATERIAL
            })?;

        let ticket_hash = ticket.context_hash().map_err(|error| {
            tracing::warn!(
                target: "codes.audit",
                error = %error,
                "the ticket could not be encoded for the key context"
            );
            audit::REASON_KEY_MATERIAL
        })?;
        let context = KeyContext::new(&self.config.device_number, ticket_hash);
        let key = derive_key(&secret, &context).map_err(|error| {
            tracing::warn!(
                target: "codes.audit",
                error = %error,
                "the shared key could not be derived"
            );
            audit::REASON_KEY_MATERIAL
        })?;

        Ok(verify_code(
            &key,
            &attempt.challenge().code_input(),
            &self.config.params,
            presented,
        )
        .is_ok())
    }

    /// Takes the exclusive hold on the state of this device.
    ///
    /// The guard is held for a whole transaction — load, mutate, save — rather
    /// than around each write. The writes were always atomic; what was missing
    /// is that the value written was computed from a snapshot another process
    /// had already made stale.
    fn lock(&self) -> Result<lock::StateLock, CodeLoginError> {
        lock::StateLock::acquire(&self.config.paths.state_dir).map_err(|error| {
            CodeLoginError::State {
                reason: format!("the code state of this device could not be locked: {error}"),
            }
        })
    }

    /// Loads the persisted state, mapping its failures to the method's.
    ///
    /// What is persisted is the throttle and nothing else, so there is no
    /// rollback to detect here any more: the file the load used to compare
    /// against a counter came back from a snapshot together with that counter.
    fn load_state(&self, markers: &BootMarkers) -> Result<CodeState, CodeLoginError> {
        CodeState::load(&self.config.paths.state_dir, markers).map_err(|error| {
            CodeLoginError::State {
                reason: error.to_string(),
            }
        })
    }

    /// Persists the state, mapping its failures to the method's.
    fn save_state(&self, state: &CodeState) -> Result<(), CodeLoginError> {
        state
            .save(&self.config.paths.state_dir)
            .map_err(|error| CodeLoginError::State {
                reason: error.to_string(),
            })
    }

    /// Records a refusal in the journal and returns the one error a caller sees.
    fn deny(
        &self,
        request: &AttemptRequest<'_>,
        nonce: Option<&str>,
        ticket_number: Option<&str>,
        reason: &str,
    ) -> CodeLoginError {
        audit::emit_denied(&audit::Denial {
            nonce,
            role_id: request.role_id,
            level: request.level.get(),
            epoch: self.config.epoch.get(),
            ticket_number,
            claimed_engineer_no: Some(request.engineer_id),
            reason,
        });
        CodeLoginError::Denied
    }

    /// Records a temporary refusal in the journal and returns it.
    ///
    /// Separate from [`CodeMethod::deny`] on purpose: a denial says the attempt
    /// was wrong, while this says the device is not answering yet and will.
    /// Folding them together would leave an engineer at a machine unable to
    /// tell "wait" from "this will never work".
    fn throttled(
        &self,
        request: &AttemptRequest<'_>,
        ticket_number: Option<&str>,
        retry_after: Duration,
        reason: &str,
    ) -> CodeLoginError {
        audit::emit_denied(&audit::Denial {
            nonce: None,
            role_id: request.role_id,
            level: request.level.get(),
            epoch: self.config.epoch.get(),
            ticket_number,
            claimed_engineer_no: Some(request.engineer_id),
            reason,
        });
        CodeLoginError::TemporarilyLocked { retry_after }
    }

    /// Reports an attempt whose budget of wrong codes ran out.
    ///
    /// The attempt itself is not marked spent here: the caller holds it by
    /// exclusive reference and drops it on this error, which is what ends it.
    /// What has to outlive the process is the run of failures on the role, and
    /// that is what reaches the disk.
    fn exhaust(&self, state: &mut CodeState, attempt: &StartedAttempt, now: u64) -> CodeLoginError {
        let request = attempt.request();
        // A spent budget is a failed attempt on this role, and the run of them
        // is what arms the lock: without this, an attacker starts a fresh
        // conversation with a fresh budget and the per-attempt limit bounds
        // nothing at all.
        state.throttle_mut().note_failure(request.role_id, now);
        if let Err(error) = self.save_state(state) {
            return error;
        }
        audit::emit_attempts_exhausted(
            attempt.challenge().nonce().as_str(),
            request.role_id,
            request.level.get(),
            self.config.epoch.get(),
            &attempt.ticket_number,
            request.engineer_id,
        );
        CodeLoginError::AttemptsExhausted
    }
}

/// The refusal every unusable artefact store writes down.
///
/// Reached before an engineer has been asked for anything: there is no role, no
/// level and no personal number to name, and the journal says so rather than
/// inventing values.
/// Signs a challenge with the long-lived key of this device.
///
/// ECDSA over SHA-256, which is what every document of this channel is verified
/// under on the issuing side. That is a narrower thing than the key agreement
/// profile of the fleet: the profile says how `K` is agreed, and the signature
/// here is checked by code that reads SEC1 points on P-256 and nothing else.
///
/// The consequence is deliberate and belongs at the start of an attempt: a
/// device whose container holds a key this cannot sign with — a ГОСТ key, or an
/// X25519 pair, which has no signature algorithm at all — refuses before an
/// engineer has been asked for anything. Signing with an algorithm the issuing
/// side cannot verify would refuse at the end of the conversation instead, and
/// name the wrong reason when it did.
fn sign_challenge(
    key: &openssl::pkey::PKey<openssl::pkey::Private>,
    challenge: &Challenge,
) -> Result<Signature, CodeLoginError> {
    let message = challenge
        .signing_message()
        .map_err(|error| CodeLoginError::State {
            reason: format!("the challenge could not be encoded for signing: {error}"),
        })?;

    let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), key)
        .map_err(|error| CodeLoginError::State {
            reason: format!("the device key cannot sign the challenge: {error}"),
        })?;
    let der = signer
        .sign_oneshot_to_vec(&message)
        .map_err(|error| CodeLoginError::State {
            reason: format!("the device key did not sign the challenge: {error}"),
        })?;

    Signature::new(der).map_err(|error| CodeLoginError::State {
        reason: format!("the device key produced no signature: {error}"),
    })
}

fn artefact_refusal(epoch: Epoch) -> audit::Denial<'static> {
    audit::Denial {
        nonce: None,
        role_id: audit::UNKNOWN,
        level: 0,
        epoch: epoch.get(),
        ticket_number: None,
        claimed_engineer_no: None,
        reason: audit::REASON_ARTEFACTS,
    }
}

/// Reports whether this platform can carry the method at all.
///
/// The whole method rests on being able to check the permissions of the files
/// it keeps: the device key is stored without a password, because codes have to
/// be verified after a reboot with nobody there to type one, so the permissions
/// are what protect it. Outside Unix there is no mode word — the equivalent is
/// a DACL, and none is written here.
///
/// Written as one function rather than as a `cfg` around the body of
/// [`CodeMethod::open`] so that both platforms compile the same code and only
/// the answer differs: a `cfg` around the body would leave arguments unused and
/// lines unreachable on one side, and every one of those is a warning that has
/// to be silenced somewhere.
#[cfg_attr(
    unix,
    expect(
        clippy::unnecessary_wraps,
        reason = "the Result is not spurious: it is the signature the other arm has, \
                  and the one call site reaches both with `?`. Narrowing this arm to \
                  `()` would move the platform difference from one `cfg` here into the \
                  opening of the method"
    )
)]
fn platform_offers_the_method() -> Result<(), CodeLoginError> {
    #[cfg(unix)]
    {
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(CodeLoginError::UnsupportedPlatform)
    }
}

/// Reads the boot markers, mapping the failure to the method's error.
fn read_markers() -> Result<BootMarkers, CodeLoginError> {
    BootMarkers::read().map_err(|error| CodeLoginError::BootMarkers {
        reason: error.to_string(),
    })
}

// Every test in this module stands up a real store, and a store is what this
// platform cannot carry: the device key is kept without a password — codes are
// verified after a reboot with nobody there to type one — so what protects it
// is the mode of the files beside it, and outside Unix there is no mode word.
// The product answers the same question in `platform_offers_the_method`, and
// the same boundary is stated in `codes::store`, `codes::lock` and the storage
// of `tessera_hashchain`. One gate for the module, because there is not one
// test here that would still mean anything without the store.
#[cfg(all(test, unix))]
mod tests;
