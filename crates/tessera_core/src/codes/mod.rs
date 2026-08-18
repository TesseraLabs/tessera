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
//! It is the device half of the method: assembling the challenge, keeping the
//! nonce counter and the spent nonces, checking the operator ticket, deriving
//! the key and verifying the code. It is not the PAM branch — it prompts for
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
//! spent attempt budget, an exhausted counter, a rolled-back state.
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
//! The nonce is hybrid: a monotonic counter persisted as a single number, plus
//! a random tail drawn from the system generator. The counter never wraps —
//! a device that has used up its width owes a key epoch rotation — and a spent
//! nonce is remembered on disk, so a reboot does not hand a code a second life.
//! A reboot or a monotonic clock dragged backwards invalidates every attempt
//! that was pending, because an attempt whose lifetime cannot be measured is
//! refused rather than extended. See [`state`] for the mechanics.

pub mod agreement;
pub mod artefacts;
pub mod audit;
pub mod boot;
pub mod counter;
pub mod epoch;
pub mod error;
pub mod lock;
pub mod roles;
pub mod state;
pub mod store;
pub mod tail;
pub mod throttle;
pub mod tickets;

use std::path::PathBuf;
use std::time::Duration;

use tessera_codes_contract::canon::Level;
use tessera_codes_contract::challenge::Challenge;
use tessera_codes_contract::code::verify_code;
use tessera_codes_contract::device_number::CheckedDeviceNumber;
use tessera_codes_contract::key::{derive_key, Epoch, KeyAgreement as _, KeyContext};
use tessera_codes_contract::nonce::{Nonce, NonceError};
use tessera_codes_contract::params::FleetParams;
use tessera_codes_contract::ticket::SignedTicket;
use tessera_codes_contract::time::ClaimedTime;

use self::agreement::DeviceKeyAgreement;
use self::boot::BootMarkers;
use self::state::CodeState;
use self::tickets::{TicketAnchor, TicketRejection, TicketStore};

pub use self::artefacts::{ArtefactError, CodesDelivery, DeliveredKey};
pub use self::error::CodeLoginError;
pub use self::roles::LocalRoles;
pub use self::store::CodesPaths;
pub use self::tickets::DeviceScope;

/// Default local lifetime of a printed challenge.
///
/// The value is a device policy and is not part of the MAC: the two sides agree
/// on a code, not on how long the device is willing to wait for it. Measured
/// against the monotonic markers of the running system, never against the wall
/// clock an engineer can set.
pub const DEFAULT_CODE_TTL: Duration = Duration::from_mins(5);

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
    pub operator_id: &'a str,
    /// The moment the device claims, for the term of the ticket.
    pub now: ClaimedTime,
}

/// An attempt that has been started and whose challenge has been issued.
#[derive(Debug, Clone)]
pub struct StartedAttempt {
    challenge: Challenge,
    ticket_number: String,
    claimed_at: ClaimedTime,
}

impl StartedAttempt {
    /// Returns the challenge, for the caller to print.
    #[must_use]
    pub const fn challenge(&self) -> &Challenge {
        &self.challenge
    }

    /// Returns the challenge in the grouped form it is read aloud in.
    #[must_use]
    pub fn spoken_form(&self) -> String {
        self.challenge.spoken_form()
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
            role_id: self.challenge.role_id(),
            level: self.challenge.level(),
            operator_id: self.challenge.operator_id(),
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
            audit::emit_denied(
                None,
                "-",
                0,
                config.epoch.get(),
                None,
                audit::REASON_ARTEFACTS,
            );
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
            audit::emit_denied(
                None,
                "-",
                0,
                config.epoch.get(),
                None,
                audit::REASON_ARTEFACTS,
            );
            CodeLoginError::State {
                reason: format!("the persisted key epoch could not be read: {error}"),
            }
        })?;
        config.epoch = epoch::effective(config.epoch, persisted_epoch).map_err(|error| {
            audit::emit_denied(
                None,
                "-",
                0,
                config.epoch.get(),
                None,
                audit::REASON_ARTEFACTS,
            );
            CodeLoginError::State {
                reason: error.to_string(),
            }
        })?;
        if privileged {
            config.paths.check_trusted().map_err(|reason| {
                audit::emit_denied(
                    None,
                    "-",
                    0,
                    config.epoch.get(),
                    None,
                    audit::REASON_ARTEFACTS,
                );
                CodeLoginError::State { reason }
            })?;
        }
        let tickets = TicketStore::load(&config.paths.tickets, &config.paths.ticket_revocations)
            .map_err(|error| {
                audit::emit_denied(
                    None,
                    "-",
                    0,
                    config.epoch.get(),
                    None,
                    audit::REASON_ARTEFACTS,
                );
                CodeLoginError::State {
                    reason: error.to_string(),
                }
            })?;
        if tickets.is_empty() {
            return Err(CodeLoginError::Unavailable);
        }
        let anchor = TicketAnchor::load(&config.paths.ticket_authority).map_err(|error| {
            audit::emit_denied(
                None,
                "-",
                0,
                config.epoch.get(),
                None,
                audit::REASON_ARTEFACTS,
            );
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
    /// does not admit the request, [`CodeLoginError::CounterExhausted`] when
    /// the nonce counter has used up the width of the fleet parameters,
    /// [`CodeLoginError::StateRollback`] when the persisted state moved
    /// backwards, [`CodeLoginError::Rng`] when the system generator refuses,
    /// and [`CodeLoginError::State`] when the state cannot be read or written.
    pub fn begin_with_markers(
        &self,
        request: &AttemptRequest<'_>,
        markers: &BootMarkers,
    ) -> Result<StartedAttempt, CodeLoginError> {
        let ticket = self.admit(request)?;
        let ticket_number = ticket.ticket().number().as_str().to_owned();

        // Held from here to the end of the call. Two logins running at once —
        // a console and an SSH session, which is the normal case on a device
        // reachable both ways — would otherwise read the same counter and
        // issue the same nonce. See [`lock`].
        let _transaction = self.lock()?;
        let mut state = self.load_state(markers, request, Some(&ticket_number))?;

        // Before the counter, never after it. The challenge is printed before
        // any code is presented, so every call that reaches this point spends
        // one value of a counter that never wraps and never comes back; a limit
        // applied after the value is taken would be no limit at all.
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

        let counter = state
            .next_counter()
            .map_err(|error| CodeLoginError::State {
                reason: error.to_string(),
            })?;
        let tail = tail::draw_tail(&self.config.params).map_err(|error| match error {
            tail::TailError::Rng { reason } => CodeLoginError::Rng { reason },
            tail::TailError::Exhausted => CodeLoginError::Rng {
                reason: error.to_string(),
            },
        })?;
        let nonce =
            Nonce::new(counter, &tail, &self.config.params).map_err(|error| match error {
                NonceError::CounterOverflow { .. } => CodeLoginError::CounterExhausted,
                other => CodeLoginError::State {
                    reason: other.to_string(),
                },
            })?;

        let challenge = Challenge::new(
            self.config.device_number.clone(),
            self.config.epoch,
            nonce,
            request.role_id,
            request.level,
            request.operator_id,
        )
        .map_err(|error| CodeLoginError::State {
            reason: error.to_string(),
        })?;

        // The counter is published before the attempt is recorded: a crash
        // between the two writes burns a nonce, while the reverse order would
        // record an attempt whose counter the device could hand out again.
        counter::write_issued(&self.config.paths.state_dir, counter).map_err(|error| {
            CodeLoginError::State {
                reason: error.to_string(),
            }
        })?;
        state.record_issued(counter, markers.since_boot_secs());
        // Counted once the challenge exists: a request refused for any other
        // reason spent no counter value, and charging it would let a stranger
        // naming an operator nobody holds keep an engineer waiting.
        state.throttle_mut().note_issued(markers.since_boot_secs());
        state
            .save(&self.config.paths.state_dir)
            .map_err(|error| CodeLoginError::State {
                reason: error.to_string(),
            })?;

        Ok(StartedAttempt {
            challenge,
            ticket_number,
            claimed_at: request.now,
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
        attempt: &StartedAttempt,
        presented: &str,
    ) -> Result<Accepted, CodeLoginError> {
        self.verify_with_markers(attempt, presented, &read_markers()?)
    }

    /// Verifies the code against explicit boot markers.
    ///
    /// # Errors
    ///
    /// [`CodeLoginError::Denied`] when the code does not meet, the attempt is
    /// no longer pending, its local lifetime has passed, or the ticket stopped
    /// admitting the request; [`CodeLoginError::AttemptsExhausted`] when the
    /// budget of the nonce is spent; [`CodeLoginError::StateRollback`] and
    /// [`CodeLoginError::State`] for the persisted state.
    pub fn verify_with_markers(
        &self,
        attempt: &StartedAttempt,
        presented: &str,
        markers: &BootMarkers,
    ) -> Result<Accepted, CodeLoginError> {
        let challenge = &attempt.challenge;
        let request = attempt.request();
        let nonce = challenge.nonce().as_str().to_owned();
        let counter = challenge.nonce().counter();

        // Held from here to the end of the call, key agreement included. The
        // attempt budget is a read-modify-write against a file every login on
        // this device shares: without the lock a second process writing back
        // an older snapshot resets `attempts_used` to zero, and a budget that
        // can be reset is not a budget. See [`lock`].
        let _transaction = self.lock()?;
        let mut state = self.load_state(markers, &request, Some(&attempt.ticket_number))?;
        if let Some(retry_after) = state
            .throttle()
            .check_verify(request.role_id, markers.since_boot_secs())
            .wait()
        {
            return Err(self.throttled(
                &request,
                Some(&attempt.ticket_number),
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

        // The attempt is taken from the budget and written down BEFORE the code
        // is looked at. Charging afterwards makes the budget depend on this
        // process living long enough to record what it just learned: a caller
        // who cuts the process off between the comparison and the write gets
        // the guess for free and the budget back, and there is no lockout
        // anywhere else in this method that would notice.
        let used = state.charge_attempt(counter).unwrap_or(u8::MAX);
        self.save_state(&state)?;

        let accepted = self.code_meets(ticket, challenge, presented);
        match accepted {
            Ok(true) => {
                state.throttle_mut().note_success(request.role_id);
                state.consume(counter);
                self.save_state(&state)?;
                // No success event here: the login is not over. See the note
                // on `Accepted` — the caller emits it once nothing is left
                // that can still refuse.
                Ok(Accepted {
                    role_id: request.role_id.to_owned(),
                    level: request.level,
                    level_ceiling,
                    ticket_number: attempt.ticket_number.clone(),
                    nonce_ref: nonce.clone(),
                })
            }
            Ok(false) => {
                // A wrong code inside the budget is not a failed attempt: the
                // budget is what bounds it, and arming the role lock here would
                // take the remaining tries away from the engineer the fleet
                // parameters granted them to. The attempt is counted where it
                // ends — in `exhaust`.
                if used >= self.config.params.attempts_per_nonce() {
                    return Err(self.exhaust(
                        &mut state,
                        &request,
                        &SpentAttempt {
                            counter,
                            nonce: &nonce,
                            ticket_number: &attempt.ticket_number,
                        },
                        markers.since_boot_secs(),
                    ));
                }
                // The run of failures this wrong code just extended has to
                // reach the disk. The charge was written before the comparison;
                // what the throttle learned from the answer is written here,
                // and a lock that lives only in this process locks nothing.
                self.save_state(&state)?;
                Err(self.deny(
                    &request,
                    Some(&nonce),
                    Some(&attempt.ticket_number),
                    audit::REASON_CODE_MISMATCH,
                ))
            }
            // A key that could not be assembled is not a wrong code: it costs
            // the engineer no attempt, and it is the device's failure to state.
            // The charge above is given back here rather than skipped there —
            // an attempt is charged before anybody knows what it will turn out
            // to be, and a refund that fails to reach the disk costs one
            // attempt, which is the direction this must fail in.
            Err(reason) => {
                state.refund_attempt(counter);
                if let Err(error) = self.save_state(&state) {
                    tracing::warn!(
                        target: "codes.audit",
                        error = %error,
                        "the attempt charged for a device-side failure could not be given back"
                    );
                }
                Err(self.deny(&request, Some(&nonce), Some(&attempt.ticket_number), reason))
            }
        }
    }

    /// Refuses unless this code still belongs to an attempt the device is
    /// holding open for it.
    ///
    /// Everything here refuses before a key is derived, and every one of these
    /// refusals is about the attempt rather than about the code: a nonce
    /// already spent, a nonce nobody is holding open, a budget that ran out, a
    /// challenge older than the device is willing to wait for.
    fn refuse_unless_live(
        &self,
        state: &mut CodeState,
        attempt: &StartedAttempt,
        markers: &BootMarkers,
    ) -> Result<(), CodeLoginError> {
        let request = attempt.request();
        let nonce = attempt.challenge.nonce().as_str().to_owned();
        let counter = attempt.challenge.nonce().counter();

        if state.is_consumed(counter) {
            return Err(self.deny(
                &request,
                Some(&nonce),
                Some(&attempt.ticket_number),
                audit::REASON_NONCE_CONSUMED,
            ));
        }
        let Some(pending) = state.pending(counter) else {
            return Err(self.deny(
                &request,
                Some(&nonce),
                Some(&attempt.ticket_number),
                audit::REASON_NO_PENDING_ATTEMPT,
            ));
        };
        if pending.attempts_used >= self.config.params.attempts_per_nonce() {
            return Err(self.exhaust(
                state,
                &request,
                &SpentAttempt {
                    counter,
                    nonce: &nonce,
                    ticket_number: &attempt.ticket_number,
                },
                markers.since_boot_secs(),
            ));
        }
        let age = markers
            .since_boot_secs()
            .saturating_sub(pending.started_since_boot);
        if age > self.config.code_ttl.as_secs() {
            state.consume(counter);
            self.save_state(state)?;
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
            .ticket_number_of(request.operator_id)
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

    /// Recomputes the code and reports whether the presented one meets it.
    ///
    /// The error side names the audit reason of a device-side failure — a key
    /// container that would not open, a peer point the profile rejects — which
    /// is never a wrong code and never costs an attempt.
    fn code_meets(
        &self,
        ticket: &SignedTicket,
        challenge: &Challenge,
        presented: &str,
    ) -> Result<bool, &'static str> {
        // Nothing a person typed opens this container, and nothing the
        // configuration holds either: the stored key carries no password, and
        // what guards it is the mode and ownership the method has already
        // checked — see `store::load_device_key`.
        let device_key = store::load_device_key(
            &self.config.paths.device_key_container,
            self.config.gost_engine_path.as_deref(),
        )
        .map_err(|error| {
            tracing::warn!(
                target: "codes.audit",
                error = %error,
                "the device key container did not open"
            );
            audit::REASON_KEY_MATERIAL
        })?;

        let agreement = DeviceKeyAgreement::new(&device_key, self.config.params.profile())
            .map_err(|error| {
                tracing::warn!(
                    target: "codes.audit",
                    error = %error,
                    "the device key agreement could not be set up"
                );
                audit::REASON_KEY_MATERIAL
            })?;
        let secret = agreement
            .agree(ticket.ticket().public_key().as_bytes())
            .map_err(|error| {
                tracing::warn!(
                    target: "codes.audit",
                    error = %error,
                    "the key agreement with the operator key failed"
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
        let context = KeyContext::new(&self.config.device_number, self.config.epoch, ticket_hash);
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
            &challenge.code_input(),
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
    fn load_state(
        &self,
        markers: &BootMarkers,
        request: &AttemptRequest<'_>,
        ticket_number: Option<&str>,
    ) -> Result<CodeState, CodeLoginError> {
        CodeState::load(&self.config.paths.state_dir, markers).map_err(|error| match error {
            state::StateError::Rollback => {
                audit::emit_denied(
                    None,
                    request.role_id,
                    request.level.get(),
                    self.config.epoch.get(),
                    ticket_number,
                    audit::REASON_ARTEFACTS,
                );
                CodeLoginError::StateRollback
            }
            other => CodeLoginError::State {
                reason: other.to_string(),
            },
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
        audit::emit_denied(
            nonce,
            request.role_id,
            request.level.get(),
            self.config.epoch.get(),
            ticket_number,
            reason,
        );
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
        audit::emit_denied(
            None,
            request.role_id,
            request.level.get(),
            self.config.epoch.get(),
            ticket_number,
            reason,
        );
        CodeLoginError::TemporarilyLocked { retry_after }
    }

    /// Spends the nonce whose attempt budget ran out and reports it.
    fn exhaust(
        &self,
        state: &mut CodeState,
        request: &AttemptRequest<'_>,
        spent: &SpentAttempt<'_>,
        now: u64,
    ) -> CodeLoginError {
        let SpentAttempt {
            counter,
            nonce,
            ticket_number,
        } = *spent;
        // A spent budget is a failed attempt on this role, and the run of them
        // is what arms the lock: without this, an attacker starts a fresh
        // conversation with a fresh budget and the per-nonce limit bounds
        // nothing at all.
        state.throttle_mut().note_failure(request.role_id, now);
        // The nonce is spent as well as reported: a budget that ran out must
        // not be refilled by starting the conversation again on the same
        // challenge.
        state.consume(counter);
        if let Err(error) = self.save_state(state) {
            return error;
        }
        audit::emit_attempts_exhausted(
            nonce,
            request.role_id,
            request.level.get(),
            self.config.epoch.get(),
            ticket_number,
        );
        CodeLoginError::AttemptsExhausted
    }
}

/// The attempt whose budget ran out, as the journal names it.
///
/// The three values travel together because two of them are strings of the same
/// shape — the nonce and the ticket number — and they are exactly the pair the
/// journal is reconciled by, so a call site that swapped them would produce
/// records that pair with nothing and say so nowhere.
struct SpentAttempt<'a> {
    /// Counter half of the nonce.
    counter: u64,
    /// Nonce as it was read out.
    nonce: &'a str,
    /// Number of the ticket the operator worked under.
    ticket_number: &'a str,
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
