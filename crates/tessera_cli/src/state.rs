//! Central state-manager task.
//!
//! Owns the [`SessionRegistry`], the [`RegistryStore`], the suspend-tracking
//! state, and the per-session grace-token map. Receives every external
//! stimulus through a single `mpsc::UnboundedReceiver<Event>`. Emits action
//! requests for the action-runner task.

use std::collections::HashMap;
use std::io::{self, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use tessera_core::mac::audit as mac_audit;
use tessera_core::mac::backend::MacBackend;
use tessera_core::mac::IntegrityLabel;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use tessera_proto::{ServerMessage, SessionTarget};

use crate::logind::LogindSignal;
use crate::registry::{ActiveSession, RegistryStore, SessionRegistry};
use crate::udev_monitor::{UdevAction, UdevEvent};
use crate::udev_query::{UdevDeviceIdentity, UdevQuery};

/// Credential transport selected by the shared daemon/PAM configuration.
///
/// PKCS#12 credentials are observable as USB block devices and therefore use
/// udev presence/removal enforcement. PKCS#11 token serials live in a
/// different namespace; the PAM authentication flow rejects strict
/// continuous-presence mode until a native token-event monitor exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialMode {
    /// PKCS#12 bundle discovered on a USB block device.
    Pkcs12,
    /// PKCS#11 token accessed through a provider.
    Pkcs11,
}

/// What the daemon should do when a USB device is removed past the grace
/// window. Mirrors the validated config enum but lives here so that the
/// monitord crate does not need to depend on the full validated config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnUsbRemoved {
    /// Lock the logind session.
    Lock,
    /// Terminate the logind session.
    Logout,
    /// Run a hook script.
    Hook {
        /// Path to the hook executable.
        path: std::path::PathBuf,
    },
    /// Power off the host.
    Shutdown,
}

/// Suspend tracking — separate from [`OnUsbRemoved`] because suspend is
/// orthogonal to which action a removal triggers.
#[derive(Debug, Clone, Copy)]
pub enum SuspendState {
    /// Awake.
    Awake,
    /// Logind announced an imminent suspend at this instant.
    SuspendingAt(Instant),
    /// Logind reported a resume at this instant.
    ResumedAt(Instant),
}

impl SuspendState {
    /// Are we currently inside the suspend grace window?
    #[must_use]
    pub fn is_in_grace_window(&self, secs: u64) -> bool {
        match self {
            SuspendState::Awake => false,
            SuspendState::SuspendingAt(_) => true,
            SuspendState::ResumedAt(t) => t.elapsed() < Duration::from_secs(secs),
        }
    }
}

/// Configuration for [`spawn_state_manager`].
#[derive(Debug, Clone)]
pub struct StateConfig {
    /// Credential transport used by PAM and monitord.
    pub credential_mode: CredentialMode,
    /// Grace seconds between USB removal and the configured action.
    pub grace_seconds: u64,
    /// Suspend grace seconds: removals seen during/just after suspend are
    /// ignored.
    pub suspend_grace_seconds: u64,
    /// Action to take on a confirmed USB removal.
    pub on_usb_removed: OnUsbRemoved,
    /// Persistence backend.
    pub registry_store: RegistryStore,
}

impl StateConfig {
    /// Sensible defaults for unit tests.
    #[must_use]
    pub fn test_defaults(store: RegistryStore) -> Self {
        Self {
            credential_mode: CredentialMode::Pkcs12,
            grace_seconds: 5,
            suspend_grace_seconds: 30,
            on_usb_removed: OnUsbRemoved::Lock,
            registry_store: store,
        }
    }
}

/// IPC requests fed into the state manager.
#[derive(Debug)]
pub enum IpcRequest {
    /// Hello acknowledgement (no-op for state, but we accept it for
    /// completeness).
    Hello {
        /// Reply channel.
        reply: oneshot::Sender<ServerMessage>,
    },
    /// Open session.
    SessionOpen {
        /// Session struct that we should add to the registry.
        session: Box<ActiveSession>,
        /// Reply channel.
        reply: oneshot::Sender<ServerMessage>,
    },
    /// Close session.
    SessionClose {
        /// Session id.
        session_id: Uuid,
        /// Closed at.
        closed_at: SystemTime,
        /// Reply channel.
        reply: oneshot::Sender<ServerMessage>,
    },
    /// Ping.
    Ping {
        /// Reply channel.
        reply: oneshot::Sender<ServerMessage>,
    },
    /// Look up the active session for a Unix uid.
    GetActiveSessionByUid {
        /// Unix uid to look up.
        uid: u32,
        /// Reply channel.
        reply: oneshot::Sender<ServerMessage>,
    },
    /// Update the [`SessionTarget`] of an already-open registry entry.
    ///
    /// Emitted on receipt of a
    /// [`tessera_proto::ClientMessage::UpdateSessionTarget`] frame
    /// (PAM session phase pushing the logind id it discovered via
    /// `XDG_SESSION_ID`).
    UpdateSessionTarget {
        /// Session id to update.
        session_id: Uuid,
        /// New target.
        new_target: SessionTarget,
        /// Reply channel.
        reply: oneshot::Sender<ServerMessage>,
    },
}

/// Top-level event accepted by the state manager.
#[derive(Debug)]
pub enum Event {
    /// IPC request.
    Ipc(IpcRequest),
    /// Udev event.
    Udev(UdevEvent),
    /// Logind signal.
    Logind(LogindSignal),
}

/// Action requests dispatched to the action-runner task.
#[derive(Debug, Clone)]
pub enum ActionRequest {
    /// USB device was removed past the grace window — execute the configured
    /// action against this session.
    HandleUsbRemoved {
        /// Session.
        session: ActiveSession,
        /// Action.
        action: OnUsbRemoved,
    },
    /// The session's bounded role TTL elapsed — revoke continued access using
    /// the same session-ending action configured for USB removal. Both mean
    /// "the authorised window is over"; reusing the action keeps a single
    /// fail-closed code path (Lock / Logout / Hook / Shutdown, including the
    /// reboot fallback when no logind id is known).
    HandleSessionExpired {
        /// Session that reached its deadline.
        session: ActiveSession,
        /// Session-ending action to run.
        action: OnUsbRemoved,
    },
}

/// Identity of a TTL timer firing back into the single-writer state manager.
///
/// `opened_at` and `deadline` make stale timer messages harmless after a
/// duplicate `SessionOpen` replaces a session under the same UUID.
#[derive(Debug, Clone, Copy)]
struct TtlExpired {
    session_id: Uuid,
    opened_at: SystemTime,
    deadline: SystemTime,
}

/// Spawn the state-manager task.
#[must_use]
pub fn spawn_state_manager(
    cfg: StateConfig,
    registry: SessionRegistry,
    mut rx: mpsc::UnboundedReceiver<Event>,
    action_tx: mpsc::UnboundedSender<ActionRequest>,
    udev_query: Arc<dyn UdevQuery>,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut grace_tokens: HashMap<Uuid, CancellationToken> = HashMap::new();
        // Per-session cancellation handles for bounded-TTL termination timers,
        // keyed by session id. Mirrors `grace_tokens` but addresses sessions
        // (a TTL is a per-session deadline) rather than USB serials.
        let mut ttl_tokens: HashMap<Uuid, CancellationToken> = HashMap::new();
        // TTL tasks fire once and then wait for the state manager to durably
        // retire the session. A bounded queue prevents an expiry burst from
        // growing memory without limit.
        let (ttl_expired_tx, mut ttl_expired_rx) = mpsc::channel::<TtlExpired>(64);
        let mut suspend_state = SuspendState::Awake;

        // Re-arm TTL timers for sessions restored from the persisted registry.
        // Without this a daemon restart would forget every deadline and a
        // role session could outlive its ceiling indefinitely. Sessions whose
        // deadline already passed while the daemon was down are terminated
        // immediately by `schedule_session_ttl` (remaining time saturates to
        // zero).
        for session in registry.snapshot() {
            schedule_session_ttl(&session, &ttl_expired_tx, &mut ttl_tokens);
        }

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                expired = ttl_expired_rx.recv() => {
                    let Some(expired) = expired else { break };
                    handle_session_expired(
                        &cfg,
                        &registry,
                        &action_tx,
                        &ttl_expired_tx,
                        &mut grace_tokens,
                        &mut ttl_tokens,
                        expired,
                    ).await;
                }
                ev = rx.recv() => {
                    let Some(ev) = ev else { break };
                    match ev {
                        Event::Ipc(req) => handle_ipc(
                            &cfg,
                            &registry,
                            udev_query.as_ref(),
                            &ttl_expired_tx,
                            &mut grace_tokens,
                            &mut ttl_tokens,
                            req,
                        ).await,
                        Event::Udev(u) => handle_udev(&cfg, &registry, &mut grace_tokens, &suspend_state, &action_tx, u),
                        Event::Logind(s) => handle_logind(&cfg, &mut suspend_state, &registry, &mut grace_tokens, &mut ttl_tokens, s).await,
                    }
                }
            }
        }
        // Cancel any outstanding grace and TTL timers on shutdown.
        for (_session_id, tok) in grace_tokens.drain() {
            tok.cancel();
        }
        for (_session_id, tok) in ttl_tokens.drain() {
            tok.cancel();
        }
    })
}

/// Persist `snapshot` on a blocking thread-pool worker so the JSON
/// serialise + rename + fsync path does not stall a tokio runtime worker.
///
/// Returns the outcome so callers can decide whether a durable write is a
/// precondition (session open — the client must not be told the session is
/// registered until it survives a restart) or best-effort (close / target
/// update / logind teardown, where losing the write only risks a stale
/// entry that later reconciliation removes).
///
/// # Errors
///
/// Returns an `io::Error` when the underlying [`RegistryStore::persist`]
/// fails, or when the blocking worker panics/cancels (surfaced as
/// [`io::ErrorKind::Other`]).
async fn persist_async(store: &RegistryStore, snapshot: Vec<ActiveSession>) -> io::Result<()> {
    let store = store.clone();
    match tokio::task::spawn_blocking(move || store.persist(&snapshot)).await {
        Ok(res) => res,
        Err(join_err) => Err(io::Error::other(format!(
            "registry persist task join failed: {join_err}"
        ))),
    }
}

/// Persist a snapshot where losing the write is tolerable, logging a
/// warning on failure. Used by session-close, target-update, and
/// logind-teardown paths, whose in-memory mutation has already been
/// committed and where a missed write only leaves a stale on-disk entry
/// that startup reconciliation (or the next successful write) corrects.
async fn persist_best_effort(store: &RegistryStore, snapshot: Vec<ActiveSession>, context: &str) {
    if let Err(e) = persist_async(store, snapshot).await {
        tracing::warn!(
            target: "tessera.monitord",
            error = %e,
            context,
            "registry persist failed (best-effort)"
        );
    }
}

/// Register a new session, acknowledging it only once the registry write is
/// durable.
///
/// Three fail-closed guards bracket the `Ack`:
/// 1. for PKCS#12, a SessionOpen-vs-Remove race check verifies the full USB
///    identity PAM captured, not only the cloneable descriptor serial;
/// 2. the candidate snapshot is durably written before any in-memory entry or
///    timer changes, so a failed duplicate open cannot destroy the previous
///    valid session;
/// 3. after persistence, the registry entry and bounded-TTL timer are replaced
///    synchronously before the client can observe `Ack`.
// The parameters are the state-manager task's own borrows (config, registry,
// udev probe, action channel, TTL-timer map) plus the request payload; folding
// them into a parameter struct would only relocate the same coupling without
// making any caller clearer.
#[expect(
    clippy::too_many_arguments,
    reason = "threads the state-manager task's borrows plus the request payload"
)]
async fn handle_session_open(
    cfg: &StateConfig,
    registry: &SessionRegistry,
    udev_query: &dyn UdevQuery,
    ttl_expired_tx: &mpsc::Sender<TtlExpired>,
    grace_tokens: &mut HashMap<Uuid, CancellationToken>,
    ttl_tokens: &mut HashMap<Uuid, CancellationToken>,
    session: Box<ActiveSession>,
    reply: oneshot::Sender<ServerMessage>,
) {
    // SessionOpen vs Remove race (T19): PKCS#12 is observable through the
    // block-device udev namespace, so require the exact captured device to
    // still be present. PKCS#11 token serials are deliberately never compared
    // to block-device serials; permissive PKCS#11 is best-effort and strict
    // PKCS#11 is rejected by the PAM authentication flow.
    if cfg.credential_mode == CredentialMode::Pkcs12 {
        if let Some(serial) = session.usb_serial.as_deref() {
            if !udev_query.is_device_present(UdevDeviceIdentity {
                serial,
                vid_pid: session.usb_vid_pid.as_deref(),
                devnode: session.usb_devnode.as_deref(),
            }) {
                // Best-effort: клиент мог отключиться, ответ можно потерять.
                drop(reply.send(ServerMessage::Error {
                    code: tessera_proto::error_codes::DEVICE_GONE,
                    message: format!("authenticated usb device {serial} is not present"),
                }));
                return;
            }
        }
    }
    let s = *session;
    let session_id = s.session_id;

    // Build the replacement snapshot without mutating the live registry.
    // State-manager events are serialized, so while this write is in flight
    // readers continue seeing the previous valid session. If persistence
    // fails, neither that entry nor its existing timer is touched.
    let mut candidate = registry.snapshot();
    candidate.retain(|existing| existing.session_id != session_id);
    candidate.push(s.clone());
    if let Err(e) = persist_async(&cfg.registry_store, candidate).await {
        tracing::error!(
            target: "tessera.monitord",
            session_id = %session_id,
            error = %e,
            "SessionOpen persist failed; previous in-memory session and timer preserved"
        );
        // Best-effort: клиент мог отключиться, ответ можно потерять.
        drop(reply.send(ServerMessage::Error {
            code: tessera_proto::error_codes::INTERNAL,
            message: format!("session registry persist failed: {e}"),
        }));
        return;
    }

    // Commit memory and timers only after the candidate is durable. A
    // successful retry/replacement must retire any removal grace task that
    // captured the previous record under this UUID; the full presence check
    // above already proved the replacement's PKCS#12 device is present.
    if let Some(token) = grace_tokens.remove(&session_id) {
        token.cancel();
    }
    registry.add(s.clone());
    schedule_session_ttl(&s, ttl_expired_tx, ttl_tokens);
    // Best-effort: клиент мог отключиться, ответ можно потерять.
    drop(reply.send(ServerMessage::Ack));
}

#[expect(
    clippy::too_many_arguments,
    reason = "single-writer state manager threads its bounded timer maps and injected I/O dependencies"
)]
async fn handle_ipc(
    cfg: &StateConfig,
    registry: &SessionRegistry,
    udev_query: &dyn UdevQuery,
    ttl_expired_tx: &mpsc::Sender<TtlExpired>,
    grace_tokens: &mut HashMap<Uuid, CancellationToken>,
    ttl_tokens: &mut HashMap<Uuid, CancellationToken>,
    req: IpcRequest,
) {
    match req {
        IpcRequest::Hello { reply } => {
            // Best-effort: если клиент уже отвалился, ответ слать некому.
            drop(reply.send(ServerMessage::HelloAck {
                server_version: env!("CARGO_PKG_VERSION").to_string(),
                protocol_version: tessera_proto::PROTOCOL_VERSION,
            }));
        }
        IpcRequest::Ping { reply } => {
            // Best-effort: клиент мог отключиться, ответ можно потерять.
            drop(reply.send(ServerMessage::Pong));
        }
        IpcRequest::GetActiveSessionByUid { uid, reply } => {
            let msg = match registry.find_by_uid(uid) {
                Some(rec) => ServerMessage::ActiveSession {
                    session_id: rec.session_id.to_string(),
                    cert_cn: rec.cert_cn,
                    engineer_ski: rec.engineer_ski,
                    engineer_cert_sha256: rec.engineer_cert_sha256,
                    host_id_hash: rec.host_id_hash,
                },
                None => ServerMessage::Error {
                    code: tessera_proto::error_codes::NO_ACTIVE_SESSION,
                    message: format!("no active session for uid {uid}"),
                },
            };
            // Best-effort: клиент мог отключиться, ответ можно потерять.
            drop(reply.send(msg));
        }
        IpcRequest::SessionOpen { session, reply } => {
            handle_session_open(
                cfg,
                registry,
                udev_query,
                ttl_expired_tx,
                grace_tokens,
                ttl_tokens,
                session,
                reply,
            )
            .await;
        }
        IpcRequest::SessionClose {
            session_id,
            closed_at: _,
            reply,
        } => {
            // A cleanly-closed session must not later trip its TTL action.
            if let Some(tok) = ttl_tokens.remove(&session_id) {
                tok.cancel();
            }
            if let Some(tok) = grace_tokens.remove(&session_id) {
                tok.cancel();
            }
            let _removed = registry.remove(session_id);
            persist_best_effort(&cfg.registry_store, registry.snapshot(), "session_close").await;
            // Best-effort: клиент мог отключиться, ответ можно потерять.
            drop(reply.send(ServerMessage::Ack));
        }
        IpcRequest::UpdateSessionTarget {
            session_id,
            new_target,
            reply,
        } => {
            // Persist on success so the new target survives a daemon
            // restart — without persistence the next monitord boot would
            // resurrect the pre-update Tty/Display/Unknown target and the
            // Lock/Logout dispatch would break in exactly the same way as
            // the bug this whole pathway fixes (0.3.10 production:
            // "Logout requested but session has no logind id").
            let msg = match registry.update_target(session_id, new_target.clone()) {
                Ok(()) => {
                    persist_best_effort(
                        &cfg.registry_store,
                        registry.snapshot(),
                        "update_session_target",
                    )
                    .await;
                    tracing::info!(
                        target: "tessera.monitord",
                        session_id = %session_id,
                        ?new_target,
                        "session target updated"
                    );
                    ServerMessage::SessionTargetUpdated {
                        session_id: session_id.to_string(),
                    }
                }
                Err(err) => ServerMessage::Error {
                    code: tessera_proto::error_codes::BAD_REQUEST,
                    message: format!("update_session_target {session_id}: {err}"),
                },
            };
            // Best-effort: клиент мог отключиться, ответ можно потерять.
            drop(reply.send(msg));
        }
    }
}

/// Whether a udev `add` event is strong enough evidence that the same
/// physical device that authenticated `session` has returned, and may
/// therefore cancel a pending credential-removal action.
///
/// The USB descriptor serial is attacker-controlled and cloneable, so it is
/// treated only as the map key. Every device-topology field the session
/// captured at authentication time (VID/PID and the block-device node) must
/// match the event:
///
/// - a field the session never recorded (a PKCS#11 token, or a client that
///   predates topology capture) is left unconstrained, preserving the
///   serial-only behaviour for those legacy sessions;
/// - a field the session recorded but the event omits counts as a mismatch,
///   so a pending removal is never cancelled on partial evidence.
///
/// Requiring both VID/PID and devpath to match is deliberately strict:
/// a genuine re-seat that the kernel assigns a new devnode will not cancel,
/// which is why a zero removal grace (no cancellation window at all) is the
/// recommended terminal profile. A full re-add private-key challenge is the
/// stronger future option and is out of scope here.
fn add_event_rebinds_session(
    session: &ActiveSession,
    event_vid_pid: Option<&str>,
    event_devnode: Option<&str>,
) -> bool {
    let vid_pid_ok = match session.usb_vid_pid.as_deref() {
        None => true,
        Some(captured) => event_vid_pid == Some(captured),
    };
    let devnode_ok = match session.usb_devnode.as_deref() {
        None => true,
        Some(captured) => event_devnode == Some(captured),
    };
    vid_pid_ok && devnode_ok
}

/// Whether a remove event can refer to this session's authenticating device.
///
/// A populated event field must match the captured value. Missing fields are
/// treated as unknown rather than mismatch: acting on every ambiguous
/// same-serial session is fail-closed, while suppressing all of them would let
/// a sparse udev remove event bypass enforcement.
fn remove_event_may_match_session(
    session: &ActiveSession,
    event_vid_pid: Option<&str>,
    event_devnode: Option<&str>,
) -> bool {
    let vid_pid_ok = match (session.usb_vid_pid.as_deref(), event_vid_pid) {
        (Some(captured), Some(observed)) => captured == observed,
        _ => true,
    };
    let devnode_ok = match (session.usb_devnode.as_deref(), event_devnode) {
        (Some(captured), Some(observed)) => captured == observed,
        _ => true,
    };
    vid_pid_ok && devnode_ok
}

#[expect(
    clippy::too_many_lines,
    reason = "remove and add branches share one destructured udev event and per-session timer map"
)]
fn handle_udev(
    cfg: &StateConfig,
    registry: &SessionRegistry,
    grace_tokens: &mut HashMap<Uuid, CancellationToken>,
    suspend_state: &SuspendState,
    action_tx: &mpsc::UnboundedSender<ActionRequest>,
    event: UdevEvent,
) {
    // PKCS#11 token serials and USB block-device serials are unrelated
    // namespaces. Permissive PKCS#11 deliberately has no continuous-presence
    // enforcement until a native token-event source exists; reacting to an
    // attacker-controlled block device with a colliding serial would only
    // create a spurious session-ending action.
    if cfg.credential_mode == CredentialMode::Pkcs11 {
        return;
    }

    let UdevEvent {
        action,
        devnode,
        serial,
        vid_pid,
        is_usb: _,
    } = event;
    match (action, serial) {
        (UdevAction::Remove, Some(serial)) => {
            if suspend_state.is_in_grace_window(cfg.suspend_grace_seconds) {
                tracing::info!(
                    target: "tessera.monitord",
                    serial,
                    "udev remove suppressed by suspend grace"
                );
                return;
            }
            let event_vid_pid = vid_pid.map(|(v, p)| format!("{v:04x}:{p:04x}"));
            let sessions: Vec<ActiveSession> = registry
                .find_by_serial(&serial)
                .into_iter()
                .filter(|session| {
                    remove_event_may_match_session(
                        session,
                        event_vid_pid.as_deref(),
                        devnode.as_deref(),
                    )
                })
                .collect();
            if sessions.is_empty() {
                return;
            }
            let grace = Duration::from_secs(cfg.grace_seconds);
            for session in sessions {
                let session_id = session.session_id;
                if grace_tokens
                    .get(&session_id)
                    .is_some_and(|token| !token.is_cancelled())
                {
                    // Duplicate remove/hub event for this exact session.
                    continue;
                }
                grace_tokens.remove(&session_id);
                let token = CancellationToken::new();
                grace_tokens.insert(session_id, token.clone());
                let completed = token.clone();
                let action_tx = action_tx.clone();
                let action = cfg.on_usb_removed.clone();
                let serial_for_log = serial.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = tokio::time::sleep(grace) => {
                            tracing::info!(
                                target: "tessera.monitord",
                                serial = serial_for_log,
                                %session_id,
                                "grace window expired, dispatching action"
                            );
                            // Best-effort: если приёмник действий уже закрыт,
                            // демон всё равно завершается — терять нечего.
                            drop(action_tx.send(ActionRequest::HandleUsbRemoved {
                                session,
                                action,
                            }));
                            // Mark the map entry reusable without retaining a
                            // permanently "pending" timer after dispatch.
                            completed.cancel();
                        }
                        _ = token.cancelled() => {
                            tracing::info!(
                                target: "tessera.monitord",
                                serial = serial_for_log,
                                %session_id,
                                "grace cancelled"
                            );
                        }
                    }
                });
            }
        }
        (UdevAction::Add, Some(serial)) => {
            // A cloned serial must not be able to cancel enforcement on its
            // own. Cancel only each exact session whose captured topology
            // matches; same-serial sessions for other devices keep their own
            // independent grace timers.
            let event_vid_pid = vid_pid.map(|(v, p)| format!("{v:04x}:{p:04x}"));
            let sessions = registry.find_by_serial(&serial);
            let mut cancelled = 0_usize;
            for session in sessions {
                if add_event_rebinds_session(&session, event_vid_pid.as_deref(), devnode.as_deref())
                {
                    if let Some(t) = grace_tokens.remove(&session.session_id) {
                        cancelled += 1;
                        t.cancel();
                    }
                }
            }
            if cancelled > 0 {
                tracing::info!(
                    target: "tessera.monitord",
                    serial,
                    cancelled,
                    "re-add matches authenticated device topology; cancelling pending removals"
                );
            } else if grace_tokens.iter().any(|(session_id, _)| {
                registry
                    .find_by_session_id(*session_id)
                    .is_some_and(|session| session.usb_serial.as_deref() == Some(serial.as_str()))
            }) {
                tracing::warn!(
                    target: "tessera.monitord",
                    serial,
                    event_vid_pid = ?event_vid_pid,
                    event_devnode = ?devnode,
                    "re-add serial matches but device topology differs; NOT cancelling pending removal"
                );
            }
        }
        _ => {}
    }
}

/// Arm a bounded-TTL termination timer for `session`.
///
/// No-op when the session carries no `session_expiry` (non-role sessions have
/// no time ceiling). The deadline is the absolute wall-clock instant the PAM
/// module computed at authentication time — already clamped to the
/// certificate's `notAfter` — so the daemon schedules directly against it with
/// no re-anchoring at its own `opened_at`; that is what keeps the enforced
/// deadline from ever drifting past certificate expiry. The remaining sleep is
/// `deadline − now`, saturating to zero when the deadline is already in the
/// past (a restored session that expired while the daemon was down is then
/// terminated on the next scheduler tick).
///
/// Any pre-existing timer for the same session id is cancelled first so a
/// duplicate `SessionOpen` cannot leave two timers racing. Cancellation via
/// the stored [`CancellationToken`] (on clean `SessionClose`, logind teardown,
/// or shutdown) suppresses the action.
fn schedule_session_ttl(
    session: &ActiveSession,
    ttl_expired_tx: &mpsc::Sender<TtlExpired>,
    ttl_tokens: &mut HashMap<Uuid, CancellationToken>,
) {
    // Replacing a session with no TTL must cancel the previous bounded timer
    // too; checking `session_expiry` before this point would leave that stale
    // timer armed.
    if let Some(old) = ttl_tokens.remove(&session.session_id) {
        old.cancel();
    }

    let Some(deadline) = session.session_expiry else {
        return;
    };
    let remaining = deadline
        .duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO);

    let token = CancellationToken::new();
    ttl_tokens.insert(session.session_id, token.clone());

    let ttl_expired_tx = ttl_expired_tx.clone();
    let session_id = session.session_id;
    let opened_at = session.opened_at;
    tokio::spawn(async move {
        tokio::select! {
            () = tokio::time::sleep(remaining) => {
                tracing::warn!(
                    target: "tessera.monitord",
                    session_id = %session_id,
                    session_expiry = ?deadline,
                    "bounded role-session TTL reached; revoking continued access"
                );
                if ttl_expired_tx
                    .send(TtlExpired {
                        session_id,
                        opened_at,
                        deadline,
                    })
                    .await
                    .is_err()
                {
                    tracing::debug!(
                        target: "tessera.monitord",
                        %session_id,
                        "state manager stopped before TTL expiry could be retired"
                    );
                }
            }
            () = token.cancelled() => {
                tracing::debug!(
                    target: "tessera.monitord",
                    session_id = %session_id,
                    "bounded TTL timer cancelled before expiry"
                );
            }
        }
    });
}

/// Retire an expired session in the single-writer state manager before
/// dispatching the configured enforcement action.
///
/// Removing the registry record first ensures role lookups fail closed even
/// when Lock is the configured action or the action backend itself fails.
/// Persistence is best-effort after the in-memory revocation: an old on-disk
/// record still carries the absolute expired deadline and is retired
/// immediately on the next daemon start.
#[expect(
    clippy::too_many_arguments,
    reason = "expiry atomically coordinates registry, action queue, persistence, and both timer maps"
)]
async fn handle_session_expired(
    cfg: &StateConfig,
    registry: &SessionRegistry,
    action_tx: &mpsc::UnboundedSender<ActionRequest>,
    ttl_expired_tx: &mpsc::Sender<TtlExpired>,
    grace_tokens: &mut HashMap<Uuid, CancellationToken>,
    ttl_tokens: &mut HashMap<Uuid, CancellationToken>,
    expired: TtlExpired,
) {
    let Some(session) = registry.find_by_session_id(expired.session_id) else {
        return;
    };
    if session.opened_at != expired.opened_at || session.session_expiry != Some(expired.deadline) {
        tracing::debug!(
            target: "tessera.monitord",
            session_id = %expired.session_id,
            "ignoring stale TTL event for replaced session"
        );
        return;
    }

    // Wall-clock time can move backwards while the monotonic sleep is
    // running. Re-arm against the same absolute deadline instead of expiring
    // early after such an adjustment.
    if expired.deadline > SystemTime::now() {
        schedule_session_ttl(&session, ttl_expired_tx, ttl_tokens);
        return;
    }

    if let Some(token) = ttl_tokens.remove(&expired.session_id) {
        token.cancel();
    }
    if let Some(token) = grace_tokens.remove(&expired.session_id) {
        token.cancel();
    }
    let Some(session) = registry.remove(expired.session_id) else {
        return;
    };

    // Dispatch immediately after the in-memory revocation; a slow fsync must
    // not postpone the security action.
    drop(action_tx.send(ActionRequest::HandleSessionExpired {
        session,
        action: cfg.on_usb_removed.clone(),
    }));
    persist_best_effort(&cfg.registry_store, registry.snapshot(), "session_expired").await;
}

async fn handle_logind(
    cfg: &StateConfig,
    suspend_state: &mut SuspendState,
    registry: &SessionRegistry,
    grace_tokens: &mut HashMap<Uuid, CancellationToken>,
    ttl_tokens: &mut HashMap<Uuid, CancellationToken>,
    sig: LogindSignal,
) {
    match sig {
        LogindSignal::PrepareForSleep(true) => {
            *suspend_state = SuspendState::SuspendingAt(Instant::now());
            // Cancel any pending grace timers — the suspend may legitimately
            // explain the removal.
            for (_session_id, tok) in grace_tokens.drain() {
                tok.cancel();
            }
        }
        LogindSignal::PrepareForSleep(false) => {
            *suspend_state = SuspendState::ResumedAt(Instant::now());
        }
        LogindSignal::SessionRemoved { id, .. } => {
            // Drop any active session whose target matches this logind id.
            let to_remove: Vec<Uuid> = registry
                .all()
                .into_iter()
                .filter(|s| s.target.logind_id() == Some(id.as_str()))
                .map(|s| s.session_id)
                .collect();
            if to_remove.is_empty() {
                return;
            }
            for uuid in to_remove {
                // logind already tore the session down; drop its TTL timer so
                // it does not later fire an action against a dead session.
                if let Some(tok) = ttl_tokens.remove(&uuid) {
                    tok.cancel();
                }
                if let Some(tok) = grace_tokens.remove(&uuid) {
                    tok.cancel();
                }
                let _ = registry.remove(uuid);
            }
            // Persist after removals so a daemon restart does not
            // resurrect sessions that logind has already torn down.
            // Mirrors the SessionClose persistence policy: best-effort, log a
            // warning on failure.
            persist_best_effort(&cfg.registry_store, registry.snapshot(), "logind_teardown").await;
        }
    }
}

/// Atomically write the sessions registry snapshot to `final_path` with
/// an МКЦ integrity (`level=0`) label applied to the file descriptor
/// BEFORE the inode becomes visible at the published path. This closes
/// the path-based TOCTOU window between `open()` and `set_file_label()`
/// per MAC integrity spec §5.3.1: a peer never observes the file
/// without the integrity label attached.
///
/// The kernel rejects the `irelax` flag through the fd-based API
/// (`pdp_set_fd` returns `EINVAL` for `"0:0:0:irelax"`), so the fd is
/// labeled with the bare `"0:0:0"` form (`irelax=false`). The daemon
/// runs at level 0 already and does not need write-down semantics for
/// its own state file; `irelax` remains available on the path-based
/// [`MacBackend::set_file_label`] for callers that do.
///
/// Labeling is best-effort — if `set_fd_label` fails the write still
/// proceeds and an `mac_sessions_file_label_warning` audit event is
/// emitted; DAC mode (`0600`) and `iinh` on the parent directory remain
/// the guardrails. The file is `fsync`'d before the atomic rename.
///
/// # Errors
/// Returns the underlying `io::Error` for any tempfile/write/sync/rename
/// failure. Label failures are downgraded to a warning and do not
/// propagate.
pub fn write_sessions_atomic<B: MacBackend + ?Sized>(
    final_path: &Path,
    bytes: &[u8],
    backend: &B,
) -> io::Result<()> {
    let parent = final_path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent dir"))?;
    // `NamedTempFile::new_in` opens with `O_CREAT|O_EXCL` and a secure
    // mode in the same filesystem as the destination, so `persist`
    // becomes a same-fs `rename(2)`.
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    let fd = tmp.as_file().as_raw_fd();
    let label = IntegrityLabel {
        level: 0,
        categories: 0_u64,
    };
    if let Err(e) = backend.set_fd_label(fd, label, /* irelax= */ false) {
        mac_audit::emit_sessions_file_warn(&final_path.to_string_lossy(), Some(&format!("{e}")));
        // Continue — best-effort labeling; DAC + parent dir iinh still apply.
    }
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(final_path).map_err(|e| e.error)?;
    Ok(())
}
