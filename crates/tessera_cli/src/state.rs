//! Central state-manager task.
//!
//! Owns the [`SessionRegistry`], the [`RegistryStore`], the suspend-tracking
//! state, and the per-serial grace-token map. Receives every external
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
use crate::udev_query::UdevQuery;

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
        let mut grace_tokens: HashMap<String, CancellationToken> = HashMap::new();
        // Per-session cancellation handles for bounded-TTL termination timers,
        // keyed by session id. Mirrors `grace_tokens` but addresses sessions
        // (a TTL is a per-session deadline) rather than USB serials.
        let mut ttl_tokens: HashMap<Uuid, CancellationToken> = HashMap::new();
        let mut suspend_state = SuspendState::Awake;

        // Re-arm TTL timers for sessions restored from the persisted registry.
        // Without this a daemon restart would forget every deadline and a
        // role session could outlive its ceiling indefinitely. Sessions whose
        // deadline already passed while the daemon was down are terminated
        // immediately by `schedule_session_ttl` (remaining time saturates to
        // zero).
        for session in registry.snapshot() {
            schedule_session_ttl(&session, &cfg.on_usb_removed, &action_tx, &mut ttl_tokens);
        }

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                ev = rx.recv() => {
                    let Some(ev) = ev else { break };
                    match ev {
                        Event::Ipc(req) => handle_ipc(&cfg, &registry, udev_query.as_ref(), &action_tx, &mut ttl_tokens, req).await,
                        Event::Udev(u) => handle_udev(&cfg, &registry, &mut grace_tokens, &suspend_state, &action_tx, u),
                        Event::Logind(s) => handle_logind(&cfg, &mut suspend_state, &registry, &mut grace_tokens, &mut ttl_tokens, s).await,
                    }
                }
            }
        }
        // Cancel any outstanding grace and TTL timers on shutdown.
        for (_serial, tok) in grace_tokens.drain() {
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
/// 1. a SessionOpen-vs-Remove race check — if the USB serial is already gone
///    the open is refused (`DEVICE_GONE`);
/// 2. a bounded-TTL termination timer is armed before the session becomes
///    visible, so a role session's deadline is live the instant any other
///    task can observe it;
/// 3. a durability check — if the on-disk write fails, both the in-memory
///    insert AND the TTL timer just armed are rolled back, and the client is
///    told (`INTERNAL`) so a strict-mode PAM client fails the authentication
///    instead of believing a never-persisted session is active. Cancelling the
///    timer is essential: a rejected session must never later fire
///    `HandleSessionExpired`.
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
    action_tx: &mpsc::UnboundedSender<ActionRequest>,
    ttl_tokens: &mut HashMap<Uuid, CancellationToken>,
    session: Box<ActiveSession>,
    reply: oneshot::Sender<ServerMessage>,
) {
    // SessionOpen vs Remove race (T19): if the device was already unplugged
    // between PAM completing and us receiving, refuse.
    if let Some(serial) = session.usb_serial.as_deref() {
        if !udev_query.is_serial_present(serial) {
            // Best-effort: клиент мог отключиться, ответ можно потерять.
            drop(reply.send(ServerMessage::Error {
                code: tessera_proto::error_codes::DEVICE_GONE,
                message: format!("usb serial {serial} not present"),
            }));
            return;
        }
    }
    let s = *session;
    let session_id = s.session_id;
    // Arm the bounded-TTL termination timer (no-op when the session carries no
    // TTL). Scheduled before `add` so the deadline is live the instant the
    // session becomes visible.
    schedule_session_ttl(&s, &cfg.on_usb_removed, action_tx, ttl_tokens);
    registry.add(s);
    // Durability is a precondition for acknowledging the open: the client (in
    // strict monitor mode) treats a non-`Ack` reply as a failed, fail-closed
    // authentication. If the write does not land, roll back everything the open
    // provisionally created — the in-memory insert and the TTL timer — so the
    // registry, the on-disk snapshot, and the scheduled-action state all stay
    // consistent. Otherwise a daemon restart would silently drop this session
    // and its future removal action while the client believed it was
    // registered, and a leaked TTL timer would later fire `HandleSessionExpired`
    // against a session the daemon rejected.
    if let Err(e) = persist_async(&cfg.registry_store, registry.snapshot()).await {
        registry.remove(session_id);
        // Cancel and drop the TTL token armed above, using the same key
        // `schedule_session_ttl` inserted under (the session id).
        if let Some(tok) = ttl_tokens.remove(&session_id) {
            tok.cancel();
        }
        tracing::error!(
            target: "tessera.monitord",
            session_id = %session_id,
            error = %e,
            "SessionOpen persist failed; rolled back in-memory registration and TTL timer"
        );
        // Best-effort: клиент мог отключиться, ответ можно потерять.
        drop(reply.send(ServerMessage::Error {
            code: tessera_proto::error_codes::INTERNAL,
            message: format!("session registry persist failed: {e}"),
        }));
        return;
    }
    // Best-effort: клиент мог отключиться, ответ можно потерять.
    drop(reply.send(ServerMessage::Ack));
}

async fn handle_ipc(
    cfg: &StateConfig,
    registry: &SessionRegistry,
    udev_query: &dyn UdevQuery,
    action_tx: &mpsc::UnboundedSender<ActionRequest>,
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
                cfg, registry, udev_query, action_tx, ttl_tokens, session, reply,
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
            let removed = registry.remove(session_id);
            if let Some(s) = &removed {
                if let Some(serial) = s.usb_serial.as_deref() {
                    // If this was the only session bound to that serial, we
                    // can drop the active grace timer (handled in
                    // handle_udev when checked next; here we just persist).
                    let _ = serial;
                }
            }
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

fn handle_udev(
    cfg: &StateConfig,
    registry: &SessionRegistry,
    grace_tokens: &mut HashMap<String, CancellationToken>,
    suspend_state: &SuspendState,
    action_tx: &mpsc::UnboundedSender<ActionRequest>,
    event: UdevEvent,
) {
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
            let sessions = registry.find_by_serial(&serial);
            if sessions.is_empty() {
                return;
            }
            if grace_tokens.contains_key(&serial) {
                // Hub-disconnect dedup.
                return;
            }
            let token = CancellationToken::new();
            grace_tokens.insert(serial.clone(), token.clone());
            let action_tx = action_tx.clone();
            let action = cfg.on_usb_removed.clone();
            let grace = Duration::from_secs(cfg.grace_seconds);
            let serial_for_log = serial.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = tokio::time::sleep(grace) => {
                        tracing::info!(target: "tessera.monitord", serial = serial_for_log, "grace window expired, dispatching action");
                        for s in sessions {
                            // Best-effort: если приёмник действий уже закрыт,
                            // демон всё равно завершается — терять нечего.
                            drop(action_tx.send(ActionRequest::HandleUsbRemoved {
                                session: s,
                                action: action.clone(),
                            }));
                        }
                    }
                    _ = token.cancelled() => {
                        tracing::info!(target: "tessera.monitord", serial = serial_for_log, "grace cancelled");
                    }
                }
            });
        }
        (UdevAction::Add, Some(serial)) => {
            if !grace_tokens.contains_key(&serial) {
                // Nothing pending for this serial — a bare add is a no-op.
                return;
            }
            // A cloned serial must not be able to cancel enforcement on its
            // own. Only cancel when the re-added device matches the topology
            // (VID/PID + devnode) of the device that actually authenticated
            // one of the sessions bound to this serial.
            let event_vid_pid = vid_pid.map(|(v, p)| format!("{v:04x}:{p:04x}"));
            let sessions = registry.find_by_serial(&serial);
            let rebinds = sessions.iter().any(|s| {
                add_event_rebinds_session(s, event_vid_pid.as_deref(), devnode.as_deref())
            });
            if rebinds {
                if let Some(t) = grace_tokens.remove(&serial) {
                    t.cancel();
                    tracing::info!(
                        target: "tessera.monitord",
                        serial,
                        "re-add matches authenticated device topology; cancelling pending removal"
                    );
                }
            } else {
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
    action: &OnUsbRemoved,
    action_tx: &mpsc::UnboundedSender<ActionRequest>,
    ttl_tokens: &mut HashMap<Uuid, CancellationToken>,
) {
    let Some(deadline) = session.session_expiry else {
        return;
    };
    let remaining = deadline
        .duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO);

    // Replace any stale timer for this session id.
    if let Some(old) = ttl_tokens.remove(&session.session_id) {
        old.cancel();
    }
    let token = CancellationToken::new();
    ttl_tokens.insert(session.session_id, token.clone());

    let action_tx = action_tx.clone();
    let action = action.clone();
    let session = session.clone();
    let session_id = session.session_id;
    tokio::spawn(async move {
        tokio::select! {
            () = tokio::time::sleep(remaining) => {
                tracing::warn!(
                    target: "tessera.monitord",
                    session_id = %session_id,
                    session_expiry = ?deadline,
                    pam_user = %session.pam_user,
                    "bounded role-session TTL reached; revoking continued access"
                );
                // Best-effort: if the action runner is already gone the daemon
                // is shutting down and there is nothing left to enforce.
                drop(action_tx.send(ActionRequest::HandleSessionExpired { session, action }));
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

async fn handle_logind(
    cfg: &StateConfig,
    suspend_state: &mut SuspendState,
    registry: &SessionRegistry,
    grace_tokens: &mut HashMap<String, CancellationToken>,
    ttl_tokens: &mut HashMap<Uuid, CancellationToken>,
    sig: LogindSignal,
) {
    match sig {
        LogindSignal::PrepareForSleep(true) => {
            *suspend_state = SuspendState::SuspendingAt(Instant::now());
            // Cancel any pending grace timers — the suspend may legitimately
            // explain the removal.
            for (_serial, tok) in grace_tokens.drain() {
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
pub fn write_sessions_atomic<B: MacBackend>(
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
