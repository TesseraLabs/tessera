//! Active session registry.
//!
//! Holds every session that monitord knows about. Persisted via
//! [`store::RegistryStore`] to `/run/tessera/sessions.json` (writable
//! by root only, atomic temp-file replace).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use parking_lot::Mutex;
use uuid::Uuid;

use tessera_proto::SessionTarget;

pub mod store;

pub use store::RegistryStore;

/// Errors raised by [`SessionRegistry::update_target`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UpdateTargetError {
    /// No session with the supplied id is currently tracked.
    #[error("no active session for the supplied id")]
    NotFound,
}

/// Snapshot of one active session as known to monitord.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActiveSession {
    /// Session id (matches what the PAM module sent in `SessionOpen`).
    pub session_id: Uuid,
    /// PAM user.
    pub pam_user: String,
    /// PAM service.
    pub pam_service: String,
    /// Where the session lives.
    pub target: SessionTarget,
    /// USB serial that authorised the session.
    pub usb_serial: Option<String>,
    /// Hex host id hash.
    pub host_id_hash: String,
    /// Wall-clock open time.
    #[serde(with = "tessera_proto::system_time_serde")]
    pub opened_at: SystemTime,
    /// Cert CN.
    pub cert_cn: String,
    /// Cert serial.
    pub cert_serial: String,
    /// Lowercase hex of the engineer cert `SubjectKeyIdentifier`. v2.
    #[serde(default)]
    pub engineer_ski: String,
    /// Lowercase hex of `SHA-256(cert DER)` of the engineer leaf. v2.
    #[serde(default)]
    pub engineer_cert_sha256: String,
    /// Unix uid the PAM module authenticated. v2 — used as the lookup
    /// key for `find_by_uid`. `0` means "v1 client / unknown".
    #[serde(default)]
    pub uid: u32,
    /// Absolute wall-clock instant at which a bounded role session must end,
    /// as computed by the PAM module at authentication time (earliest of the
    /// role/default TTL measured from the authentication instant and the
    /// certificate's `notAfter`). `None` for sessions with no role/TTL.
    /// Persisted so the deadline survives a daemon restart and the scheduled
    /// termination is re-armed against the same absolute instant on startup.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "tessera_proto::system_time_serde::option"
    )]
    pub session_expiry: Option<SystemTime>,
}

/// Two-level state held under one mutex: `by_id` is the primary store,
/// `by_uid` is a reverse index keyed by `uid` so the daemon can answer
/// `GetActiveSessionByUid` in O(1).
///
/// `uid == 0` entries are NOT placed into `by_uid` — `0` is our sentinel
/// for "v1 client / unknown uid" and we never want a wildcard lookup to
/// match an arbitrary session.
#[derive(Default)]
struct Inner {
    by_id: HashMap<Uuid, ActiveSession>,
    by_uid: HashMap<u32, Uuid>,
}

/// Thread-safe in-memory registry.
#[derive(Default, Clone)]
pub struct SessionRegistry {
    inner: Arc<Mutex<Inner>>,
}

impl std::fmt::Debug for SessionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionRegistry")
            .field("len", &self.inner.lock().by_id.len())
            .finish()
    }
}

impl SessionRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct from a pre-loaded vector of sessions (used at startup).
    #[must_use]
    pub fn from_snapshot(sessions: Vec<ActiveSession>) -> Self {
        let mut inner = Inner::default();
        for s in sessions {
            if s.uid != 0 {
                inner.by_uid.insert(s.uid, s.session_id);
            }
            inner.by_id.insert(s.session_id, s);
        }
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    /// Insert a session (overwrites any existing entry with the same id).
    pub fn add(&self, s: ActiveSession) {
        let mut g = self.inner.lock();
        // If this session id was already present under a different uid,
        // drop the stale reverse-index entry so we don't strand it.
        let stale_uid: Option<u32> = g.by_id.get(&s.session_id).and_then(|existing| {
            if existing.uid != 0
                && existing.uid != s.uid
                && g.by_uid.get(&existing.uid) == Some(&s.session_id)
            {
                Some(existing.uid)
            } else {
                None
            }
        });
        if let Some(uid) = stale_uid {
            g.by_uid.remove(&uid);
        }
        if s.uid != 0 {
            g.by_uid.insert(s.uid, s.session_id);
        }
        g.by_id.insert(s.session_id, s);
    }

    /// Remove and return a session by id.
    pub fn remove(&self, id: Uuid) -> Option<ActiveSession> {
        let mut g = self.inner.lock();
        let removed = g.by_id.remove(&id)?;
        if removed.uid != 0 && g.by_uid.get(&removed.uid) == Some(&id) {
            g.by_uid.remove(&removed.uid);
        }
        Some(removed)
    }

    /// Get a session by id.
    pub fn find_by_session_id(&self, id: Uuid) -> Option<ActiveSession> {
        self.inner.lock().by_id.get(&id).cloned()
    }

    /// Replace the [`SessionTarget`] of an existing entry in-place.
    ///
    /// Returns `Ok(())` when the entry was found and updated, and
    /// `Err(())` when no entry matches `id` — callers (the IPC handler)
    /// turn the latter into a `BAD_REQUEST` server reply so that a stale
    /// `UpdateSessionTarget` from a long-gone PAM call never silently
    /// resurrects a session.
    ///
    /// This intentionally does NOT touch the `by_uid` reverse index:
    /// `target` is independent of `uid`, and re-keying the index here
    /// would race with [`Self::find_by_uid`] callers that already hold a
    /// snapshot. Persistence is the caller's responsibility (the state
    /// manager calls `persist_async` after a successful update so the
    /// new target survives a daemon restart — important for `Logout`
    /// dispatch correctness after the user already logged in).
    ///
    /// # Errors
    ///
    /// Returns [`UpdateTargetError::NotFound`] when no session with `id`
    /// is currently tracked.
    pub fn update_target(
        &self,
        id: Uuid,
        new_target: SessionTarget,
    ) -> Result<(), UpdateTargetError> {
        let mut g = self.inner.lock();
        match g.by_id.get_mut(&id) {
            Some(entry) => {
                entry.target = new_target;
                Ok(())
            }
            None => Err(UpdateTargetError::NotFound),
        }
    }

    /// Look up the active session for `uid`. Returns `None` when no session
    /// is currently tracked for that uid, or when `uid == 0` (sentinel
    /// for "no uid recorded").
    pub fn find_by_uid(&self, uid: u32) -> Option<ActiveSession> {
        if uid == 0 {
            return None;
        }
        let g = self.inner.lock();
        let session_id = *g.by_uid.get(&uid)?;
        g.by_id.get(&session_id).cloned()
    }

    /// Return every session whose `usb_serial` matches `serial`.
    pub fn find_by_serial(&self, serial: &str) -> Vec<ActiveSession> {
        self.inner
            .lock()
            .by_id
            .values()
            .filter(|s| s.usb_serial.as_deref() == Some(serial))
            .cloned()
            .collect()
    }

    /// Snapshot of every active session.
    #[must_use]
    pub fn snapshot(&self) -> Vec<ActiveSession> {
        self.inner.lock().by_id.values().cloned().collect()
    }

    /// Convenience alias for [`Self::snapshot`].
    #[must_use]
    pub fn all(&self) -> Vec<ActiveSession> {
        self.snapshot()
    }

    /// Number of active sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().by_id.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().by_id.is_empty()
    }
}
