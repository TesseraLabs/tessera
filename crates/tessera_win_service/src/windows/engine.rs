//! The verification core as the service uses it.
//!
//! This is the only place in the crate that touches the authentication path,
//! and it touches it the way the PAM module does: it assembles the same
//! collaborators through the same wiring and calls the same
//! `authenticate_pkcs12`. Nothing about how a credential is judged is decided
//! here — a second implementation of that would be a second answer to what a
//! valid credential is.
//!
//! Everything is built per request rather than cached: configuration, trust
//! material and the role store are re-read for every attempt, which is what the
//! PAM path does on every login. An operator who fixes a role slice does not
//! have to restart the service to see the fix, and a service that has been up
//! for a month is not still verifying against the file it read in the first
//! minute.
//!
//! # Where the media is read
//!
//! By the service, never by the client. The client sends a role and a PIN; the
//! volume is enumerated here and the credential is read here. A client that
//! could hand over credential material would be a client that could hand over
//! *any* credential material.

use std::sync::Arc;

use secrecy::SecretString;
use tessera_core::role::{RoleOs, RoleStore, SystemAccounts, TrustMode};
use tessera_proto::{Admission, Denial, RoleSummary, WireSecret};

use crate::engine::{AuthEngine, AuthRequest, EngineError};
use crate::journal::{Event, JournalMonitor};
use crate::paths::{DataDir, AUDIT_SERVICE_NAME};

use super::prepare;

/// The production engine.
pub struct WindowsEngine {
    data_dir: DataDir,
    account_name: String,
    journal: Arc<JournalMonitor>,
}

/// The journal, borrowed as a monitor client for one attempt.
///
/// The flow takes ownership of a boxed client, and the journal outlives every
/// attempt, so the box holds a shared handle rather than the journal itself.
struct SharedJournal(Arc<JournalMonitor>);

impl tessera_core::ipc::MonitorClient for SharedJournal {
    fn hello(&self) -> Result<(), tessera_core::error::IpcError> {
        self.0.hello()
    }

    fn open_session(
        &self,
        info: &tessera_core::ipc::OpenSessionInfo<'_>,
    ) -> Result<(), tessera_core::error::IpcError> {
        self.0.open_session(info)
    }

    fn close_session(
        &self,
        session_id: &str,
        reason: &str,
    ) -> Result<(), tessera_core::error::IpcError> {
        self.0.close_session(session_id, reason)
    }

    fn ping(&self) -> Result<(), tessera_core::error::IpcError> {
        self.0.ping()
    }
}

impl WindowsEngine {
    /// An engine reading `data_dir`, admitting into `account_name`, recording
    /// into `journal`.
    #[must_use]
    pub fn new(data_dir: DataDir, account_name: String, journal: Arc<JournalMonitor>) -> Self {
        Self {
            data_dir,
            account_name,
            journal,
        }
    }

    /// The validated configuration, read through the trust walk.
    fn config(&self) -> Result<tessera_core::config::ValidatedConfig, EngineError> {
        tessera_core::config::load_privileged_validated_config(&self.data_dir.config())
            .map_err(|e| EngineError::Config(e.to_string()))
    }

    /// The role store, read through the trust walk.
    fn store(cfg: &tessera_core::config::ValidatedConfig) -> Result<RoleStore, EngineError> {
        RoleStore::load_privileged(
            &cfg.roles.dir,
            RoleOs::Windows,
            TrustMode::Standalone,
            SystemAccounts::device(cfg.roles.account_lookup_timeout),
        )
        .map_err(|e| EngineError::RoleStore(e.to_string()))
    }

    /// Records a refusal in full. A journal that cannot be written is logged
    /// and the refusal stands: the attempt is being denied either way, and
    /// turning a denial into something else because the record failed would be
    /// the wrong direction to fail in.
    fn record_denial(&self, session_id: &str, role: &str, error: &str, code: i32) {
        if let Err(journal_error) = self.journal.record(Event::AttemptDenied {
            session_id: session_id.to_owned(),
            role: role.to_owned(),
            error: error.to_owned(),
            code,
        }) {
            tracing::error!(
                target: "tessera.engine",
                error = %journal_error,
                "refusal could not be journaled"
            );
        }
    }

    /// Runs one attempt, with everything built for it.
    fn attempt(&self, request: &AuthRequest<'_>, session_id: &str) -> Result<Admission, Denial> {
        use pam_tessera::flow::{authenticate_pkcs12, Deps, RoleStage};
        use pam_tessera::volume_flow::VolumeFlowIo;

        // The stored password is read before anything is verified. A device
        // that cannot produce it cannot complete a login, and finding that out
        // after a session has been journaled as opened would leave a record of
        // an admission that never happened.
        let password = prepare::stored_password(&self.data_dir).map_err(|e| {
            tracing::error!(target: "tessera.engine", error = %e, "account secret unavailable");
            self.record_denial(session_id, request.role, &e.to_string(), 4);
            crate::engine::internal_denial()
        })?;

        let cfg = self
            .config()
            .map_err(|e| self.setup_denial(session_id, request.role, &e))?;
        let (host_id_source, host_id_raw, host_id_hash) = pam_tessera::resolve_host_identity(&cfg)
            .map_err(|e| {
                self.setup_denial(
                    session_id,
                    request.role,
                    &EngineError::HostIdentity(e.to_string()),
                )
            })?;
        let store =
            Self::store(&cfg).map_err(|e| self.setup_denial(session_id, request.role, &e))?;

        let monitor: Box<dyn tessera_core::ipc::MonitorClient> =
            Box::new(SharedJournal(Arc::clone(&self.journal)));
        let wired =
            pam_tessera::di::wire_with_monitor(cfg, &host_id_raw, monitor).map_err(|e| {
                self.setup_denial(session_id, request.role, &EngineError::Trust(e.to_string()))
            })?;

        // Hooks are `fork`/`exec` on Unix and have no Windows implementation.
        // The certificate path does not depend on them, so they are off rather
        // than half-wired.
        let hooks = tessera_core::hooks::NoopExecutor::new();
        let accounts = tessera_core::role::AccountCheck::from_store(&store);
        let deps = Deps {
            cfg: &wired.cfg,
            trust: &wired.trust,
            monitor: &*wired.monitor,
            hook_executor: &hooks,
            host_id_hash: &host_id_hash,
            host_id_source,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: RoleStage {
                store: &store,
                default_session_ttl: wired.cfg.roles.default_session_ttl,
                accounts,
            },
            // Device tags carry delegation envelopes, whose source is not
            // configured on this platform yet; an empty set makes any
            // `requireTags` envelope unsatisfiable, which is the fail-closed
            // direction.
            device_tags: pam_tessera::flow::empty_device_tags(),
        };

        let io = VolumeFlowIo::for_removable_volumes(wired.cfg.usb_wait);
        // The PIN is handed back on every prompt the retry loop makes. There is
        // one PIN in a request, so a wrong one exhausts the budget and the
        // attempt ends as "the presented PIN did not open this credential" —
        // which is what happened. The engineer retries by making another
        // request, not by being asked again inside this one.
        let pin = SecretString::from(request.pin.expose().to_owned());
        let prompt = |_prompt: &str| -> Result<SecretString, tessera_core::pam_conv::PamConvError> {
            Ok(pin.clone())
        };

        match authenticate_pkcs12(
            deps,
            &io,
            request.role,
            AUDIT_SERVICE_NAME,
            session_id.to_owned(),
            prompt,
        ) {
            Ok(outcome) => {
                let ctx = &outcome.auth_ctx;
                let (role, role_version) = ctx.role.as_ref().map_or_else(
                    || (request.role.to_owned(), 0),
                    |r| (r.role.as_str().to_owned(), r.role_version),
                );
                Ok(Admission {
                    account: self.account_name.clone(),
                    password: WireSecret::new(password.to_string()),
                    role,
                    role_version,
                    cert_cn: ctx.cert_cn.clone(),
                    session_id: session_id.to_owned(),
                })
            }
            Err(error) => {
                let denial = crate::engine::denial_for(&error);
                self.record_denial(session_id, request.role, &error.to_string(), denial.code);
                Err(denial)
            }
        }
    }

    /// A refusal caused by the service's own state, recorded in full.
    fn setup_denial(&self, session_id: &str, role: &str, error: &EngineError) -> Denial {
        tracing::error!(target: "tessera.engine", error = %error, "attempt could not be started");
        let denial = crate::engine::internal_denial();
        self.record_denial(session_id, role, &error.to_string(), denial.code);
        denial
    }
}

impl AuthEngine for WindowsEngine {
    fn list_roles(&self) -> Result<Vec<RoleSummary>, EngineError> {
        let cfg = self.config()?;
        let store = Self::store(&cfg)?;
        Ok(crate::roles::summaries(&store))
    }

    fn authenticate(&self, request: &AuthRequest<'_>) -> Result<Admission, Denial> {
        let session_id = format!("win-{}", uuid::Uuid::new_v4().simple());
        tracing::info!(
            target: "tessera.engine",
            session_id = %session_id,
            role = %request.role,
            "authentication requested"
        );
        self.attempt(request, &session_id)
    }
}
