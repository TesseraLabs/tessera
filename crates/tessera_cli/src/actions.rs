//! Action-runner task.
//!
//! Receives [`ActionRequest`]s from the state manager and dispatches them
//! through a [`LogindActionsTrait`] backend (real zbus on Linux, no-op or
//! recording in tests). USB-removal hooks run inside `spawn_blocking` since
//! the existing hook executor in `tessera_core` is sync.

use std::sync::Arc;

use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::logind::LogindActionsTrait;
use crate::state::{ActionRequest, OnUsbRemoved};

/// Spawn the action-runner task.
#[must_use]
pub fn spawn_action_runner(
    mut rx: UnboundedReceiver<ActionRequest>,
    actions: Arc<dyn LogindActionsTrait>,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                req = rx.recv() => {
                    let Some(req) = req else { break };
                    if let Err(e) = handle(&actions, req).await {
                        tracing::warn!(target: "tessera.monitord", error = %e, "action handler failed");
                    }
                }
            }
        }
    })
}

async fn handle(actions: &Arc<dyn LogindActionsTrait>, req: ActionRequest) -> anyhow::Result<()> {
    match req {
        ActionRequest::HandleUsbRemoved { session, action } => {
            let logind_id = session.target.logind_id().map(str::to_string);
            match action {
                OnUsbRemoved::Lock => match logind_id {
                    Some(id) => actions.lock_session(&id).await?,
                    None => fail_closed_no_logind_id(actions, "Lock", &session).await?,
                },
                OnUsbRemoved::Logout => match logind_id {
                    Some(id) => actions.terminate_session(&id).await?,
                    None => fail_closed_no_logind_id(actions, "Logout", &session).await?,
                },
                OnUsbRemoved::Hook { path } => {
                    let session_clone = session.clone();
                    let path_clone = path.clone();
                    tokio::task::spawn_blocking(move || run_hook(&path_clone, &session_clone))
                        .await
                        .map_err(|e| anyhow::anyhow!("hook task join error: {e}"))??;
                }
                OnUsbRemoved::Shutdown => {
                    tracing::error!(
                        target: "tessera.monitord",
                        session_id = %session.session_id,
                        "ALERT: powering off due to usb removal"
                    );
                    actions.power_off().await?;
                }
            }
        }
    }
    Ok(())
}

/// Fail closed when a configured Lock/Logout action cannot reach logind
/// because the session has no `LogindSession` target (Tty/Display/Unknown,
/// e.g. `pam_systemd.so` missing or ordered after `pam_tessera.so`).
///
/// Dropping the action here would leave the engineer logged in with the
/// authorising token unplugged — the exact access the USB-removal policy
/// exists to revoke. Instead we escalate to an `error` diagnostic and
/// reboot the host: this destroys the session just like the fail-closed
/// mechanism used by [`OnUsbRemoved::Shutdown`], but the workstation comes
/// back up to the login screen rather than staying powered off. The operator
/// still gets the PAM-stack tip so the root misconfiguration
/// (`XDG_SESSION_ID` absent during `pam_sm_open_session`) can be corrected.
async fn fail_closed_no_logind_id(
    actions: &Arc<dyn LogindActionsTrait>,
    action: &str,
    session: &crate::registry::ActiveSession,
) -> anyhow::Result<()> {
    tracing::error!(
        target: "tessera.monitord",
        action,
        session_id = %session.session_id,
        target = ?session.target,
        pam_user = %session.pam_user,
        pam_service = %session.pam_service,
        "ALERT: USB-removal {action} has no logind id; failing closed with reboot"
    );
    tracing::info!(
        target: "tessera.monitord",
        "tip: pam_sm_open_session pushes XDG_SESSION_ID to monitord via UpdateSessionTarget; \
         ensure pam_systemd.so precedes pam_tessera.so in the session phase of /etc/pam.d/<{service}> \
         (see docs/install.md §10)",
        service = session.pam_service,
    );
    actions.reboot().await
}

fn run_hook(
    path: &std::path::Path,
    session: &crate::registry::ActiveSession,
) -> anyhow::Result<()> {
    use std::process::Command;
    let mut cmd = Command::new(path);
    cmd.env("CERT_CN", &session.cert_cn);
    cmd.env("PAM_USER", &session.pam_user);
    cmd.env("PAM_SERVICE", &session.pam_service);
    cmd.env("USB_SERIAL", session.usb_serial.clone().unwrap_or_default());
    cmd.env("HOST_ID_HASH", &session.host_id_hash);
    cmd.env("SESSION_ID", session.session_id.to_string());
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("hook returned non-zero status: {status}");
    }
    Ok(())
}
