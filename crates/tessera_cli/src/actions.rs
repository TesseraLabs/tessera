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
            run_session_ending_action(actions, &session, action).await
        }
        ActionRequest::HandleSessionExpired { session, action } => {
            // Distinct diagnostic so operators can tell a time-bound expiry
            // apart from a physical token removal in the audit trail; the
            // enforcement that follows is identical.
            tracing::warn!(
                target: "tessera.monitord",
                session_id = %session.session_id,
                pam_user = %session.pam_user,
                pam_service = %session.pam_service,
                "bounded role-session TTL expired; enforcing configured session-ending action"
            );
            run_session_ending_action(actions, &session, action).await
        }
    }
}

/// Execute the configured session-ending `action` against `session`.
///
/// Shared by USB-removal and TTL-expiry dispatch: both revoke an
/// already-authorised session and must fail closed the same way — a
/// Lock/Logout that cannot reach logind escalates to a reboot rather than
/// silently leaving the engineer logged in.
async fn run_session_ending_action(
    actions: &Arc<dyn LogindActionsTrait>,
    session: &crate::registry::ActiveSession,
    action: OnUsbRemoved,
) -> anyhow::Result<()> {
    let logind_id = session.target.logind_id().map(str::to_string);
    match action {
        OnUsbRemoved::Lock => match logind_id {
            Some(id) => {
                if let Err(e) = actions.lock_session(&id).await {
                    fail_closed_logind_error(actions, "Lock", session, &e).await?;
                }
            }
            None => fail_closed_no_logind_id(actions, "Lock", session).await?,
        },
        OnUsbRemoved::Logout => match logind_id {
            Some(id) => {
                if let Err(e) = actions.terminate_session(&id).await {
                    fail_closed_logind_error(actions, "Logout", session, &e).await?;
                }
            }
            None => fail_closed_no_logind_id(actions, "Logout", session).await?,
        },
        OnUsbRemoved::Hook { path } => {
            let session_clone = session.clone();
            let path_clone = path.clone();
            let result =
                match tokio::task::spawn_blocking(move || run_hook(&path_clone, &session_clone))
                    .await
                {
                    Ok(result) => result,
                    Err(e) => Err(anyhow::anyhow!("hook task join error: {e}")),
                };
            if let Err(e) = result {
                fail_closed_action_error(actions, "Hook", session, &e).await?;
            }
        }
        OnUsbRemoved::Shutdown => {
            tracing::error!(
                target: "tessera.monitord",
                session_id = %session.session_id,
                "ALERT: powering off to revoke access"
            );
            if let Err(e) = actions.power_off().await {
                fail_closed_action_error(actions, "Shutdown", session, &e).await?;
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
         (see docs/ru/install.md §10)",
        service = session.pam_service,
    );
    actions.reboot().await
}

/// Fail closed when a Lock/Logout call reached logind (the session had a
/// `LogindSession` target) but the call itself returned an error — logind
/// unreachable, the D-Bus method failed, or the session id was already gone.
///
/// Dropping that error would leave the engineer authenticated with the token
/// unplugged or the bounded TTL already expired: exactly the access the
/// USB-removal / TTL-expiry policy exists to revoke. Rather than log-and-forget
/// (with no retry and no escalation), escalate to the same reboot fallback used
/// when no logind id is available — the workstation is forced back to the login
/// screen. This mirrors the contract of [`run_session_ending_action`]: a
/// Lock/Logout that cannot be carried out must never leave the session active.
async fn fail_closed_logind_error(
    actions: &Arc<dyn LogindActionsTrait>,
    action: &str,
    session: &crate::registry::ActiveSession,
    error: &anyhow::Error,
) -> anyhow::Result<()> {
    tracing::error!(
        target: "tessera.monitord",
        action,
        session_id = %session.session_id,
        target = ?session.target,
        pam_user = %session.pam_user,
        pam_service = %session.pam_service,
        error = %error,
        "ALERT: session-ending {action} reached logind but failed; failing closed with reboot"
    );
    actions.reboot().await
}

/// Fail closed when a non-logind session-ending action (Hook / Shutdown)
/// cannot complete.
async fn fail_closed_action_error(
    actions: &Arc<dyn LogindActionsTrait>,
    action: &str,
    session: &crate::registry::ActiveSession,
    error: &anyhow::Error,
) -> anyhow::Result<()> {
    tracing::error!(
        target: "tessera.monitord",
        action,
        session_id = %session.session_id,
        pam_user = %session.pam_user,
        pam_service = %session.pam_service,
        error = %error,
        "ALERT: session-ending {action} failed; failing closed with reboot"
    );
    actions.reboot().await
}

/// Runs the operator-configured USB-removal hook as root.
///
/// # Security
///
/// Several environment variables passed to the hook are UNTRUSTED and must
/// never be interpolated into a shell command unquoted by the hook script:
///
/// * `USB_SERIAL` — taken from the udev attributes of a physically-inserted
///   device, so an attacker controls its bytes (it can contain shell
///   metacharacters);
/// * `CERT_CN` — derived from the presented certificate's subject and is
///   likewise attacker-influenced.
///
/// This function spawns the hook with [`std::process::Command`], which passes
/// the environment verbatim and performs no shell interpretation, so there is
/// no injection here. The residual risk is entirely downstream: a hook that
/// does `eval`/`sh -c` with `$USB_SERIAL` or `$CERT_CN` would execute
/// attacker input as root. Hook authors must treat these values as data and
/// always quote them (or avoid the shell). `PAM_USER`, `PAM_SERVICE`,
/// `HOST_ID_HASH`, and `SESSION_ID` originate from validated/internal state.
fn run_hook(
    path: &std::path::Path,
    session: &crate::registry::ActiveSession,
) -> anyhow::Result<()> {
    use std::process::Command;
    // Validate every component immediately before execution. Keeping the
    // descriptor alive through `status()` pins the validated leaf while the
    // canonical path is resolved by exec; non-root users cannot replace any
    // validated ancestor or the root-owned leaf.
    let validated = tessera_core::privileged_path::validate_path(
        path,
        tessera_core::privileged_path::ExecTrust::Root,
    )
    .map_err(|e| anyhow::anyhow!("unsafe root hook path {}: {e}", path.display()))?;
    let canonical = validated.canonical().to_owned();
    let _validated_descriptor = validated.into_descriptor();

    let mut cmd = Command::new(canonical);
    cmd.env_clear();
    cmd.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    cmd.env("LANG", "C");
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
