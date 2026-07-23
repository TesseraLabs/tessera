#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]
//! Action-runner dispatch tests using the `RecordingActions` stub.

use std::sync::Arc;
use std::time::SystemTime;

use tessera_cli::actions::spawn_action_runner;
use tessera_cli::logind::LogindActionsTrait;
use tessera_cli::registry::ActiveSession;
use tessera_cli::state::{ActionRequest, OnUsbRemoved};
use tessera_cli::testing::RecordingActions;
use tessera_proto::SessionTarget;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Logind stub whose `lock_session` / `terminate_session` always fail, so the
/// tests can prove a cleanly-reached-but-failing Lock/Logout still fails closed
/// with a reboot rather than silently leaving the session active. `reboot` and
/// `power_off` succeed and are recorded so the escalation is observable.
#[derive(Debug, Default)]
struct FailingLogindActions {
    calls: parking_lot::Mutex<Vec<String>>,
}

#[derive(Debug, Default)]
struct FailingPowerOffActions {
    calls: parking_lot::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl LogindActionsTrait for FailingPowerOffActions {
    async fn lock_session(&self, id: &str) -> anyhow::Result<()> {
        self.calls.lock().push(format!("LockSession({id})"));
        Ok(())
    }
    async fn terminate_session(&self, id: &str) -> anyhow::Result<()> {
        self.calls.lock().push(format!("TerminateSession({id})"));
        Ok(())
    }
    async fn power_off(&self) -> anyhow::Result<()> {
        self.calls.lock().push("PowerOff".to_string());
        anyhow::bail!("power-off failed")
    }
    async fn reboot(&self) -> anyhow::Result<()> {
        self.calls.lock().push("Reboot".to_string());
        Ok(())
    }
}

#[async_trait::async_trait]
impl LogindActionsTrait for FailingLogindActions {
    async fn lock_session(&self, id: &str) -> anyhow::Result<()> {
        self.calls.lock().push(format!("LockSession({id})"));
        anyhow::bail!("logind unreachable")
    }
    async fn terminate_session(&self, id: &str) -> anyhow::Result<()> {
        self.calls.lock().push(format!("TerminateSession({id})"));
        anyhow::bail!("logind unreachable")
    }
    async fn power_off(&self) -> anyhow::Result<()> {
        self.calls.lock().push("PowerOff".to_string());
        Ok(())
    }
    async fn reboot(&self) -> anyhow::Result<()> {
        self.calls.lock().push("Reboot".to_string());
        Ok(())
    }
}

fn sample_logind_session(id: &str) -> ActiveSession {
    ActiveSession {
        session_id: Uuid::from_u128(1),
        pam_user: "u".into(),
        pam_service: "s".into(),
        target: SessionTarget::logind(id),
        usb_serial: Some("AB".into()),
        usb_vid_pid: None,
        usb_devnode: None,
        host_id_hash: "h".into(),
        opened_at: SystemTime::UNIX_EPOCH,
        cert_cn: "cn".into(),
        cert_serial: "01".into(),
        engineer_ski: String::new(),
        engineer_cert_sha256: String::new(),
        uid: 0,
        session_expiry: None,
    }
}

#[tokio::test]
async fn lock_dispatches_logind_lock() {
    let recorder = Arc::new(RecordingActions::default());
    let actions: Arc<dyn LogindActionsTrait> = recorder.clone();
    let shutdown = CancellationToken::new();
    let (tx, rx) = mpsc::unbounded_channel();
    let _h = spawn_action_runner(rx, actions, shutdown.clone());
    tx.send(ActionRequest::HandleUsbRemoved {
        session: sample_logind_session("c1"),
        action: OnUsbRemoved::Lock,
    })
    .expect("send");
    // Allow the action runner to process.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let calls = recorder.calls.lock();
    assert_eq!(calls.last().map(String::as_str), Some("LockSession(c1)"));
    shutdown.cancel();
}

#[tokio::test]
async fn logout_dispatches_logind_terminate() {
    let recorder = Arc::new(RecordingActions::default());
    let actions: Arc<dyn LogindActionsTrait> = recorder.clone();
    let shutdown = CancellationToken::new();
    let (tx, rx) = mpsc::unbounded_channel();
    let _h = spawn_action_runner(rx, actions, shutdown.clone());
    tx.send(ActionRequest::HandleUsbRemoved {
        session: sample_logind_session("c2"),
        action: OnUsbRemoved::Logout,
    })
    .expect("send");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let calls = recorder.calls.lock();
    assert_eq!(
        calls.last().map(String::as_str),
        Some("TerminateSession(c2)")
    );
    shutdown.cancel();
}

#[tokio::test]
async fn shutdown_calls_poweroff() {
    let recorder = Arc::new(RecordingActions::default());
    let actions: Arc<dyn LogindActionsTrait> = recorder.clone();
    let shutdown = CancellationToken::new();
    let (tx, rx) = mpsc::unbounded_channel();
    let _h = spawn_action_runner(rx, actions, shutdown.clone());
    tx.send(ActionRequest::HandleUsbRemoved {
        session: sample_logind_session("c3"),
        action: OnUsbRemoved::Shutdown,
    })
    .expect("send");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let calls = recorder.calls.lock();
    assert_eq!(calls.last().map(String::as_str), Some("PowerOff"));
    shutdown.cancel();
}

#[tokio::test]
async fn failing_shutdown_fails_closed_with_reboot() {
    let recorder = Arc::new(FailingPowerOffActions::default());
    let actions: Arc<dyn LogindActionsTrait> = recorder.clone();
    let shutdown = CancellationToken::new();
    let (tx, rx) = mpsc::unbounded_channel();
    let _h = spawn_action_runner(rx, actions, shutdown.clone());
    tx.send(ActionRequest::HandleSessionExpired {
        session: sample_logind_session("c8"),
        action: OnUsbRemoved::Shutdown,
    })
    .expect("send");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let calls = recorder.calls.lock();
    assert_eq!(
        calls.as_slice(),
        &["PowerOff".to_string(), "Reboot".to_string()]
    );
    shutdown.cancel();
}

#[tokio::test]
async fn unsafe_or_missing_root_hook_fails_closed_with_reboot() {
    let recorder = Arc::new(RecordingActions::default());
    let actions: Arc<dyn LogindActionsTrait> = recorder.clone();
    let shutdown = CancellationToken::new();
    let (tx, rx) = mpsc::unbounded_channel();
    let _h = spawn_action_runner(rx, actions, shutdown.clone());
    tx.send(ActionRequest::HandleSessionExpired {
        session: sample_logind_session("c9"),
        action: OnUsbRemoved::Hook {
            path: std::path::PathBuf::from("/definitely/not/a/tessera-hook"),
        },
    })
    .expect("send");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let calls = recorder.calls.lock();
    assert_eq!(calls.as_slice(), &["Reboot".to_string()]);
    shutdown.cancel();
}

#[tokio::test]
async fn missing_logind_id_fails_closed_with_reboot_for_lock() {
    let recorder = Arc::new(RecordingActions::default());
    let actions: Arc<dyn LogindActionsTrait> = recorder.clone();
    let shutdown = CancellationToken::new();
    let (tx, rx) = mpsc::unbounded_channel();
    let _h = spawn_action_runner(rx, actions, shutdown.clone());
    let mut s = sample_logind_session("c4");
    s.target = SessionTarget::tty("/dev/tty1");
    tx.send(ActionRequest::HandleUsbRemoved {
        session: s,
        action: OnUsbRemoved::Lock,
    })
    .expect("send");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let calls = recorder.calls.lock();
    // A TTY-targeted Lock cannot reach logind; the daemon must fail closed
    // by rebooting rather than silently dropping the action and leaving
    // the engineer logged in with the token unplugged.
    assert_eq!(calls.as_slice(), &["Reboot".to_string()]);
    shutdown.cancel();
}

#[tokio::test]
async fn failing_logind_lock_fails_closed_with_reboot() {
    let recorder = Arc::new(FailingLogindActions::default());
    let actions: Arc<dyn LogindActionsTrait> = recorder.clone();
    let shutdown = CancellationToken::new();
    let (tx, rx) = mpsc::unbounded_channel();
    let _h = spawn_action_runner(rx, actions, shutdown.clone());
    // A logind-targeted Lock that logind rejects (D-Bus down, session gone)
    // must not be dropped: the daemon escalates to a reboot so the session is
    // destroyed instead of surviving with the token unplugged.
    tx.send(ActionRequest::HandleSessionExpired {
        session: sample_logind_session("c6"),
        action: OnUsbRemoved::Lock,
    })
    .expect("send");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let calls = recorder.calls.lock();
    assert_eq!(
        calls.as_slice(),
        &["LockSession(c6)".to_string(), "Reboot".to_string()]
    );
    shutdown.cancel();
}

#[tokio::test]
async fn failing_logind_logout_fails_closed_with_reboot() {
    let recorder = Arc::new(FailingLogindActions::default());
    let actions: Arc<dyn LogindActionsTrait> = recorder.clone();
    let shutdown = CancellationToken::new();
    let (tx, rx) = mpsc::unbounded_channel();
    let _h = spawn_action_runner(rx, actions, shutdown.clone());
    tx.send(ActionRequest::HandleUsbRemoved {
        session: sample_logind_session("c7"),
        action: OnUsbRemoved::Logout,
    })
    .expect("send");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let calls = recorder.calls.lock();
    assert_eq!(
        calls.as_slice(),
        &["TerminateSession(c7)".to_string(), "Reboot".to_string()]
    );
    shutdown.cancel();
}

#[tokio::test]
async fn missing_logind_id_fails_closed_with_reboot_for_logout() {
    let recorder = Arc::new(RecordingActions::default());
    let actions: Arc<dyn LogindActionsTrait> = recorder.clone();
    let shutdown = CancellationToken::new();
    let (tx, rx) = mpsc::unbounded_channel();
    let _h = spawn_action_runner(rx, actions, shutdown.clone());
    let mut s = sample_logind_session("c5");
    s.target = SessionTarget::tty("/dev/tty2");
    tx.send(ActionRequest::HandleUsbRemoved {
        session: s,
        action: OnUsbRemoved::Logout,
    })
    .expect("send");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let calls = recorder.calls.lock();
    assert_eq!(calls.as_slice(), &["Reboot".to_string()]);
    shutdown.cancel();
}
