//! Test-support helpers: in-process server for integration tests, recording
//! `LogindActions` stubs, etc.
//!
//! Always compiled (gated only by the public-API surface), so dependent
//! crates can pull `testing::spawn_test_server` without enabling a feature.

use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::actions;
use crate::logind::{LogindActionsTrait, NoopActions};
use crate::registry::{RegistryStore, SessionRegistry};
use crate::server;
use crate::state::{spawn_state_manager, OnUsbRemoved, StateConfig};
use crate::udev_query::{AlwaysPresent, UdevQuery};

/// Handle returned by [`spawn_test_server`].
pub struct TestServerHandle {
    /// Cancellation token that ends the server.
    pub shutdown: CancellationToken,
    /// Join handle for the accept loop.
    pub accept_handle: JoinHandle<()>,
    /// Join handle for the state manager.
    pub state_handle: JoinHandle<()>,
    /// Join handle for the action runner.
    pub action_handle: JoinHandle<()>,
    /// Recorded action requests.
    pub actions: Arc<RecordingActions>,
}

impl TestServerHandle {
    /// Cancel and wait for all tasks. Best-effort.
    pub async fn shutdown_and_join(self) {
        self.shutdown.cancel();
        // Best-effort: ждём завершения задач, исход join (в т.ч. panic/abort)
        // в тестовом teardown нас не интересует.
        drop(self.accept_handle.await);
        drop(self.state_handle.await);
        drop(self.action_handle.await);
    }
}

/// Recording action backend used by tests in lieu of a real D-Bus.
#[derive(Debug, Default)]
pub struct RecordingActions {
    /// Calls captured.
    pub calls: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl LogindActionsTrait for RecordingActions {
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
        Ok(())
    }
    async fn reboot(&self) -> anyhow::Result<()> {
        self.calls.lock().push("Reboot".to_string());
        Ok(())
    }
}

/// Spawn an in-process server backed by stub udev/logind. The accept loop
/// runs against the given socket path.
///
/// Peer-credential enforcement is disabled by default in tests so the
/// (non-root) test process can connect to itself. Use
/// [`spawn_test_server_enforcing`] to opt back into the real check.
pub async fn spawn_test_server(
    socket: PathBuf,
    registry: SessionRegistry,
    store: RegistryStore,
) -> std::io::Result<TestServerHandle> {
    spawn_test_server_with(
        socket,
        registry,
        store,
        Arc::new(AlwaysPresent),
        OnUsbRemoved::Lock,
    )
    .await
}

/// Spawn a test server that DOES enforce peer-credentials. Used by the
/// dedicated "credential rejection" integration test.
pub async fn spawn_test_server_enforcing(
    socket: PathBuf,
    registry: SessionRegistry,
    store: RegistryStore,
) -> std::io::Result<TestServerHandle> {
    spawn_inner(
        socket,
        registry,
        store,
        Arc::new(AlwaysPresent),
        OnUsbRemoved::Lock,
        true,
    )
    .await
}

/// Generic version that lets the caller swap the udev backend or change the
/// configured `on_usb_removed` policy.
pub async fn spawn_test_server_with(
    socket: PathBuf,
    registry: SessionRegistry,
    store: RegistryStore,
    udev: Arc<dyn UdevQuery>,
    on_usb_removed: OnUsbRemoved,
) -> std::io::Result<TestServerHandle> {
    spawn_inner(socket, registry, store, udev, on_usb_removed, false).await
}

async fn spawn_inner(
    socket: PathBuf,
    registry: SessionRegistry,
    store: RegistryStore,
    udev: Arc<dyn UdevQuery>,
    on_usb_removed: OnUsbRemoved,
    enforce_peercred: bool,
) -> std::io::Result<TestServerHandle> {
    let listener = server::bind_listener(&socket).await?;
    let shutdown = CancellationToken::new();
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let (action_tx, action_rx) = mpsc::unbounded_channel();
    let actions = Arc::new(RecordingActions::default());
    let actions_dyn: Arc<dyn LogindActionsTrait> = actions.clone();
    let cfg = StateConfig {
        grace_seconds: 1,
        suspend_grace_seconds: 5,
        on_usb_removed,
        registry_store: store,
    };
    let state_handle =
        spawn_state_manager(cfg, registry, event_rx, action_tx, udev, shutdown.clone());
    let action_handle = actions::spawn_action_runner(action_rx, actions_dyn, shutdown.clone());
    let shutdown_for_accept = shutdown.clone();
    let cfg_accept = server::AcceptConfig {
        enforce_peercred,
        ..server::AcceptConfig::default()
    };
    let accept_handle = tokio::spawn(async move {
        server::run_accept_loop_with(listener, event_tx, shutdown_for_accept, cfg_accept).await;
    });
    Ok(TestServerHandle {
        shutdown,
        accept_handle,
        state_handle,
        action_handle,
        actions,
    })
}

/// `NoopActions` factory exposed for callers that don't need recording.
#[must_use]
pub fn noop_actions() -> Arc<dyn LogindActionsTrait> {
    Arc::new(NoopActions)
}
