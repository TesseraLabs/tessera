//! `org.freedesktop.login1.Manager` signal listener.
//!
//! Production builds (Linux + zbus) subscribe to `PrepareForSleep` and
//! `SessionRemoved`. Non-Linux builds expose only the [`LogindSignal`]
//! enum so that the rest of the crate can be compiled and unit-tested.

#[cfg(not(target_os = "linux"))]
use tokio::sync::mpsc::UnboundedSender;
#[cfg(not(target_os = "linux"))]
use tokio::task::JoinHandle;

/// Signals we care about from logind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogindSignal {
    /// `PrepareForSleep(true)` → host is about to suspend; `false` → just
    /// resumed.
    PrepareForSleep(bool),
    /// `SessionRemoved(id, object_path)`.
    SessionRemoved {
        /// Session id (matches `XDG_SESSION_ID`).
        id: String,
        /// D-Bus object path of the removed session.
        object_path: String,
    },
}

/// How to connect to the bus.
#[derive(Debug, Clone)]
pub enum BusAddress {
    /// System bus (default).
    System,
    /// Custom bus address (used by tests).
    Custom(String),
}

#[cfg(target_os = "linux")]
pub use linux_impl::spawn_logind_listener;

/// Stub spawn for non-Linux dev builds. Returns an immediately-completing
/// task because there is no logind to talk to.
#[cfg(not(target_os = "linux"))]
pub fn spawn_logind_listener(
    _bus: BusAddress,
    _tx: UnboundedSender<LogindSignal>,
) -> JoinHandle<()> {
    tokio::spawn(async {})
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::{BusAddress, LogindSignal};
    use futures_util::stream::StreamExt;
    use tokio::sync::mpsc::UnboundedSender;
    use tokio::task::JoinHandle;

    /// Connect to logind and start forwarding signals.
    ///
    /// Returns a join handle for the background task; the task lives until
    /// the channel is closed or the connection drops.
    pub fn spawn_logind_listener(
        bus: BusAddress,
        tx: UnboundedSender<LogindSignal>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(e) = run(bus, tx).await {
                tracing::warn!(target: "tessera.monitord", error = %e, "logind listener exited");
            }
        })
    }

    async fn run(bus: BusAddress, tx: UnboundedSender<LogindSignal>) -> anyhow::Result<()> {
        let conn = match bus {
            BusAddress::System => zbus::Connection::system().await?,
            BusAddress::Custom(addr) => {
                zbus::ConnectionBuilder::address(addr.as_str())?
                    .build()
                    .await?
            }
        };
        let proxy = zbus::Proxy::new(
            &conn,
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .await?;
        let mut prepare = proxy.receive_signal("PrepareForSleep").await?;
        let mut removed = proxy.receive_signal("SessionRemoved").await?;
        loop {
            tokio::select! {
                Some(msg) = prepare.next() => {
                    if let Ok(b) = msg.body().deserialize::<bool>() {
                        if tx.send(LogindSignal::PrepareForSleep(b)).is_err() {
                            return Ok(());
                        }
                    }
                }
                Some(msg) = removed.next() => {
                    if let Ok((id, op)) = msg.body().deserialize::<(String, zbus::zvariant::OwnedObjectPath)>() {
                        let sig = LogindSignal::SessionRemoved {
                            id,
                            object_path: op.as_str().to_string(),
                        };
                        if tx.send(sig).is_err() {
                            return Ok(());
                        }
                    }
                }
                else => break,
            }
        }
        Ok(())
    }
}
