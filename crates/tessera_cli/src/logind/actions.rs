//! Action helpers calling logind's `LockSession` / `TerminateSession` /
//! `PowerOff` / `Reboot` methods. The trait abstraction lets tests inject a
//! `RecordingActions` stub.

/// Actions monitord can ask logind to perform.
#[async_trait::async_trait]
pub trait LogindActionsTrait: Send + Sync {
    /// Lock the named session.
    async fn lock_session(&self, id: &str) -> anyhow::Result<()>;
    /// Terminate the named session.
    async fn terminate_session(&self, id: &str) -> anyhow::Result<()>;
    /// Power off the host.
    async fn power_off(&self) -> anyhow::Result<()>;
    /// Reboot the host.
    async fn reboot(&self) -> anyhow::Result<()>;
}

/// No-op implementation for tests / non-Linux dev builds.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopActions;

#[async_trait::async_trait]
impl LogindActionsTrait for NoopActions {
    async fn lock_session(&self, id: &str) -> anyhow::Result<()> {
        tracing::info!(target: "tessera.monitord", id, "noop lock_session");
        Ok(())
    }
    async fn terminate_session(&self, id: &str) -> anyhow::Result<()> {
        tracing::info!(target: "tessera.monitord", id, "noop terminate_session");
        Ok(())
    }
    async fn power_off(&self) -> anyhow::Result<()> {
        tracing::info!(target: "tessera.monitord", "noop power_off");
        Ok(())
    }
    async fn reboot(&self) -> anyhow::Result<()> {
        tracing::info!(target: "tessera.monitord", "noop reboot");
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod real {
    use super::LogindActionsTrait;
    use std::sync::Arc;

    /// Real logind backend.
    pub struct LogindActions {
        conn: Arc<zbus::Connection>,
    }

    impl LogindActions {
        /// Construct from an existing connection.
        #[must_use]
        pub fn new(conn: Arc<zbus::Connection>) -> Self {
            Self { conn }
        }

        async fn proxy(&self) -> zbus::Result<zbus::Proxy<'_>> {
            zbus::Proxy::new(
                &self.conn,
                "org.freedesktop.login1",
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
            )
            .await
        }
    }

    #[async_trait::async_trait]
    impl LogindActionsTrait for LogindActions {
        async fn lock_session(&self, id: &str) -> anyhow::Result<()> {
            self.proxy()
                .await?
                .call_method("LockSession", &(id,))
                .await?;
            Ok(())
        }
        async fn terminate_session(&self, id: &str) -> anyhow::Result<()> {
            self.proxy()
                .await?
                .call_method("TerminateSession", &(id,))
                .await?;
            Ok(())
        }
        async fn power_off(&self) -> anyhow::Result<()> {
            self.proxy()
                .await?
                .call_method("PowerOff", &(false,))
                .await?;
            Ok(())
        }
        async fn reboot(&self) -> anyhow::Result<()> {
            self.proxy().await?.call_method("Reboot", &(false,)).await?;
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
pub use real::LogindActions;

#[cfg(not(target_os = "linux"))]
/// On non-Linux dev builds we expose `NoopActions` under the same name so
/// downstream code can still compile.
pub type LogindActions = NoopActions;
