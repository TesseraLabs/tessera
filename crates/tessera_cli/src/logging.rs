//! Logging initialization for monitord.

use anyhow::Result;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Initialize tracing. Idempotent.
pub fn init() -> Result<()> {
    use std::sync::OnceLock;
    static INIT: OnceLock<()> = OnceLock::new();
    if INIT.get().is_some() {
        return Ok(());
    }
    let env = tracing_subscriber::EnvFilter::try_from_env("TESSERA_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(env)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .try_init()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    // Идемпотентно: гонку с параллельным init разрешает сам OnceLock,
    // проигравший просто игнорирует результат.
    let _already_set = INIT.set(());
    Ok(())
}
