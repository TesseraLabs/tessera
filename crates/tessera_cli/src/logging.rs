//! Logging initialization for monitord.

use anyhow::Result;
use tessera_core::LogLevel;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{reload, EnvFilter, Registry};

/// Handle for swapping the level filter after init (see
/// [`apply_config_level`]).  Set exactly once by [`init`].
static RELOAD_HANDLE: std::sync::OnceLock<reload::Handle<EnvFilter, Registry>> =
    std::sync::OnceLock::new();

/// Initialize tracing. Idempotent.
///
/// The initial filter comes from the `TESSERA_LOG` environment variable and
/// falls back to `info`.  The daemon refines the fallback from
/// `[logging].level` once the config is loaded — see [`apply_config_level`].
pub fn init() -> Result<()> {
    use std::sync::OnceLock;
    static INIT: OnceLock<()> = OnceLock::new();
    if INIT.get().is_some() {
        return Ok(());
    }
    let env =
        EnvFilter::try_from_env("TESSERA_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    // The filter sits behind a reload layer so `apply_config_level` can
    // replace it after the config file has been parsed (logging must come
    // up before config loading so load errors are visible).
    let (filter, handle) = reload::Layer::new(env);
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .try_init()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let _already_stored = RELOAD_HANDLE.set(handle);
    // Идемпотентно: гонку с параллельным init разрешает сам OnceLock,
    // проигравший просто игнорирует результат.
    let _already_set = INIT.set(());
    Ok(())
}

/// Apply `[logging].level` from the validated config to the live filter.
///
/// Priority stays `TESSERA_LOG` env > `[logging].level` > `info`: when the
/// environment variable is set (even to an unparsable value) the config
/// level is ignored and this function is a no-op.
pub fn apply_config_level(level: LogLevel) -> Result<()> {
    if std::env::var_os("TESSERA_LOG").is_some() {
        return Ok(());
    }
    let handle = RELOAD_HANDLE
        .get()
        .ok_or_else(|| anyhow::anyhow!("logging::init must run before apply_config_level"))?;
    handle
        .reload(EnvFilter::new(level.as_str()))
        .map_err(|e| anyhow::anyhow!("failed to apply [logging].level: {e}"))?;
    Ok(())
}
