//! Graceful shutdown helpers.

use std::path::Path;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Listen for `SIGTERM` / `SIGINT` and cancel the supplied token.
#[cfg(unix)]
pub async fn install_signal_handlers(token: CancellationToken) -> anyhow::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = term.recv() => tracing::info!("SIGTERM received"),
        _ = int.recv() => tracing::info!("SIGINT received"),
    }
    token.cancel();
    Ok(())
}

/// Fallback signal handler for non-Unix targets (kept to make `cargo check
/// --target windows-*` lint-clean even though the binary is Linux-only).
#[cfg(not(unix))]
pub async fn install_signal_handlers(token: CancellationToken) -> anyhow::Result<()> {
    tokio::signal::ctrl_c().await?;
    token.cancel();
    Ok(())
}

/// Wait for `handles` to finish or `budget` to elapse, then unlink the
/// socket file. Always succeeds.
pub async fn graceful_finish(handles: Vec<JoinHandle<()>>, budget: Duration, socket_path: &Path) {
    // Исход не важен: и таймаут, и нормальное завершение ведут к одному —
    // снять сокет и выйти. По задачам join тоже best-effort.
    let _timed_out = tokio::time::timeout(budget, async {
        for h in handles {
            drop(h.await);
        }
    })
    .await;
    // Best-effort cleanup: сокета может уже не быть.
    drop(std::fs::remove_file(socket_path));
}
