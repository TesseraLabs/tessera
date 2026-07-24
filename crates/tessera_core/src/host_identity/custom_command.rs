//! Custom command host identity source.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::HostIdentityError;
use crate::host_identity::{HostIdSource, HostIdSourceKind};

/// Custom command source.
pub struct CustomCommandSource {
    cmd: PathBuf,
    timeout: Duration,
}

impl CustomCommandSource {
    /// Create a source.
    #[must_use]
    pub fn new(cmd: PathBuf, timeout: Duration) -> Self {
        Self { cmd, timeout }
    }
}

impl HostIdSource for CustomCommandSource {
    fn kind(&self) -> HostIdSourceKind {
        HostIdSourceKind::CustomCommand
    }

    fn fetch(&self, _fs_root: &Path) -> Result<String, HostIdentityError> {
        // The command runs with the PAM host's root authority. Re-validate the
        // whole path — every ancestor owned by root, no group/other write —
        // immediately before spawning, so a helper swapped for an
        // attacker-owned file after startup cannot escalate to root. Execute
        // the canonical (symlink-free) path the walk validated. The check runs
        // on every resolution because host identity is re-resolved per auth.
        let validated = crate::privileged_path::validate_path(
            &self.cmd,
            crate::privileged_path::ExecTrust::Root,
        )
        .map_err(|source| HostIdentityError::CommandUntrusted { source })?;
        self.run_command(validated.canonical())
    }
}

impl CustomCommandSource {
    /// Spawn `cmd`, enforce the timeout, and return its trimmed stdout.
    ///
    /// Separated from [`CustomCommandSource::fetch`] so the spawn/drain/timeout/
    /// reap machinery can be exercised in tests against a caller-owned script,
    /// while `fetch` layers the root-ownership gate on top.
    ///
    /// # Errors
    ///
    /// [`HostIdentityError::Read`] when the child cannot be spawned or waited
    /// on, [`HostIdentityError::CommandTimeout`] when it exceeds the deadline,
    /// or [`HostIdentityError::CommandFailed`] when it exits non-zero.
    // Все игнорируемые результаты ниже — best-effort очистка на путях таймаута
    // и ошибки (drain stdout/stderr, kill/wait/reap, join потоков-читателей):
    // диагностику уже сформировал основной путь, реагировать на сбой cleanup нечем.
    #[allow(clippy::let_underscore_must_use)]
    fn run_command(&self, cmd: &Path) -> Result<String, HostIdentityError> {
        // Spawn the child with piped stdout/stderr so we can drain them
        // even if the child outlives our wait window. On timeout we kill
        // the process and reap it, ensuring no orphaned PIDs / fds leak.
        let mut child = Command::new(cmd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| HostIdentityError::Read {
                path: cmd.to_path_buf(),
                source,
            })?;

        // Drain stdout/stderr on dedicated threads so a chatty child
        // can't deadlock on a full pipe before we notice the timeout.
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let stdout_handle = stdout.map(|mut s| {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = s.read_to_end(&mut buf);
                buf
            })
        });
        let stderr_handle = stderr.map(|mut s| {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = s.read_to_end(&mut buf);
                buf
            })
        });

        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        // Kill and reap so we don't leak the child PID.
                        let _ = child.kill();
                        let _ = child.wait();
                        // Drain reader threads to release their fds; the
                        // pipes will be closed by the kernel when the
                        // process is gone.
                        if let Some(h) = stdout_handle {
                            let _ = h.join();
                        }
                        if let Some(h) = stderr_handle {
                            let _ = h.join();
                        }
                        return Err(HostIdentityError::CommandTimeout);
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                Err(source) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(HostIdentityError::Read {
                        path: cmd.to_path_buf(),
                        source,
                    });
                }
            }
        };

        let stdout_bytes = stdout_handle
            .and_then(|h| h.join().ok())
            .unwrap_or_default();
        let stderr_bytes = stderr_handle
            .and_then(|h| h.join().ok())
            .unwrap_or_default();

        if !status.success() {
            return Err(HostIdentityError::CommandFailed {
                stderr: String::from_utf8_lossy(&stderr_bytes).trim().to_string(),
                code: status.code(),
            });
        }
        Ok(String::from_utf8_lossy(&stdout_bytes).trim().to_string())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    // The spawn/drain/timeout/reap machinery is tested via `run_command`, which
    // takes an already-resolved path and does not gate on ownership. `fetch`
    // (which runs the command as root) additionally enforces the root-ownership
    // walk, tested separately below; a caller-owned test script could never
    // pass that gate, so these tests target the lower layer directly.

    #[test]
    #[cfg(unix)]
    fn timeout_kills_long_running_child_and_reaps_promptly() {
        // A long-running child must be killed and reaped on timeout.
        // The wrapper script loops indefinitely; the 100 ms budget
        // guarantees we hit the timeout branch.
        let dir = tempfile::tempdir().expect("tempdir");
        let script_path = dir.path().join("loop.sh");
        std::fs::write(&script_path, "#!/bin/sh\nwhile true; do sleep 1; done\n").expect("write");
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        let src = CustomCommandSource::new(script_path.clone(), Duration::from_millis(100));
        let start = Instant::now();
        let result = src.run_command(&script_path);
        let elapsed = start.elapsed();
        assert!(matches!(result, Err(HostIdentityError::CommandTimeout)));
        // Generous upper bound: timeout (100 ms) + reap latency, well
        // under 2 s. Guards against the old behaviour where the child
        // ran to completion (would block the recv_timeout return).
        assert!(
            elapsed < Duration::from_secs(2),
            "run_command took {elapsed:?} — child not reaped promptly"
        );
    }

    #[test]
    #[cfg(unix)]
    fn successful_command_returns_trimmed_stdout() {
        let dir = tempfile::tempdir().expect("tempdir");
        let script_path = dir.path().join("ok.sh");
        std::fs::write(&script_path, "#!/bin/sh\nprintf 'host-xyz\\n'\n").expect("write");
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        let src = CustomCommandSource::new(script_path.clone(), Duration::from_secs(2));
        let result = src.run_command(&script_path).expect("ok");
        assert_eq!(result, "host-xyz");
    }

    /// SEC-008 negative case: a custom command whose path is owned by a
    /// non-root uid must be refused before execution, because it runs with the
    /// PAM host's root authority. The test does not run as root, so a script it
    /// creates is owned by a non-root uid — exactly the rejection case.
    #[test]
    #[cfg(unix)]
    fn fetch_rejects_non_root_owned_command() {
        if nix::unistd::Uid::effective().is_root() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let script_path = dir.path().join("host-id.sh");
        std::fs::write(&script_path, "#!/bin/sh\nprintf 'host-xyz\\n'\n").expect("write");
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        let src = CustomCommandSource::new(script_path, Duration::from_secs(2));
        let result = src.fetch(Path::new("/"));
        assert!(
            matches!(result, Err(HostIdentityError::CommandUntrusted { .. })),
            "non-root-owned custom command must be rejected, got {result:?}"
        );
    }
}
