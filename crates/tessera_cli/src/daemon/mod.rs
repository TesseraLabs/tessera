//! Daemon subcommand: the long-running monitor process.
//!
//! Historically the body of this module lived as the top-level `main()` of
//! the `tessera-monitord` binary. As part of the Phase 0 pre-flight for
//! scopes / M-of-N (see `docs/superpowers/plans/2026-05-12-scopes-and-m-of-n.md`)
//! the binary was renamed to `tessera` and grew clap subcommands; this
//! module owns the `daemon` subcommand's lifecycle so future siblings
//! (`execute`, `policy`, …) can sit alongside it without disturbing the
//! daemon's wiring.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

mod singleton;
mod stale_mounts;
mod token_presence;
mod watchdog;
use singleton::{DaemonLock, LockError};

use clap::Args;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use tessera_core::config::validated::OnUsbRemoved as CoreOnUsbRemoved;

#[cfg(target_os = "linux")]
use crate::logind::LogindActions;
use crate::logind::{LogindActionsTrait, NoopActions};
use crate::registry::{RegistryStore, SessionRegistry};
use crate::state::{spawn_state_manager, CredentialMode, OnUsbRemoved, StateConfig};
use crate::udev_query::{AlwaysPresent, UdevQuery};
use crate::{actions, logging, logind, notify, registry, server, shutdown, state, udev_monitor};

/// CLI arguments for `tessera daemon`.
///
/// Long flag names match the legacy `tessera-monitord` binary so the
/// shipped systemd unit (`ExecStart=/usr/bin/tessera daemon
/// --config …`) and any operator scripts keep working unchanged.
#[derive(Debug, Args)]
pub struct DaemonArgs {
    /// Path to the shared TOML config file. When present, fields under
    /// `[monitor]` populate the daemon's runtime knobs; CLI flags below
    /// (when supplied) override the config values.
    #[arg(long, default_value = "/etc/tessera/config.toml")]
    pub config: PathBuf,
    /// Unix socket path. Overrides `monitor.socket_path`.
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// Path to the persisted session registry. Overrides
    /// `monitor.state_file_path`.
    #[arg(long)]
    pub state_file: Option<PathBuf>,
    /// Grace seconds between USB removal and the configured action.
    /// Overrides `monitor.usb_removed_grace_seconds`.
    #[arg(long)]
    pub grace_seconds: Option<u64>,
    /// Suspend grace window in seconds. Overrides
    /// `monitor.suspend_grace_seconds`.
    #[arg(long)]
    pub suspend_grace_seconds: Option<u64>,
    /// Skip launching the udev monitor thread.
    ///
    /// When set, the [`UdevQuery`] used by `SessionOpen` race-checks also
    /// degrades to [`AlwaysPresent`] so e2e tests that disable the udev
    /// thread don't get spurious `DEVICE_GONE` rejections from a
    /// `RealUdevQuery` that would scan a non-functional bus.
    #[arg(long, default_value_t = false)]
    pub no_udev: bool,
    /// Skip connecting to D-Bus.
    ///
    /// When set, the actions backend degrades to a no-op (lock/terminate/
    /// power-off requests are logged but never sent) and the logind signal
    /// listener is not started. Production must NEVER set this — the whole
    /// point of the monitor daemon is to enforce removal via logind.
    #[arg(long, default_value_t = false)]
    pub no_dbus: bool,
}

/// Run the monitor daemon to completion.
///
/// Returns `ExitCode::SUCCESS` on clean shutdown (SIGTERM/SIGINT) and
/// `ExitCode::FAILURE` on fatal init errors (config load, D-Bus connect,
/// socket bind). The actual async lifecycle runs inside a freshly built
/// tokio runtime so `main()` itself stays attribute-free.
pub fn run(args: DaemonArgs) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to build tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    match rt.block_on(run_async(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tessera daemon: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn run_async(args: DaemonArgs) -> anyhow::Result<()> {
    logging::init()?;
    tracing::info!(target: "tessera.monitord", "starting");

    // Load the shared validated config: the monitor daemon and the PAM cdylib
    // MUST agree on socket path / state file / removal action / grace timers.
    // Operators previously had to edit the systemd unit's CLI flags AND
    // config.toml in lockstep; with this change the daemon reads the same
    // file as PAM and CLI flags only act as overrides.
    //
    // Loaded through the privileged path check, like PAM: the daemon is
    // long-lived and root, and the config names native modules it will load
    // into its own address space, so a config or module that some other user
    // can rewrite must stop startup rather than be trusted.
    let validated =
        tessera_core::config::load_privileged_validated_config(&args.config).map_err(|e| {
            anyhow::anyhow!(
                "failed to load monitord config from {}: {e}",
                args.config.display()
            )
        })?;

    // Logging came up before the config could be read; now that
    // `[logging].level` is known, swap it into the live filter.  The
    // `TESSERA_LOG` environment variable keeps precedence (no-op then).
    logging::apply_config_level(validated.logging.level)?;

    // Run the startup-validation sweep once per boot. Log every record at
    // its severity level; if any check reported `Error`, refuse to start
    // so misconfigurations surface loudly in `systemctl status` instead of
    // silently degrading every subsequent auth.
    //
    // The gost-engine is probed before the plugin is loaded: loading
    // verifies the plugin's detached signature through OpenSSL, and the
    // first call into libcrypto registers gost-engine ambiently from
    // Astra's `openssl.cnf`, after which our own explicit load of the
    // engine is refused. Probing later would report a broken engine on a
    // host where authentication works.
    let gost_readiness = crate::startup_check::gost::probe(&validated);
    let mac_backend: Arc<dyn tessera_core::mac::MacBackend> = Arc::from(
        tessera_core::plugin::load_enforcement_backend(validated.mac.backend.as_deref(), ""),
    );
    let startup_opts = crate::startup_check::StartupCheckOptions::default();
    let report = crate::startup_check::run_startup_checks_with_backend_and_gost(
        &validated,
        &startup_opts,
        mac_backend.as_ref(),
        gost_readiness,
    );
    report.log();
    if report.has_errors() {
        anyhow::bail!(
            "startup validation reported {n} error(s); refusing to start. Re-run \
             'tessera check --config {cfg}' for the same summary without restarting.",
            n = report.count(crate::startup_check::StartupCheckSeverity::Error),
            cfg = args.config.display(),
        );
    }

    // Astra greeter wallpaper: resolve the host identity once and (when
    // enabled) bake the host_id into the fly-dm login-screen background
    // JPG so it is visible to the operator. On Astra МКЦ-3 the
    // fly-modern theme hard-codes the headline string and ignores
    // GreetString, so the wallpaper is the only reliable surface. Failures
    // MUST NOT block startup — a broken filesystem / missing image is not
    // a reason to refuse authentication. We log and continue. Without
    // this banner the daemon still works (the `host_id` PAM_TEXT_INFO
    // from flow.rs remains as universal fallback for TTY/sshd/sudo).
    {
        let resolver = tessera_core::host_identity::HostIdentityResolver::from_validated(
            &validated.host_identity,
            std::path::PathBuf::from("/"),
        );
        match resolver.resolve() {
            Ok(host_identity) => {
                match crate::fly_dm_wallpaper_writer::update(
                    &validated.fly_dm_greeter,
                    &host_identity,
                ) {
                    Ok(outcome) => tracing::info!(
                        target: "tessera.fly_dm_greeter",
                        ?outcome,
                        "fly-dm wallpaper update finished"
                    ),
                    Err(e) => tracing::warn!(
                        target: "tessera.fly_dm_greeter",
                        error = %e,
                        "fly-dm wallpaper update failed (continuing)"
                    ),
                }
            }
            Err(e) => tracing::warn!(
                target: "tessera.fly_dm_greeter",
                error = %e,
                "host identity resolution failed for wallpaper update"
            ),
        }
    }

    let monitor_cfg = &validated.monitor;

    let socket_path = args
        .socket
        .clone()
        .unwrap_or_else(|| monitor_cfg.socket_path.clone());
    let state_file_path = args
        .state_file
        .clone()
        .unwrap_or_else(|| monitor_cfg.state_file_path.clone());
    let grace_seconds = args
        .grace_seconds
        .unwrap_or(monitor_cfg.usb_removed_grace.as_secs());
    let suspend_grace_seconds = args
        .suspend_grace_seconds
        .unwrap_or(monitor_cfg.suspend_grace.as_secs());

    // Singleton-защита: захватываем эксклюзивный flock(2) на daemon.lock
    // ДО загрузки реестра и привязки сокета. Так второй экземпляр демона
    // (ручной запуск рядом с systemd-юнитом либо двойной старт из-за ошибки
    // оператора) отвалится здесь, а не позже — когда уже начал бы бороться
    // за тот же сокет, файл состояния и enforcement-канал.
    //
    // Замок кладётся рядом с файлом состояния; каталог создаётся при
    // необходимости (демон может стартовать раньше tmpfiles.d); фолбэк
    // /var/lib/tessera/daemon/daemon.lock — для патологического случая пути
    // без родителя. `lock_path` вычисляем ДО `RegistryStore::new`, который
    // забирает `state_file_path` во владение.
    let lock_path = state_file_path.parent().map_or_else(
        || PathBuf::from("/var/lib/tessera/daemon/daemon.lock"),
        |dir| dir.join("daemon.lock"),
    );
    if let Some(lock_dir) = lock_path.parent() {
        std::fs::create_dir_all(lock_dir).map_err(|e| {
            anyhow::anyhow!(
                "не удалось создать каталог для daemon.lock: {} ({e})",
                lock_dir.display()
            )
        })?;
    }
    let daemon_lock = match DaemonLock::acquire(&lock_path) {
        Ok(lock) => lock,
        Err(LockError::AlreadyHeld { path, pid }) => {
            tracing::error!(
                target: "tessera.daemon.singleton",
                event = "daemon_already_running",
                lock_path = %path.display(),
                conflicting_pid = ?pid,
                audit_level = "CRITICAL",
                "another tessera daemon already holds the singleton lock; refusing to start"
            );
            return Err(LockError::AlreadyHeld { path, pid }.into());
        }
        Err(e) => return Err(e.into()),
    };
    tracing::info!(
        target: "tessera.daemon.singleton",
        lock_path = %daemon_lock.path().display(),
        "acquired daemon singleton lock"
    );

    let store = RegistryStore::with_backend(state_file_path, Arc::clone(&mac_backend));
    // Fail closed on a corrupt or unreadable registry rather than silently
    // starting empty: an empty registry would drop every active session and
    // its pending credential-removal action, defeating continuous-presence
    // enforcement across a restart. A missing file is not an error — it
    // simply means a fresh host with no sessions yet.
    let initial = store.load().map_err(|e| {
        tracing::error!(
            target: "tessera.monitord",
            error = %e,
            audit_level = "CRITICAL",
            "session registry could not be loaded; refusing to start with an empty registry"
        );
        anyhow::Error::new(e)
            .context("load persisted session registry (refusing to start fail-open)")
    })?;
    let registry = SessionRegistry::from_snapshot(initial);

    let shutdown_tok = CancellationToken::new();
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let (action_tx, action_rx) = mpsc::unbounded_channel();

    // Production runs the real udev query so SessionOpen race checks
    // (T19 / T08) actually consult the bus. When `--no-udev` is set we
    // fall back to `AlwaysPresent`: dev/test runs that have no working
    // udev still need SessionOpen to succeed instead of failing closed
    // on a non-functional bus.
    let udev_q: Arc<dyn UdevQuery> = if args.no_udev {
        Arc::new(AlwaysPresent)
    } else {
        // RealUdevQuery is a unit struct on Linux and a type-alias to a unit
        // struct (AlwaysAbsent) on non-Linux dev builds; ::default() is the
        // single expression that compiles on both.
        #[allow(clippy::default_trait_access)]
        Arc::new(<crate::udev_query::RealUdevQuery as Default>::default())
    };
    // Map the validated `[monitor].on_usb_removed` (a fieldless enum in
    // tessera_core) onto monitord's local `OnUsbRemoved` (which
    // carries the hook path inline for `Hook` mode). The validator
    // already guaranteed `on_usb_removed_hook_path` is `Some` whenever
    // the action is `Hook`, so the unwrap-style match is safe — but we
    // bail with a structured error instead of panicking, per
    // err-no-unwrap-prod.
    let on_usb_removed = match monitor_cfg.on_usb_removed {
        CoreOnUsbRemoved::Lock => OnUsbRemoved::Lock,
        CoreOnUsbRemoved::Logout => OnUsbRemoved::Logout,
        CoreOnUsbRemoved::Shutdown => OnUsbRemoved::Shutdown,
        CoreOnUsbRemoved::Hook => {
            let path = monitor_cfg
                .on_usb_removed_hook_path
                .clone()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                    "monitor.on_usb_removed = \"hook\" requires monitor.on_usb_removed_hook_path; \
                     validator should have rejected this config"
                )
                })?;
            OnUsbRemoved::Hook { path }
        }
    };
    let credential_mode = credential_mode_for(&validated);
    let cfg = StateConfig {
        credential_mode,
        grace_seconds,
        suspend_grace_seconds,
        on_usb_removed,
        registry_store: store.clone(),
        monitor_fail_mode: monitor_cfg.fail_mode,
    };

    let state_handle = spawn_state_manager(
        cfg,
        registry.clone(),
        event_rx,
        action_tx,
        udev_q,
        shutdown_tok.clone(),
    );

    // Build the actions backend.
    //
    // - On Linux with D-Bus enabled: open a system-bus connection once and
    //   share it via `Arc`. Failure to connect is fail-fast — silently
    //   falling back to `NoopActions` would defeat removal enforcement.
    // - On Linux with `--no-dbus`: NoopActions (test/dev escape hatch only).
    // - On non-Linux dev builds: `LogindActions` aliases to `NoopActions`,
    //   so the same code path compiles without zbus.
    let actions_backend: Arc<dyn LogindActionsTrait> = if args.no_dbus {
        Arc::new(NoopActions)
    } else {
        #[cfg(target_os = "linux")]
        {
            let conn = zbus::Connection::system().await.map_err(|e| {
                anyhow::anyhow!(
                    "monitord requires a working system D-Bus connection for logind actions; \
                     pass --no-dbus only for tests/dev. Underlying error: {e}"
                )
            })?;
            Arc::new(LogindActions::new(Arc::new(conn)))
        }
        #[cfg(not(target_os = "linux"))]
        {
            // On non-Linux dev builds `LogindActions` is a type alias for
            // `NoopActions`; construct the underlying value directly.
            Arc::new(NoopActions)
        }
    };
    let action_handle =
        actions::spawn_action_runner(action_rx, actions_backend, shutdown_tok.clone());

    let udev_handle = if args.no_udev {
        None
    } else {
        let (udev_tx, mut udev_rx) = mpsc::unbounded_channel();
        let _udev_thread = udev_monitor::spawn_udev_thread(udev_tx, shutdown_tok.clone());
        let event_tx = event_tx.clone();
        let token = shutdown_tok.clone();
        Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    Some(ev) = udev_rx.recv() => {
                        if event_tx.send(state::Event::Udev(ev)).is_err() { break; }
                    }
                }
            }
        }))
    };

    // Strict monitoring promises the session ends with its carrier. Two ways
    // to hold that promise without being able to keep it are known and both
    // are refused here rather than discovered at a locked screen: a carrier
    // nothing polls, and a stalled poll nothing recovers from. The check runs
    // before the socket is bound so it surfaces in `systemctl status`.
    if let Some(refusal) = strict_presence_refusal(
        monitor_cfg.fail_mode,
        credential_mode,
        token_presence_module(&validated).is_some(),
        watchdog::recovery_available(),
    ) {
        anyhow::bail!("{}", refusal.message());
    }

    let (token_presence_handle, poller_liveness) = match token_presence_module(&validated) {
        Some(module) => {
            let (handle, liveness) = token_presence::spawn(
                module,
                validated.pkcs11_locking_mode,
                monitor_cfg.token_poll_interval,
                event_tx.clone(),
                shutdown_tok.clone(),
            );
            (Some(handle), Some(liveness))
        }
        None => (None, None),
    };
    // Feeding the systemd watchdog only while the poller answers is what turns
    // a call hung inside the provider — which nothing in this process can
    // cancel — into a restart that restores observation.
    let watchdog_handle = watchdog::spawn(
        poller_liveness,
        monitor_cfg
            .token_poll_interval
            .saturating_add(token_presence::POLL_CALL_TIMEOUT),
        shutdown_tok.clone(),
    );

    let logind_handle = if args.no_dbus {
        None
    } else {
        let (sig_tx, mut sig_rx) = mpsc::unbounded_channel();
        let _h =
            logind::listener::spawn_logind_listener(logind::listener::BusAddress::System, sig_tx);
        let event_tx = event_tx.clone();
        let token = shutdown_tok.clone();
        Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    Some(s) = sig_rx.recv() => {
                        if event_tx.send(state::Event::Logind(s)).is_err() { break; }
                    }
                }
            }
        }))
    };

    // Sweep stale USB mountpoints before binding the IPC socket. Leftovers
    // appear when a PAM process crashes (MountGuard::drop never runs) or
    // when its rmdir lost the EBUSY race; /run is tmpfs and only resets on
    // reboot while the fleet runs for weeks. Best-effort: failures are
    // logged by the sweep itself and MUST NOT block startup.
    let stale_removed = stale_mounts::cleanup_stale_mounts(
        &tessera_core::mount_guard::RealMountOps,
        std::path::Path::new(tessera_core::mount::usb::MOUNTPOINT_BASE),
    );
    if stale_removed > 0 {
        tracing::info!(
            target: "tessera.mount",
            removed = stale_removed,
            "removed stale USB mountpoints left over from previous runs"
        );
    }

    let listener = server::bind_listener_with_backend(&socket_path, mac_backend.as_ref()).await?;
    let accept_event_tx = event_tx.clone();
    let accept_token = shutdown_tok.clone();
    // Plumb the validated `[monitor]` IPC knobs (idle timeout, connection
    // cap) into the accept loop; without this the daemon silently ran on
    // AcceptConfig::default() and ignored the operator's config.
    let accept_cfg = server::AcceptConfig::from_monitor(monitor_cfg);
    let accept_handle = tokio::spawn(async move {
        server::run_accept_loop_with(listener, accept_event_tx, accept_token, accept_cfg).await;
    });

    let mut notify_handle = notify::NotifyHandle::system_default();
    notify::notify_ready(&mut notify_handle);

    // Результат не важен: к этому моменту токен уже отменён сигналом либо
    // ошибкой установки обработчика, и дальше мы в любом случае гасим демон.
    let _signal_wait = shutdown::install_signal_handlers(shutdown_tok.clone()).await;

    let mut handles = vec![accept_handle, state_handle, action_handle];
    if let Some(h) = udev_handle {
        handles.push(h);
    }
    if let Some(h) = logind_handle {
        handles.push(h);
    }
    if let Some(h) = token_presence_handle {
        handles.push(h);
    }
    if let Some(h) = watchdog_handle {
        handles.push(h);
    }
    shutdown::graceful_finish(handles, Duration::from_secs(5), &socket_path).await;

    // Удерживаем singleton-замок живым до самого конца run_async. `daemon_lock`
    // не помечен `_`, чтобы компилятор не вздумал считать его временным и
    // уронить раньше времени: Drop у `Flock` отпускает kernel-held flock, и
    // ранний дроп открыл бы окно, в котором второй демон смог бы стартовать
    // ещё до завершения graceful-shutdown первого. Эта строка — нагруженная
    // привязка: ссылаемся на замок здесь, чтобы зафиксировать его время жизни.
    // Имя `_lock_kept_alive` (а не `let _ = …`) обязательно: `DaemonLock`
    // помечен `#[must_use]`, и non-binding `let _` уронил бы значение сразу.
    let _lock_kept_alive = &daemon_lock;

    // Reference unused symbols to silence dead-code in the binary build.
    let _ = registry::ActiveSession {
        session_id: uuid::Uuid::nil(),
        pam_user: String::new(),
        pam_service: String::new(),
        target: tessera_proto::SessionTarget::Unknown,
        usb_serial: None,
        usb_vid_pid: None,
        usb_devnode: None,
        carrier: None,
        host_id_hash: String::new(),
        opened_at: std::time::SystemTime::UNIX_EPOCH,
        cert_cn: String::new(),
        cert_serial: String::new(),
        engineer_ski: String::new(),
        engineer_cert_sha256: String::new(),
        uid: 0,
        session_expiry: None,
    };
    Ok(())
}

/// Which identifier namespace the daemon should read `usb_serial` in.
///
/// The distinction is the carrier, not the authentication mode. A USB medium
/// puts a block-device serial there and the daemon can look that device up in
/// udev; a PKCS#11 token — whether it signs (`mode = "pkcs11"`) or merely
/// carries the envelope (`pkcs12_source = "token_object"`) — puts a token
/// serial there, and no block device answers to it.
///
/// Reading a token serial as a block-device serial is not a cosmetic mistake:
/// the session-open path would find no such device and refuse the login, and
/// the removal path would let any USB stick whose descriptor serial collides
/// with the token's end somebody's session.
/// Why a host configured for strict monitoring must not start.
///
/// Strict promises the session ends with its carrier. Two ways to hold that
/// promise without being able to keep it are known, and neither announces
/// itself later: the daemon would run, answer IPC, and enforce nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StrictPresenceRefusal {
    /// A token carrier with no provider for the daemon to ask.
    NoPollableModule,
    /// No way to replace a process whose poll has stalled inside the provider.
    NoRecoveryMechanism,
}

impl StrictPresenceRefusal {
    /// The operator-facing reason, naming both ways out.
    const fn message(self) -> &'static str {
        match self {
            Self::NoPollableModule => {
                "monitor.fail_mode = \"strict\" promises continuous carrier presence, but this \
                 token carrier has no pkcs11_module for the daemon to poll. Set pkcs11_module, \
                 or use monitor.fail_mode = \"permissive\"."
            }
            Self::NoRecoveryMechanism => {
                "monitor.fail_mode = \"strict\" promises continuous carrier presence, but no \
                 systemd watchdog is configured (WATCHDOG_USEC is unset). A PKCS#11 call that \
                 hangs inside the provider cannot be cancelled from within this process, so \
                 without WatchdogSec the daemon would keep running while observing nothing. \
                 Set WatchdogSec= in the unit (the shipped tessera.service does), or use \
                 monitor.fail_mode = \"permissive\"."
            }
        }
    }
}

/// Whether this configuration promises more than the daemon can deliver.
///
/// Only strict monitoring of a token carrier can: a USB carrier is watched by
/// udev, which needs neither a provider nor a restart to keep working, and
/// permissive promises nothing that lost observation would break.
fn strict_presence_refusal(
    fail_mode: tessera_core::config::validated::MonitorFailMode,
    credential_mode: CredentialMode,
    has_pollable_module: bool,
    recovery_available: bool,
) -> Option<StrictPresenceRefusal> {
    if fail_mode != tessera_core::config::validated::MonitorFailMode::Strict
        || credential_mode != CredentialMode::Pkcs11
    {
        return None;
    }
    if !has_pollable_module {
        return Some(StrictPresenceRefusal::NoPollableModule);
    }
    if !recovery_available {
        return Some(StrictPresenceRefusal::NoRecoveryMechanism);
    }
    None
}

/// The PKCS#11 module whose tokens the daemon should poll for presence, or
/// `None` when the carrier is observable through udev instead.
///
/// Both token carriers are covered by the one answer: a token that signs
/// (`mode = "pkcs11"`) and a token that only carries the envelope
/// (`pkcs12_source = "token_object"`) are equally invisible to the block
/// subsystem, and the session records the same kind of serial for both.
///
/// A token carrier without a module is a configuration the validator refuses,
/// so reaching that case means a config built in code. It is logged rather
/// than polled with a guessed path — and logged loudly, because it is the one
/// shape in which the daemon runs with presence enforcement silently absent.
fn token_presence_module(validated: &tessera_core::config::ValidatedConfig) -> Option<PathBuf> {
    if credential_mode_for(validated) != CredentialMode::Pkcs11 {
        return None;
    }
    let module = validated.pkcs11_module.clone();
    if module.is_none() {
        tracing::error!(
            target: "tessera.monitord",
            audit_level = "CRITICAL",
            "token carrier configured without pkcs11_module; token presence is NOT observed"
        );
    }
    module
}

fn credential_mode_for(validated: &tessera_core::config::ValidatedConfig) -> CredentialMode {
    use tessera_core::config::validated::{Mode, Pkcs12Source};

    match (validated.mode, &validated.pkcs12_source) {
        (Mode::Pkcs12, Pkcs12Source::UsbPartition) => CredentialMode::Pkcs12,
        (Mode::Pkcs11, _) | (Mode::Pkcs12, Pkcs12Source::TokenObject { .. }) => {
            CredentialMode::Pkcs11
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod credential_mode_tests {
    use super::{credential_mode_for, token_presence_module, CredentialMode};
    use tessera_core::config::validated::{Mode, Pkcs12Source};

    /// A validated config whose carrier keys are the ones under test.
    ///
    /// Built through the real validator so the mapping is exercised against
    /// what an operator's file actually produces.
    fn cfg(mode: Mode, source: &Pkcs12Source) -> tessera_core::config::ValidatedConfig {
        let dir = tempfile::tempdir().expect("tempdir");
        let anchor = dir.path().join("ca.pem");
        std::fs::write(
            &anchor,
            "-----BEGIN CERTIFICATE-----\nXX\n-----END CERTIFICATE-----\n",
        )
        .expect("anchor");
        let (mode_key, source_keys) = match (mode, source) {
            (Mode::Pkcs11, _) => ("pkcs11", String::new()),
            (Mode::Pkcs12, Pkcs12Source::UsbPartition) => ("pkcs12", String::new()),
            (Mode::Pkcs12, Pkcs12Source::TokenObject { object_label }) => (
                "pkcs12",
                format!(
                    "pkcs12_source = \"token_object\"\npkcs12_token_object_label = \"{object_label}\"\n"
                ),
            ),
        };
        let body = format!(
            r#"crypto_backend = "openssl"
mode = "{mode_key}"
pkcs11_module = "/bin/sh"
usb_wait_seconds = 10
on_usb_removed = "lock"
usb_removed_grace_seconds = 5
suspend_grace_seconds = 5
monitor_fail_mode = "permissive"
{source_keys}
[trust]
anchors = ["{anchor}"]
intermediates = []
max_chain_depth = 5
clock_skew_seconds = 60
allowed_signature_algorithms = []

[trust.revocation]
mode = "none"
crl_paths = []

[trust.pinning]
enabled = false
allowed_root_spki_sha256 = []

[host_identity]
sources = ["hostname"]
fallback = "warn"
custom_command_timeout_seconds = 5

[logging]
level = "info"
"#,
            anchor = anchor.display()
        );
        let path = dir.path().join("config.toml");
        std::fs::write(&path, body).expect("config");
        tessera_core::config::load_validated_config(&path).expect("validate config")
    }

    #[test]
    fn a_usb_carrier_is_read_in_the_block_device_namespace() {
        assert_eq!(
            credential_mode_for(&cfg(Mode::Pkcs12, &Pkcs12Source::UsbPartition)),
            CredentialMode::Pkcs12
        );
    }

    /// The envelope came off a token, so `usb_serial` holds a token serial.
    /// Judged as a block-device serial it matches no device, and the daemon
    /// would answer the login with `DEVICE_GONE`.
    #[test]
    fn a_token_carrier_is_not_read_in_the_block_device_namespace() {
        assert_eq!(
            credential_mode_for(&cfg(
                Mode::Pkcs12,
                &Pkcs12Source::TokenObject {
                    object_label: "tessera-credential".to_owned()
                }
            )),
            CredentialMode::Pkcs11
        );
    }

    #[test]
    fn a_signing_token_is_unchanged() {
        assert_eq!(
            credential_mode_for(&cfg(Mode::Pkcs11, &Pkcs12Source::UsbPartition)),
            CredentialMode::Pkcs11
        );
    }

    /// The only configuration that promises more than the daemon can deliver
    /// is strict monitoring of a token carrier without something to poll or
    /// something to restart it. Both halves are refused at startup, where an
    /// operator sees them in `systemctl status`, rather than at a locked
    /// screen — or, worse, at a screen that never locks.
    #[test]
    fn strict_monitoring_without_observation_refuses_to_start() {
        use super::{strict_presence_refusal, StrictPresenceRefusal};
        use tessera_core::config::validated::MonitorFailMode::Strict;

        assert_eq!(
            strict_presence_refusal(Strict, CredentialMode::Pkcs11, false, true),
            Some(StrictPresenceRefusal::NoPollableModule),
            "a token carrier with no provider to ask observes nothing"
        );
        assert_eq!(
            strict_presence_refusal(Strict, CredentialMode::Pkcs11, true, false),
            Some(StrictPresenceRefusal::NoRecoveryMechanism),
            "a stalled poll with no way to replace the process observes nothing either"
        );
    }

    /// Everything else must start. A refusal that fired too widely would take
    /// the fleet down on upgrade, which is worse than the hole it closes.
    #[test]
    fn every_other_configuration_still_starts() {
        use super::strict_presence_refusal;
        use tessera_core::config::validated::MonitorFailMode::{Permissive, Strict};

        assert_eq!(
            strict_presence_refusal(Strict, CredentialMode::Pkcs11, true, true),
            None,
            "a pollable token carrier with a watchdog keeps its promise"
        );
        for module in [false, true] {
            for recovery in [false, true] {
                assert_eq!(
                    strict_presence_refusal(Permissive, CredentialMode::Pkcs11, module, recovery),
                    None,
                    "permissive promises nothing that lost observation would break \
                     (module={module}, recovery={recovery})"
                );
                assert_eq!(
                    strict_presence_refusal(Strict, CredentialMode::Pkcs12, module, recovery),
                    None,
                    "a USB carrier is watched by udev, which needs neither \
                     (module={module}, recovery={recovery})"
                );
            }
        }
    }

    /// An operator who hits either refusal must be told both ways out, or the
    /// message only says the daemon will not start.
    #[test]
    fn each_refusal_names_both_ways_out() {
        use super::StrictPresenceRefusal;

        for refusal in [
            StrictPresenceRefusal::NoPollableModule,
            StrictPresenceRefusal::NoRecoveryMechanism,
        ] {
            let message = refusal.message();
            assert!(
                message.contains("permissive"),
                "{refusal:?} must offer the mode that makes no such promise: {message}"
            );
            assert!(
                message.contains("pkcs11_module") || message.contains("WatchdogSec"),
                "{refusal:?} must name the setting that fixes it: {message}"
            );
        }
    }

    /// The presence hole is the same for a token that signs and a token that
    /// merely carries the envelope, so both must get the poller — and the USB
    /// carrier, whose removal udev reports, must not.
    #[test]
    fn every_token_carrier_gets_a_presence_poller() {
        let signing = cfg(Mode::Pkcs11, &Pkcs12Source::UsbPartition);
        assert_eq!(
            token_presence_module(&signing).as_deref(),
            signing.pkcs11_module.as_deref(),
            "a signing token has the same presence hole and the same fix"
        );

        let carrier = cfg(
            Mode::Pkcs12,
            &Pkcs12Source::TokenObject {
                object_label: "tessera-credential".to_owned(),
            },
        );
        assert_eq!(
            token_presence_module(&carrier).as_deref(),
            carrier.pkcs11_module.as_deref()
        );

        assert!(
            token_presence_module(&cfg(Mode::Pkcs12, &Pkcs12Source::UsbPartition)).is_none(),
            "polling a provider for a USB stick would ask the wrong subsystem entirely"
        );
    }
}
