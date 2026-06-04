# daemon-lifecycle Specification

## Purpose

Жизненный цикл `tessera daemon`: systemd-юнит, startup-проверки, sd_notify, graceful shutdown.

Код: `crates/tessera_cli/src/{daemon/mod.rs, startup_check*, notify.rs, shutdown.rs}`, `dist/systemd/tessera.service`.

## Requirements

### Requirement: systemd unit

`Type=notify`; `User=tessera/Group=tessera` (НЕ root — привилегированные logind-действия через polkit-rule `49-tessera.rules`); `After=systemd-udevd systemd-logind dbus`, `Requires=systemd-logind`; `Restart=on-failure/5s`; hardening (ProtectSystem=strict, NoNewPrivileges, `MemoryDenyWriteExecute=no` из-за OpenSSL/gost W^X); `CAP_DAC_READ_SEARCH`; `RuntimeDirectory/StateDirectory/CacheDirectory=tessera` (0750). Демон ДОЛЖЕН (MUST) стартовать ДО display manager (USB hot-plug до логина).

#### Scenario: Старт до display manager
- **WHEN** система загружается и поднимается display manager
- **THEN** демон уже запущен и удерживает USB hot-plug события до момента логина

### Requirement: Startup-check — fail-closed gate

При старте (и в `tessera check`) ДОЛЖЕН (MUST) прогоняться pipeline: pam_stack ordering (включая `pam_stack_session_misorder`), `[mac].runtime` vs реальное ядро, trust anchors наличие/читаемость, world-writable на `/etc/tessera/ca/`, PARSEC_CAP_CHMAC, host_identity probe. ЛЮБАЯ Error-запись → демон ДОЛЖЕН (MUST) отказаться стартовать (bail, exit FAILURE); Info/Warn — только лог (startup_check.rs:230–247, daemon/mod.rs:125–135).

#### Scenario: Error-запись в pipeline
- **WHEN** хотя бы одна проверка pipeline возвращает Error-запись
- **THEN** демон отказывается стартовать (bail, exit FAILURE)

#### Scenario: Только Info/Warn
- **WHEN** pipeline даёт только Info/Warn-записи без Error
- **THEN** демон стартует, записи попадают только в лог

### Requirement: sd_notify

После bind listener + spawn всех тасков демон ДОЛЖЕН (MUST) послать `READY=1` (идемпотентно); отсутствие NOTIFY_SOCKET — не фатально (notify.rs:54–71).

#### Scenario: Готовность отправлена
- **WHEN** listener забинден и все таски заспавнены
- **THEN** демон шлёт `READY=1` идемпотентно; при отсутствии NOTIFY_SOCKET старт продолжается без ошибки

### Requirement: Shutdown

SIGTERM/SIGINT → cancel-токен; все таски слушают его; `graceful_finish` ДОЛЖНА (MUST) ждать join до 5s, затем unlink сокета; state-manager отменяет outstanding grace-таймеры (shutdown.rs, state.rs:202–205).

#### Scenario: Graceful shutdown по сигналу
- **WHEN** демон получает SIGTERM или SIGINT
- **THEN** взводится cancel-токен, `graceful_finish` ждёт join до 5s, затем unlink сокета и отмена outstanding grace-таймеров

### Requirement: Runtime-флаги

`--no-udev` — udev-thread не стартует, device-query = AlwaysPresent (DEVICE_GONE-проверка всегда проходит). `--no-dbus` — actions → Noop (лог вместо действий), removal-enforcement НЕ работает; production НЕ ДОЛЖЕН (MUST NOT) использовать `--no-dbus`. D-Bus connect — fail-fast: без system-bus демон падает, не деградирует молча (daemon/mod.rs:67–72,269–274).

#### Scenario: D-Bus недоступен в production
- **WHEN** демон запускается без `--no-dbus` и system-bus недоступен
- **THEN** демон падает (fail-fast), не деградируя молча

### Requirement: Best-effort шаги старта

Fly-dm wallpaper update при старте — best-effort и НЕ ДОЛЖЕН (MUST NOT) блокировать старт (daemon/mod.rs:146–175).

#### Scenario: Сбой wallpaper update
- **WHEN** fly-dm wallpaper update при старте завершается ошибкой
- **THEN** старт демона продолжается, шаг считается best-effort

- Замечание: tokio runtime жёстко `worker_threads(2)` — docs утверждают «системный default», неверно (daemon/mod.rs:82–84).
- Замечание (история): flock-singleton и `execute_attempt` audit существовали в 0.2.3 (ветка fix/daemon-singleton-and-audit-trail, 37 коммитов не в main) — в текущем main flock НЕ обнаружен. Ветка — кандидат на ревью человеком.
