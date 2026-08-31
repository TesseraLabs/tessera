---
id: daemon-lifecycle
kind: операция
context: runtime
name: "Жизненный цикл демона"
aliases:
  - "daemon-lifecycle"
relations:
  references:
    - runtime.monitor-daemon
anchors:
  code:
    - "crates/tessera_cli/src/daemon/mod.rs"
  test:
    - "tests/e2e/cases/23-monitord.yaml"
requirements:
  DAE-001:
    kind: операционное
    subjects:
      - runtime.daemon-lifecycle
    origins:
      - "daemon-lifecycle::systemd unit"
    evidence:
      code:
        - "crates/tessera_cli/src/daemon/mod.rs"
  DAE-002:
    kind: liveness
    subjects:
      - runtime.daemon-lifecycle
    origins:
      - "daemon-lifecycle::Startup-check — fail-closed gate"
    evidence:
      test:
        - "tests/e2e/cases/23-monitord.yaml"
  DAE-003:
    kind: инвариант
    subjects:
      - runtime.daemon-lifecycle
    origins:
      - "daemon-lifecycle::Singleton через flock"
    evidence:
      test:
        - "tests/e2e/cases/23-monitord.yaml"
  DAE-004:
    kind: liveness
    subjects:
      - runtime.daemon-lifecycle
    origins:
      - "daemon-lifecycle::Startup-cleanup остаточных USB mountpoint"
    evidence:
      test:
        - "tests/e2e/cases/23-monitord.yaml"
  DAE-005:
    kind: операционное
    subjects:
      - runtime.daemon-lifecycle
    origins:
      - "daemon-lifecycle::sd_notify"
    evidence:
      code:
        - "crates/tessera_cli/src/daemon/mod.rs"
  DAE-006:
    kind: liveness
    subjects:
      - runtime.daemon-lifecycle
    origins:
      - "daemon-lifecycle::Shutdown"
    evidence:
      test:
        - "tests/e2e/cases/23-monitord.yaml"
  DAE-007:
    kind: операционное
    subjects:
      - runtime.daemon-lifecycle
    origins:
      - "daemon-lifecycle::Runtime-флаги"
    evidence:
      code:
        - "crates/tessera_cli/src/daemon/mod.rs"
  DAE-008:
    kind: операционное
    subjects:
      - runtime.daemon-lifecycle
    origins:
      - "daemon-lifecycle::Best-effort шаги старта"
    evidence:
      code:
        - "crates/tessera_cli/src/daemon/mod.rs"
---
# Жизненный цикл демона

Эта страница заменяет процедурную capability-спеку OpenSpec «daemon-lifecycle»: она
помещает каждое прежнее требование в адресуемую норму с владельцем, видом и
проверяемым происхождением. Под каждым нормативным предложением сохранены подробные условия, отрицательные
сценарии и rationale; они входят в ту же страницу и уточняют границы нормы.

### DAE-001 — systemd unit

[[runtime.daemon-lifecycle|Жизненный цикл демона]] MUST соблюдать правило «systemd unit» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/daemon-lifecycle/spec.md, requirement «systemd unit».

`Type=notify`; `User=tessera/Group=tessera` (НЕ root — привилегированные logind-действия через polkit-rule `49-tessera.rules`); `After=systemd-udevd systemd-logind dbus`, `Requires=systemd-logind`; `Restart=on-failure/5s`; hardening (ProtectSystem=strict, NoNewPrivileges, `MemoryDenyWriteExecute=no` из-за OpenSSL/gost W^X); `CAP_DAC_READ_SEARCH`; `RuntimeDirectory/StateDirectory/CacheDirectory=tessera` (0750). Демон должен стартовать ДО display manager (USB hot-plug до логина).

#### Scenario: Старт до display manager
- **WHEN** система загружается и поднимается display manager
- **THEN** демон уже запущен и удерживает USB hot-plug события до момента логина

### DAE-002 — Startup-check — fail-closed gate

[[runtime.daemon-lifecycle|Жизненный цикл демона]] MUST соблюдать правило «Startup-check — fail-closed gate» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/daemon-lifecycle/spec.md, requirement «Startup-check — fail-closed gate».

При старте (и в `tessera check`) должен прогоняться pipeline: pam_stack ordering (включая `pam_stack_session_misorder`), `[mac].runtime` vs реальное ядро, trust anchors наличие/читаемость, world-writable на `/etc/tessera/ca/`, PARSEC_CAP_CHMAC, host_identity probe. ЛЮБАЯ Error-запись → демон должен отказаться стартовать (bail, exit FAILURE); Info/Warn — только лог (startup_check.rs:230–247, daemon/mod.rs:125–135).

#### Scenario: Error-запись в pipeline
- **WHEN** хотя бы одна проверка pipeline возвращает Error-запись
- **THEN** демон отказывается стартовать (bail, exit FAILURE)

#### Scenario: Только Info/Warn
- **WHEN** pipeline даёт только Info/Warn-записи без Error
- **THEN** демон стартует, записи попадают только в лог

### DAE-003 — Singleton через flock

[[runtime.daemon-lifecycle|Жизненный цикл демона]] MUST соблюдать правило «Singleton через flock» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/daemon-lifecycle/spec.md, requirement «Singleton через flock».

Демон должен до загрузки реестра и привязки сокета захватить эксклюзивный неблокирующий `flock(2)` (`LOCK_EX | LOCK_NB`) на `<state_dir>/daemon.lock` (mode 0600, O_CLOEXEC; фолбэк-путь `/var/lib/tessera/daemon.lock`) — `daemon/singleton.rs`, `daemon/mod.rs:197–240`, коммит ec4185b. При контенции (EWOULDBLOCK) второй экземпляр должен эмитнуть CRITICAL audit-событие `daemon_already_running` (target `tessera.daemon.singleton`, поле `conflicting_pid` — best-effort PID из lock-файла) и завершиться с ошибкой. При успехе PID пишется через тот же fd, что держит flock (truncate+write+sync), закрывая TOCTOU-окно чтения PID предшественника. Замок должен удерживаться до самого конца graceful-shutdown (`run_async` держит `DaemonLock` живым после `graceful_finish`); ядро освобождает flock при выходе/краше процесса автоматически.

#### Scenario: Второй экземпляр демона
- **WHEN** `tessera daemon` запускается, пока другой экземпляр держит flock на daemon.lock
- **THEN** второй экземпляр эмитит CRITICAL-событие `daemon_already_running` с конфликтующим PID и немедленно завершается с ошибкой, не трогая сокет/состояние

#### Scenario: Замок живёт до конца shutdown
- **WHEN** демон получает сигнал и проходит graceful shutdown
- **THEN** flock удерживается до завершения `run_async` — новый экземпляр не может стартовать, пока первый не закончил shutdown

### DAE-004 — Startup-cleanup остаточных USB mountpoint

[[runtime.daemon-lifecycle|Жизненный цикл демона]] MUST соблюдать правило «Startup-cleanup остаточных USB mountpoint» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/daemon-lifecycle/spec.md, requirement «Startup-cleanup остаточных USB mountpoint».

При старте, ДО bind IPC-сокета, демон должен пройтись по `/run/tessera/mounts/*` (константа `mount::usb::MOUNTPOINT_BASE`, общая с PAM-модулем) и для каждого остаточного каталога выполнить best-effort `umount2(MNT_DETACH)` + rmdir, логируя WARN на каждый найденный остаток (target `tessera.mount`, daemon/stale_mounts.rs). Остатки возникают при crash PAM-процесса (Drop MountGuard не выполняется) и при исчерпании EBUSY-ретраев rmdir; `/run` — tmpfs и чистится только на reboot. Сбой очистки (включая отсутствие привилегий на umount/rmdir) не должен блокировать старт.

#### Scenario: Остатки после crash PAM-процесса
- **WHEN** под `/run/tessera/mounts/` остались каталоги от упавшего PAM-процесса и демон стартует
- **THEN** демон до bind сокета выполняет lazy-umount + rmdir каждого остатка и эмитит WARN на каждый; старт продолжается независимо от исхода очистки

### DAE-005 — sd_notify

[[runtime.daemon-lifecycle|Жизненный цикл демона]] MUST соблюдать правило «sd_notify» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/daemon-lifecycle/spec.md, requirement «sd_notify».

После bind listener + spawn всех тасков демон должен послать `READY=1` (идемпотентно); отсутствие NOTIFY_SOCKET — не фатально (notify.rs:54–71).

#### Scenario: Готовность отправлена
- **WHEN** listener забинден и все таски заспавнены
- **THEN** демон шлёт `READY=1` идемпотентно; при отсутствии NOTIFY_SOCKET старт продолжается без ошибки

### DAE-006 — Shutdown

[[runtime.daemon-lifecycle|Жизненный цикл демона]] MUST соблюдать правило «Shutdown» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/daemon-lifecycle/spec.md, requirement «Shutdown».

SIGTERM/SIGINT → cancel-токен; все таски слушают его; `graceful_finish` должна ждать join до 5s, затем unlink сокета; state-manager отменяет outstanding grace-таймеры (shutdown.rs, state.rs:202–205).

#### Scenario: Graceful shutdown по сигналу
- **WHEN** демон получает SIGTERM или SIGINT
- **THEN** взводится cancel-токен, `graceful_finish` ждёт join до 5s, затем unlink сокета и отмена outstanding grace-таймеров

### DAE-007 — Runtime-флаги

[[runtime.daemon-lifecycle|Жизненный цикл демона]] MUST соблюдать правило «Runtime-флаги» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/daemon-lifecycle/spec.md, requirement «Runtime-флаги».

`--no-udev` — udev-thread не стартует, device-query = AlwaysPresent (DEVICE_GONE-проверка всегда проходит). `--no-dbus` — actions → Noop (лог вместо действий), removal-enforcement НЕ работает; production не должен использовать `--no-dbus`. D-Bus connect — fail-fast: без system-bus демон падает, не деградирует молча (daemon/mod.rs:67–72,269–274).

#### Scenario: D-Bus недоступен в production
- **WHEN** демон запускается без `--no-dbus` и system-bus недоступен
- **THEN** демон падает (fail-fast), не деградируя молча

### DAE-008 — Best-effort шаги старта

[[runtime.daemon-lifecycle|Жизненный цикл демона]] MUST соблюдать правило «Best-effort шаги старта» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/daemon-lifecycle/spec.md, requirement «Best-effort шаги старта».

Fly-dm wallpaper update при старте — best-effort и не должен блокировать старт (daemon/mod.rs:146–175).

#### Scenario: Сбой wallpaper update
- **WHEN** fly-dm wallpaper update при старте завершается ошибкой
- **THEN** старт демона продолжается, шаг считается best-effort

- Замечание: tokio runtime жёстко `worker_threads(2)` — docs утверждают «системный default», неверно (daemon/mod.rs:82–84).
- Замечание (история): flock-singleton существовал в 0.2.3 (ветка fix/daemon-singleton-and-audit-trail), затем отсутствовал в main и заново реализован в ec4185b (см. Requirement «Singleton через flock»). `execute_attempt` audit из той же ветки в main по-прежнему отсутствует.

