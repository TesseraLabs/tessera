---
id: lifecycle-hooks
kind: операция
context: runtime
name: "Хуки жизненного цикла"
aliases:
  - "hooks"
relations:
  references:
    - auth.pam-module
    - runtime.monitor-daemon
anchors:
  code:
    - "crates/tessera_core/src/hooks/executor.rs"
  test:
    - "tests/e2e/cases/21-hooks.yaml"
requirements:
  HOOK-001:
    kind: операционное
    subjects:
      - runtime.lifecycle-hooks
    origins:
      - "hooks::Стадии"
    evidence:
      code:
        - "crates/tessera_core/src/hooks/executor.rs"
  HOOK-002:
    kind: контракт
    subjects:
      - runtime.lifecycle-hooks
    origins:
      - "hooks::Схема [[hooks]]"
    evidence:
      test:
        - "tests/e2e/cases/21-hooks.yaml"
  HOOK-003:
    kind: операционное
    subjects:
      - runtime.lifecycle-hooks
    origins:
      - "hooks::Плейсхолдеры"
    evidence:
      code:
        - "crates/tessera_core/src/hooks/executor.rs"
  HOOK-004:
    kind: контракт
    subjects:
      - runtime.lifecycle-hooks
    origins:
      - "hooks::Контракт исполнения child"
    evidence:
      test:
        - "tests/e2e/cases/21-hooks.yaml"
  HOOK-005:
    kind: операционное
    subjects:
      - runtime.lifecycle-hooks
    origins:
      - "hooks::Окружение"
    evidence:
      code:
        - "crates/tessera_core/src/hooks/executor.rs"
  HOOK-006:
    kind: liveness
    subjects:
      - runtime.lifecycle-hooks
    origins:
      - "hooks::Таймаут и kill"
    evidence:
      test:
        - "tests/e2e/cases/21-hooks.yaml"
  HOOK-007:
    kind: инвариант
    subjects:
      - runtime.lifecycle-hooks
    origins:
      - "hooks::Матрица on_failure"
    evidence:
      test:
        - "tests/e2e/cases/21-hooks.yaml"
---
# Хуки жизненного цикла

Эта страница заменяет процедурную capability-спеку OpenSpec «hooks»: она
помещает каждое прежнее требование в адресуемую норму с владельцем, видом и
проверяемым происхождением. Под каждым нормативным предложением сохранены подробные условия, отрицательные
сценарии и rationale; они входят в ту же страницу и уточняют границы нормы.

### HOOK-001 — Стадии

[[runtime.lifecycle-hooks|Хуки жизненного цикла]] MUST соблюдать правило «Стадии» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/hooks/spec.md, requirement «Стадии».

Ровно 5: `pre_auth` (до касания носителя), `post_auth_success` (после всех проверок, ДО set_pam_data — может отменить вход), `session_open`, `session_close`, `usb_removed` (демон-сторона). Хуки стадии должны исполняться последовательно в порядке объявления; первая ошибка (после on_failure-политики) должна пропускать остальные хуки стадии (runner.rs:33–44).

#### Scenario: Ошибка прерывает стадию
- **WHEN** хук стадии завершается ошибкой (после применения on_failure-политики)
- **THEN** остальные хуки этой стадии пропускаются

### HOOK-002 — Схема hooks

[[runtime.lifecycle-hooks|Хуки жизненного цикла]] MUST соблюдать правило «Схема hooks» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/hooks/spec.md, requirement «Схема hooks».

Каждая запись `hooks` должна иметь: `stage` (enum), `command` (Vec<String>, `command[0]` absolute), `timeout_seconds` (10, 1..=120), `on_failure` (warn|ignore; иное/опечатка тихо → Abort; дефолт: pre_auth→Abort, прочие→Warn), `run_as` ("user"→PAM-user, иначе root), `env` (map значений-шаблонов).

#### Scenario: Невалидный command[0]
- **WHEN** `command[0]` не является абсолютным путём
- **THEN** запись хука отвергается при загрузке конфига

- Плейсхолдеры `${...}` должны подставляться ТОЛЬКО в `env`-значениях; `command` передаётся буквально (fork_exec.rs:104–110) — by design: динамика идёт через `env`, argv-injection невозможен.

### HOOK-003 — Плейсхолдеры

[[runtime.lifecycle-hooks|Хуки жизненного цикла]] MUST соблюдать правило «Плейсхолдеры» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/hooks/spec.md, requirement «Плейсхолдеры».

Поддерживается 10 переменных: pam_user, pam_service, host_id, host_id_hash, host_id_source, cert_cn, cert_serial, usb_serial, usb_vid_pid, session_id. Для `pre_auth` разрешены только первые 5 (cert/usb/session ещё неизвестны); валидация должна выполняться при загрузке конфига. Синтаксис: `${name}`, `$$` = литерал `$`; незакрытый/пустой/неизвестный → ConfigInvalid.

#### Scenario: Недоступный плейсхолдер в pre_auth
- **WHEN** хук стадии `pre_auth` использует `${cert_cn}` (или иной из ещё неизвестных)
- **THEN** загрузка конфига завершается ошибкой ConfigInvalid

### HOOK-004 — Контракт исполнения child

[[runtime.lifecycle-hooks|Хуки жизненного цикла]] MUST соблюдать правило «Контракт исполнения child» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/hooks/spec.md, requirement «Контракт исполнения child».

Child должен: setpgid (своя группа для group-kill) → setsid → stdin=/dev/null, stdout/stderr=pipes → закрыть все FD≥3 (close_range / loop) → rlimit caps (CPU=2×timeout, NOFILE=256, NPROC=64, FSIZE=1MiB) → umask 0077 → `PR_SET_NO_NEW_PRIVS` → drop privileges (setgroups→setgid→setuid при run_as=user) → execve. Любой сбой → `_exit(127)` (child_setup.rs:202–339). Все аллокации — в родителе ДО fork (anti-deadlock на heap-mutex).

#### Scenario: Сбой настройки child
- **WHEN** любой шаг подготовки child (setpgid, rlimit, drop privileges и т.д.) завершается ошибкой
- **THEN** процесс завершается через `_exit(127)`

### HOOK-005 — Окружение

[[runtime.lifecycle-hooks|Хуки жизненного цикла]] MUST соблюдать правило «Окружение» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/hooks/spec.md, requirement «Окружение».

Окружение должно собираться из трёх слоёв: whitelist (`PATH=/usr/sbin:/usr/bin:/sbin:/bin`, HOME, USER, LOGNAME, LANG=C.UTF-8) → все `TESSERA_*` (STAGE, USER, SERVICE, HOST_ID, HOST_ID_HASH, HOST_ID_SOURCE, CERT_CN, CERT_SERIAL, USB_SERIAL, USB_VID_PID, SESSION_ID; пустая строка для None) → пользовательские шаблоны. Любое env-значение с `\n`/`\r`/NUL/C0-control должно отвергаться (`EnvValueRejected`) — защита от env-injection через CN серта (env.rs:116–151).

#### Scenario: Control-байт в env-значении
- **WHEN** env-значение хука содержит `\n`, `\r`, NUL или C0-control (например через CN серта)
- **THEN** значение отвергается с `EnvValueRejected`

### HOOK-006 — Таймаут и kill

[[runtime.lifecycle-hooks|Хуки жизненного цикла]] MUST соблюдать правило «Таймаут и kill» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/hooks/spec.md, requirement «Таймаут и kill».

Раннер должен поллить waitpid каждые 50ms; по таймауту `killpg(SIGTERM)` → 2s → `killpg(SIGKILL)` → reap. Exit-код signaled = 128+signo (wait.rs:82–166).

#### Scenario: Хук превысил таймаут
- **WHEN** хук не завершился к истечению `timeout_seconds`
- **THEN** раннер шлёт `killpg(SIGTERM)`, ждёт 2s, затем `killpg(SIGKILL)` и reap

### HOOK-007 — Матрица on_failure

[[runtime.lifecycle-hooks|Хуки жизненного цикла]] MUST соблюдать правило «Матрица on_failure» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/hooks/spec.md, requirement «Матрица on_failure».

Исход хука должен разрешаться по матрице ниже:

| Состояние | Abort | Warn | Ignore |
|---|---|---|---|
| exit 0 | Ok | Ok | Ok |
| exit ≠0 | Err | Ok+WARN | Ok |
| timeout | Err | **Err** | Ok |
| HookError | Err | Ok+WARN | Ok |

Timeout под Warn должен давать ошибку (SIGKILL структурный); только Ignore подавляет (executor.rs:129–163).

#### Scenario: Timeout под политикой Warn
- **WHEN** хук с `on_failure=warn` завершается по таймауту
- **THEN** исход = ошибка (Err), а не предупреждение — подавляет только Ignore

- Hook-security тесты (no_new_privs, uid-drop, fd-leak) — `#[ignore]` в CI из-за RLIMIT_NPROC=64 на shared-UID раннерах, верифицируются вручную; их автоматизация — proposal [ci-hardening](../../changes/ci-hardening/).

