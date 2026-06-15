# Proposal: linux-session-enforcement

## Why

Спека утверждает, что Linux OS-enforcement (supplementary-группы, sudo-роль,
RLIMIT и systemd-лимиты сессии) **работает в открытой сборке**:

- `role-selection/spec.md` (Requirement «Роль, требующая недоступный enforcement»):
  «Роли, чей payload полностью покрыт доступными backend'ами (**группы/sudo/лимиты**),
  работают в открытой сборке полностью»; сценарий — «роль только с группами/sudo работает».
- `tessera-platform.md` (§per-OS адаптеры): «`linux` — supplementary-группы (своя
  реализация, не `pam_group`), sudoers-роли, systemd-лимиты сессии».

Код v0.4.0 этого к пользовательской сессии **не применяет**:

- `SessionRolePayload` (`tessera_core/src/role/selection.rs:238`) переносит из роли
  только `role/role_version/ttl/mac_mask`. Поля `groups`, `sudo_role`, `limits`
  парсятся и валидируются (`role/schema.rs`), но до сессии не доходят.
- Все `setgroups`/`setrlimit` — только в `crates/tessera_core/src/hooks/`
  (`child_setup.rs`, `rlimit.rs`), т.е. на пути `fork`→`execve` **hook-процессов**,
  а не входа инженера. `HookVars` для `session_open` не несёт payload роли.
- К самой сессии применяется только `mac_mask` через `ParsecBackend` (МКЦ, Astra,
  коммерческая часть).

Итог-разрыв: на Linux без МКЦ роли `oper`/`serv` различают только **личность и TTL**,
но не дают разных групп, sudo-прав и лимитов. На открытой сборке вне Astra
дифференциации прав по ролям фактически нет — вопреки заявлению спеки.

## What Changes

- **`SessionRolePayload` несёт полный Linux-payload** — `groups`, `sudo_role`,
  `limits`, `[session]`-лимиты, а не только `mac_mask`. Снапшот на момент открытия
  (как требует «фиксация payload в сессии»).
- **Backend применения для Linux-сессии** по паттерну `MacBackend` (trait +
  реализация в открытом ядре, в отличие от МКЦ — он коммерческий): применение
  supplementary-групп (своя реализация, не `pam_group`), `RLIMIT_NOFILE/NPROC`,
  systemd-лимитов сессии (`MemoryMax`/`TasksMax`/`CPUWeight`/`IOWeight`).
- **Точка применения** — группы и `RLIMIT` в `pam_sm_setcred` (`entry.rs:510`,
  сейчас роль не применяет), systemd cgroup-лимиты в `open_session` через logind
  DBus `SetUnitProperties` (решения — design.md).
- **Группы** — replace набором роли (`setgroups` = ровно группы роли),
  least-privilege поверх бесправной технической учётки.
- **`sudo_role` депрекейтится** — sudo-доступ выражается членством в группе
  (`groups`), на которую заранее настроено правило в `sudoers.d`; Tessera не
  пишет в `sudoers.d` на лету.
- **Fail-closed**: примитив, который не удалось применить, ведёт к отказу входа
  с диагностикой — не молчаливое сужение прав (тот же принцип, что для `mac_mask`).

## Capabilities

### Modified Capabilities

- `role-selection`: требование «полное покрытие payload группами/sudo/лимитами
  работает в открытой сборке» подкрепляется реальным backend применения;
  `SessionRolePayload` фиксирует полный Linux-payload, а не только `mac_mask`.

### Added Capabilities

- `linux-session-enforcement`: контракт применения Linux OS-примитивов к
  пользовательской сессии (группы, sudo-роль, RLIMIT, systemd-лимиты), фазы PAM,
  поведение fail-closed, граница с МКЦ/SELinux.

## Impact

- `tessera_core`: `role/selection.rs` (`SessionRolePayload` + перенос payload),
  новый модуль применения (по образцу `mac/` — trait + open-ядро backend),
  `role/schema.rs` (уже парсит — без изменений формата).
- `pam_tessera`: `entry.rs` (`pam_sm_setcred` / session-open — точки применения),
  `session.rs` (вплетение Linux-backend рядом с MAC-orchestrator).
- Open/commercial: Linux-enforcement — **открытая** часть (по `role-format` split);
  МКЦ (ParsecBackend) и SELinux-адаптер остаются коммерческими — не затрагиваются.
- Тесты: unit на перенос payload и выбор примитивов; интеграционные — реальное
  членство в группах и лимиты в открытой сессии (root-окружение/контейнер).
- `docs/`: после реализации заявления `architecture.md` и доки (вкл. раздел
  `atm-deployment.md`) про группы/sudo/лимиты становятся правдой.
- Не затрагивает: МКЦ-путь, PKCS#11/PKCS#12-аутентификацию, hook-механизм
  (его `setgroups`/`setrlimit` — отдельный путь для дочерних процессов).
