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

- **`SessionRolePayload` несёт полный Linux-payload** — `groups`, `limits`,
  `[session]`-лимиты, а не только `mac_mask`. Снапшот на момент открытия (как
  требует «фиксация payload в сессии»). `sudo_role` депрекейтится (см. ниже).
- **Группы — через NSS** (`libnss_tessera`), не `setgroups`-в-`setcred`. NSS-модуль
  становится источником строки `group:` в `nsswitch.conf`; штатный `initgroups()`
  приложения (login/fly-dm/sshd) при входе получает от него группы активной роли.
  Перетирать нечего — мы и есть источник, который читает приложение. Активная роль
  доставляется в NSS через registry-по-процессу (расширение monitord; детали —
  design.md). Replace набором роли: NSS отдаёт ровно группы роли поверх бесправной
  техучётки (least-privilege).
- **`RLIMIT_NOFILE/NPROC`** — в `pam_sm_setcred` (`entry.rs:510`, сейчас роль не
  применяет); `setrlimit` не страдает от `initgroups`.
- **systemd cgroup-лимиты** (`MemoryMax`/`TasksMax`/`CPUWeight`/`IOWeight`) — в
  `open_session` через logind DBus `SetUnitProperties` на session-scope; logind
  недоступен → fail-closed.
- **`sudo_role` депрекейтится** — sudo-доступ выражается членством в группе
  (`groups`), на которую заранее настроено правило в `sudoers.d`; Tessera не
  пишет в `sudoers.d` на лету.
- **Fail-safe NSS / fail-closed enforcement**: NSS при отсутствии записи →
  `NOTFOUND` (тихо к следующему источнику, не ломать разрешение групп системы);
  `RLIMIT`/systemd-лимит, который не удалось применить → отказ входа с
  диагностикой (не молчаливое сужение прав, как для `mac_mask`).

Почему NSS, а не `setgroups`-в-`setcred`: login/fly-dm при `setuid` сами зовут
`initgroups()` и могут перетереть набор, выставленный нашим `setcred`. NSS
устраняет зависимость от порядка PAM-фаз и поведения приложения — приложение
само спрашивает нас в `getgrouplist()`.

## Capabilities

### Modified Capabilities

- `role-selection`: требование «полное покрытие payload группами/sudo/лимитами
  работает в открытой сборке» подкрепляется реальным backend применения;
  `SessionRolePayload` фиксирует полный Linux-payload, а не только `mac_mask`.

### Added Capabilities

- `linux-session-enforcement`: контракт применения Linux OS-примитивов к
  пользовательской сессии — группы через NSS-источник (`libnss_tessera`) с
  доставкой активной роли через registry-по-процессу и fail-safe; `RLIMIT` в
  `setcred`; systemd cgroup-лимиты через logind; ЗПС-подпись модулей; граница
  open/commercial (Linux — открытая, МКЦ/SELinux — коммерческие).

## Impact

- **Новый crate `nss_tessera`** — `libnss_tessera.so` (C-ABI, источник `group:`):
  `initgroups_dyn` + `getgrnam_r`/`getgrgid_r` для групп роли; fail-safe NOTFOUND.
- `tessera_core`: `role/selection.rs` (`SessionRolePayload` + перенос payload);
  расширение monitord session-registry полем роль/группы; `RLIMIT`/logind-применение
  (по образцу `mac/` — trait + open-ядро backend); `role/schema.rs` (уже парсит).
- `pam_tessera`: регистрация активной роли в registry в `auth`; `RLIMIT` в
  `pam_sm_setcred`; systemd-лимиты в `open_session` (`entry.rs`, `session.rs`).
- Интеграция: `nsswitch.conf` (`group: files tessera systemd`) и ЗПС-подпись
  `libnss_tessera.so` + `libpam_tessera.so` (`bsign`) — в `integrate-pam.sh`/инсталлятор.
- Open/commercial: Linux-enforcement (NSS+RLIMIT+logind) — **открытая** часть (по
  `role-format` split); МКЦ (ParsecBackend) и SELinux-адаптер остаются коммерческими.
- Тесты: unit на перенос payload, registry, fail-safe NSS; интеграционные — реальное
  членство в группах в сессии login/fly-dm/sshd на Astra SE (NSS-прототип) и лимиты.
- `docs/`: после реализации заявления `architecture.md` и доки (вкл. раздел
  `terminal-deployment.md`) про группы/sudo/лимиты становятся правдой.
- Не затрагивает: МКЦ-путь, PKCS#11/PKCS#12-аутентификацию, hook-механизм
  (его `setgroups`/`setrlimit` — отдельный путь для дочерних процессов).
