---
id: session-monitoring
kind: операция
context: runtime
name: "Мониторинг активной сессии"
aliases:
  - "session-monitoring"
relations:
  references:
    - runtime.active-session
    - runtime.session-registry
anchors:
  code:
    - "crates/tessera_cli/src/registry.rs"
  test:
    - "tests/e2e/cases/23-monitord.yaml"
requirements:
  MON-001:
    kind: операционное
    subjects:
      - runtime.session-monitoring
    origins:
      - "session-monitoring::Регистрация сессии (SessionOpen)"
    evidence:
      code:
        - "crates/tessera_cli/src/registry.rs"
  MON-002:
    kind: операционное
    subjects:
      - runtime.session-monitoring
    origins:
      - "session-monitoring::Реестр"
    evidence:
      code:
        - "crates/tessera_cli/src/registry.rs"
  MON-003:
    kind: liveness
    subjects:
      - runtime.session-monitoring
    origins:
      - "session-monitoring::udev REMOVE → grace → action"
    evidence:
      test:
        - "tests/e2e/cases/23-monitord.yaml"
  MON-004:
    kind: операционное
    subjects:
      - runtime.session-monitoring
    origins:
      - "session-monitoring::Removal actions"
    evidence:
      code:
        - "crates/tessera_cli/src/registry.rs"
  MON-005:
    kind: операционное
    subjects:
      - runtime.session-monitoring
    origins:
      - "session-monitoring::UpdateSessionTarget"
    evidence:
      code:
        - "crates/tessera_cli/src/registry.rs"
  MON-006:
    kind: операционное
    subjects:
      - runtime.session-monitoring
    origins:
      - "session-monitoring::Suspend/resume"
    evidence:
      code:
        - "crates/tessera_cli/src/registry.rs"
  MON-007:
    kind: операционное
    subjects:
      - runtime.session-monitoring
    origins:
      - "session-monitoring::Очистка по logind SessionRemoved"
    evidence:
      code:
        - "crates/tessera_cli/src/registry.rs"
  MON-008:
    kind: liveness
    subjects:
      - runtime.session-monitoring
    origins:
      - "session-monitoring::Persist и рестарт"
    evidence:
      test:
        - "tests/e2e/cases/23-monitord.yaml"
  MON-009:
    kind: операционное
    subjects:
      - runtime.session-monitoring
    origins:
      - "session-monitoring::peercred"
    evidence:
      code:
        - "crates/tessera_cli/src/registry.rs"
---
# Мониторинг активной сессии

Эта страница заменяет процедурную capability-спеку OpenSpec «session-monitoring»: она
помещает каждое прежнее требование в адресуемую норму с владельцем, видом и
проверяемым происхождением. Под каждым нормативным предложением сохранены подробные условия, отрицательные
сценарии и rationale; они входят в ту же страницу и уточняют границы нормы.

### MON-001 — Регистрация сессии (SessionOpen)

[[runtime.session-monitoring|Мониторинг активной сессии]] MUST соблюдать правило «Регистрация сессии (SessionOpen)» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/session-monitoring/spec.md, requirement «Регистрация сессии (SessionOpen)».

При `SessionOpen` демон должен проверить race «устройство уже вынуто»: если у сессии есть `usb_serial` и udev-query его не видит → ответ `Error{DEVICE_GONE 1001}`, сессия не добавляется (fail-closed против гонки auth↔remove, T19) (state.rs:262–278). Иначе — `registry.add` + атомарный persist + Ack.

#### Scenario: Устройство вынуто между auth и SessionOpen
- **WHEN** у регистрируемой сессии есть `usb_serial`, а udev-query его уже не видит
- **THEN** возвращается `Error{DEVICE_GONE 1001}`, сессия не добавляется

### MON-002 — Реестр

[[runtime.session-monitoring|Мониторинг активной сессии]] MUST соблюдать правило «Реестр» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/session-monitoring/spec.md, requirement «Реестр».

`ActiveSession`: session_id (Uuid), pam_user, pam_service, target (SessionTarget), usb_serial, host_id_hash, opened_at, cert_cn, cert_serial, engineer_ski/cert_sha256 (v2), uid (v2). Индексы by_id + by_uid; `uid==0` — sentinel «unknown», не должен попадать в by_uid и не должен матчиться `find_by_uid(0)` (защита от wildcard-матча) (registry.rs:29–195).

#### Scenario: Сессия с uid==0
- **WHEN** регистрируется сессия с `uid==0` (sentinel «unknown»)
- **THEN** она не попадает в индекс by_uid и не матчится `find_by_uid(0)`

### MON-003 — udev REMOVE → grace → action

[[runtime.session-monitoring|Мониторинг активной сессии]] MUST соблюдать правило «udev REMOVE → grace → action» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/session-monitoring/spec.md, requirement «udev REMOVE → grace → action».

При `(Remove, serial)` демон должен: (1) подавить, если в suspend-grace окне; (2) найти ВСЕ сессии с этим serial; (3) dedup hub-disconnect (один grace-token на serial); (4) запустить grace-таймер (`usb_removed_grace_seconds`); по истечении — `ActionRequest` на каждую сессию. `(Add, serial)` внутри grace должен отменять таймер (реинзёршн) (state.rs:330–386).

#### Scenario: Реинзёршн в grace-окне
- **WHEN** после `(Remove, serial)` в пределах grace-окна приходит `(Add, serial)`
- **THEN** grace-таймер отменяется, `ActionRequest` не отправляется

### MON-004 — Removal actions

[[runtime.session-monitoring|Мониторинг активной сессии]] MUST соблюдать правило «Removal actions» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/session-monitoring/spec.md, requirement «Removal actions».

Демон должен исполнить действие из `monitor.on_usb_removed` (fallback на top-level):

| Action | Исполнение |
|---|---|
| lock | D-Bus logind `LockSession(id)` |
| logout | D-Bus logind `TerminateSession(id)` — закрывается только сессия владельца носителя, хост и параллельные сессии живут |
| hook | spawn `on_usb_removed_hook_path` с env CERT_CN/PAM_USER/PAM_SERVICE/USB_SERIAL/HOST_ID_HASH/SESSION_ID |
| shutdown | ALERT-лог + D-Bus `PowerOff(false)` |

#### Scenario: Нет logind id у сессии
- **WHEN** target сессии не `LogindSession` (PAM-стек не прислал UpdateSessionTarget)
- **THEN** lock/logout должен дропаться с WARN «Logout requested but session has no logind id» (fail-open для действия, не для auth) (actions.rs:51–57)
- Это был баг 0.3.10–0.3.12; путь починен в v0.3.13/0.3.14 через `UpdateSessionTarget` (PAM-сторона шлёт XDG_SESSION_ID; демон персистит новый target — переживает рестарт). **Код-путь в main рабочий** при корректном порядке PAM-стека.

### MON-005 — UpdateSessionTarget

[[runtime.session-monitoring|Мониторинг активной сессии]] MUST соблюдать правило «UpdateSessionTarget» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/session-monitoring/spec.md, requirement «UpdateSessionTarget».

Демон должен обрабатывать `UpdateSessionTarget{session_id,new_target}`: `registry.update_target` in-place + persist снапшота (state.rs:296–326).

#### Scenario: PAM-сторона прислала XDG_SESSION_ID
- **WHEN** приходит `UpdateSessionTarget{session_id,new_target}`
- **THEN** target сессии обновляется in-place и снапшот персистится (переживает рестарт демона)

### MON-006 — Suspend/resume

[[runtime.session-monitoring|Мониторинг активной сессии]] MUST соблюдать правило «Suspend/resume» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/session-monitoring/spec.md, requirement «Suspend/resume».

Демон должен обрабатывать сигналы сна: `PrepareForSleep(true)` → состояние Suspending + отмена ВСЕХ активных grace-таймеров (suspend объясняет отключение). `PrepareForSleep(false)` → Resumed(now); REMOVE подавляются ещё `suspend_grace_seconds` после resume (state.rs:49–70,388–406).

#### Scenario: REMOVE сразу после resume
- **WHEN** в пределах `suspend_grace_seconds` после `PrepareForSleep(false)` приходит udev REMOVE
- **THEN** событие подавляется (отключение объясняется suspend/resume)

### MON-007 — Очистка по logind SessionRemoved

[[runtime.session-monitoring|Мониторинг активной сессии]] MUST соблюдать правило «Очистка по logind SessionRemoved» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/session-monitoring/spec.md, requirement «Очистка по logind SessionRemoved».

При `SessionRemoved{id}` демон должен удалить все сессии с `target.logind_id()==id` + persist — единственный автоматический close помимо явного `SessionClose` (state.rs:407–426).

#### Scenario: logind закрыл сессию
- **WHEN** приходит `SessionRemoved{id}`
- **THEN** удаляются все сессии с `target.logind_id()==id`, снапшот персистится

### MON-008 — Persist и рестарт

[[runtime.session-monitoring|Мониторинг активной сессии]] MUST соблюдать правило «Persist и рестарт» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/session-monitoring/spec.md, requirement «Persist и рестарт».

Снапшот должен писаться атомарно: tempfile → МКЦ-метка на fd (level=0, до rename — закрывает TOCTOU) → write+sync → rename → fsync каталога; файл 0600 на tmpfs `/run/tessera/sessions.json` (volatile между reboot — компромисс: при reboot процессы и так умирают). Load fail-soft: нет файла/corrupt → пустой реестр + WARN (state.rs:453–478, registry/store.rs).

#### Scenario: Снапшот повреждён при старте
- **WHEN** при старте демона файл снапшота отсутствует или повреждён
- **THEN** реестр загружается пустым + WARN (fail-soft)

### MON-009 — peercred

[[runtime.session-monitoring|Мониторинг активной сессии]] MUST соблюдать правило «peercred» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/session-monitoring/spec.md, requirement «peercred».

Демон должен принимать соединения только от peer uid==0 (SO_PEERCRED); чужой uid → reject до handshake (peercred.rs:45–47, server.rs:251–256). Демон сам работает под `User=tessera`; привилегированные D-Bus действия — через polkit-rule.

#### Scenario: Соединение от непривилегированного uid
- **WHEN** на сокет подключается peer с uid != 0
- **THEN** соединение отклоняется ещё до handshake

