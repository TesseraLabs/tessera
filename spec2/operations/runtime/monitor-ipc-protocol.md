---
id: monitor-ipc-protocol
kind: операция
context: runtime
name: "Протокол PAM — monitord"
aliases:
  - "ipc-protocol"
relations:
  references:
    - runtime.pam-monitord-ipc
anchors:
  code:
    - "crates/tessera_proto/src/wire.rs"
  test:
    - "crates/tessera_proto/tests/v2_messages.rs"
requirements:
  IPCR-001:
    kind: операционное
    subjects:
      - runtime.monitor-ipc-protocol
    origins:
      - "ipc-protocol::Транспорт и bind"
    evidence:
      code:
        - "crates/tessera_proto/src/wire.rs"
  IPCR-002:
    kind: операционное
    subjects:
      - runtime.monitor-ipc-protocol
    origins:
      - "ipc-protocol::Framing"
    evidence:
      code:
        - "crates/tessera_proto/src/wire.rs"
  IPCR-003:
    kind: операционное
    subjects:
      - runtime.monitor-ipc-protocol
    origins:
      - "ipc-protocol::PROTOCOL_VERSION = 2, строгое равенство"
    evidence:
      code:
        - "crates/tessera_proto/src/wire.rs"
  IPCR-004:
    kind: контракт
    subjects:
      - runtime.monitor-ipc-protocol
    origins:
      - "ipc-protocol::Сообщения"
    evidence:
      test:
        - "crates/tessera_proto/tests/v2_messages.rs"
  IPCR-005:
    kind: контракт
    subjects:
      - runtime.monitor-ipc-protocol
    origins:
      - "ipc-protocol::Коды ошибок"
    evidence:
      test:
        - "crates/tessera_proto/tests/v2_messages.rs"
  IPCR-006:
    kind: liveness
    subjects:
      - runtime.monitor-ipc-protocol
    origins:
      - "ipc-protocol::Серверные таймауты и лимиты"
    evidence:
      test:
        - "crates/tessera_proto/tests/v2_messages.rs"
  IPCR-007:
    kind: инвариант
    subjects:
      - runtime.monitor-ipc-protocol
    origins:
      - "ipc-protocol::Клиент — connect-per-call + FailMode"
    evidence:
      test:
        - "crates/tessera_proto/tests/v2_messages.rs"
  IPCR-008:
    kind: контракт
    subjects:
      - runtime.monitor-ipc-protocol
    origins:
      - "ipc-protocol::Роль в сообщениях сессии"
    evidence:
      test:
        - "crates/tessera_proto/tests/v2_messages.rs"
---
# Протокол PAM — monitord

Эта страница заменяет процедурную capability-спеку OpenSpec «ipc-protocol»: она
помещает каждое прежнее требование в адресуемую норму с владельцем, видом и
проверяемым происхождением. Под каждым нормативным предложением сохранены подробные условия, отрицательные
сценарии и rationale; они входят в ту же страницу и уточняют границы нормы.

### IPCR-001 — Транспорт и bind

[[runtime.monitor-ipc-protocol|Протокол PAM — monitord]] MUST соблюдать правило «Транспорт и bind» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/ipc-protocol/spec.md, requirement «Транспорт и bind».

Сокет `/run/tessera/monitord.sock` (конфиг `monitor.socket_path`, абсолютный), mode 0660, владелец из systemd `User/Group=tessera`. Bind должен быть TOCTOU-free: bind на `<name>.tmp.<PID>` → chmod 0660 → МКЦ-метка по fd (best-effort на не-Astra) → atomic rename (server.rs:64–130).

#### Scenario: TOCTOU-free bind сокета
- **WHEN** демон биндит управляющий сокет
- **THEN** bind идёт на `<name>.tmp.<PID>` → chmod 0660 → МКЦ-метка → atomic rename (без окна TOCTOU)

### IPCR-002 — Framing

[[runtime.monitor-ipc-protocol|Протокол PAM — monitord]] MUST соблюдать правило «Framing» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/ipc-protocol/spec.md, requirement «Framing».

Один кадр = одна строка UTF-8 JSON + `\n`; `MAX_FRAME_BYTES = 64 KiB`. Encode должен отвергать oversize и встроенный `\n`; серверный read должен быть bounded (никогда не аллоцирует > max+1) (wire.rs:10–84, server.rs:192–222).

#### Scenario: Oversize-кадр
- **WHEN** кадр для encode превышает `MAX_FRAME_BYTES` или содержит встроенный `\n`
- **THEN** encode отвергает его; серверный read никогда не аллоцирует > max+1

### IPCR-003 — PROTOCOL_VERSION = 2, строгое равенство

[[runtime.monitor-ipc-protocol|Протокол PAM — monitord]] MUST соблюдать правило «PROTOCOL_VERSION = 2, строгое равенство» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/ipc-protocol/spec.md, requirement «PROTOCOL_VERSION = 2, строгое равенство».

Первый кадр должен быть `Hello{protocol_version}`; `pv != 2` → `Error{1000 PROTOCOL_MISMATCH}` + close. Negotiation НЕТ — апгрейд требует одновременной замены .so и демона (намеренный break при v1→v2). v2-поля SessionOpen имеют `#[serde(default)]` (forward-compat внутри v2) (version.rs:14, server.rs:375–426).

#### Scenario: Несовпадение версии протокола
- **WHEN** первый кадр `Hello` несёт `protocol_version != 2`
- **THEN** возвращается `Error{1000 PROTOCOL_MISMATCH}` и соединение закрывается

### IPCR-004 — Сообщения

[[runtime.monitor-ipc-protocol|Протокол PAM — monitord]] MUST соблюдать правило «Сообщения» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/ipc-protocol/spec.md, requirement «Сообщения».

Протокол должен поддерживать заданный набор сообщений. ClientMessage: `Hello`, `SessionOpen` (+v2: engineer_ski, engineer_cert_sha256, uid), `GetActiveSessionByUid` (v2), `SessionClose`, `UpdateSessionTarget` (0.3.10+), `Ping`. ServerMessage: `HelloAck`, `Ack`, `SessionTargetUpdated`, `Pong`, `ActiveSession` (v2), `Error{code,message}`. `SessionTarget`: Tty | Display | LogindSession | Unknown.

#### Scenario: Ping/Pong
- **WHEN** клиент после Hello шлёт `Ping`
- **THEN** сервер отвечает `Pong`

### IPCR-005 — Коды ошибок

[[runtime.monitor-ipc-protocol|Протокол PAM — monitord]] MUST соблюдать правило «Коды ошибок» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/ipc-protocol/spec.md, requirement «Коды ошибок».

Сервер должен использовать фиксированный набор числовых кодов ошибок:

| Код | Значение |
|---|---|
| 1000 | PROTOCOL_MISMATCH (close) |
| 1001 | DEVICE_GONE — serial из SessionOpen отсутствует (fail-closed) |
| 1003 | UNAUTHORIZED |
| 1100 | BAD_REQUEST (не Hello первым / не-UTF8 / decode fail) |
| 1101 | PROTOCOL_VIOLATION (oversize / idle-timeout; close) |
| 1200 | NO_ACTIVE_SESSION (v2) |
| 1500 | INTERNAL |

#### Scenario: Первый кадр не Hello
- **WHEN** первым кадром приходит не `Hello` (или не-UTF8 / decode fail)
- **THEN** сервер отвечает кодом `1100 BAD_REQUEST`

### IPCR-006 — Серверные таймауты и лимиты

[[runtime.monitor-ipc-protocol|Протокол PAM — monitord]] MUST соблюдать правило «Серверные таймауты и лимиты» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/ipc-protocol/spec.md, requirement «Серверные таймауты и лимиты».

Сервер должен применять таймауты и лимиты: handshake budget 2s; per-connection idle (→1101+close) и потолок одновременных соединений (Semaphore, permit ДО spawn); внутренний reply-timeout state-manager 5s → INTERNAL. Idle-таймаут и потолок должны браться из валидированной секции `[monitor]` — `idle_timeout_seconds` (дефолт 30) и `max_concurrent_connections` (дефолт 64) пробрасываются в accept-loop через `AcceptConfig::from_monitor` (server.rs:185–193, daemon/mod.rs:379). Peer-cred enforcement при этом всегда включён — это production-инвариант, не операторская ручка.

#### Scenario: Idle-соединение
- **WHEN** соединение простаивает дольше `monitor.idle_timeout_seconds` (дефолт 30s)
- **THEN** сервер шлёт `1101 PROTOCOL_VIOLATION` и закрывает соединение

#### Scenario: Операторский override лимитов
- **WHEN** в `[monitor]` заданы `idle_timeout_seconds` / `max_concurrent_connections`, отличные от дефолтов
- **THEN** accept-loop применяет именно операторские значения (AcceptConfig строится из валидированного `[monitor]`)

### IPCR-007 — Клиент — connect-per-call + FailMode

[[runtime.monitor-ipc-protocol|Протокол PAM — monitord]] MUST соблюдать правило «Клиент — connect-per-call + FailMode» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/ipc-protocol/spec.md, requirement «Клиент — connect-per-call + FailMode».

PAM-клиент должен открывать свежее соединение на каждый RPC (Hello → запрос → ответ → close); таймаут `monitor.timeout_ms` (дефолт 2000, 100..=60000) на read+write. FailMode: `strict` — все ошибки пропагируются; `permissive` — connect/IO/decode → WARN+Ok; `DeviceGone` и `Unauthorized` должны пропагироваться ДАЖЕ в permissive (ipc/client.rs, failmode.rs:37–39).

#### Scenario: DeviceGone в permissive FailMode
- **WHEN** FailMode = `permissive` и RPC возвращает `DeviceGone` либо `Unauthorized`
- **THEN** ошибка пропагируется (не глотается), в отличие от connect/IO/decode-ошибок

### IPCR-008 — Роль в сообщениях сессии

[[runtime.monitor-ipc-protocol|Протокол PAM — monitord]] MUST соблюдать правило «Роль в сообщениях сессии» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/ipc-protocol/spec.md, requirement «Роль в сообщениях сессии».

Сообщения открытия сессии должны нести поля `role` (role_id) и `role_version` (u32),
опциональные на проводе (отсутствие = вход без enforcement ролей, `roles.enforce=false`).
Добавление полей должно быть обратно совместимым в рамках PROTOCOL_VERSION = 2
(новые опциональные поля NDJSON; строгое равенство версии сохраняется). Если совместимость
нарушится иными изменениями этого change — bump до 3 по существующему правилу строгого равенства.

#### Scenario: Session open с ролью
- **WHEN** pam_tessera открывает сессию с ролью `serv` v7
- **THEN** в IPC-сообщении присутствуют `role="serv"`, `role_version=7`; демон пишет их в свои события

#### Scenario: Session open без роли (enforce=false)
- **WHEN** вход выполнен при `roles.enforce = "false"`
- **THEN** поля `role`/`role_version` отсутствуют, сообщение валидно для PROTOCOL_VERSION = 2

- Замечание: `uuid_from_session_id` дублируется в `xdg_capture::session_uuid_from_string` (признано в комментарии) — кандидат на дедуп.

