# ipc-protocol Specification

## Purpose

Wire-протокол PAM-cdylib ↔ monitord: AF_UNIX SOCK_STREAM, NDJSON-фреймы, строгая версия.

Код: `crates/tessera_proto/src/`, `crates/tessera_core/src/ipc/`, серверная часть `tessera_cli/src/server.rs`.

## Requirements

### Requirement: Транспорт и bind

Сокет `/run/tessera/monitord.sock` (конфиг `monitor.socket_path`, абсолютный), mode 0660, владелец из systemd `User/Group=tessera`. Bind ДОЛЖЕН (MUST) быть TOCTOU-free: bind на `<name>.tmp.<PID>` → chmod 0660 → МКЦ-метка по fd (best-effort на не-Astra) → atomic rename (server.rs:64–130).

#### Scenario: TOCTOU-free bind сокета
- **WHEN** демон биндит управляющий сокет
- **THEN** bind идёт на `<name>.tmp.<PID>` → chmod 0660 → МКЦ-метка → atomic rename (без окна TOCTOU)

- ⚠ KNOWN GAP (docs): architecture.md и реальная unix-группа демона исторически расходились в имени (под прежним именем проекта — `pam_certauth` vs `pamcertauth`) — после переименования обе сводятся к `tessera`; «flock» в persist-описании отсутствует в коде; `/run/tessera/health` упомянут, в коде не найден.

### Requirement: Framing

Один кадр = одна строка UTF-8 JSON + `\n`; `MAX_FRAME_BYTES = 64 KiB`. Encode ДОЛЖЕН (MUST) отвергать oversize и встроенный `\n`; серверный read ДОЛЖЕН (MUST) быть bounded (никогда не аллоцирует > max+1) (wire.rs:10–84, server.rs:192–222).

#### Scenario: Oversize-кадр
- **WHEN** кадр для encode превышает `MAX_FRAME_BYTES` или содержит встроенный `\n`
- **THEN** encode отвергает его; серверный read никогда не аллоцирует > max+1

### Requirement: PROTOCOL_VERSION = 2, строгое равенство

Первый кадр ДОЛЖЕН (MUST) быть `Hello{protocol_version}`; `pv != 2` → `Error{1000 PROTOCOL_MISMATCH}` + close. Negotiation НЕТ — апгрейд требует одновременной замены .so и демона (намеренный break при v1→v2). v2-поля SessionOpen имеют `#[serde(default)]` (forward-compat внутри v2) (version.rs:14, server.rs:375–426).

#### Scenario: Несовпадение версии протокола
- **WHEN** первый кадр `Hello` несёт `protocol_version != 2`
- **THEN** возвращается `Error{1000 PROTOCOL_MISMATCH}` и соединение закрывается

- ⚠ KNOWN GAP (docs): architecture.md говорит PROTOCOL_VERSION=1 — устарело (doc 0.1.1).

### Requirement: Сообщения

Протокол ДОЛЖЕН (MUST) поддерживать заданный набор сообщений. ClientMessage: `Hello`, `SessionOpen` (+v2: engineer_ski, engineer_cert_sha256, uid), `GetActiveSessionByUid` (v2), `SessionClose`, `UpdateSessionTarget` (0.3.10+), `Ping`. ServerMessage: `HelloAck`, `Ack`, `SessionTargetUpdated`, `Pong`, `ActiveSession` (v2), `Error{code,message}`. `SessionTarget`: Tty | Display | LogindSession | Unknown.

#### Scenario: Ping/Pong
- **WHEN** клиент после Hello шлёт `Ping`
- **THEN** сервер отвечает `Pong`

### Requirement: Коды ошибок

Сервер ДОЛЖЕН (MUST) использовать фиксированный набор числовых кодов ошибок:

| Код | Значение |
|---|---|
| 1000 | PROTOCOL_MISMATCH (close) |
| 1001 | DEVICE_GONE — serial из SessionOpen отсутствует (fail-closed) |
| 1003 | UNAUTHORIZED |
| 1100 | BAD_REQUEST (не Hello первым / не-UTF8 / decode fail) |
| 1101 | PROTOCOL_VIOLATION (oversize / idle-timeout; close) |
| 1200 | NO_ACTIVE_SESSION (v2) |
| 1500 | INTERNAL |

- ⚠ KNOWN GAP (docs): 1101 и 1200 отсутствуют в doc-таблице architecture.md 10.6.

#### Scenario: Первый кадр не Hello
- **WHEN** первым кадром приходит не `Hello` (или не-UTF8 / decode fail)
- **THEN** сервер отвечает кодом `1100 BAD_REQUEST`

### Requirement: Серверные таймауты и лимиты

Сервер ДОЛЖЕН (MUST) применять таймауты и лимиты: handshake budget 2s; per-connection idle 30s (→1101+close); max 64 concurrent (Semaphore, permit ДО spawn); внутренний reply-timeout state-manager 5s → INTERNAL (server.rs:168–169,314–328,547–552).

#### Scenario: Idle-соединение
- **WHEN** соединение простаивает дольше 30s
- **THEN** сервер шлёт `1101 PROTOCOL_VIOLATION` и закрывает соединение

- ⚠ KNOWN GAP (bug/тех-долг): конфиг-ключи `monitor.idle_timeout_seconds` и `monitor.max_concurrent_connections` валидируются, но НЕ доходят до accept-loop — используется хардкод `AcceptConfig::default()` (daemon/mod.rs:330). Операторские override молча игнорируются (совпадение с дефолтами маскирует баг).

### Requirement: Клиент — connect-per-call + FailMode

PAM-клиент ДОЛЖЕН (MUST) открывать свежее соединение на каждый RPC (Hello → запрос → ответ → close); таймаут `monitor.timeout_ms` (дефолт 2000, 100..=60000) на read+write. FailMode: `strict` — все ошибки пропагируются; `permissive` — connect/IO/decode → WARN+Ok; `DeviceGone` и `Unauthorized` ДОЛЖНЫ (MUST) пропагироваться ДАЖЕ в permissive (ipc/client.rs, failmode.rs:37–39).

#### Scenario: DeviceGone в permissive FailMode
- **WHEN** FailMode = `permissive` и RPC возвращает `DeviceGone` либо `Unauthorized`
- **THEN** ошибка пропагируется (не глотается), в отличие от connect/IO/decode-ошибок

- Замечание: `uuid_from_session_id` дублируется в `xdg_capture::session_uuid_from_string` (признано в комментарии) — кандидат на дедуп.
