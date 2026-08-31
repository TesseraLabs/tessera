---
id: pam-monitord-ipc
kind: контракт
context: runtime
name: IPC между PAM и демоном
owner: runtime
compatibility: additive-fields-within-v2
relations:
  provider: runtime.monitor-daemon
  consumers:
    - auth.pam-module
  references:
    - auth.pkcs12-login
    - runtime.active-session
    - runtime.open-monitored-session
anchors:
  schema:
    - crates/tessera_proto/src/client.rs#ClientMessage
    - crates/tessera_proto/src/server.rs#ServerMessage
  test:
    - crates/tessera_cli/tests/handshake.rs
    - crates/tessera_proto/tests/v2_messages.rs
  code:
    - crates/tessera_cli/src/server.rs#perform_handshake
requirements:
  IPC-001:
    kind: контракт
    subjects:
      - runtime.pam-monitord-ipc
    evidence:
      schema:
        - crates/tessera_proto/src/client.rs#ClientMessage
      test:
        - crates/tessera_cli/tests/handshake.rs
  IPC-002:
    kind: контракт
    subjects:
      - runtime.pam-monitord-ipc
    evidence:
      schema:
        - crates/tessera_proto/src/client.rs#SessionOpenPayload
      test:
        - crates/tessera_proto/tests/v2_messages.rs#session_open_v1_payload_still_parses
  IPC-003:
    kind: операционное
    subjects:
      - runtime.pam-monitord-ipc
    evidence:
      code:
        - crates/tessera_proto/src/wire.rs#MAX_FRAME_BYTES
      test:
        - crates/tessera_cli/tests/server_hardening.rs
---

# IPC между PAM и демоном

## Purpose

Опубликованный NDJSON-контракт между [[auth.pam-module|PAM-модулем]] и
[[runtime.monitor-daemon|демоном контроля сессий]]. Он переносит результат
[[auth.pkcs12-login|аутентификации]] в runtime-контекст, но не публикует
внутренние шаги проверки удостоверения.

## Граница

PAM-модуль является клиентом Unix socket и отправляет `ClientMessage`. Демон
принимает сообщение, изменяет [[runtime.active-session|реестр активных сессий]]
и отвечает `ServerMessage`. Формой владеет крейт `tessera_proto`; эта страница
владеет смыслом границы и правилами её эволюции.

## Совместимость

Текущая версия протокола — 2. Новые поля внутри `SessionOpen` добавляются как
optional/defaulted, чтобы кадр предыдущего клиента продолжал разбираться.
Изменение варианта сообщения или смысла существующего поля требует новой версии
протокола, а не тихой смены поведения внутри v2.

## Отказы

Первый кадр, отличный от `Hello`, несовпадение версии, слишком большой кадр,
ошибка JSON и idle timeout закрывают соединение с явным wire error. Ошибка
регистрации сессии возвращается в [[auth.pkcs12-login|процесс входа]] и
участвует в его fail-closed решении.

## Requirements

### IPC-001 — Hello предшествует рабочим сообщениям

[[runtime.pam-monitord-ipc|IPC-контракт]] MUST принимать рабочее сообщение
только после `Hello` с точным совпадением `PROTOCOL_VERSION`.

#### Scenario: SessionOpen первым кадром
- **WHEN** клиент отправляет `SessionOpen` до `Hello`
- **THEN** демон отклоняет handshake и не создаёт сессию

### IPC-002 — Старый v1 payload остаётся читаемым

[[runtime.pam-monitord-ipc|IPC-контракт]] MUST разбирать `SessionOpen` без
полей, добавленных в v2, подставляя только объявленные безопасные defaults.

#### Scenario: Кадр без v2-полей
- **WHEN** клиент предыдущей версии не передаёт `engineer_ski`, `uid` и `session_expiry`
- **THEN** кадр разбирается, а отсутствующие поля получают документированные значения

### IPC-003 — Размер кадра ограничен до выделения неограниченной памяти

[[runtime.pam-monitord-ipc|IPC-контракт]] MUST отклонять кадр длиннее
`MAX_FRAME_BYTES` до его передачи JSON-декодеру.

#### Scenario: Кадр больше лимита
- **WHEN** клиент не завершает строку до превышения `MAX_FRAME_BYTES`
- **THEN** сервер возвращает protocol error и закрывает соединение
