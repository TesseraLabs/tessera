---
id: ticket
kind: сущность
context: codes
name: Билет оператора
aliases:
  - билет
  - билет оператора
migrated_from: openspec/changes/codes-contract/specs/codes-contract/spec.md
relations:
  references:
    - auth.credential
    - auth.device-config
    - codes.codes-contract
    - codes.ticket
anchors:
  type:
    - crates/tessera_codes_contract/src/ticket.rs#SignedTicket
    - crates/tessera_codes_contract/src/ticket.rs#TicketScope
  test:
    - tests/e2e/cases/27-codes-phone.yaml
applies:
  - pattern: strict-parse
requirements:
  TICKET-001:
    kind: контракт
    subjects:
      - codes.ticket
      - codes.codes-contract
    evidence:
      test:
        - tests/e2e/cases/27-codes-phone.yaml
      code:
        - crates/tessera_codes_contract/src/ticket.rs#verify
    outcomes:
      - билет разобран
      - подпись не сходится
      - структура не соответствует формату
      - срок истёк
  TICKET-002:
    kind: инвариант
    decided_by:
      - codes.ADR-004
    subjects:
      - codes.ticket
      - codes.codes-contract
    evidence:
      test:
        - tests/e2e/cases/27-codes-phone.yaml
      code:
        - crates/tessera_codes_contract/src/ticket.rs
outcome_map:
  TICKET-001:
    Ok: билет разобран
    "Err::Wire": структура не соответствует формату
    "Err::EmptyScope": структура не соответствует формату
    "Err::EmptyRoles": структура не соответствует формату
    "Err::RoleMarkerNotAlone": структура не соответствует формату
    "Err::UnusableTicketNumber": структура не соответствует формату
    "Err::Canon": структура не соответствует формату
    "Err::Signature": подпись не сходится
    "Err::Expired": срок истёк
conformance:
  strict-parse/SP-001:
    test:
      - tests/e2e/cases/27-codes-phone.yaml
  strict-parse/SP-002:
    code:
      - crates/tessera_codes_contract/src/ticket.rs
  strict-parse/SP-003:
    code:
      - crates/tessera_codes_contract/src/ticket.rs
---

# Билет оператора

## Purpose

Подписанный документ, дающий оператору право выдавать коды: идентификатор,
публичный ключ, рамки — теги и регион, максимальный уровень, непустой перечень
ролей, — срок и номер. Смысловой близнец [[auth.credential|удостоверения]]
из контекста аутентификации: рамки назначает выпускающая сторона, предъявитель их
не меняет. Но объект другой, живёт по другим правилам и связан с ним только через
опубликованный контракт.

## Requirements

### TICKET-001 — Разбор билета строгий

[[codes.ticket|Билет оператора]] MUST отвергаться при разборе, если содержит
поле, не описанное форматом текущей версии контракта.
[[codes.codes-contract|Крейт контракта]] MUST NOT отбрасывать неизвестное поле молча.

Молча отброшенное поле — это способ доставить билет, который одна сторона читает
с ограничением, а другая без него.

#### Scenario: Неизвестное поле в билете
- **WHEN** билет содержит поле, не описанное форматом текущей версии
- **THEN** исход `структура не соответствует формату`

#### Scenario: Билет корректен
- **WHEN** структура соответствует формату версии, подпись сходится, срок не истёк
- **THEN** исход `билет разобран`

#### Scenario: Подпись билета не сходится
- **WHEN** подпись билета не проверяется против якоря доверия потребителя
- **THEN** исход `подпись не сходится`

#### Scenario: Срок билета истёк
- **WHEN** срок действия билета в прошлом относительно времени проверки
- **THEN** исход `срок истёк`

### TICKET-002 — Якоря доверия хранит потребитель

[[codes.ticket|Билет оператора]] MUST проверяться на подпись через trait
верификатора. [[codes.codes-contract|Крейт контракта]] MUST NOT содержать собственного
хранилища якорей доверия.

Хранилище якорей — это политика конкретного развёртывания, и место ей рядом с
[[auth.device-config|конфигурацией устройства]], а не в переносимой
библиотеке, которая компилируется в том числе в браузер.
