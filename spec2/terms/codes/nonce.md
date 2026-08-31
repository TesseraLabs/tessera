---
id: nonce
kind: сущность
context: codes
name: Гибридный nonce
aliases:
  - nonce
migrated_from: openspec/changes/codes-contract/specs/codes-contract/spec.md
relations:
  references:
    - codes.codes-contract
    - codes.nonce
anchors:
  type:
    - crates/tessera_codes_contract/src/nonce.rs#Nonce
  test:
    - tests/e2e/cases/27-codes-phone.yaml
applies:
  - pattern: strict-parse
requirements:
  NONCE-001:
    kind: инвариант
    subjects:
      - codes.nonce
    evidence:
      test:
        - tests/e2e/cases/27-codes-phone.yaml
      code:
        - crates/tessera_codes_contract/src/nonce.rs#next_with_tail
    outcomes:
      - nonce собран
      - переполнение счётчика
      - неверная ширина или алфавит
  NONCE-002:
    kind: инвариант
    decided_by:
      - codes.ADR-004
    subjects:
      - codes.nonce
      - codes.codes-contract
    evidence:
      test:
        - tests/e2e/cases/27-codes-phone.yaml
      code:
        - crates/tessera_codes_contract/src/nonce.rs
outcome_map:
  NONCE-001:
    Ok: nonce собран
    "Err::CounterOverflow": переполнение счётчика
    "Err::CounterNotDecimal": неверная ширина или алфавит
    "Err::LengthMismatch": неверная ширина или алфавит
    "Err::TailWidthMismatch": неверная ширина или алфавит
    "Err::TailAlphabet": неверная ширина или алфавит
conformance:
  strict-parse/SP-001:
    test:
      - tests/e2e/cases/27-codes-phone.yaml
  strict-parse/SP-002:
    code:
      - crates/tessera_codes_contract/src/nonce.rs
  strict-parse/SP-003:
    code:
      - crates/tessera_codes_contract/src/nonce.rs
---

# Гибридный nonce

## Purpose

Монотонный счётчик и случайный хвост. Счётчик не даёт повторить выдачу, хвост не
даёт предсказать следующую.

## Requirements

### NONCE-001 — Переполнение счётчика — отдельный отказ

[[codes.nonce|Nonce]] MUST возвращать отдельную, отличимую от прочих ошибку
при переполнении счётчика. [[codes.nonce|Nonce]] MUST NOT переносить счётчик
по модулю.

Перенос по модулю означает повтор ранее выданного nonce, то есть повтор кода.
Отличимая ошибка нужна, чтобы потребитель начал смену эпохи ключа, а не
продолжал выдачу.

#### Scenario: Переполнение счётчика
- **WHEN** счётчик достиг предела ширины профиля
- **THEN** исход `переполнение счётчика`; сборка следующего nonce возвращает отличимую ошибку

#### Scenario: Хвост верной ширины
- **WHEN** случайный хвост подан внешним источником и прошёл проверку ширины и алфавита
- **THEN** исход `nonce собран`

#### Scenario: Хвост неверной ширины
- **WHEN** случайный хвост короче ширины профиля либо содержит символы вне алфавита
- **THEN** исход `неверная ширина или алфавит`, nonce не собирается

### NONCE-002 — Случайный хвост приходит извне

[[codes.nonce|Nonce]] MUST принимать случайный хвост снаружи.
[[codes.nonce|Nonce]] MUST проверять ширину и алфавит поданного хвоста. [[codes.codes-contract|Крейт контракта]] MUST NOT генерировать случайный хвост сам.

Источник случайности принадлежит платформе: в устройстве это системный генератор,
в кабинете — браузерный. Свой генератор внутри контракта означал бы третью
реализацию криптографии там, где их и так две.
