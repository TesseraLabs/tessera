---
id: code-verify
kind: операция
context: codes
name: Сверка кода
aliases:
  - сверка кода
  - верификация кода
migrated_from: openspec/changes/codes-contract/specs/codes-contract/spec.md
relations:
  references:
    - auth.pam-module
    - codes.ADR-004
    - codes.code
    - codes.code-verify
    - codes.fleet-params
    - codes.nonce
anchors:
  code:
    - crates/tessera_codes_contract/src/code.rs
  test:
    - tests/e2e/cases/27-codes-phone.yaml
applies:
  - pattern: fail-closed
    bindings:
      неопределимость: codes.ADR-004
requirements:
  CODE-005:
    kind: инвариант
    subjects:
      - codes.code-verify
    evidence:
      test:
        - tests/e2e/cases/27-codes-phone.yaml
      code:
        - crates/tessera_codes_contract/src/code.rs
    outcomes:
      - код совпал
      - код не совпал
      - попытки исчерпаны
conformance:
  fail-closed/FC-001:
    test:
      - tests/e2e/cases/27-codes-phone.yaml
  fail-closed/FC-002:
    code:
      - crates/tessera_codes_contract/src/code.rs
  fail-closed/FC-003:
    code:
      - crates/tessera_codes_contract/src/params.rs
---

# Сверка кода

## Purpose

Пересчёт [[codes.code|кода]] на устройстве и сравнение с продиктованным.
Выполняется в [[auth.pam-module|PAM-модуле]] — это точка, где контекст
кодов встречается с контекстом аутентификации.

## Requirements

### CODE-005 — Исчерпание попыток на nonce закрывает nonce

[[codes.code-verify|Сверка кода]] MUST прекращать приём кода для данного
[[codes.nonce]] по исчерпании числа попыток из
[[codes.fleet-params|параметров парка]].

Без предела на попытки короткий код перебирается: восьмизначный десятичный код —
это сто миллионов вариантов, что много для человека и мало для скрипта.

#### Scenario: Попытки исчерпаны
- **WHEN** число неудачных сверок для одного nonce достигло предела параметров парка
- **THEN** исход `попытки исчерпаны`, дальнейшие коды для этого nonce не принимаются

#### Scenario: Код сошёлся с первой попытки
- **WHEN** продиктованный код совпал с пересчитанным на устройстве
- **THEN** исход `код совпал`

#### Scenario: Код не сошёлся, попытки остались
- **WHEN** код не совпал, но бюджет попыток для nonce не исчерпан
- **THEN** исход `код не совпал`, приём кода продолжается
