---
id: fleet-params
kind: сущность
context: codes
name: Параметры парка
aliases:
  - параметры парка
migrated_from: openspec/changes/codes-contract/specs/codes-contract/spec.md
relations:
  references:
    - codes.codes-contract
    - codes.fleet-params
anchors:
  type:
    - crates/tessera_codes_contract/src/params.rs#FleetParams
    - crates/tessera_codes_contract/src/params.rs#FleetParamsInput
  test:
    - tests/e2e/cases/27-codes-phone.yaml
applies:
  - pattern: strict-parse
  - pattern: explicit-config
requirements:
  PARAM-001:
    kind: инвариант
    subjects:
      - codes.fleet-params
      - codes.codes-contract
    evidence:
      test:
        - tests/e2e/cases/27-codes-phone.yaml
      code:
        - crates/tessera_codes_contract/src/params.rs#parse
    outcomes:
      - параметры приняты
      - значение слабее минимума
      - значение вне допустимого диапазона
      - профиль не подтверждён
  PARAM-002:
    kind: инвариант
    subjects:
      - codes.fleet-params
    evidence:
      test:
        - tests/e2e/cases/27-codes-phone.yaml
  PARAM-003:
    kind: инвариант
    subjects:
      - codes.fleet-params
    evidence:
      test:
        - tests/e2e/cases/27-codes-phone.yaml
outcome_map:
  PARAM-001:
    Ok: параметры приняты
    "Err::CodeTooShort": значение слабее минимума
    "Err::TooManyAttempts": значение слабее минимума
    "Err::CodeTooLong": значение вне допустимого диапазона
    "Err::NoAttempts": значение вне допустимого диапазона
    "Err::CounterWidthOutOfRange": значение вне допустимого диапазона
    "Err::TailWidthOutOfRange": значение вне допустимого диапазона
    "Err::UnconfirmedProfile": профиль не подтверждён
conformance:
  strict-parse/SP-001:
    test:
      - tests/e2e/cases/27-codes-phone.yaml
  strict-parse/SP-002:
    code:
      - crates/tessera_codes_contract/src/params.rs
  strict-parse/SP-003:
    code:
      - crates/tessera_codes_contract/src/params.rs
  explicit-config/EC-001:
    test:
      - tests/e2e/cases/27-codes-phone.yaml
  explicit-config/EC-002:
    test:
      - tests/e2e/cases/27-codes-phone.yaml
---

# Параметры парка

## Purpose

Длина кода, число попыток на nonce, алфавит, ширины счётчика и хвоста, профиль
алгоритма. То, что настраивает владелец парка, — и то, где ослабление стоит
дешевле всего, потому что выглядит как настройка удобства.

## Requirements

### PARAM-001 — Параметры усиливаются только в строгую сторону

[[codes.fleet-params|Параметры парка]] MUST отвергаться при разборе, если
значение слабее минимума контракта. [[codes.codes-contract|Крейт контракта]] MUST NOT подставлять умолчание
вместо слабого значения.

Код короче шести цифр и больше десяти попыток на nonce — не настройка, а снятие
защиты, и оно обязано быть отказом, а не тихой заменой.

#### Scenario: Профиль алгоритма не подтверждён
- **WHEN** выбран профиль, вендорский гейт по которому не закрыт, без признака принятия риска
- **THEN** исход `профиль не подтверждён`, объект параметров не создаётся

#### Scenario: Значение слабее минимума
- **WHEN** конфигурация парка задаёт код в четыре цифры
- **THEN** исход `значение слабее минимума`, объект параметров не создаётся

#### Scenario: Значение вне допустимого диапазона
- **WHEN** длина, число попыток или ширина части nonce не представимы контрактом
- **THEN** исход `значение вне допустимого диапазона`, объект параметров не создаётся

#### Scenario: Конфигурация в пределах минимума
- **WHEN** все значения не слабее минимума контракта, профиль подтверждён
- **THEN** исход `параметры приняты`

### PARAM-002 — Сравнение параметров — частичный порядок

[[codes.fleet-params|Параметры парка]] MUST признаваться усилением другого
набора, только если не слабее по каждой координате.

Размен строгости усилением не является: удлинить код и одновременно увеличить
число попыток — это переложить риск, а не уменьшить его. Полный порядок здесь
дал бы ложное «стало строже».

#### Scenario: Размен строгости
- **WHEN** конфигурация удлиняет код и увеличивает число попыток
- **THEN** набор не признаётся усилением исходного

### PARAM-003 — Неподтверждённый профиль требует явного признака

[[codes.fleet-params|Параметры парка]] MUST отвергаться при выборе
неподтверждённого профиля алгоритма без явного признака принятия риска.

#### Scenario: ГОСТ-профиль без признака риска
- **WHEN** конфигурация выбирает ГОСТ-профиль, гейт вендора не закрыт, признак не выставлен
- **THEN** исход `профиль не подтверждён`, разбор указывает на открытый гейт
