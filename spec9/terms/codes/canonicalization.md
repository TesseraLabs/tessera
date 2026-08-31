---
id: canonicalization
kind: операция
context: codes
name: Каноническая сериализация
aliases:
  - канонизация
  - каноническая сериализация
migrated_from: openspec/changes/codes-contract/specs/codes-contract/spec.md
relations:
  references:
    - codes.canonicalization
anchors:
  code:
    - crates/tessera_codes_contract/src/canon.rs
  test:
    - tests/e2e/cases/27-codes-phone.yaml
applies:
  - pattern: strict-parse
requirements:
  CODE-003:
    kind: контракт
    subjects:
      - codes.canonicalization
    evidence:
      schema:
        - crates/tessera_codes_contract/src/golden_tests.rs
      test:
        - tests/e2e/cases/27-codes-phone.yaml
  CODE-004:
    kind: инвариант
    subjects:
      - codes.canonicalization
    evidence:
      type:
        - crates/tessera_codes_contract/src/device_number.rs#CheckedDeviceNumber
      test:
        - tests/e2e/cases/28-codes-enrollment.yaml
conformance:
  strict-parse/SP-001:
    test:
      - tests/e2e/cases/27-codes-phone.yaml
  strict-parse/SP-002:
    code:
      - crates/tessera_codes_contract/src/canon.rs
  strict-parse/SP-003:
    code:
      - crates/tessera_codes_contract/src/canon.rs
---

# Каноническая сериализация

## Purpose

Единственная форма, в которой вход MAC превращается в байты. Существует потому,
что формулу считают **две** независимые реализации — устройство и кабинет
оператора в WASM, — и расхождение в одном байте выглядит как «код почти сошёлся»,
что отлаживается по телефону с объекта.

## Requirements

### CODE-003 — Байты не выводятся из структур языка

[[codes.canonicalization|Каноническая сериализация]] MUST кодировать поля в
фиксированном порядке с явной длиной каждого поля.
[[codes.canonicalization|Каноническая сериализация]] MUST NOT выводить порядок
полей из порядка полей структуры языка. [[codes.canonicalization|Каноническая
сериализация]] MUST NOT выводить кодировку из производной реализации сериализации.

Порядок полей структуры меняется рефакторингом, о котором никто не подумает как
об изменении протокола, — и парк расходится с кабинетом молча.

#### Scenario: Перестановка полей структуры
- **WHEN** порядок полей во внутренней структуре изменён рефакторингом
- **THEN** байты канонизации остаются прежними, голден-векторы проходят

#### Scenario: Паритет натив и WASM
- **WHEN** голден-векторы прогоняются нативной сборкой и сборкой под WASM
- **THEN** обе дают идентичные байты; расхождение проваливает сборку

### CODE-004 — Номер устройства канонизуется значимой формой

[[codes.canonicalization|Каноническая сериализация]] MUST принимать номер
устройства типом, несущим значимую форму, а не произвольной строкой.

Разделители и регистр номера не меняют его значения, поэтому два написания
обязаны давать один код. Если выбор написания достаётся вызывающему, устройство
и кабинет разойдутся в байтах, оставаясь оба «правыми».

#### Scenario: Два написания одного номера
- **WHEN** номер подан с разделителями в нижнем регистре, затем без разделителей в верхнем
- **THEN** байты канонизации совпадают
