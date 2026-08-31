---
id: shared-key
kind: сущность
context: codes
name: Общий ключ
aliases:
  - общий ключ
  - K
migrated_from: openspec/changes/codes-contract/specs/codes-contract/spec.md
relations:
  references:
    - codes.ADR-004
    - codes.code
    - codes.codes-contract
    - codes.shared-key
    - codes.ticket
anchors:
  type:
    - crates/tessera_codes_contract/src/key.rs#DerivedKey
    - crates/tessera_codes_contract/src/key.rs#SharedSecret
  code:
    - crates/tessera_codes_contract/src/key.rs
  test:
    - tests/e2e/cases/27-codes-phone.yaml
requirements:
  KEY-001:
    kind: инвариант
    decided_by:
      - codes.ADR-004
    subjects:
      - codes.shared-key
      - codes.codes-contract
    evidence:
      code:
        - crates/tessera_codes_contract/src/key.rs
      test:
        - tests/e2e/cases/27-codes-phone.yaml
  KEY-002:
    kind: инвариант
    subjects:
      - codes.shared-key
    evidence:
      test:
        - tests/e2e/cases/27-codes-phone.yaml
  KEY-003:
    kind: операционное
    subjects:
      - codes.shared-key
    evidence:
      code:
        - crates/tessera_codes_contract/src/key.rs
---

# Общий ключ

## Purpose

Ключ, из которого выводится [[codes.code|код]]. Считается обеими сторонами
независимо из результата обмена ключами и контекста — номера устройства, эпохи и
хеша [[codes.ticket|билета оператора]]. Контекст в выводе ключа не украшение:
он привязывает код к конкретному устройству, конкретной эпохе и конкретным рамкам.

## Requirements

### KEY-001 — Обмен ключами выполняется снаружи контракта

[[codes.shared-key|Общий ключ]] MUST выводиться из результата обмена ключами,
поданного извне через trait. [[codes.codes-contract|Крейт контракта]] MUST NOT выполнять обмен ключами сам.

Одна и та же формула компилируется и в устройство с программной криптографией, и
в кабинет, где приватный ключ живёт на токене. Вшитая реализация обмена сделала бы
второе невозможным.

**Почему:** [[codes.ADR-004]]

#### Scenario: Реализация обмена подаётся снаружи
- **WHEN** контракт собирается под WASM для кабинета
- **THEN** обмен ключами выполняет агент токена, а формула вывода ключа не меняется

### KEY-002 — Подмена рамок билета разводит ключи

[[codes.shared-key|Общий ключ]] MUST включать в контекст вывода хеш
канонического подписанного [[codes.ticket|билета]].

Это второй слой: первый — проверка подписи билета потребителем. Правка любого
поля билета после подписи меняет хеш, ключ не сходится, и код не сходится тоже.

#### Scenario: Поле билета изменено после подписи
- **WHEN** любое поле билета изменено после подписи
- **THEN** ключ не совпадает и код не верифицируется

### KEY-003 — Материал ключа затирается

[[codes.shared-key|Общий ключ]] MUST затираться при уничтожении.
