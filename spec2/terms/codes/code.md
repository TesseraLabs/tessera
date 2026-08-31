---
id: code
kind: сущность
context: codes
name: Код входа
aliases:
  - код
  - код входа
forbidden:
  - пароль
migrated_from: openspec/changes/codes-contract/specs/codes-contract/spec.md
relations:
  references:
    - codes.ADR-004
    - codes.canonicalization
    - codes.code
    - codes.code-verify
    - codes.shared-key
anchors:
  type:
    - crates/tessera_codes_contract/src/code.rs#Code
  code:
    - crates/tessera_codes_contract/src/code.rs
  test:
    - tests/e2e/cases/27-codes-phone.yaml
applies:
  - pattern: fail-closed
    bindings:
      неопределимость: codes.ADR-004
requirements:
  CODE-001:
    kind: инвариант
    subjects:
      - codes.code
    evidence:
      test:
        - tests/e2e/cases/27-codes-phone.yaml
      code:
        - crates/tessera_codes_contract/src/code.rs#verify_code
    outcomes:
      - код совпал
      - код не совпал
  CODE-002:
    kind: инвариант
    subjects:
      - codes.code-verify
    evidence:
      test:
        - tests/e2e/cases/27-codes-phone.yaml
      code:
        - crates/tessera_codes_contract/src/code.rs#verify_code
outcome_map:
  CODE-001:
    Ok: код совпал
    Err: код не совпал
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

# Код входа

## Purpose

Короткая строка, которую оператор диктует по телефону, а устройство пересчитывает
у себя. Код не передаётся и не хранится: обе стороны выводят его независимо из
[[codes.shared-key|общего ключа]] и [[codes.canonicalization|канонического
входа]]. Совпадение кодов и есть доказательство — расхождение хотя бы в одном
байте канонизации делает вход невозможным.

## Requirements

### CODE-001 — Код выводится из ключа и канонического входа

[[codes.code|Код]] MUST вычисляться как усечение HMAC от
[[codes.shared-key|общего ключа]] по
[[codes.canonicalization|каноническому входу]].

[[codes.code|Код]] MUST усекаться равномерно по значению. Взятие остатка на неполном
диапазоне даёт смещение, то есть часть кодов становится вероятнее прочих.

#### Scenario: Код совпал
- **WHEN** обе стороны вывели один ключ и одинаковый канонический вход
- **THEN** исход `код совпал`, вход разрешён

#### Scenario: Код не совпал
- **WHEN** ключ, роль, уровень или nonce у сторон различаются
- **THEN** исход `код не совпал`, вход отклонён

### CODE-002 — Сверка не сообщает, что именно не сошлось

[[codes.code-verify|Сверка кода]] MUST выполняться за константное время.
[[codes.code-verify|Сверка кода]] MUST NOT сообщать вызывающему, какое поле
или какой шаг не сошлись.

Различимые причины отказа превращают сверку в оракул: подбирая поля по одному,
предъявитель сокращает перебор с полного пространства до суммы по координатам.

#### Scenario: Разные причины дают одну ошибку
- **WHEN** код не сходится из-за неверной роли, из-за неверного nonce или из-за неверного ключа
- **THEN** вызывающий получает одну и ту же ошибку сверки
