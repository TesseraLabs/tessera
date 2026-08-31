---
id: pam-module
kind: сущность
context: auth
name: PAM-модуль
aliases:
  - модуль
  - pam_tessera
no_anchor:
  type: разделяемая библиотека целиком; единого типа, представляющего её, нет
migrated_from: openspec/specs/pam-module-runtime/spec.md
relations:
  references:
    - auth.ADR-002
    - auth.pam-module
anchors:
  code:
    - crates/pam_tessera/src/flow.rs#authenticate
  test:
    - tests/e2e/cases/18-pam-runtime.yaml
applies:
  - pattern: fail-closed
    bindings:
      неопределимость: auth.ADR-002
requirements:
  AUTH-003:
    kind: инвариант
    subjects:
      - auth.pam-module
    evidence:
      test:
        - tests/e2e/cases/18-pam-runtime.yaml
      code:
        - crates/pam_tessera/src/flow.rs#authenticate
conformance:
  fail-closed/FC-001:
    test:
      - tests/e2e/cases/18-pam-runtime.yaml
  fail-closed/FC-002:
    code:
      - crates/pam_tessera/src/flow.rs#FlowError
  fail-closed/FC-003:
    code:
      - crates/tessera_core/src/config/validated.rs#Validated
---

# PAM-модуль

## Purpose

`pam_tessera.so` — сторона, которая принимает решение о входе. Заведён отдельным
термином не ради полноты: он субъект доброго десятка норм, и без него они
пишутся безличными оборотами, где непонятно, кто обязан обеспечить требуемое.

## Requirements

### AUTH-003 — Паника не выходит за границу модуля

[[auth.pam-module|Модуль]] MUST перехватывать панику на границе FFI и
превращать её в отказ входа.

Паника, вышедшая за границу FFI, — неопределённое поведение в вызывающем
процессе, то есть в чужом демоне аутентификации.

#### Scenario: Паника внутри обработки
- **WHEN** во время аутентификации возникает паника
- **THEN** она перехватывается на границе, вход отклоняется
