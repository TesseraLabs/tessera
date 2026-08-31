---
id: trust-chain
kind: сущность
context: auth
name: Цепочка доверия
aliases:
  - цепочка доверия
  - trust chain
no_anchor:
  type: цепочка представлена срезом удостоверений, отдельного типа нет
migrated_from: openspec/specs/trust-chain-validation/spec.md
relations:
  references:
    - auth.ADR-002
    - auth.ADR-003
    - auth.carrier
    - auth.credential
    - auth.device-config
    - auth.revocation-check
    - auth.trust-chain
anchors:
  code:
    - crates/tessera_core/src/x509/signatures.rs#verify_chain_signatures
    - crates/tessera_core/src/trust/openssl_verifier.rs#check_revocation_dispatch
  test:
    - tests/e2e/cases/25-trust-chain.yaml
applies:
  - pattern: fail-closed
    bindings:
      неопределимость: auth.ADR-002
requirements:
  TRUST-002:
    kind: инвариант
    decided_by:
      - auth.ADR-003
    subjects:
      - auth.trust-chain
      - auth.carrier
    evidence:
      test:
        - tests/e2e/cases/25-trust-chain.yaml
      code:
        - crates/pam_tessera/src/flow.rs#authenticate_pkcs11
  TRUST-003:
    kind: инвариант
    subjects:
      - auth.trust-chain
    evidence:
      test:
        - tests/e2e/cases/25-trust-chain.yaml
      code:
        - crates/tessera_core/src/trust/openssl_verifier.rs#check_revocation_dispatch
    outcomes:
      - цепочка проверена
      - подпись не сходится
      - ограничения нарушены
      - статус отзыва неопределим
conformance:
  fail-closed/FC-001:
    test:
      - tests/e2e/cases/25-trust-chain.yaml
  fail-closed/FC-002:
    code:
      - crates/pam_tessera/src/flow.rs#FlowError
  fail-closed/FC-003:
    code:
      - crates/tessera_core/src/config/validated.rs#Validated
---

# Цепочка доверия

## Purpose

Путь от [[auth.credential|удостоверения]] предъявителя до anchor'а,
которому устройство доверяет по конфигурации. Строится на устройстве, а не
принимается от предъявителя.

## Requirements

### TRUST-002 — Материал доверия берётся только из конфигурации

[[auth.trust-chain|Цепочка доверия]] MUST строиться исключительно из
anchors и промежуточных удостоверений, заданных
[[auth.device-config|конфигурацией устройства]].
[[auth.carrier|Носитель]] MUST NOT поставлять материал для построения цепочки.

**Почему:** [[auth.ADR-003]]

#### Scenario: Токен предъявляет промежуточные удостоверения
- **WHEN** PKCS#11-токен содержит промежуточные удостоверения
- **THEN** они не участвуют в построении цепочки; используются только config-intermediates

### TRUST-003 — Отзыв проверяется до вердикта

[[auth.trust-chain|Цепочка доверия]] MUST считаться проверенной только после
того, как [[auth.revocation-check|проверка отзыва]] дала определённый статус
для каждого non-anchor удостоверения.

#### Scenario: Статус отзыва не определён
- **WHEN** проверка отзыва не смогла установить статус промежуточного удостоверения
- **THEN** исход `статус отзыва неопределим`, вход отклоняется

#### Scenario: Цепочка построена и проверена
- **WHEN** подписи сходятся, ограничения соблюдены, статус отзыва определён для каждого non-anchor удостоверения
- **THEN** исход `цепочка проверена`

#### Scenario: Подпись в цепочке не сходится
- **WHEN** подпись одного из удостоверений не проверяется против вышестоящего
- **THEN** исход `подпись не сходится`

#### Scenario: Нарушены ограничения цепочки
- **WHEN** нарушено ограничение пути, срока либо назначения ключа
- **THEN** исход `ограничения нарушены`
