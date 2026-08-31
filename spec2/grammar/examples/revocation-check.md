---
id: revocation-check
kind: операция
context: auth
name: Проверка отзыва
relations:
  references: [auth.credential, auth.crl, auth.ocsp-responder]
anchors:
  code: [crates/tessera_core/src/crl/store.rs#check_revocation]
  test: [tests/e2e/cases/25-trust-chain.yaml]
requirements:
  REV-002:
    kind: инвариант
    subjects: [auth.revocation-check]
    evidence:
      test: [tests/e2e/cases/25-trust-chain.yaml]
    outcomes: [не отозвано, отозвано, неопределимо]
---

# Проверка отзыва

## Purpose

Устанавливает статус [[auth.credential|удостоверения]] по опубликованным
источникам отзыва.

### REV-002 — Неопределимый статус отклоняет вход

Проверка отзыва MUST завершать вход отказом, если статус установить нельзя.

#### Scenario: Responder недоступен

- **WHEN** responder не отвечает и валидного кэша нет
- **THEN** исход `неопределимо`
