---
id: ocsp-responder
kind: сущность
context: auth
name: OCSP-responder
aliases:
  - responder
  - OCSP-сервис
no_anchor:
  type: внешняя сторона за сетью; в коде есть клиент и статус ответа, но не она сама
migrated_from: openspec/specs/revocation/spec.md
relations:
  references:
    - auth.crl
    - auth.ocsp-responder
    - auth.revocation-check
anchors:
  code:
    - crates/tessera_core/src/ocsp/http.rs
  test:
    - tests/e2e/cases/25-trust-chain.yaml
requirements:
  REV-008:
    kind: операционное
    subjects:
      - auth.revocation-check
    evidence:
      code:
        - crates/tessera_core/src/ocsp/cache.rs
      test:
        - tests/e2e/cases/25-trust-chain.yaml
---

# OCSP-responder

## Purpose

Внешняя сторона, отвечающая на вопрос о статусе конкретного удостоверения.
Доступен только в сегментах с сетью; для zero-egress-машин источником статуса
остаётся [[auth.crl|CRL]].

## Requirements

### REV-008 — Ответ responder'а кэшируется, но не заменяет проверку

[[auth.revocation-check|Проверка отзыва]] MAY использовать кэшированный ответ
[[auth.ocsp-responder|responder'а]] в пределах его срока годности.
[[auth.revocation-check|Проверка отзыва]] MUST считать просроченный кэш
отсутствующим.

#### Scenario: Кэш просрочен, responder молчит
- **WHEN** валидный кэш отсутствует и responder не отвечает
- **THEN** статус неопределим, вход отклоняется
