---
id: credential-revoked
kind: событие
context: auth
name: Удостоверение отозвано
relations:
  producer: auth.revocation-check
  references:
    - auth.credential
    - auth.trust-chain
anchors:
  test:
    - tests/e2e/cases/25-trust-chain.yaml
requirements:
  REV-009:
    kind: операционное
    subjects:
      - auth.revocation-check
    evidence:
      test:
        - tests/e2e/cases/22-logging-audit.yaml
---

# Удостоверение отозвано

## Purpose

Факт установления того, что предъявленное [[auth.credential|удостоверение]]
или удостоверение его [[auth.trust-chain|цепочки]] числится отозванным.
Внутреннее доменное событие: наружу оно не публикуется и схемы не имеет — при
попытке опубликовать понадобится отдельный контракт.

## Requirements

### REV-009 — Отзыв фиксируется в аудите

[[auth.revocation-check|Проверка отзыва]] MUST записать в аудит факт отзыва
с указанием источника статуса.

Различие между «отозвано по CRL» и «отозвано по OCSP» нужно при разборе:
источники расходятся, и расхождение — само по себе сигнал.

#### Scenario: Отзыв установлен по CRL
- **WHEN** серийный номер найден в списке отзыва
- **THEN** в аудит пишется отказ с источником `crl`
