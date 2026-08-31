---
id: crl
kind: сущность
context: auth
name: Список отзыва
aliases:
  - CRL
  - список отзыва
migrated_from: openspec/specs/revocation/spec.md
relations:
  references:
    - auth.ADR-001
    - auth.crl
    - auth.revocation-check
anchors:
  type:
    - crates/tessera_core/src/crl/store.rs#Crl
  code:
    - crates/tessera_core/src/crl/store.rs#CrlStore
  test:
    - tests/e2e/cases/25-trust-chain.yaml
requirements:
  REV-007:
    kind: операционное
    subjects:
      - auth.crl
      - auth.revocation-check
    evidence:
      test:
        - tests/e2e/cases/22-logging-audit.yaml
      code:
        - crates/tessera_core/src/crl/store.rs#CrlStore
---

# Список отзыва (CRL)

## Purpose

Подписанный выпускающей стороной перечень отозванных удостоверений. Доставляется
на устройство внешним каналом — сети до выпускающего у zero-egress-машины нет.
Именно поэтому канал доставки не входит в периметр доверия
(см. [[auth.ADR-001]]).

## Requirements

### REV-007 — Свежесть непроверяема — это сообщается

[[auth.crl|Список отзыва]] без `nextUpdate` при незаданном
`crl_max_age_hours` MAY использоваться.
[[auth.revocation-check|Проверка отзыва]] MUST записать в журнал `tessera.crl`
предупреждение о непроверяемой свежести такого списка.

Это документированное поведение, а не недосмотр: отказ здесь сломал бы
развёртывания, где выпускающий не проставляет `nextUpdate`, а молчание
скрыло бы от оператора, что срок жизни списка неизвестен.
