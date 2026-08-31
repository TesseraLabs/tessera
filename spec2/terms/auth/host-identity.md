---
id: host-identity
kind: сущность
context: auth
name: Идентичность устройства
aliases:
  - идентичность устройства
  - host_id
migrated_from: openspec/specs/host-identity/spec.md
relations:
  references:
    - auth.credential
    - auth.host-identity
    - auth.pam-module
anchors:
  code:
    - crates/tessera_core/src/host_identity/chain.rs
  type:
    - crates/tessera_core/src/host_identity/chain.rs#ResolvedHostId
  test:
    - tests/e2e/cases/19-host-identity.yaml
requirements:
  AUTH-002:
    kind: инвариант
    subjects:
      - auth.pam-module
    evidence:
      test:
        - tests/e2e/cases/19-host-identity.yaml
---

# Идентичность устройства

## Purpose

Устойчивый идентификатор машины, к которому привязывается
[[auth.credential|удостоверение]]. Резолвится по правилу first-working-wins
из нескольких источников, нормализуется и хешируется.

## Requirements

### AUTH-002 — Невозможность резолвить идентичность отклоняет вход

[[auth.pam-module|Модуль]] MUST отклонять вход с `PAM_AUTHINFO_UNAVAIL`, если
[[auth.host-identity|идентичность устройства]] не резолвится ни одним
источником.

Без идентичности не проверить `pam_cert_host_binding`, то есть неизвестно,
для этой ли машины выпущено удостоверение.
