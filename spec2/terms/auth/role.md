---
id: role
kind: сущность
context: auth
name: Роль
aliases:
  - роль
  - ролевая учётная запись
migrated_from: openspec/specs/role-selection/spec.md
relations:
  references:
    - auth.role
anchors:
  code:
    - crates/tessera_core/src/role/store.rs
  type:
    - crates/tessera_core/src/role/schema.rs#RoleSlice
    - crates/tessera_core/src/role/schema.rs#RoleOs
    - crates/tessera_core/src/role/schema.rs#Payload
    - crates/tessera_core/src/role/store.rs#RoleStore
  test:
    - tests/e2e/cases/30-roles.yaml
requirements:
  ROLE-001:
    kind: инвариант
    subjects:
      - auth.role
    evidence:
      test:
        - tests/e2e/cases/30-roles.yaml
---

# Роль

## Purpose

Имя учётной записи входа, под которой предъявитель просит сессию. Роль — это
не атрибут человека, а запрошенная учётная запись: `PAM_USER` и есть роль.

## Requirements

### ROLE-001 — Системная учётная запись ролью быть не может

[[auth.role|Роль]] MUST NOT совпадать с именем системной учётной записи.
[[auth.role|Ролевой срез]] с именем системной учётной записи MUST
отклоняться при загрузке.
