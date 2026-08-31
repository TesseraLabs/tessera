---
id: leaf-issuance-scope
kind: значение
context: issuance
name: Рамки выпуска листа
aliases:
  - scope выпуска
relations:
  references:
    - auth.role
anchors:
  type:
    - crates/tessera_issuer/src/csr.rs#LeafScope
    - crates/tessera_issuer/src/profile.rs#LeafRequest
  test:
    - crates/tessera_issuer/src/tests.rs#leaf_scope_wider_than_parent_rejected_with_dimension
---

# Рамки выпуска листа

## Purpose

Неидентифицируемое значение, объединяющее срок, привязку к устройствам,
разрешённые [[auth.role|роли]], потолок целостности и версию профиля. Рамки
задаёт [[issuance.issuer-operator|оператор]], после чего они только сужаются
относительно делегирования родительского CA.
