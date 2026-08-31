---
id: parent-ca-certificate
kind: значение
context: issuance
name: Родительский CA-сертификат
relations:
  references:
    - issuance.leaf-issuance-scope
anchors:
  type:
    - crates/tessera_core/src/x509/mod.rs#Certificate
  code:
    - crates/tessera_issuer/src/monotonicity.rs#parent_constraints
  test:
    - crates/tessera_issuer/src/tests.rs#leaf_ttl_above_parent_rejected
---

# Родительский CA-сертификат

## Purpose

Сертификат непосредственного издателя листа. Его delegation envelope задаёт
верхнюю границу для [[issuance.leaf-issuance-scope|рамок выпуска]]; отсутствие
envelope делает выпуск листа недопустимым.
