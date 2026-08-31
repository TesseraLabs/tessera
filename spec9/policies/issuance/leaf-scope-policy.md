---
id: leaf-scope-policy
kind: политика
context: issuance
name: Политика рамок листового сертификата
relations:
  references:
    - issuance.leaf-issuance-scope
    - issuance.parent-ca-certificate
applies:
  - pattern: fail-closed
anchors:
  code:
    - crates/tessera_issuer/src/monotonicity.rs#check_leaf_within_parent
  test:
    - crates/tessera_issuer/src/tests.rs#leaf_scope_wider_than_parent_rejected_with_dimension
requirements:
  ISS-110:
    kind: инвариант
    subjects:
      - issuance.leaf-scope-policy
    evidence:
      test:
        - crates/tessera_issuer/src/tests.rs#leaf_scope_wider_than_parent_rejected_with_dimension
  ISS-111:
    kind: инвариант
    subjects:
      - issuance.leaf-scope-policy
    evidence:
      test:
        - crates/tessera_issuer/src/tests.rs#incomplete_extension_set_rejected_before_signing
conformance:
  fail-closed/FC-001:
    test:
      - crates/tessera_issuer/src/tests.rs#leaf_scope_wider_than_parent_rejected_with_dimension
  fail-closed/FC-002:
    code:
      - crates/tessera_issuer/src/monotonicity.rs#check_leaf_within_parent
  fail-closed/FC-003:
    code:
      - crates/tessera_issuer/src/error.rs#IssueError
---

# Политика рамок листового сертификата

## Purpose

Определяет, какие [[issuance.leaf-issuance-scope|рамки]] допустимо подписать под
конкретным [[issuance.parent-ca-certificate|родительским CA]]. Равные рамки
допустимы; расширение хотя бы одного измерения — нет.

## Requirements

### ISS-110 — Рамки листа не шире родительских

[[issuance.leaf-scope-policy|Политика рамок]] MUST до подписи проверить, что
роли являются подмножеством, уровень integrity не выше потолка, а срок листа не
длиннее разрешённого TTL родителя.

#### Scenario: Добавлена неразрешённая роль

- **WHEN** лист запрашивает роль, отсутствующую в allowRoles родителя
- **THEN** выпуск отклоняется с измерением `AllowRoles`, подпись не выполняется

### ISS-111 — Обязательные расширения существуют до подписи

[[issuance.leaf-scope-policy|Политика рамок]] MUST отклонять пустой host binding,
невалидный срок или неполный профиль до сборки подписанного сертификата.

#### Scenario: Host binding пуст

- **WHEN** оператор не задал ни одной привязки к устройству
- **THEN** возвращается `MissingHostBinding`, signing backend не вызывается
