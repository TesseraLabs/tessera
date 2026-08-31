---
id: certificate-signing-request
kind: контракт
context: issuance
name: Запрос на подпись сертификата
aliases:
  - CSR
  - PKCS#10
owner: issuance
compatibility: PKCS#10 с поддерживаемыми Tessera алгоритмами подписи
relations:
  provider: issuance.certificate-requester
  consumers:
    - issuance.issuer-operator
anchors:
  schema:
    - crates/tessera_issuer/src/csr.rs#Csr
    - crates/tessera_issuer/src/csr.rs#LeafRequestFromCsr
  test:
    - crates/tessera_issuer/src/tests.rs#valid_p256_csr_issues_with_csr_key_and_subject
    - crates/tessera_issuer/src/tests.rs#broken_self_signature_rejected_before_signing
requirements:
  ISS-101:
    kind: контракт
    subjects:
      - issuance.certificate-signing-request
    evidence:
      test:
        - crates/tessera_issuer/src/tests.rs#broken_self_signature_rejected_before_signing
  ISS-102:
    kind: инвариант
    subjects:
      - issuance.certificate-signing-request
    evidence:
      test:
        - crates/tessera_issuer/src/tests.rs#requested_extensions_do_not_shape_the_certificate
---

# Запрос на подпись сертификата

## Purpose

PKCS#10-граница между [[issuance.certificate-requester|заявителем]] и
[[issuance.issuer-operator|оператором выпуска]]. CSR переносит subject и
публичный ключ с доказательством владения; requested extensions являются лишь
подсказками интерфейсу.

## Граница

Контракт принимает DER либо PEM. Поддерживаемый алгоритм, корректность ключа и
самоподпись проверяются до обращения к подписывающему backend.

## Совместимость

Добавление поддерживаемого алгоритма или допустимого PKCS#10-атрибута
аддитивно. Изменение смысла уже принятого атрибута не может молча менять рамки
выпуска.

## Отказы

Ошибка разбора, неподдерживаемый или слабый ключ и неверная proof-of-possession
отклоняют запрос до подписи сертификата.

## Requirements

### ISS-101 — CSR доказывает владение ключом

[[issuance.certificate-signing-request|CSR]] MUST пройти проверку самоподписи
публичным ключом из самого запроса до вызова backend выпуска.

#### Scenario: Самоподпись повреждена

- **WHEN** подпись CSR не проверяется его публичным ключом
- **THEN** запрос отвергается и backend сертификата не вызывается

### ISS-102 — CSR не назначает рамки доступа

[[issuance.certificate-signing-request|CSR]] MUST NOT переносить requested
extensions в итоговые полномочия; host binding, роли, срок и integrity задаются
[[issuance.issuer-operator|оператором]] через рамки выпуска.

#### Scenario: CSR просит cA=TRUE

- **WHEN** requested extensions содержат `basicConstraints cA=TRUE`
- **THEN** выпущенный лист остаётся `cA=FALSE` и получает только операторский scope
