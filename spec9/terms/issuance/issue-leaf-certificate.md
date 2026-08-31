---
id: issue-leaf-certificate
kind: операция
context: issuance
name: Выпустить листовой сертификат
relations:
  accepts:
    - issuance.certificate-signing-request
    - issuance.leaf-issuance-scope
  produces:
    - auth.credential
  emits:
    - issuance.leaf-certificate-issued
  writes:
    - issuance.issuance-journal
  references:
    - issuance.parent-ca-certificate
    - issuance.leaf-scope-policy
    - issuance.artifact-release-policy
anchors:
  code:
    - crates/tessera_issuer/src/lib.rs#issue_leaf
    - crates/tessera_issuer/src/csr.rs#issue_leaf_from_csr
  test:
    - crates/tessera_issuer/src/tests.rs#valid_p256_csr_issues_with_csr_key_and_subject
    - crates/tessera_issuer/src/tests.rs#journal_write_failure_fails_closed
---

# Выпустить листовой сертификат

## Purpose

Операция принимает публичный ключ напрямую либо из
[[issuance.certificate-signing-request|CSR]], применяет операторские
[[issuance.leaf-issuance-scope|рамки]], проверяет их относительно
[[issuance.parent-ca-certificate|родительского CA]], подписывает и независимо
проверяет итоговый [[auth.credential|сертификат]].

Успешный возврат означает, что запись уже добавлена в
[[issuance.issuance-journal|журнал выпуска]]. Запись файла CLI выполняется после
ядра и потому относится к доставке артефакта, а не к факту его выпуска.
