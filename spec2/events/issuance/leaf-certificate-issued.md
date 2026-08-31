---
id: leaf-certificate-issued
kind: событие
context: issuance
name: Листовой сертификат выпущен
relations:
  producer: issuance.issue-leaf-certificate
  references:
    - auth.credential
    - issuance.issuance-journal
anchors:
  test:
    - crates/tessera_issuer/src/tests.rs#journal_write_failure_fails_closed
    - crates/tessera_issuer/src/tests.rs#valid_p256_csr_issues_with_csr_key_and_subject
---

# Листовой сертификат выпущен

## Purpose

Факт наступает только после подписи, независимой самопроверки и durable append
в [[issuance.issuance-journal|журнал]]. Он означает существование нового
[[auth.credential|удостоверения]], даже если последующая запись выходного файла
или упаковка носителя не доставила его оператору.

Ошибки валидации до подписи и ошибка журнала не создают этот факт.
