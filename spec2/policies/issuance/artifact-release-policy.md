---
id: artifact-release-policy
kind: политика
context: issuance
name: Политика выдачи выпущенного артефакта
relations:
  references:
    - issuance.issuance-journal
    - auth.credential
applies:
  - pattern: fail-closed
anchors:
  code:
    - crates/tessera_issuer/src/lib.rs#issue_leaf_recording_origin
  test:
    - crates/tessera_issuer/src/tests.rs#journal_write_failure_fails_closed
requirements:
  ISS-120:
    kind: инвариант
    subjects:
      - issuance.artifact-release-policy
    evidence:
      test:
        - crates/tessera_issuer/src/tests.rs#self_check_leaf_independently_rejects_ttl_above_parent
  ISS-121:
    kind: инвариант
    subjects:
      - issuance.artifact-release-policy
    evidence:
      test:
        - crates/tessera_issuer/src/tests.rs#journal_write_failure_fails_closed
conformance:
  fail-closed/FC-001:
    test:
      - crates/tessera_issuer/src/tests.rs#journal_write_failure_fails_closed
  fail-closed/FC-002:
    code:
      - crates/tessera_issuer/src/lib.rs#issue_leaf_recording_origin
  fail-closed/FC-003:
    code:
      - crates/tessera_issuer/src/error.rs#IssueError
---

# Политика выдачи выпущенного артефакта

## Purpose

Отделяет факт получения подписи от доменного факта выпуска. Подписанный DER ещё
не является выданным [[auth.credential|удостоверением]]: он должен пройти
независимую проверку и попасть в [[issuance.issuance-journal|журнал выпуска]].

## Requirements

### ISS-120 — Подписанный лист проверяется общим парсером

[[issuance.artifact-release-policy|Политика выдачи]] MUST прогнать собранный
сертификат через общий с Engine разбор расширений и проверку профиля до возврата
артефакта вызывающей стороне.

#### Scenario: Подпись есть, профиль недопустим

- **WHEN** подписанный сертификат нарушает TTL или обязательное расширение
- **THEN** самопроверка отклоняет его и артефакт не возвращается

### ISS-121 — Запись журнала предшествует выдаче

[[issuance.artifact-release-policy|Политика выдачи]] MUST возвращать артефакт
только после успешного durable append записи `issue_leaf`.

#### Scenario: Хранилище журнала недоступно

- **WHEN** append возвращает storage error
- **THEN** операция завершается `IssueError::Journal` и не возвращает сертификат
