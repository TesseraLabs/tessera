---
id: issuance-journal
kind: хранилище
context: issuance
name: Журнал выпуска
owner: issuance
format: hash-chained NDJSON
compatibility: append-only tagged payloads with stable genesis domain
anchors:
  type:
    - crates/tessera_issuer/src/journal.rs#Journal
  code:
    - crates/tessera_issuer/src/journal.rs#Journal
  schema:
    - crates/tessera_issuer/src/journal.rs#Payload
  test:
    - crates/tessera_issuer/src/tests.rs#journal_write_failure_fails_closed
    - crates/tessera_issuer/src/tests.rs#tampered_record_breaks_chain_at_position
requirements:
  JRN-001:
    kind: инвариант
    subjects:
      - issuance.issuance-journal
    evidence:
      test:
        - crates/tessera_issuer/src/tests.rs#tampered_record_breaks_chain_at_position
  JRN-002:
    kind: контракт
    subjects:
      - issuance.issuance-journal
    evidence:
      code:
        - crates/tessera_issuer/src/journal.rs#JournalStorage
      test:
        - crates/tessera_issuer/src/tests.rs#journal_write_failure_fails_closed
---

# Журнал выпуска

## Purpose

Append-only инвентарь выпущенных сертификатов и CRL. Журнал служит evidence для
инвентаризации и расследований, а не принимает решения о доступе.

## Граница

Ядро работает с последовательностью NDJSON-записей через `JournalStorage`.
Нативный CLI использует файл; браузерный кабинет может предоставить другое
durable storage, сохраняя тот же контракт append/read-order.

## Совместимость

Новые tagged payload добавляются аддитивно. Genesis domain, порядок полей уже
записанной строки и смысл существующего `op` не меняются: изменение байтов
ломает hash chain.

## Отказы

Ошибка чтения или append возвращается вызывающей операции. Повреждение,
удаление или перестановка строк обнаруживается верификацией с позицией первого
разрыва и не интерпретируется как пустой журнал.

## Requirements

### JRN-001 — Изменение истории обнаружимо

[[issuance.issuance-journal|Журнал выпуска]] MUST связывать каждую запись с
хешем предыдущей строки и отдельным genesis domain выпуска.

#### Scenario: Строка была изменена

- **WHEN** сохранённый payload редактируется после append
- **THEN** verify сообщает позицию первого разрыва цепочки

### JRN-002 — Успешный append означает durable запись

[[issuance.issuance-journal|Журнал выпуска]] MUST считать append успешным только
после сохранения строки. [[issuance.issuance-journal|Журнал выпуска]] MUST
возвращать записи в порядке добавления.

#### Scenario: Storage не сохранил строку

- **WHEN** реализация `JournalStorage` не может выполнить durable append
- **THEN** append возвращает ошибку и состояние head/next_seq не продвигается
