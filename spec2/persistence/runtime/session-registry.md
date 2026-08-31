---
id: session-registry
kind: хранилище
context: runtime
name: Реестр активных сессий
owner: runtime
format: JSON snapshot
compatibility: additive-serde-defaults
relations:
  references:
    - runtime.active-session
    - runtime.monitor-daemon
anchors:
  code:
    - crates/tessera_cli/src/registry/store.rs#RegistryStore
  schema:
    - crates/tessera_cli/src/registry.rs#ActiveSession
  test:
    - crates/tessera_cli/tests/registry_store.rs
  type:
    - crates/tessera_cli/src/registry.rs#ActiveSession
requirements:
  STORE-001:
    kind: инвариант
    subjects:
      - runtime.session-registry
    evidence:
      test:
        - crates/tessera_cli/tests/registry_store.rs#corrupt_file_is_fail_closed
  STORE-002:
    kind: операционное
    subjects:
      - runtime.session-registry
    evidence:
      code:
        - crates/tessera_cli/src/registry/store.rs#persist
      test:
        - crates/tessera_cli/tests/registry_store.rs#persist_twice_is_atomic_overwrite
---

# Реестр активных сессий

## Purpose

Снимок [[runtime.active-session|активных сессий]], необходимый
[[runtime.monitor-daemon|демону]] после перезапуска. По умолчанию хранится в
`/run/tessera/sessions.json`; это не база данных и у него нет отдельного
миграционного движка.

## Граница

Хранилище связывает текущий процесс демона с состоянием, записанным предыдущим
процессом. Другие сервисы не являются потребителями файла; интеграция через
прямое чтение JSON не считается поддерживаемым контрактом.

## Совместимость

Эволюция формата аддитивна: новое необязательное поле получает serde-default.
Удаление или смена смысла поля требует явной миграции снимка. Отсутствующий файл
означает свежий runtime и пустой реестр.

## Отказы

Существующий, но нечитаемый или повреждённый JSON не заменяется пустым реестром:
такой reset потерял бы контроль над уже открытыми сессиями. Публикация нового
снимка выполняется атомарной заменой файла.

## Requirements

### STORE-001 — Повреждение снимка не сбрасывает контроль сессий

[[runtime.session-registry|Реестр сессий]] MUST возвращать ошибку при
повреждённом существующем JSON. [[runtime.session-registry|Реестр сессий]]
MUST NOT трактовать повреждение как пустой реестр.

#### Scenario: Повреждённый sessions.json
- **WHEN** файл существует, но не разбирается как список `ActiveSession`
- **THEN** загрузка завершается ошибкой и демон не продолжает с пустым состоянием

### STORE-002 — Новый снимок публикуется атомарно

[[runtime.session-registry|Реестр сессий]] MUST публиковать новый снимок через
временный файл, синхронизацию и rename в той же файловой системе.

#### Scenario: Повторная запись
- **WHEN** демон сохраняет второй снимок поверх первого
- **THEN** читатель видит целиком старый либо целиком новый JSON, но не частичную запись
