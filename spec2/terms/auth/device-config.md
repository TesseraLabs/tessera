---
id: device-config
kind: конфигурация
context: auth
name: Конфигурация устройства
aliases:
  - конфигурация устройства
  - config.toml
owner: auth.operator
source: /etc/tessera/config.toml
reload: each-pam-call-and-daemon-start
migrated_from: openspec/specs/configuration/spec.md
relations:
  references:
    - auth.carrier
    - auth.device-config
    - auth.operator
    - auth.pam-module
anchors:
  type:
    - crates/tessera_core/src/config/validated.rs#ValidatedConfig
    - crates/tessera_core/src/config/validated.rs#Mode
  code:
    - crates/tessera_core/src/config/validated.rs#Validated
  test:
    - tests/e2e/cases/15-configuration.yaml
applies:
  - pattern: explicit-config
requirements:
  AUTH-001:
    kind: инвариант
    subjects:
      - auth.device-config
      - auth.pam-module
    evidence:
      test:
        - tests/e2e/cases/15-configuration.yaml
      code:
        - crates/tessera_core/src/config/validated.rs#Validated
conformance:
  explicit-config/EC-001:
    test:
      - tests/e2e/cases/15-configuration.yaml
  explicit-config/EC-002:
    test:
      - tests/e2e/cases/15-configuration.yaml
---

# Конфигурация устройства

## Граница

Файл находится на границе между [[auth.operator|оператором устройства]] и
исполняемыми компонентами Tessera. Значения из него задаёт ограничивающая
сторона; данные из [[auth.carrier|носителя]] не могут подменять эту политику.

## Совместимость

Конфигурация разбирается строго: неизвестный ключ не игнорируется. PAM-модуль
перечитывает файл при каждой попытке входа, а демон — при запуске; динамического
частичного применения внутри уже начатой операции нет.

## Purpose

`/etc/tessera/config.toml` — то, что администратор устройства утверждает как
политику: anchors, режим проверки отзыва, носитель, послабления. Всё, что
задаётся здесь, задано **ограничивающей** стороной; всё, что приходит с
носителя, — **ограничиваемой**. Граница между ними — главная линия модели.

## Requirements

### AUTH-001 — Невалидная конфигурация отклоняет вход

[[auth.device-config|Конфигурация устройства]], не прошедшая валидацию,
MUST приводить к отказу входа с `PAM_AUTHINFO_UNAVAIL`.
[[auth.pam-module|Модуль]] MUST NOT продолжать работу на частично
разобранной конфигурации.

#### Scenario: Синтаксическая ошибка в config.toml
- **WHEN** конфигурация не разбирается либо не проходит валидацию
- **THEN** вход отклоняется с `PAM_AUTHINFO_UNAVAIL`
