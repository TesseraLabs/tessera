---
id: device-enrollment
kind: операция
context: fleet
name: "Регистрация устройства"
aliases:
  - "device-enrollment"
relations:
  references:
    - auth.host-identity
    - auth.role
anchors:
  code:
    - "crates/tessera_core/src/enrollment/import.rs"
  test:
    - "tests/e2e/cases/14-device-enrollment.yaml"
requirements:
  ENR-001:
    kind: операционное
    subjects:
      - fleet.device-enrollment
    origins:
      - "device-enrollment::Импорт enrollment-пакета"
    evidence:
      code:
        - "crates/tessera_core/src/enrollment/import.rs"
  ENR-002:
    kind: инвариант
    subjects:
      - fleet.device-enrollment
    origins:
      - "device-enrollment::Baseline anti-rollback"
    evidence:
      test:
        - "tests/e2e/cases/14-device-enrollment.yaml"
  ENR-003:
    kind: операционное
    subjects:
      - fleet.device-enrollment
    origins:
      - "device-enrollment::Раскатка без сервера (standalone)"
    evidence:
      code:
        - "crates/tessera_core/src/enrollment/import.rs"
---
# Регистрация устройства

Эта страница заменяет процедурную capability-спеку OpenSpec «device-enrollment»: она
помещает каждое прежнее требование в адресуемую норму с владельцем, видом и
проверяемым происхождением. Под каждым нормативным предложением сохранены подробные условия, отрицательные
сценарии и rationale; они входят в ту же страницу и уточняют границы нормы.

### ENR-001 — Импорт enrollment-пакета

[[fleet.device-enrollment|Регистрация устройства]] MUST соблюдать правило «Импорт enrollment-пакета» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/device-enrollment/spec.md, requirement «Импорт enrollment-пакета».

После flip (`clone-image-bootstrap`) устройство должно импортировать enrollment-пакет,
содержащий per-host удостоверение (`.p12` под PIN — существующий путь) и набор тегов + первый
bundle (роли+CRL). В managed-режиме теги и bundle должны проверяться по подписи и
`bundle_version` (механизм `role-store`); в standalone-режиме источником должен служить
локальный файл под доверием прав ФС. Импортированные теги должны попадать только в
доверенный источник `device-tags`; произвольный локальный конфиг тегов не должен
приниматься как источник.

#### Scenario: Managed-импорт с валидной подписью
- **WHEN** импортируется подписанный enrollment-пакет с тегами и bundle
- **THEN** подпись и `bundle_version` проверяются, теги попадают в доверенный источник, устройство становится рабочим

#### Scenario: Битый enrollment-пакет
- **WHEN** manifest пакета не проходит проверку подписи (managed)
- **THEN** импорт отвергается (fail-closed), устройство остаётся в прежнем состоянии

### ENR-002 — Baseline anti-rollback

[[fleet.device-enrollment|Регистрация устройства]] MUST соблюдать правило «Baseline anti-rollback» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/device-enrollment/spec.md, requirement «Baseline anti-rollback».

Первый принятый импорт должен фиксировать базовый `bundle_version` (персист); последующий
импорт с `bundle_version` меньше зафиксированного должен отвергаться (anti-rollback).
Повторный импорт того же `bundle_version` должен быть no-op (идемпотентность). Частичный
сбой импорта должен приводить к атомарному откату — устройство остаётся в согласованном
прежнем состоянии (fail-closed).

#### Scenario: Реплей старого bundle
- **WHEN** импортируется manifest с `bundle_version` меньше зафиксированного baseline
- **THEN** импорт отвергается (anti-rollback)

#### Scenario: Повторный импорт того же bundle
- **WHEN** импортируется manifest с тем же `bundle_version`, что уже применён
- **THEN** операция — no-op (идемпотентность)

### ENR-003 — Раскатка без сервера (standalone)

[[fleet.device-enrollment|Регистрация устройства]] MUST соблюдать правило «Раскатка без сервера (standalone)» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/device-enrollment/spec.md, requirement «Раскатка без сервера (standalone)».

Раскатка из золотого образа должна быть возможна полностью без сервера: per-host серт
выпускается администратором своим CA-ключом вручную (существующий путь), теги и роли
раскладываются локально под доверием прав ФС. Отсутствие сервера не должно блокировать
enrollment; сервер добавляет подпись/anti-rollback/автоматизацию, не является условием раскатки.

#### Scenario: Standalone enrollment без сервера
- **WHEN** администратор выпускает per-host серт своим CA-ключом и раскладывает файл тегов + роли под FS-perms
- **THEN** устройство становится рабочим без обращения к серверу

