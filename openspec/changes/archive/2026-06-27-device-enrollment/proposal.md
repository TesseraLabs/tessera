# Proposal: device-enrollment

## Why

`clone-image-bootstrap` + `host-identity` закрывают раскатку из золотого образа на уровне
**host_id-flip и per-host серта**: клон стартует с `override="installation"`, `finish-bootstrap.sh`
атомарно переключает источники, `dump-host-id` отдаёт `hash_hex`, CA выпускает per-host серт.
Но с введением **тегов устройства** и **рамок делегирования** (change `tags-delegation`,
дизайн `tessera-ws/specs/2026-06-08-device-tags-delegation-design.md`) у клона нет per-device
тегов, и при enrollment нужно доставить теги и первый bundle (роли+теги+CRL) с зафиксированным
baseline `bundle_version` (anti-rollback). Дизайн-сессия 2026-06-08
(`tessera-ws/specs/2026-06-08-enrollment-lifecycle-design.md`) определила enrollment-поток.

Инвариант: **раскатка работает и без сервера** (open-core). Сервер добавляет подпись/anti-rollback/
автоматизацию, не является условием раскатки. Вне scope: Tessera Codes и per-device ключ Codes-MAC
(только cert-путь).

## What Changes

- Новая capability **device-enrollment**: контракт импорта enrollment-пакета на устройство после
  flip — per-host серт (`.p12` под PIN, существующее) **+** доставка тегов и первого bundle
  (роли+теги+CRL). Теги/bundle не секретны → едут открыто на том же USB-возврате.
- **Два режима** (паритет `role-store`): managed (подписанный manifest, anti-rollback baseline,
  Control мапит `hash_hex`→теги) и standalone (файл тегов + роли под доверием прав ФС, ручной
  выпуск серта своим CA-ключом).
- **Baseline anti-rollback**: первый импорт фиксирует базовый `bundle_version`; реплей меньшего
  → reject. Идемпотентность: повторный импорт того же — no-op.
- **Назначение тегов — серверная сторона** (Control inventory / оператор при установке); device
  принимает теги только из доверенного источника, не из произвольного локального конфига.
- `clone-image-bootstrap` CA-контракт расширяется: на возврате CA отдаёт подписанный manifest
  (теги+роли+CRL) рядом с per-host сертом.
- trust-anchor (корень CA) пиннится в золотом образе (SPKI-pin, существующее); ротация — отложено (H2).
- Audit: `device_enrolled`.

## Capabilities

### New Capabilities

- `device-enrollment`: контракт импорта enrollment-пакета (per-host серт + теги + первый bundle),
  два режима (standalone/managed), baseline anti-rollback, идемпотентность, доверенный источник
  тегов, audit-событие.

### Modified Capabilities

- `clone-image-bootstrap`: CA-контракт на возврате — подписанный manifest (теги+роли+CRL) рядом
  с per-host сертом; импорт пакета после flip.
- `role-store`: инициализация baseline `bundle_version` при первом enrollment (managed).
- `logging-audit`: событие `device_enrolled`.

## Impact

- `tessera_core`: модуль импорта enrollment-пакета (переиспользует верификацию manifest role-store
  и источник device-tags); инициализация персиста `bundle_version`.
- `tessera_cli`: подкоманда импорта enrollment-пакета (после `finish-bootstrap`); standalone-режим
  (раскладка файлов под FS-perms).
- Документация: `docs/clone-image.md` — шаг доставки тегов/bundle на возврате USB; CA-сторона
  (вне репо) — формат enrollment-пакета как контракт.
- Control (закрытый, будущий): inventory `hash_hex`→теги, выпуск подписанного manifest — контракт.
- Зависимость: capability `device-tags` (источник тегов) и `tags-delegation` (потребление) —
  enrollment их наполняет.
