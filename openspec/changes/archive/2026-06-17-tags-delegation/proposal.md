# Proposal: tags-delegation

## Why

Сегодня цепочка X.509 валидируется по стандарту RFC 5280 (подписи, `CA=TRUE`/pathLen/`keyCertSign`,
SPKI-pin — `trust-chain-validation`), а авторизация привязана к листу (`host_binding`, `user_binding`,
`max_integrity` — `cert-scope-binding`). Рамок делегирования нет: промежуточный CA может выпустить
что угодно в пределах стандартной валидации. Платформенная спека (tessera-ws) и дизайн-сессия
2026-06-08 (`tessera-ws/specs/2026-06-08-device-tags-delegation-design.md`) зафиксировали семантику
для открытого вопроса **H4** (name-constraints на custom-OID + делегация атрибутов) и уточнение
**H5** (объём path validation = периметр сертификации). Пора положить это в спеки tessera как
контракт реализации.

Цель: подрядный/региональный промежуточный CA вправе выпускать удостоверения только на свою
группу устройств (по тегам), с ограниченным набором ролей, потолком уровня и TTL; гарантия
проверяется **на устройстве, офлайн** по собственным подписанным тегам устройства, а не по слову
выпускающего. Это сжимает blast radius компрометации промежуточного CA до его рамок.

## What Changes

- Вводятся **теги устройства** — опаковый для Engine набор пар `key=value` (`region`, `class`, …),
  доставляемый в managed-режиме тем же подписанным манифестом и `bundle_version` (anti-rollback),
  что база ролей (`role-store`); standalone — локальный файл под доверием прав ФС. Engine **не знает
  имён тегов** — сравнение generic, новые теги добавляются без изменения кода.
- Новое critical-расширение серта **`pam_cert_delegation_constraints`** (только при `CA=TRUE`):
  `requireTags` (AND равенств) + `allowRoles` (allowlist) + `maxLevel` + `maxTtl`. Конверт
  делегирования выпускающего CA.
- Новое critical-расширение серта **`pam_cert_profile_version`** (на любом серте): целое; Engine
  знает `max_supported`, серт версии выше → reject всей цепи (version-gate, fail-closed).
- **Path validation расширяется** (`trust-chain-validation`): version-gate; для каждого CA-серта
  с конвертом — `device.tags ⊇ requireTags` (generic superset) и запрошенная роль/уровень/TTL
  в пределах конверта; AND/MIN по **всем** звеньям (misissued дочерний CA не вырывается из
  родительского конверта). `delegation_constraints` на листе (`CA=FALSE`) → malformed → reject.
- **Wildcard `host_binding` сужается до группы**: лист с `host_binding=*`, выпущенный под
  конвертом CA, работает на всех устройствах группы и только на них (раньше `*` = любое устройство
  парка, только bootstrap + короткий TTL). Лист с `sha256:<host>` остаётся per-host.
- Словарь audit-событий: `delegation_denied`, `tag_manifest_applied`, `profile_version_rejected`.
- Конфиг: `max_supported_profile_version`, путь/режим источника тегов.

Совместимость: существующие серты (без новых расширений) валидируются как раньше. Новые
critical-расширения отвергаются старым Engine — это намеренный fail-closed (rollout Engine-first).

## Capabilities

### New Capabilities

- `device-tags`: формат набора тегов устройства (generic map), источник и доверие (managed-манифест
  с anti-rollback / standalone права ФС), чтение собственных тегов Engine, поведение при отсутствии
  тегов.

### Modified Capabilities

- `cert-scope-binding`: два новых **critical** OID-расширения (`pam_cert_delegation_constraints`,
  `pam_cert_profile_version`); правила размещения (`delegation_constraints` только на `CA=TRUE`);
  извлечение только из `VerifiedX509`, fail-closed на malformed.
- `trust-chain-validation`: version-gate; проверка конверта делегирования по тегам устройства
  (generic superset, AND по всем CA-звеньям); потолки роли/уровня/TTL по цепи; reject
  `delegation_constraints` на листе.
- `logging-audit`: словарь audit-событий делегирования и тегов.
- `configuration`: `max_supported_profile_version`, источник тегов устройства.

## Impact

- `tessera_core`: `x509/` — два новых расширения (`delegation_constraints_ext.rs`,
  `profile_version_ext.rs`) + OID в `oids.rs`; `trust/` — шаги version-gate и проверки конверта;
  новый модуль `tags/` (формат, источник, generic-match) с переиспользованием manifest-машинерии
  `role-store`.
- `pam_tessera`: запрошенные роль/уровень уже во flow — передаются в проверку конверта; код PAM
  только в cdylib.
- `tessera_cli`: `tags show`/`lint`; доставка тегов в managed-манифесте (заготовка под Control).
- `tessera_proto`: при необходимости — поле причины delegation-deny в IPC (опционально).
- Документация: issuance-тулинг (openssl CA-конфиги) — секции `delegation_constraints` и
  `profile_version`; обновить таблицу OID в main-спеке `cert-scope-binding`.
- Codes/Control (закрытые, будущие): авторинг тегов, словарь тегов (реестр ключей), issuance-side
  проверка конверта как builtin-проверка PDP (`issuance-signals`) — фиксируется здесь как контракт.
