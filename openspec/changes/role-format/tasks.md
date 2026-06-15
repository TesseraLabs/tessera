# Tasks: role-format

## 1. Схема и парсер роли (tessera_core, открытое)

- [x] 1.1 Модуль `role/schema.rs`: типы RoleSlice/Payload/Session, serde `deny_unknown_fields`, regex role_id; unit-тесты строгости (неизвестное поле, битые типы, role≠имя файла, чужой os, граничные role_id)
- [x] 1.2 Property-тесты (proptest): парсер не паникует на произвольных байтах; roundtrip role_id ↔ имя файла
- [x] 1.3 Валидация payload по os: astra (mac_mask), linux (groups/sudo_role/limits), selinux-секция — схема парсится в открытой сборке

## 2. role-store (tessera_core, открытое)

- [x] 2.1 `role/store.rs`: загрузка каталога `/var/lib/tessera/roles/`, standalone-режим (права ФС), per-роль отказ при битом файле + audit-событие
- [x] 2.2 Формат manifest.toml + верификация: подпись над байтами, hash срезов, монотонный bundle_version (персист), fail-closed всей базы; тесты rollback/mix-and-match/чужой ключ
- [x] 2.3 Атомарное обновление: tmp-каталог → валидация → rename(); тест сбоя посреди обновления
- [x] 2.4 `tessera-cli role lint` и `role list`; ship примеров ролей в dist/

## 3. Расширение серта allowed-roles (tessera_core, открытое)

- [x] 3.1 Выделить OID в арке 2.25.<UUID>, зафиксировать в `x509/oids.rs` + обновить таблицу OID в main-спеке cert-scope-binding
- [x] 3.2 `x509/allowed_roles_ext.rs`: DER SEQUENCE OF UTF8String, извлечение только из VerifiedX509, fail-closed на malformed (вкл. невалидный role_id в списке); тесты по сценариям дельта-спеки
- [x] 3.3 Обновить issuance-тулинг (openssl CA конфиги в docs/cert-issuance.md): секция allowed_roles

## 4. Выбор роли в pam_tessera

- [x] 4.1 Суффикс-парсер `user+role` + канонизация PAM_USER (`pam_set_item`) в начале `pam_sm_authenticate`; таблица edge cases из дельта-спеки role-selection как unit-тесты
- [x] 4.2 Текстовый prompt (PAM_TEXT_INFO + PAM_PROMPT_ECHO_ON) при отсутствии суффикса; отказ без выбора
- [x] 4.3 Резолв из store + membership-покрытие сертом одной стадией во flow; конфиг `roles.enforce = false|warn|require` (дефолт false на этом этапе); audit-поля (канон-имя, роль, причина deny)
- [x] 4.4 Сессия: копия payload, TTL = min(удостоверение, session.max_ttl, глобальный дефолт); отказ при payload с недоступным backend (stub) — тест «mac_mask на открытой сборке»

## 5. Интеграция МКЦ (mac-integrity)

- [x] 5.1 Orchestrator: запрошенная метка из mac_mask роли, пересечение с потолком серта и МНКЦ; отказ при непокрытии маски потолком (не сужение); прежняя семантика при роли без mac_mask — тесты на все три сценария дельта-спеки
- [x] 5.2 IPC (tessera_proto): роль в сообщениях session open; обновить версию протокола при необходимости

## 6. Документация и спеки

- [x] 6.1 Обновить docs/configuration.md (`roles.*`), README (роль/выбор на логине), дельта в main-спеки через `/opsx:sync` или archive
- [x] 6.2 Платформенная спека tessera-ws: глоссарная строка «Сертификат» обогащена (allowed_roles + max_integrity); §7 «формат роли» уже в «Решено» со ссылкой на change role-format
- [x] 6.3 E2E-сценарий на Astra VM: `ivanov+serv` по серту с allowed_roles → сессия с группами; отказы (нет роли, нет покрытия, malformed расширение) — validated 2026-06-15 на Astra SE 1.8.4 через production `pam_tessera.so` 0.4.0, 5/5 (R1 success+`role_session_open` role=serv v1 method=cert ttl=14400; R2 `role_deny not_covered`; R3 `role_deny not_found`; R4 `cert_allowed_roles_parse_failed`+not_covered; R5 enforce=false → skip). Harness: `vagrant/scripts/test-roles.sh` (USB-эмуляция loop+udev), фикстуры `tests/fixtures/roles/`.
