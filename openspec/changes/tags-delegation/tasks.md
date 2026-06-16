# Tasks: tags-delegation

## 1. Теги устройства (tessera_core, открытое)

- [x] 1.1 Модуль `tags/schema.rs`: тип `DeviceTags` (map `key→value`, UTF8), serde-парсер; запрет дубля ключа; unit-тесты (дубль ключа, пустой ключ, не-UTF8 байты не паникуют)
- [x] 1.2 `tags/source.rs`: managed-источник из манифеста `role-store` (переиспользовать верификацию подписи + `bundle_version`/anti-rollback); standalone-источник (файл под правами ФС, паритет с role-store standalone); fail-closed на битую подпись/откат
- [x] 1.3 Generic-match `device.tags ⊇ requireTags` (без хардкода имён ключей); property-тест: новый произвольный ключ обрабатывается как данные
- [x] 1.4 `tessera-cli tags show` (теги устройства) и `tags lint` (валидация локального файла)

## 2. Расширение profile_version (tessera_core, открытое)

- [x] 2.1 Выделить OID `pam_cert_profile_version` в арке `2.25.<UUID>`, зафиксировать в `x509/oids.rs` + таблице OID main-спеки `cert-scope-binding`; пометить **critical**
- [x] 2.2 `x509/profile_version_ext.rs`: DER INTEGER, извлечение только из `VerifiedX509`; malformed → reject (fail-closed); тесты
- [x] 2.3 Обработка critical-флага: непонятый critical OID на любом серте цепи → reject — реализовано явным сканом в `x509::profile_validation::verify_profile_and_criticals` (allowlist KNOWN_CRITICAL_OIDS = basicConstraints/keyUsage/EKU + два наших OID), вшито в `verify_at` (live). Тест unknown_critical_extension_rejected.

## 3. Расширение delegation_constraints (tessera_core, открытое)

- [x] 3.1 Выделить OID `pam_cert_delegation_constraints` в арке `2.25.<UUID>`, зафиксировать в `oids.rs` + таблице; **critical**
- [x] 3.2 `x509/delegation_constraints_ext.rs`: DER `SEQUENCE { requireTags SEQ OF {key,value}, allowRoles SEQ OF UTF8, maxLevel INTEGER, maxTtl INTEGER }`; извлечение только из `VerifiedX509`; malformed → reject
- [x] 3.3 Размещение: расширение на серте с `CA=FALSE` (лист) → malformed → reject; тест «delegation_constraints на листе»

## 4. Path validation (trust-chain-validation, tessera_core, открытое)

- [x] 4.1 Version-gate: `pam_cert_profile_version ≤ max_supported` на каждом серте цепи — вшито в `verify_at` (live); дефолт max_supported=0 (fail-closed). Тесты профиля.
- [x] 4.2 Конверт по тегам: `enforce_delegation` (trust/delegation.rs) — `device.tags ⊇ requireTags` AND по всем CA-звеньям, no-tags→reject, misissued child не вырывается. Логика+тесты done. ЖИВОЕ вшивание enforce_delegation в PAM-flow (с device-tags + запрошенной role/level) — в секции 5 (config-источник тегов + проброс).
- [x] 4.3 Потолки: роль ∈ allowRoles каждого CA, уровень ≤ maxLevel каждого CA (+ max_integrity листа), срок звена ≤ maxTtl родителя — в `enforce_delegation`, тесты по каждому. Live-wiring — секция 5 (см. 4.2).
- [x] 4.4 Wildcard `host_binding=*` + конверт: следует из 4.2 (enforce_delegation отвергает несоответствующее устройство независимо от wildcard); тесты wildcard north-pass/south-reject + canonical_north_ca_wildcard_leaf_end_to_end. Live-wiring — секция 5.

## 5. Аудит и конфиг

- [ ] 5.1 `logging-audit`: события `delegation_denied` (звено-виновник, нарушенная проверка, снимок device.tags), `tag_manifest_applied` (device_id, bundle_version), `profile_version_rejected` (serial, версия, max_supported)
- [ ] 5.2 `configuration`: `[trust].max_supported_profile_version`, `[tags]` (путь/режим источника, enforce); дефолты fail-closed-совместимы

## 6. Issuance-тулинг и доки

- [ ] 6.1 openssl CA-конфиги (`docs/cert-issuance.md`): секции выпуска `delegation_constraints` (CA-серты) и `profile_version`; примеры монотонного сужения
- [ ] 6.2 Обновить main-спеку `cert-scope-binding` (таблица OID + примечание про critical) при архивации change

## 7. Проверка

- [ ] 7.1 `openspec validate tags-delegation --strict` зелёный
- [ ] 7.2 Интеграционный тест полной цепи: корень → CA(region:north) → wildcard-лист, устройство с тегом region:north пускает, region:south отвергает
