# Tasks: tags-delegation

## 1. Теги устройства (tessera_core, открытое)

- [ ] 1.1 Модуль `tags/schema.rs`: тип `DeviceTags` (map `key→value`, UTF8), serde-парсер; запрет дубля ключа; unit-тесты (дубль ключа, пустой ключ, не-UTF8 байты не паникуют)
- [ ] 1.2 `tags/source.rs`: managed-источник из манифеста `role-store` (переиспользовать верификацию подписи + `bundle_version`/anti-rollback); standalone-источник (файл под правами ФС, паритет с role-store standalone); fail-closed на битую подпись/откат
- [ ] 1.3 Generic-match `device.tags ⊇ requireTags` (без хардкода имён ключей); property-тест: новый произвольный ключ обрабатывается как данные
- [ ] 1.4 `tessera-cli tags show` (теги устройства) и `tags lint` (валидация локального файла)

## 2. Расширение profile_version (tessera_core, открытое)

- [ ] 2.1 Выделить OID `pam_cert_profile_version` в арке `2.25.<UUID>`, зафиксировать в `x509/oids.rs` + таблице OID main-спеки `cert-scope-binding`; пометить **critical**
- [ ] 2.2 `x509/profile_version_ext.rs`: DER INTEGER, извлечение только из `VerifiedX509`; malformed → reject (fail-closed); тесты
- [ ] 2.3 Обработка critical-флага: непонятый critical OID на любом серте цепи → reject (проверить/закрепить в pre_validate/chain)

## 3. Расширение delegation_constraints (tessera_core, открытое)

- [ ] 3.1 Выделить OID `pam_cert_delegation_constraints` в арке `2.25.<UUID>`, зафиксировать в `oids.rs` + таблице; **critical**
- [ ] 3.2 `x509/delegation_constraints_ext.rs`: DER `SEQUENCE { requireTags SEQ OF {key,value}, allowRoles SEQ OF UTF8, maxLevel INTEGER, maxTtl INTEGER }`; извлечение только из `VerifiedX509`; malformed → reject
- [ ] 3.3 Размещение: расширение на серте с `CA=FALSE` (лист) → malformed → reject; тест «delegation_constraints на листе»

## 4. Path validation (trust-chain-validation, tessera_core, открытое)

- [ ] 4.1 Version-gate: `tessera_profile_version ≤ max_supported` на каждом серте цепи, иначе reject; тест «версия выше supported»
- [ ] 4.2 Конверт по тегам: для каждого CA-серта с `delegation_constraints` — `device.tags ⊇ requireTags`; нет тегов / не удовлетворяет → reject; AND по всем CA-звеньям; тест «misissued широкий дочерний CA не вырывается»
- [ ] 4.3 Потолки: запрошенная роль ∈ `allowRoles` каждого CA; запрошенный уровень ≤ `maxLevel` каждого CA (и ≤ max_integrity листа); срок звена ≤ `maxTtl` родителя; тесты по каждому
- [ ] 4.4 Wildcard `host_binding=*` + конверт: лист работает на устройствах группы и только на них; тест «wildcard под северным CA не пускает на южное устройство»

## 5. Аудит и конфиг

- [ ] 5.1 `logging-audit`: события `delegation_denied` (звено-виновник, нарушенная проверка, снимок device.tags), `tag_manifest_applied` (device_id, bundle_version), `profile_version_rejected` (serial, версия, max_supported)
- [ ] 5.2 `configuration`: `[trust].max_supported_profile_version`, `[tags]` (путь/режим источника, enforce); дефолты fail-closed-совместимы

## 6. Issuance-тулинг и доки

- [ ] 6.1 openssl CA-конфиги (`docs/cert-issuance.md`): секции выпуска `delegation_constraints` (CA-серты) и `profile_version`; примеры монотонного сужения
- [ ] 6.2 Обновить main-спеку `cert-scope-binding` (таблица OID + примечание про critical) при архивации change

## 7. Проверка

- [ ] 7.1 `openspec validate tags-delegation --strict` зелёный
- [ ] 7.2 Интеграционный тест полной цепи: корень → CA(region:north) → wildcard-лист, устройство с тегом region:north пускает, region:south отвергает
