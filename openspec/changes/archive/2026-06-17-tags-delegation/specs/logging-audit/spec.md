# logging-audit Delta Specification

## ADDED Requirements

### Requirement: Audit-события делегирования и тегов

Engine ДОЛЖЕН (MUST) эмитить audit-события для решений делегирования и применения тегов:
`delegation_denied` (звено-виновник serial, нарушенная проверка: tags/role/level/ttl/version,
снимок `device.tags`), `tag_manifest_applied` (`device_id`, `bundle_version`),
`profile_version_rejected` (serial, версия серта, `max_supported`). Причина отказа, показываемая
инженеру, ДОЛЖНА (MUST) быть обобщённой; полный вектор причин ДОЛЖЕН (MUST) попадать только в
audit (не раскрываем структуру рамок до аутентификации).

#### Scenario: Отказ по конверту делегирования
- **WHEN** цепь отвергнута из-за несоответствия `device.tags` конверту
- **THEN** эмитится `delegation_denied` с serial звена-виновника и снимком `device.tags`, инженеру — обобщённая причина

#### Scenario: Применение манифеста тегов
- **WHEN** применён новый подписанный манифест с тегами устройства
- **THEN** эмитится `tag_manifest_applied` с `device_id` и `bundle_version`
