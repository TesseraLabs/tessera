# role-store Delta Specification

## ADDED Requirements

### Requirement: Инициализация baseline bundle_version при enrollment

При первом managed-enrollment устройство ДОЛЖНО (MUST) инициализировать персист `bundle_version`
значением из принятого manifest как baseline для anti-rollback `role-store`. Дальнейшие обновления
набора ролей ДОЛЖНЫ (MUST) подчиняться существующему anti-rollback (монотонный `bundle_version`,
fail-closed при откате). Отсутствие предыдущего baseline (чистый клон после flip) НЕ ДОЛЖНО
(MUST NOT) трактоваться как «любой bundle_version принимается» после первичной инициализации.

#### Scenario: Первый manifest задаёт baseline
- **WHEN** на свежеразвёрнутое устройство импортируется первый подписанный manifest с `bundle_version = N`
- **THEN** `N` фиксируется как baseline; последующий manifest с `bundle_version < N` отвергается
