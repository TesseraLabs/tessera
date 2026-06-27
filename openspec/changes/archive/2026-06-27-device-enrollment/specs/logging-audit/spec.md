# logging-audit Delta Specification

## ADDED Requirements

### Requirement: Audit-событие device_enrolled

Engine ДОЛЖЕН (MUST) эмитить audit-событие `device_enrolled` после успешного импорта
enrollment-пакета: host_id prefix8, serial per-host серта, применённый `bundle_version`, режим
(standalone/managed). Событие ДОЛЖНО (MUST) попадать в локальный hash-chain журнал
(audit-visibility); выгрузка в Control — best-effort при связности.

#### Scenario: Успешный enrollment
- **WHEN** enrollment-пакет импортирован и `tessera check` прошёл
- **THEN** эмитится `device_enrolled` с host_id prefix8, serial, bundle_version и режимом
