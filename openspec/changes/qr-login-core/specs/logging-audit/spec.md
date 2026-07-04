# logging-audit Specification (delta)

## MODIFIED Requirements

### Requirement: Событие входа по QR-коду

Система ДОЛЖНА (MUST) при успешном входе по QR-коду эмитить событие `qr_code_login` в
hash-chain журнал: корреляция `nonce`↔локальная сессия, `role_id`, `level`, исход. Событие
ДОЛЖНО (MUST) писаться так, чтобы обеспечить сквозную корреляцию с серверной сессией Codes
(по `nonce`), но НЕ раскрывать sensitive (полный код, per-device ключ).

#### Scenario: Успешный вход по коду
- **WHEN** код прошёл локальную проверку MAC и сессия открыта
- **THEN** `qr_code_login{nonce_ref, role_id, level, outcome=success}` в журнал перед стартом сессии

#### Scenario: Отказ по коду
- **WHEN** код не прошёл (неверный MAC / истёк / rate-limit / битый уровень)
- **THEN** `qr_code_login{nonce_ref, outcome=<причина>}` в журнал (fail-closed зафиксирован)
