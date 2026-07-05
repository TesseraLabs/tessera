# logging-audit Specification (delta)

## ADDED Requirements

### Requirement: События онлайн-завершения попытки

Система ДОЛЖНА (MUST) эмитить в hash-chain журнал события жизненного цикла онлайн-завершения:
`attempt_registered` (попытка зарегистрирована у агента), `grant_received{outcome}` (грант
верифицирован и потребил nonce), `grant_discarded{reason}` (невалидный MAC | nonce потреблён |
TTL | чужой attempt), и способ завершения попытки (`completion=online|manual`) в существующем
событии `qr_code_login`. События НЕ ДОЛЖНЫ (MUST NOT) раскрывать sensitive (полный MAC,
per-device ключ); корреляция — по `nonce_ref`/`attempt_id` (сквозная с серверной сессией Codes).

#### Scenario: Вход завершён грантом
- **WHEN** грант прошёл верификацию и сессия открыта
- **THEN** `grant_received{attempt_id, nonce_ref, role_id, level}` + `qr_code_login{..., completion=online}` в журнале

#### Scenario: Поздний грант отброшен
- **WHEN** грант пришёл после потребления nonce или TTL попытки
- **THEN** `grant_discarded{attempt_id, reason}` в журнале; терминальное состояние попытки не изменено
