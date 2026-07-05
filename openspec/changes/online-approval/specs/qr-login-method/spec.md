# qr-login-method Specification (delta)

Capability вводится pending change `qr-login-core`; данный delta аддитивен и применяется
поверх (порядок архивации: `qr-login-core` → `online-approval`).

## ADDED Requirements

### Requirement: Попытка допускает два завершения

Попытка code-метода ДОЛЖНА (MUST) допускать два конкурирующих завершения на одном nonce:
ручной ввод кода (`truncate_N(MAC)`) и сетевой грант (полный MAC, capability
`online-approval`). Наличие или отсутствие сетевого завершения НЕ ДОЛЖНО (MUST NOT) менять
семантику офлайн-завершения: генерацию challenge, рендер QR, rate-limit, TTL и fail-closed
поведение.

#### Scenario: Устройство без связности
- **WHEN** sync-агент отсутствует или офлайн
- **THEN** попытка ведёт себя идентично `qr-login-core` без данного change

#### Scenario: Обрыв сети посреди ожидания
- **WHEN** онлайн-регистрация попытки оборвалась после показа QR
- **THEN** телефон показывает короткий код (серверный fallback), ручной ввод завершает попытку на том же nonce

### Requirement: Consumed-state покрывает гонку завершений

Consumed-state nonce ДОЛЖЕН (MUST) фиксировать способ потребления (ручной код | грант) и
отвергать второе завершение независимо от порядка прихода, включая границу reboot
(офлайн-персист).

#### Scenario: Грант после reboot на потреблённом nonce
- **WHEN** nonce потреблён, устройство перезагружено, агент доставил поздний `GRANT`
- **THEN** отказ (fail-closed) — consumed-state персистентен, способ потребления в аудите
