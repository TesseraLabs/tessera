# device-unenroll Delta Specification

## ADDED Requirements

### Requirement: Команда un-enroll (reverse-flip)

Команда `tessera un-enroll` (offline, root) ДОЛЖНА (MUST) выполнять зеркало `finish-bootstrap`:
(1) вытереть enrollment-состояние — per-host `.p12`/ключи, файл/manifest тегов, managed-набор
ролей, персист `bundle_version`, локальный CRL-кэш; (2) atomic rewrite конфига — продакшн-источники
→ `sources=["override"], override="installation"` (с backup, как finish-bootstrap); (3) выполнить
`tessera check`; провал → rollback из backup и exit ≠ 0 (fail-closed). Локальный hash-chain журнал
НЕ ДОЛЖЕН (MUST NOT) вытираться (forensics). После успеха устройство ДОЛЖНО (MUST) быть
bootstrap-ready: следующий старт совпадает с bootstrap-сертом.

#### Scenario: Успешный un-enroll
- **WHEN** на рабочем устройстве выполнена `tessera un-enroll`
- **THEN** enrollment-состояние вытерто, конфиг переключён в `override=installation`, `tessera check` прошёл, устройство bootstrap-ready

#### Scenario: Провал check после reverse-flip
- **WHEN** после reverse-flip `tessera check` падает
- **THEN** выполняется rollback из backup, exit ≠ 0 (fail-closed)

#### Scenario: Повторный un-enroll
- **WHEN** `un-enroll` запущена на уже bootstrap-ready устройстве
- **THEN** операция — no-op (идемпотентность)

### Requirement: Семантика RMA и кражи

RMA и кража НЕ ДОЛЖНЫ (MUST NOT) требовать новой device-side логики. При RMA замена железа меняет
`host_id` (источники `host-identity`) → старый per-host серт перестаёт совпадать (авто-инвалидация);
старый серт отзывается на сервере (CRL) для гигиены. При краже device-side опирается на серверный
отзыв (CRL, «отзыв вечен») и карантин (`revocation-design`); недоступное устройство покрывается
backstop'ом — короткий TTL серта.

#### Scenario: RMA — замена железа
- **WHEN** диск/конфиг переносится на новое железо с иными DMI/machine-id
- **THEN** `host_id` меняется, старый per-host серт не совпадает (авто-инвалидация), требуется новый enrollment

#### Scenario: Кража устройства
- **WHEN** устройство похищено
- **THEN** доступ отнимается серверным отзывом серта (CRL) + карантином; недоступное устройство протухает по короткому TTL серта (backstop)
