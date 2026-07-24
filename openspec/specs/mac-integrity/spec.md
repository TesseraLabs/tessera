# mac-integrity Specification (открытая часть: SPI)

## Purpose

Интеграция МКЦ (мандатный контроль целостности, Biba) Astra SE: сертификат несёт ПОТОЛОК целостности сессии, эффективная метка = `min(cert, МНКЦ_пользователя)` покомпонентно. Открытое ядро содержит SPI-контракт, политику (orchestrator), label-алгебру и StubBackend; **реальный enforcement (ParsecBackend, libpdp FFI) — закрытый компонент** коммерческой поставки (`tessera-enterprise`). Полная спецификация МКЦ-интеграции живёт там; этот документ — производная открытая часть.

Код (открытый): `crates/tessera_core/src/mac/` (orchestrator, label, audit, backend=trait+stub), `pam_tessera/src/session.rs`.

## Requirements

### Requirement: SPI MacBackend

Trait `MacBackend`, `StubBackend` и мост C-vtable ДОЛЖНЫ (MUST) оставаться в открытом
ядре. Реальный enforcement подключается подписанным runtime-плагином; один и тот же
открытый бинарь работает со StubBackend без плагина и с PluginBackend при явном выборе.

#### Scenario: Открытая сборка
- **WHEN** собран и запущен публичный host без выбранного валидного плагина
- **THEN** активен StubBackend; закрытый МКЦ-enforcement в Cargo-графе отсутствует

### Requirement: Поведение открытой сборки при required-политиках

Конфиг с `[mac].cert_integrity=required` или `[mac].runtime=required` ДОЛЖЕН (MUST)
явно называть `[mac].backend`. Названный, но отсутствующий/невалидный плагин ДОЛЖЕН
(MUST) давать runtime fail-closed и audit, а не ошибку Cargo-сборки.

#### Scenario: required в открытой сборке
- **WHEN** конфиг с required-политикой не называет backend
- **THEN** конфиг отвергается с ошибкой валидации

### Requirement: Политика применения (orchestrator) — открыта для аудита

Orchestrator (матрица ignore/optional/required, эффективная метка, audit-события `mac_*`/`integrity_*`), label-кодек (`SEQUENCE{INTEGER i8, BIT STRING}`) и конфиг-схема `[mac]` ДОЛЖНЫ (MUST) оставаться в открытом ядре — политика проверяема и аудируема независимо от закрытого FFI-слоя (orchestrator.rs, label.rs, audit.rs).

С введением ролей источник **запрошенной** метки сессии — `payload.mac_mask` выбранной роли.
Эффективная метка = пересечение `mac_mask` роли с потолком серта (`pam_cert_max_integrity`)
и МНКЦ пользователя. Если `mac_mask` роли НЕ покрывается потолком (`(потолок & mac_mask) != mac_mask`),
вход ДОЛЖЕН (MUST) быть отклонён с audit-событием — НЕ молчаливое сужение метки: роль обязана
давать ровно то, что заявляет. До введения ролей (роль без `mac_mask` или `roles.enforce != require`)
действует прежняя семантика `min(потолок серта, МНКЦ)`.

#### Scenario: Аудит политики третьей стороной
- **WHEN** безопасник заказчика исследует открытый код
- **THEN** вся логика принятия решения МКЦ (политика, алгебра меток, события) доступна; закрыт только механизм применения метки к ядру ОС

#### Scenario: mac_mask роли не покрыт потолком серта
- **WHEN** роль требует `mac_mask = 0b110`, а потолок серта = `0b100`
- **THEN** отказ входа с audit-событием (не молчаливое сужение до `0b100`)

#### Scenario: Роль без mac_mask
- **WHEN** выбрана роль без секции `mac_mask` (только группы/sudo)
- **THEN** МКЦ-метка сессии определяется прежней семантикой `min(потолок серта, МНКЦ пользователя)`

### Requirement: Расширение pam_cert_max_integrity

Расширение ДОЛЖНО (MUST) иметь OID `2.25.273824307386008814506455310913083078403`, DER `SEQUENCE { level INTEGER(-128..127), categories BIT STRING DEFAULT ''B }`, non-critical. Извлечение ДОЛЖНО (MUST) выполняться только из верифицированного сертификата (`VerifiedX509`); ошибка парсинга — audit `cert_max_integrity_parse_failed`, метка трактуется как отсутствующая (x509/max_integrity_ext.rs).

#### Scenario: Malformed расширение
- **WHEN** расширение присутствует, но DER некорректен
- **THEN** эмитится audit-событие, метка = None, аутентификация не блокируется этим полем
