# mac-integrity Specification (открытая часть: SPI)

## Purpose

Интеграция МКЦ (мандатный контроль целостности, Biba) Astra SE: сертификат несёт ПОТОЛОК целостности сессии, эффективная метка = `min(cert, МНКЦ_пользователя)` покомпонентно. Открытое ядро содержит SPI-контракт, политику (orchestrator), label-алгебру и StubBackend; **реальный enforcement (ParsecBackend, libpdp FFI) — закрытый компонент** коммерческой поставки (`tessera-enterprise`). Полная спецификация МКЦ-интеграции живёт там; этот документ — производная открытая часть.

Код (открытый): `crates/tessera_core/src/mac/` (orchestrator, label, audit, backend=trait+stub), `pam_tessera/src/session.rs`.

## Requirements

### Requirement: SPI MacBackend

Trait `MacBackend` (probe / apply_session / get_user_mnkc) и `StubBackend` ДОЛЖНЫ (MUST) оставаться в открытом ядре как стабильный публичный контракт. Реализация enforcement подключается статической линковкой в коммерческой сборке; открытая сборка ДОЛЖНА (MUST) работать только со StubBackend.

#### Scenario: Открытая сборка
- **WHEN** собран публичный репозиторий
- **THEN** backend всегда StubBackend; реальный МКЦ-enforcement недоступен

### Requirement: Поведение открытой сборки при required-политиках

Открытая сборка ДОЛЖНА (MUST) отвергать на валидации конфига `[mac].cert_integrity=required` и `[mac].runtime=required` — открытая сборка не может молча имитировать enforcement (fail-fast вместо ложного чувства безопасности).

#### Scenario: required в открытой сборке
- **WHEN** конфиг с `cert_integrity=required` загружается открытой сборкой
- **THEN** конфиг отвергается с ошибкой валидации

### Requirement: Политика применения (orchestrator) — открыта для аудита

Orchestrator (матрица ignore/optional/required, эффективная метка = min/intersect, audit-события `mac_*`/`integrity_*`), label-кодек (`SEQUENCE{INTEGER i8, BIT STRING}`) и конфиг-схема `[mac]` ДОЛЖНЫ (MUST) оставаться в открытом ядре — политика проверяема и аудируема независимо от закрытого FFI-слоя (orchestrator.rs, label.rs, audit.rs).

#### Scenario: Аудит политики третьей стороной
- **WHEN** безопасник заказчика исследует открытый код
- **THEN** вся логика принятия решения МКЦ (политика, алгебра меток, события) доступна; закрыт только механизм применения метки к ядру ОС

### Requirement: Расширение pam_cert_max_integrity

Расширение ДОЛЖНО (MUST) иметь OID `2.25.273824307386008814506455310913083078403`, DER `SEQUENCE { level INTEGER(-128..127), categories BIT STRING DEFAULT ''B }`, non-critical. Извлечение ДОЛЖНО (MUST) выполняться только из верифицированного сертификата (`VerifiedX509`); ошибка парсинга — audit `cert_max_integrity_parse_failed`, метка трактуется как отсутствующая (x509/max_integrity_ext.rs).

#### Scenario: Malformed расширение
- **WHEN** расширение присутствует, но DER некорректен
- **THEN** эмитится audit-событие, метка = None, аутентификация не блокируется этим полем
