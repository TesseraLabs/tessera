# cert-scope-binding Delta Specification

## MODIFIED Requirements

### Requirement: OID-арка (проводной контракт, НЕ менять)

OID-арка ДОЛЖНА (MUST) оставаться неизменной — это проводной контракт между выпуском сертификатов и модулем верификации.

| Расширение | OID |
|---|---|
| `pam_cert_host_binding` | `2.25.183976554325829274683049824615098` |
| `pam_cert_user_binding` | `2.25.215438916728501023845629178354627` |
| `pam_cert_max_integrity` | `2.25.273824307386008814506455310913083078403` |
| `pam_cert_allowed_roles` | `2.25.<UUID>` — выделить при имплементации, зафиксировать в `oids.rs` и здесь |

Арка `2.25.<UUID>` (RFC 4530, без PEN/IANA). Все расширения non-critical. host/user binding: `SEQUENCE OF UTF8String`; max_integrity: `SEQUENCE { level INTEGER(-128..127), categories BIT STRING DEFAULT ''B }`; allowed_roles: `SEQUENCE OF UTF8String` (каждая строка — `role_id`, `^[a-z][a-z0-9-]{0,15}$`). Существующие OID НЕ ДОЛЖНЫ (MUST NOT) меняться; добавление `pam_cert_allowed_roles` — единственное расширение таблицы в этом change.

Известное ограничение экосистемы: Go `encoding/asn1` (Vault PKI) не парсит OID-дуги >int64 → Vault не может выпускать такие серты через `pki/issue`/`sign-verbatim`; выпуск — локальным openssl CA (решение May 2026).

#### Scenario: Vault не может выпустить серт с такой OID-аркой
- **WHEN** выпуск сертификата делается через Vault PKI `pki/issue`/`sign-verbatim`
- **THEN** Go `encoding/asn1` не парсит OID-дуги >int64 → выпуск ДОЛЖЕН (MUST) выполняться локальным openssl CA

## ADDED Requirements

### Requirement: Расширение pam_cert_allowed_roles

Расширение ДОЛЖНО (MUST) извлекаться только из верифицированного сертификата (`VerifiedX509`,
trust boundary как у max_integrity). Семантика — авторизационная: запрошенная роль входит
в список → покрытие подтверждено. В отличие от max_integrity (опциональная метка, fail-open),
allowed_roles при включённом enforcement ролей — основание доступа, поэтому ошибка парсинга
ДОЛЖНА (MUST) трактоваться fail-closed: audit `cert_allowed_roles_parse_failed`, список
считается пустым → запрошенная роль не покрыта → отказ. Отсутствие расширения = серт не
даёт ролей (при `roles.enforce = require` — отказ входа по серту; при `warn` — лог и пропуск
проверки, миграционный режим).

#### Scenario: Malformed расширение allowed_roles
- **WHEN** расширение присутствует, но DER некорректен
- **THEN** audit `cert_allowed_roles_parse_failed`, список = пустой, запрошенная роль не покрыта, отказ (fail-closed)

#### Scenario: Серт без allowed_roles при enforce=require
- **WHEN** `roles.enforce = require`, в серте нет расширения allowed_roles
- **THEN** отказ входа по серту с диагностикой; audit deny

#### Scenario: Невалидный role_id внутри списка
- **WHEN** одна из строк списка не матчит `^[a-z][a-z0-9-]{0,15}$`
- **THEN** расширение трактуется как malformed (fail-closed целиком, не пропуск одной строки)
