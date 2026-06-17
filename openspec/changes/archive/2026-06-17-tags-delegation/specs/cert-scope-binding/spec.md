# cert-scope-binding Delta Specification

## MODIFIED Requirements

### Requirement: OID-арка (проводной контракт, НЕ менять)

OID-арка ДОЛЖНА (MUST) оставаться неизменной — это проводной контракт между выпуском сертификатов
и модулем верификации.

| Расширение | OID | Critical |
|---|---|---|
| `pam_cert_host_binding` | `2.25.183976554325829274683049824615098` | non-critical |
| `pam_cert_user_binding` | `2.25.215438916728501023845629178354627` | non-critical |
| `pam_cert_max_integrity` | `2.25.273824307386008814506455310913083078403` | non-critical |
| `pam_cert_delegation_constraints` | `2.25.<UUID>` — выделить при имплементации, зафиксировать в `oids.rs` и здесь | **critical** |
| `pam_cert_profile_version` | `2.25.<UUID>` — выделить при имплементации, зафиксировать в `oids.rs` и здесь | **critical** |

Арка `2.25.<UUID>` (RFC 4530, без PEN/IANA). Существующие OID НЕ ДОЛЖНЫ (MUST NOT) меняться.
В отличие от листовых scope-расширений (non-critical), `pam_cert_delegation_constraints` и
`pam_cert_profile_version` ДОЛЖНЫ (MUST) помечаться **critical**: их игнорирование = обход рамок,
что недопустимо. Известное ограничение экосистемы: Go `encoding/asn1` (Vault PKI) не парсит
OID-дуги >int64 → выпуск таких сертов ДОЛЖЕН (MUST) выполняться локальным openssl CA.

#### Scenario: Vault не может выпустить серт с такой OID-аркой
- **WHEN** выпуск сертификата делается через Vault PKI `pki/issue`/`sign-verbatim`
- **THEN** Go `encoding/asn1` не парсит OID-дуги >int64 → выпуск ДОЛЖЕН (MUST) выполняться локальным openssl CA

## ADDED Requirements

### Requirement: Расширение pam_cert_profile_version

Расширение `pam_cert_profile_version` ДОЛЖНО (MUST) кодироваться как DER INTEGER и извлекаться
только из верифицированного сертификата (`VerifiedX509`, trust boundary как у max_integrity).
Ошибка парсинга ДОЛЖНА (MUST) трактоваться fail-closed: серт отвергается. Семантика version-gate
(сравнение с `max_supported`) определяется в `trust-chain-validation`; здесь — формат и извлечение.

#### Scenario: Malformed profile_version
- **WHEN** расширение присутствует, но DER не является корректным INTEGER
- **THEN** серт отвергается (fail-closed)

### Requirement: Расширение pam_cert_delegation_constraints

Расширение `pam_cert_delegation_constraints` ДОЛЖНО (MUST) кодироваться как
`SEQUENCE { requireTags SEQUENCE OF SEQUENCE{key UTF8String, value UTF8String}, allowRoles SEQUENCE OF UTF8String, maxLevel INTEGER, maxTtl INTEGER }`
и извлекаться только из `VerifiedX509`. Ошибка парсинга ДОЛЖНА (MUST) трактоваться fail-closed
(серт отвергается). Расширение ДОЛЖНО (MUST) присутствовать только на серте с
basicConstraints `CA=TRUE`; присутствие на листе (`CA=FALSE`) ДОЛЖНО (MUST) трактоваться как
malformed → reject. Каждая строка `allowRoles` ДОЛЖНА (MUST) быть валидным `role_id`
(`^[a-z][a-z0-9-]{0,15}$`), иначе malformed.

#### Scenario: delegation_constraints на листе
- **WHEN** расширение присутствует на серте с `CA=FALSE`
- **THEN** серт отвергается как malformed (fail-closed)

#### Scenario: Malformed delegation_constraints
- **WHEN** расширение присутствует на CA-серте, но DER некорректен или `role_id` не валиден
- **THEN** серт отвергается (fail-closed)
