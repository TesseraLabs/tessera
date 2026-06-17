# cert-scope-binding Specification

## Purpose

Авторизация через custom X.509 v3 расширения в leaf-сертификате: привязка к машине (host_binding), к PAM-пользователю (user_binding), потолок МКЦ (max_integrity). «Серт — единственный носитель возможностей»: украденный носитель на чужой машине бесполезен.

Код: `crates/tessera_core/src/x509/{oids,host_binding_ext,user_binding_ext,max_integrity_ext,der_helpers}.rs`, `host_binding.rs`.
## Requirements
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

### Requirement: Дескрипторы host_binding

Каждая строка ДОЛЖНА (MUST) классифицироваться (host_binding_ext.rs:75–91):
- `"*"` → Wildcard (любой хост);
- `"sha256:<HEX>"` → Sha256Hex — ровно 64 lowercase hex после lowercase, иначе Malformed;
- иная строка → Raw (сырой machine_id; при сверке хешируется).

Назначение трёх форм (issuance-режимы): per-host (`sha256:<hex>`), wildcard (`*`, bootstrap/тест, короткий TTL), bootstrap (`installation` raw — clone-image, см. [clone-image-bootstrap](../clone-image-bootstrap/spec.md)).

#### Scenario: Классификация дескриптора по форме строки
- **WHEN** дескриптор host_binding имеет вид `sha256:<HEX>`
- **THEN** строка классифицируется как Sha256Hex при ровно 64 lowercase hex, иначе как Malformed

### Requirement: verify_host_binding — обязателен, fail-closed

Хотя бы один дескриптор ДОЛЖЕН (MUST) совпасть с host_id_hash (OR-семантика, множественные записи поддерживаются): Wildcard → true; Sha256Hex → case-insensitive сравнение; Raw → `sha256_hex(raw)` сравнивается с host_id_hash. Нет совпадений / расширение отсутствует / malformed → отказ + WARN `host_binding_violation` + on-screen prefix8 (host_binding.rs:108–130).

#### Scenario: Malformed host_binding
- **WHEN** `sha256:` с пустым/неверным hex
- **THEN** reject (fail-closed, подтверждено на боевом терминале 27.05.2026: «sha256 digest must be 64 lowercase hex chars, got ""»)

### Requirement: verify_user_binding

Проверка user_binding ДОЛЖНА (MUST) работать так: Wildcard → любой пользователь; Exact → БАЙТОВОЕ case-SENSITIVE сравнение с pam_user (Linux usernames регистрозависимы). Нет совпадений → `UserNotAllowed` + WARN (host_binding.rs:140–160).

- Вызов в проде: `authorize_user` (flow.rs, Step 10) — cert-путь приоритетен; в legacy `[[user_mapping]]` уходят только сертификаты БЕЗ расширения user_binding, присутствующее-но-malformed расширение даёт отказ (fail-closed). Нормативное описание — см. [cert-authentication-flow](../cert-authentication-flow/spec.md).

#### Scenario: Несовпадение pam_user с Exact-дескриптором
- **WHEN** user_binding содержит Exact-дескриптор, не равный байтово текущему pam_user
- **THEN** возвращается `UserNotAllowed` + WARN

### Requirement: max_integrity — извлечение только из верифицированного серта

`extract_max_integrity` ДОЛЖЕН (MUST) принимать только `VerifiedX509` (trust boundary — newtype с pub(crate) конструктором). Ошибка парсинга ДОЛЖНА (MUST) эмитить audit `cert_ext_parse_failed` и трактовать метку как отсутствующую (fail-open для метки — она опциональна) (max_integrity_ext.rs:30–44, flow.rs:678–689).

#### Scenario: Ошибка парсинга метки max_integrity
- **WHEN** расширение max_integrity присутствует, но парсинг падает
- **THEN** эмитится audit `cert_ext_parse_failed`, метка трактуется как отсутствующая (fail-open, метка опциональна)

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

### Requirement: Удалённые механизмы (история)

Текущая реализация НЕ ДОЛЖНА (MUST NOT) содержать удалённые в 0.3.0 механизмы: scopes-расширение, M-of-N/CMS work-order (`execute`), policy.toml engine, approver/TSA trust (`SCOPES_OID`, `APPROVER_EKU_OID`, крейт `pam_certauth_policy`). Реализация 0.2.x существовала и прошла red-team (25 атак / 1 документированный bypass), вырезана решением пользователя 18.05.2026. Спеки 0.2.x — историческое référence, НЕ текущая реализация. Остатки — осиротевший worktree `CertAuth-scopes-mofn/` (кандидат на удаление).

#### Scenario: Ссылка на спеку 0.2.x
- **WHEN** контрибьютор обращается к спекам scopes/M-of-N из 0.2.x
- **THEN** они трактуются как историческое reference, а не как текущая реализация (механизмы удалены в 0.3.0)

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

