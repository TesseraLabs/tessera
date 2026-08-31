---
id: certificate-scope-binding
kind: операция
context: auth
name: "Связывание области сертификата"
aliases:
  - "cert-scope-binding"
relations:
  references:
    - auth.credential
    - auth.host-identity
    - auth.role
anchors:
  code:
    - "crates/tessera_ext/src/oids.rs"
  test:
    - "tests/e2e/cases/25-trust-chain.yaml"
requirements:
  SBIND-001:
    kind: контракт
    subjects:
      - auth.certificate-scope-binding
    origins:
      - "cert-scope-binding::OID-арка (проводной контракт, НЕ менять)"
    evidence:
      test:
        - "tests/e2e/cases/25-trust-chain.yaml"
  SBIND-002:
    kind: операционное
    subjects:
      - auth.certificate-scope-binding
    origins:
      - "cert-scope-binding::Дескрипторы host_binding"
    evidence:
      code:
        - "crates/tessera_ext/src/oids.rs"
  SBIND-003:
    kind: инвариант
    subjects:
      - auth.certificate-scope-binding
    origins:
      - "cert-scope-binding::verify_host_binding — обязателен, fail-closed"
    evidence:
      test:
        - "tests/e2e/cases/25-trust-chain.yaml"
  SBIND-004:
    kind: операционное
    subjects:
      - auth.certificate-scope-binding
    origins:
      - "cert-scope-binding::max_integrity — извлечение только из верифицированного серта"
    evidence:
      code:
        - "crates/tessera_ext/src/oids.rs"
  SBIND-005:
    kind: операционное
    subjects:
      - auth.certificate-scope-binding
    origins:
      - "cert-scope-binding::Расширение pam_cert_allowed_roles"
    evidence:
      code:
        - "crates/tessera_ext/src/oids.rs"
  SBIND-006:
    kind: операционное
    subjects:
      - auth.certificate-scope-binding
    origins:
      - "cert-scope-binding::Удалённые механизмы (история)"
    evidence:
      code:
        - "crates/tessera_ext/src/oids.rs"
  SBIND-007:
    kind: операционное
    subjects:
      - auth.certificate-scope-binding
    origins:
      - "cert-scope-binding::Расширение pam_cert_profile_version"
    evidence:
      code:
        - "crates/tessera_ext/src/oids.rs"
  SBIND-008:
    kind: операционное
    subjects:
      - auth.certificate-scope-binding
    origins:
      - "cert-scope-binding::Расширение pam_cert_delegation_constraints"
    evidence:
      code:
        - "crates/tessera_ext/src/oids.rs"
---
# Связывание области сертификата

Эта страница заменяет процедурную capability-спеку OpenSpec «cert-scope-binding»: она
помещает каждое прежнее требование в адресуемую норму с владельцем, видом и
проверяемым происхождением. Под каждым нормативным предложением сохранены подробные условия, отрицательные
сценарии и rationale; они входят в ту же страницу и уточняют границы нормы.

### SBIND-001 — OID-арка (проводной контракт, НЕ менять)

[[auth.certificate-scope-binding|Связывание области сертификата]] MUST соблюдать правило «OID-арка (проводной контракт, НЕ менять)» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/cert-scope-binding/spec.md, requirement «OID-арка (проводной контракт, НЕ менять)».

OID-арка должна оставаться неизменной — это проводной контракт между выпуском сертификатов
и модулем верификации.

| Расширение | OID | Critical |
|---|---|---|
| `pam_cert_host_binding` | `2.25.183976554325829274683049824615098` | non-critical |
| `pam_cert_user_binding` | `2.25.215438916728501023845629178354627` | non-critical |
| `pam_cert_max_integrity` | `2.25.273824307386008814506455310913083078403` | non-critical |
| `pam_cert_delegation_constraints` | `2.25.<UUID>` — выделить при имплементации, зафиксировать в `oids.rs` и здесь | **critical** |
| `pam_cert_profile_version` | `2.25.<UUID>` — выделить при имплементации, зафиксировать в `oids.rs` и здесь | **critical** |

Арка `2.25.<UUID>` (RFC 4530, без PEN/IANA). Существующие OID не должны меняться.
В отличие от листовых scope-расширений (non-critical), `pam_cert_delegation_constraints` и
`pam_cert_profile_version` должны помечаться **critical**: их игнорирование = обход рамок,
что недопустимо. Известное ограничение экосистемы: Go `encoding/asn1` (Vault PKI) не парсит
OID-дуги >int64 → выпуск таких сертов должен выполняться локальным openssl CA.

#### Scenario: Vault не может выпустить серт с такой OID-аркой
- **WHEN** выпуск сертификата делается через Vault PKI `pki/issue`/`sign-verbatim`
- **THEN** Go `encoding/asn1` не парсит OID-дуги >int64 → выпуск должен выполняться локальным openssl CA

### SBIND-002 — Дескрипторы host_binding

[[auth.certificate-scope-binding|Связывание области сертификата]] MUST соблюдать правило «Дескрипторы host_binding» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/cert-scope-binding/spec.md, requirement «Дескрипторы host_binding».

Каждая строка должна классифицироваться (host_binding_ext.rs:75–91):
- `"*"` → Wildcard (любой хост);
- `"sha256:<HEX>"` → Sha256Hex — ровно 64 lowercase hex после lowercase, иначе Malformed;
- иная строка → Raw (сырой machine_id; при сверке хешируется).

Назначение трёх форм (issuance-режимы): per-host (`sha256:<hex>`), wildcard (`*`, bootstrap/тест, короткий TTL), bootstrap (`installation` raw — clone-image, см. [clone-image-bootstrap](../clone-image-bootstrap/spec.md)).

#### Scenario: Классификация дескриптора по форме строки
- **WHEN** дескриптор host_binding имеет вид `sha256:<HEX>`
- **THEN** строка классифицируется как Sha256Hex при ровно 64 lowercase hex, иначе как Malformed

### SBIND-003 — verify_host_binding — обязателен, fail-closed

[[auth.certificate-scope-binding|Связывание области сертификата]] MUST соблюдать правило «verify_host_binding — обязателен, fail-closed» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/cert-scope-binding/spec.md, requirement «verify_host_binding — обязателен, fail-closed».

Хотя бы один дескриптор должен совпасть с host_id_hash (OR-семантика, множественные записи поддерживаются): Wildcard → true; Sha256Hex → case-insensitive сравнение; Raw → `sha256_hex(raw)` сравнивается с host_id_hash. Нет совпадений / расширение отсутствует / malformed → отказ + WARN `host_binding_violation` + on-screen prefix8 (host_binding.rs:108–130).

#### Scenario: Malformed host_binding
- **WHEN** `sha256:` с пустым/неверным hex
- **THEN** reject (fail-closed, подтверждено на боевом терминале 27.05.2026: «sha256 digest must be 64 lowercase hex chars, got ""»)

### SBIND-004 — max_integrity — извлечение только из верифицированного серта

[[auth.certificate-scope-binding|Связывание области сертификата]] MUST соблюдать правило «max_integrity — извлечение только из верифицированного серта» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/cert-scope-binding/spec.md, requirement «max_integrity — извлечение только из верифицированного серта».

`extract_max_integrity` должен принимать только `VerifiedX509` (trust boundary — newtype с pub(crate) конструктором). Ошибка парсинга должна эмитить audit `cert_ext_parse_failed` и трактовать метку как отсутствующую (fail-open для метки — она опциональна) (max_integrity_ext.rs:30–44, flow.rs:678–689).

#### Scenario: Ошибка парсинга метки max_integrity
- **WHEN** расширение max_integrity присутствует, но парсинг падает
- **THEN** эмитится audit `cert_ext_parse_failed`, метка трактуется как отсутствующая (fail-open, метка опциональна)

### SBIND-005 — Расширение pam_cert_allowed_roles

[[auth.certificate-scope-binding|Связывание области сертификата]] MUST соблюдать правило «Расширение pam_cert_allowed_roles» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/cert-scope-binding/spec.md, requirement «Расширение pam_cert_allowed_roles».

Расширение должно извлекаться только из верифицированного сертификата
(`VerifiedX509`, trust boundary как у max_integrity). Семантика —
авторизационная и ЕДИНСТВЕННАЯ: запрошенная роль входит в список → допуск
подтверждён.

В модели «роль = ролевая учётная запись» этот список отвечает сразу на оба
вопроса — «в какую учётную запись пущен предъявитель» и «какую роль он вправе
активировать», — потому что это одна и та же строка. Отдельного списка учётных
записей (`pam_cert_user_binding`) в профиле листа больше не должно
быть: два списка над одной строкой описывали бы нереализуемое состояние «пущен
в `serv`, но не вправе быть `serv`».

В отличие от max_integrity (опциональная метка, fail-open), allowed_roles —
основание доступа, поэтому ошибка парсинга должна трактоваться
fail-closed: audit `cert_allowed_roles_parse_failed`, список считается пустым →
запрошенная роль не покрыта → отказ. Отсутствие расширения означает, что
удостоверение не даёт ни одной роли, а поскольку роль требуется при каждом
входе — отказ.

#### Scenario: Malformed расширение allowed_roles
- **WHEN** расширение присутствует, но DER некорректен
- **THEN** audit `cert_allowed_roles_parse_failed`, список = пустой, запрошенная роль не покрыта, отказ (fail-closed)

#### Scenario: Удостоверение без allowed_roles
- **WHEN** в удостоверении нет расширения allowed_roles
- **THEN** отказ входа с диагностикой; audit deny — роль требуется всегда, а покрыть её нечем

#### Scenario: Невалидный role_id внутри списка
- **WHEN** одна из строк списка не матчит `^[a-z][a-z0-9-]{0,15}$`
- **THEN** расширение трактуется как malformed (fail-closed целиком, не пропуск одной строки)

#### Scenario: Вход в ролевую учётную запись
- **WHEN** лист несёт `allowed_roles = [oper, serv]` и инженер входит `ssh oper@device`
- **THEN** допуск пройден; вход `admin@device` тем же листом отклоняется — роль `admin` не покрыта

### SBIND-006 — Удалённые механизмы (история)

[[auth.certificate-scope-binding|Связывание области сертификата]] MUST соблюдать правило «Удалённые механизмы (история)» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/cert-scope-binding/spec.md, requirement «Удалённые механизмы (история)».

Текущая реализация не должна содержать удалённые в 0.3.0 механизмы: scopes-расширение, M-of-N/CMS work-order (`execute`), policy.toml engine, approver/TSA trust (`SCOPES_OID`, `APPROVER_EKU_OID`, крейт `pam_certauth_policy`). Реализация 0.2.x существовала и прошла red-team (25 атак / 1 документированный bypass), вырезана решением пользователя 18.05.2026. Спеки 0.2.x — историческое référence, НЕ текущая реализация. Остатки — осиротевший worktree `CertAuth-scopes-mofn/` (кандидат на удаление).

#### Scenario: Ссылка на спеку 0.2.x
- **WHEN** контрибьютор обращается к спекам scopes/M-of-N из 0.2.x
- **THEN** они трактуются как историческое reference, а не как текущая реализация (механизмы удалены в 0.3.0)

### SBIND-007 — Расширение pam_cert_profile_version

[[auth.certificate-scope-binding|Связывание области сертификата]] MUST соблюдать правило «Расширение pam_cert_profile_version» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/cert-scope-binding/spec.md, requirement «Расширение pam_cert_profile_version».

Расширение `pam_cert_profile_version` должно кодироваться как DER INTEGER и извлекаться
только из верифицированного сертификата (`VerifiedX509`, trust boundary как у max_integrity).
Ошибка парсинга должна трактоваться fail-closed: серт отвергается. Семантика version-gate
(сравнение с `max_supported`) определяется в `trust-chain-validation`; здесь — формат и извлечение.

#### Scenario: Malformed profile_version
- **WHEN** расширение присутствует, но DER не является корректным INTEGER
- **THEN** серт отвергается (fail-closed)

### SBIND-008 — Расширение pam_cert_delegation_constraints

[[auth.certificate-scope-binding|Связывание области сертификата]] MUST соблюдать правило «Расширение pam_cert_delegation_constraints» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/cert-scope-binding/spec.md, requirement «Расширение pam_cert_delegation_constraints».

Расширение `pam_cert_delegation_constraints` должно кодироваться как
`SEQUENCE { requireTags SEQUENCE OF SEQUENCE{key UTF8String, value UTF8String}, allowRoles SEQUENCE OF UTF8String, maxLevel INTEGER, maxTtl INTEGER }`
и извлекаться только из `VerifiedX509`. Ошибка парсинга должна трактоваться fail-closed
(серт отвергается). Расширение должно присутствовать только на серте с
basicConstraints `CA=TRUE`; присутствие на листе (`CA=FALSE`) должно трактоваться как
malformed → reject. Каждая строка `allowRoles` должна быть валидным `role_id`
(`^[a-z][a-z0-9-]{0,15}$`), иначе malformed.

#### Scenario: delegation_constraints на листе
- **WHEN** расширение присутствует на серте с `CA=FALSE`
- **THEN** серт отвергается как malformed (fail-closed)

#### Scenario: Malformed delegation_constraints
- **WHEN** расширение присутствует на CA-серте, но DER некорректен или `role_id` не валиден
- **THEN** серт отвергается (fail-closed)

