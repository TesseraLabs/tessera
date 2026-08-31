---
id: credential
kind: сущность
context: auth
name: Удостоверение
aliases:
  - удостоверение
  - leaf-сертификат
  - пользовательский сертификат
forbidden:
  - сертификат
migrated_from: openspec/specs/cert-scope-binding/spec.md
relations:
  references:
    - auth.ADR-002
    - auth.credential
    - auth.device-config
    - auth.pkcs12-login
    - auth.role
anchors:
  type:
    - crates/tessera_core/src/x509/mod.rs#Certificate
  code:
    - crates/tessera_core/src/x509/signatures.rs#verify_chain_signatures
  test:
    - tests/e2e/cases/25-trust-chain.yaml
applies:
  - pattern: fail-closed
    bindings:
      неопределимость: auth.ADR-002
requirements:
  SCOPE-001:
    kind: инвариант
    subjects:
      - auth.credential
      - auth.role
      - auth.device-config
    evidence:
      test:
        - tests/e2e/cases/30-roles.yaml
      code:
        - crates/pam_tessera/src/flow.rs#authenticate_pkcs12
    outcomes:
      - роль покрыта
      - роль не покрыта
      - расширение отсутствует
      - расширение не разобрано
  SCOPE-002:
    kind: инвариант
    subjects:
      - auth.credential
      - auth.pkcs12-login
    evidence:
      test:
        - tests/e2e/cases/30-roles.yaml
      code:
        - crates/pam_tessera/src/flow.rs#FlowError
  SCOPE-003:
    kind: инвариант
    subjects:
      - auth.credential
      - auth.pkcs12-login
    evidence:
      test:
        - tests/e2e/cases/19-host-identity.yaml
      code:
        - crates/pam_tessera/src/flow.rs#authenticate_pkcs12
conformance:
  fail-closed/FC-001:
    test:
      - tests/e2e/cases/30-roles.yaml
  fail-closed/FC-002:
    test:
      - tests/e2e/cases/22-logging-audit.yaml
  fail-closed/FC-003:
    code:
      - crates/tessera_core/src/config/validated.rs#Validated
---

# Удостоверение

## Purpose

X.509-удостоверение предъявителя, находящееся на носителе — в PKCS#12-конверте
на USB или на PKCS#11-токене. Несёт не только идентичность, но и **рамки**:
к какому устройству привязано и какие роли допускает. Рамки задаёт выпускающая
сторона; предъявитель их изменить не может.

## Requirements

### SCOPE-001 — Допуск к учётной записи следует только из удостоверения

[[auth.credential|Удостоверение]] MUST нести расширение
`pam_cert_allowed_roles`. Допуск к [[auth.role|роли]] MUST решаться
исключительно вхождением роли в этот список.

[[auth.device-config|Конфигурация устройства]] MUST NOT содержать механизма,
разрешающего вход по иным признакам удостоверения — CN, SAN или любым другим,
которые выпускающая сторона не предназначала для допуска.

Рамки несёт удостоверение. Путь, где их назначает ограничиваемая сторона,
подрывает саму модель.

#### Scenario: Роль вне списка
- **WHEN** запрошена роль `admin`, а `allowed_roles` содержит только `oper` и `serv`
- **THEN** исход `роль не покрыта`, в аудит пишется отказ

#### Scenario: Роль в списке удостоверения
- **WHEN** запрошенная роль входит в `pam_cert_allowed_roles`
- **THEN** исход `роль покрыта`, допуск разрешён

#### Scenario: Расширение отсутствует
- **WHEN** удостоверение не несёт `pam_cert_allowed_roles`
- **THEN** исход `расширение отсутствует`; отката к конфигурации устройства не существует

#### Scenario: Расширение не разбирается
- **WHEN** расширение присутствует, но его DER не разбирается
- **THEN** исход `расширение не разобрано`, вход отклоняется

### SCOPE-002 — Некорректное расширение равно пустому списку

[[auth.credential|Удостоверение]] с присутствующим, но некорректным по DER
расширением `pam_cert_allowed_roles` MUST отклоняться. [[auth.pkcs12-login|Вход]] MUST NOT игнорировать
некорректное расширение.

Игнорирование сломанного расширения означало бы, что порча байтов снимает
ограничение, — то есть ослабление достигается повреждением.

#### Scenario: Битый DER в расширении
- **WHEN** расширение присутствует, но DER не разбирается
- **THEN** список считается пустым, вход отклоняется

### SCOPE-003 — Привязка к устройству обязательна

[[auth.credential|Удостоверение]] MUST нести расширение
`pam_cert_host_binding`, совпадающее с [[auth.host-identity|идентичностью
устройства]]. [[auth.pkcs12-login|Вход]] MUST отклоняться при несовпадении.

#### Scenario: Удостоверение с другого устройства
- **WHEN** ни один дескриптор `pam_cert_host_binding` не совпал с идентичностью устройства
- **THEN** вход отклоняется, предъявителю показывается диагностика о чужом устройстве
