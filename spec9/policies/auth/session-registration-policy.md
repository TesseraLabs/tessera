---
id: session-registration-policy
kind: политика
context: auth
name: Регистрация контролируемой сессии
relations:
  reacts_to:
    - auth.authentication-proven
  issues:
    - runtime.open-monitored-session
  references:
    - auth.device-config
applies:
  - pattern: fail-closed
anchors:
  code:
    - crates/pam_tessera/src/flow.rs#register_session_or_deny
  test:
    - crates/pam_tessera/src/flow.rs#pkcs12_strict_monitor_failure_denies_auth
requirements:
  AUTH-005:
    kind: инвариант
    subjects:
      - auth.session-registration-policy
    evidence:
      test:
        - crates/pam_tessera/src/flow.rs#pkcs12_strict_monitor_failure_denies_auth
  AUTH-006:
    kind: инвариант
    subjects:
      - auth.session-registration-policy
    evidence:
      test:
        - crates/pam_tessera/src/flow.rs#pkcs12_permissive_monitor_failure_succeeds
conformance:
  fail-closed/FC-001:
    test:
      - crates/pam_tessera/src/flow.rs#pkcs12_strict_monitor_failure_denies_auth
  fail-closed/FC-002:
    code:
      - crates/pam_tessera/src/flow.rs#register_session_or_deny
  fail-closed/FC-003:
    code:
      - crates/tessera_core/src/ipc/failmode.rs#FailModeWrapper
---

# Регистрация контролируемой сессии

## Purpose

Связывает [[auth.authentication-proven|доказанное право входа]] с командой
[[runtime.open-monitored-session|открытия контролируемой сессии]]. Политика
нужна потому, что криптографический вердикт и возможность дальнейшего контроля
присутствия — разные факты с настраиваемой связью между ними.

## Requirements

### AUTH-005 — Strict mode требует зарегистрированной сессии

[[auth.session-registration-policy|Политика регистрации]] в `strict` mode MUST
отклонять вход, если monitord не подтвердил открытие сессии.

#### Scenario: Monitord недоступен

- **WHEN** проверки удостоверения успешны, но IPC возвращает transport error
- **THEN** вход отклоняется как отказ по неопределимости

### AUTH-006 — Permissive mode поглощает только транспортный отказ

[[auth.session-registration-policy|Политика регистрации]] в `permissive` mode
MUST сохранять успешный вердикт при обычной недоступности транспорта.
[[auth.session-registration-policy|Политика регистрации]] MUST NOT поглощать
`DeviceGone` или `Unauthorized`: эти ответы опровергают
возможность открыть допустимую сессию независимо от fail mode.

#### Scenario: Транспорт недоступен в permissive mode

- **WHEN** monitord недоступен, а fail mode равен `permissive`
- **THEN** доказанное право входа становится окончательным PAM-успехом
