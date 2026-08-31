---
id: active-session
kind: сущность
context: runtime
name: Активная сессия
aliases:
  - активная сессия
  - сессия monitord
relations:
  references:
    - runtime.active-session
    - runtime.monitor-daemon
    - runtime.pam-monitord-ipc
    - runtime.session-registry
anchors:
  type:
    - crates/tessera_cli/src/registry.rs#ActiveSession
  code:
    - crates/tessera_cli/src/registry.rs#SessionRegistry
  test:
    - crates/tessera_cli/tests/session_ttl.rs
requirements:
  RT-001:
    kind: инвариант
    subjects:
      - runtime.active-session
    evidence:
      test:
        - crates/tessera_cli/tests/session_ttl.rs
---

# Активная сессия

## Purpose

Состоявшийся вход, за которым наблюдает [[runtime.monitor-daemon|демон]].
Сессия создаётся сообщением [[runtime.pam-monitord-ipc|SessionOpen]] и
сохраняется в [[runtime.session-registry|реестре сессий]].

## Requirements

### RT-001 — Истёкшая сессия не подтверждает активный вход

[[runtime.active-session|Активная сессия]] MUST считаться отсутствующей после
своего абсолютного `session_expiry`, даже если фоновое удаление записи ещё не
завершилось.

#### Scenario: Чтение во время задержки очистки
- **WHEN** срок сессии истёк, но запись ещё находится в реестре
- **THEN** поиск по UID не возвращает эту сессию
