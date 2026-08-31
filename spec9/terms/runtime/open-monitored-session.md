---
id: open-monitored-session
kind: операция
context: runtime
name: Открыть контролируемую сессию
relations:
  transported_by: runtime.pam-monitord-ipc
  handled_by: runtime.monitor-daemon
  writes:
    - runtime.session-registry
    - runtime.active-session
anchors:
  code:
    - crates/tessera_cli/src/state.rs#handle_session_open
  test:
    - crates/tessera_cli/tests/session_open_persist.rs#session_open_persist_success_acks_and_persists
requirements:
  RT-002:
    kind: инвариант
    subjects:
      - runtime.open-monitored-session
    evidence:
      test:
        - crates/tessera_cli/tests/session_open_persist.rs#session_open_persist_failure_rolls_back_and_errors
---

# Открыть контролируемую сессию

## Purpose

Команда приходит через [[runtime.pam-monitord-ipc|IPC-контракт]], обрабатывается
[[runtime.monitor-daemon|демоном]] и создаёт [[runtime.active-session|активную
сессию]] в [[runtime.session-registry|реестре]]. Команда не доказывает право
входа повторно: она материализует уже доказанный результат в runtime-контексте.

## Requirements

### RT-002 — Ack следует только после сохранения

[[runtime.open-monitored-session|Открытие сессии]] MUST возвращать ошибку и
откатывать изменение памяти, если новый снимок реестра сохранить не удалось.

#### Scenario: Сохранение снимка не удалось

- **WHEN** активная сессия добавлена в памяти, но атомарная публикация JSON завершилась ошибкой
- **THEN** операция восстанавливает прежний реестр и не отправляет `Ack`
