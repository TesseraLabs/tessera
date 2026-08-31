---
id: monitor-daemon
kind: сущность
context: runtime
name: Демон контроля сессий
aliases:
  - monitord
  - демон Tessera
  - tessera daemon
no_anchor:
  type: демон является процессом и набором обработчиков; единого представляющего его типа нет
relations:
  references:
    - runtime.active-session
    - runtime.pam-monitord-ipc
    - runtime.session-registry
anchors:
  code:
    - crates/tessera_cli/src/daemon/mod.rs#run
  test:
    - crates/tessera_cli/tests/server_handlers.rs
---

# Демон контроля сессий

## Purpose

Долгоживущий процесс `tessera daemon` принимает
[[runtime.pam-monitord-ipc|IPC-сообщения]] от PAM-модуля, хранит
[[runtime.active-session|активные сессии]] и применяет реакцию на исчезновение
носителя или истечение срока сессии. Снимок переживает перезапуск процесса через
[[runtime.session-registry|реестр сессий]].
