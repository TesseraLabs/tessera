---
id: cli-diagnostics
kind: операция
context: runtime
name: "Диагностика CLI"
aliases:
  - "cli-diagnostics"
relations:
  references:
    - auth.device-config
    - runtime.monitor-daemon
anchors:
  code:
    - "crates/tessera_cli/src/check.rs"
  test:
    - "tests/e2e/cases/12-cli-diagnostics.yaml"
requirements:
  CLI-001:
    kind: операционное
    subjects:
      - runtime.cli-diagnostics
    origins:
      - "cli-diagnostics::tessera check"
    evidence:
      code:
        - "crates/tessera_cli/src/check.rs"
  CLI-002:
    kind: операционное
    subjects:
      - runtime.cli-diagnostics
    origins:
      - "cli-diagnostics::tessera dump-host-id"
    evidence:
      code:
        - "crates/tessera_cli/src/check.rs"
  CLI-003:
    kind: операционное
    subjects:
      - runtime.cli-diagnostics
    origins:
      - "cli-diagnostics::Историческое"
    evidence:
      code:
        - "crates/tessera_cli/src/check.rs"
---
# Диагностика CLI

Эта страница заменяет процедурную capability-спеку OpenSpec «cli-diagnostics»: она
помещает каждое прежнее требование в адресуемую норму с владельцем, видом и
проверяемым происхождением. Под каждым нормативным предложением сохранены подробные условия, отрицательные
сценарии и rationale; они входят в ту же страницу и уточняют границы нормы.

### CLI-001 — tessera check

[[runtime.cli-diagnostics|Диагностика CLI]] MUST соблюдать правило «tessera check» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/cli-diagnostics/spec.md, requirement «tessera check».

Команда должна выполнять префлайт-валидацию БЕЗ запуска демона и без касания сокета: load config → startup-check pipeline (pam_stack ordering, mac runtime vs ядро, anchors, права CA-dir, parsec caps, host_identity probe). Вывод: строки `[INFO]/[WARN]/[ERROR]` в stdout + summary. Exit 0 ⟺ ноль ERROR; INFO/WARN на exit не влияют. Предназначен как `ExecStartPre=` hard-gate и валидатор в finish-bootstrap (check.rs:33–70).

#### Scenario: Префлайт без ERROR
- **WHEN** `tessera check` отрабатывает pipeline и не получает ни одной ERROR-записи
- **THEN** команда печатает summary и завершается с exit 0 (INFO/WARN не влияют)

### CLI-002 — tessera dump-host-id

[[runtime.cli-diagnostics|Диагностика CLI]] MUST соблюдать правило «tessera dump-host-id» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/cli-diagnostics/spec.md, requirement «tessera dump-host-id».

Команда должна пробить ВСЕ канонические host-identity источники (fan-out: machine_id, dmi_board_serial, dmi_system_uuid, dmi_system_serial, hostname, + custom_command/override если заданы), игнорируя ограничение `[host_identity].sources` — оператор видит полную картину железа (dump_host_id.rs:178–196).

TSV: 3 строки `#`-комментариев + header `source/status/hash_hex/hash_prefix/raw/normalized/active_under_current_config/reason` (8 колонок); status ∈ {ok, err}; поля санитайзятся от tab/newline. Колонка `active_under_current_config=yes` должна маркировать источник, который выбрал бы live-resolver — из неё CA-админ берёт hash_hex.

Назначения: stdout (default) | `--output PATH` (atomic, 0644) | `--usb` (RW-mount первой пригодной партиции под `/run/tessera/host-id-dump/`, файл `host-ids-<hostname>-<UTC>.tsv`, unmount). `--output` и `--usb` взаимоисключающие.

#### Scenario: Все источники мертвы
- **WHEN** ни один probe не дал ok
- **THEN** `NoActiveHostId` → exit ≠ 0 — сигнал «не выписывать серт, чинить вход» (fail-closed)

### CLI-003 — Историческое

[[runtime.cli-diagnostics|Диагностика CLI]] MUST соблюдать правило «Историческое» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/cli-diagnostics/spec.md, requirement «Историческое».

Удалённые подкоманды не должны присутствовать в CLI: подкоманды 0.2.x (`execute`, `policy`, `gc`) удалены в 0.3.0. Отдельный бинарь `tessera-hostid` отвергнут (May 26) — дублировал dump-host-id/probe_all.

#### Scenario: Вызов удалённой подкоманды
- **WHEN** оператор вызывает `tessera execute` (или `policy`/`gc`)
- **THEN** подкоманда отсутствует — CLI её не распознаёт

