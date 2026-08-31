---
id: host-identity-resolution
kind: операция
context: auth
name: "Разрешение идентичности хоста"
aliases:
  - "host-identity"
relations:
  references:
    - auth.host-identity
anchors:
  code:
    - "crates/tessera_core/src/host_identity/chain.rs"
  test:
    - "tests/e2e/cases/19-host-identity.yaml"
requirements:
  HID-001:
    kind: операционное
    subjects:
      - auth.host-identity-resolution
    origins:
      - "host-identity::Источники"
    evidence:
      code:
        - "crates/tessera_core/src/host_identity/chain.rs"
  HID-002:
    kind: операционное
    subjects:
      - auth.host-identity-resolution
    origins:
      - "host-identity::First-working-wins, без перебора при mismatch"
    evidence:
      code:
        - "crates/tessera_core/src/host_identity/chain.rs"
  HID-003:
    kind: операционное
    subjects:
      - auth.host-identity-resolution
    origins:
      - "host-identity::Нормализация и хеш"
    evidence:
      code:
        - "crates/tessera_core/src/host_identity/chain.rs"
  HID-004:
    kind: операционное
    subjects:
      - auth.host-identity-resolution
    origins:
      - "host-identity::Fallback-политика"
    evidence:
      code:
        - "crates/tessera_core/src/host_identity/chain.rs"
  HID-005:
    kind: операционное
    subjects:
      - auth.host-identity-resolution
    origins:
      - "host-identity::Override-источник"
    evidence:
      code:
        - "crates/tessera_core/src/host_identity/chain.rs"
  HID-006:
    kind: инвариант
    subjects:
      - auth.host-identity-resolution
    origins:
      - "host-identity::Эксплуатационные правила"
    evidence:
      test:
        - "tests/e2e/cases/19-host-identity.yaml"
---
# Разрешение идентичности хоста

Эта страница заменяет процедурную capability-спеку OpenSpec «host-identity»: она
помещает каждое прежнее требование в адресуемую норму с владельцем, видом и
проверяемым происхождением. Под каждым нормативным предложением сохранены подробные условия, отрицательные
сценарии и rationale; они входят в ту же страницу и уточняют границы нормы.

### HID-001 — Источники

[[auth.host-identity-resolution|Разрешение идентичности хоста]] MUST соблюдать правило «Источники» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/host-identity/spec.md, requirement «Источники».

Источники в `[host_identity].sources` должны быть из допустимого набора: `machine_id` (/etc/machine-id), `dmi_board_serial`, `dmi_system_uuid`, `dmi_system_serial` (sysfs DMI; алиасы board_serial/system_uuid/system_serial), `hostname` (/etc/hostname), `custom_command` (внешняя команда, timeout clamp 1..30s), `override` (фиксированное значение из `override`).

#### Scenario: custom_command с большим таймаутом
- **WHEN** `custom_command` задан с таймаутом вне диапазона 1..30s
- **THEN** значение clamp'ится в 1..30s

### HID-002 — First-working-wins, без перебора при mismatch

[[auth.host-identity-resolution|Разрешение идентичности хоста]] MUST соблюдать правило «First-working-wins, без перебора при mismatch» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/host-identity/spec.md, requirement «First-working-wins, без перебора при mismatch».

Резолвер должен вернуть ПЕРВЫЙ источник, давший непустое нормализованное значение (chain.rs:114–157). Multi-source matching («хоть один совпал») не должен реализовываться: weakest-link-wins даёт атакующему спуфить самый слабый источник (например, dmi в qemu) — зафиксировано в threat-model.md §4.10. Видимость drift'а — через `probe_all()` (диагностический лог всех источников при auth и старте демона), не через fallback.

#### Scenario: Несколько источников, mismatch
- **WHEN** первый источник даёт значение, не совпавшее с host_binding серта, а другой источник совпал бы
- **THEN** резолвер НЕ перебирает источники — возвращается только первый рабочий, mismatch ведёт к отказу

### HID-003 — Нормализация и хеш

[[auth.host-identity-resolution|Разрешение идентичности хоста]] MUST соблюдать правило «Нормализация и хеш» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/host-identity/spec.md, requirement «Нормализация и хеш».

Хеш идентичности должен вычисляться как `host_id_hash = lowercase_hex(SHA256(normalize(raw)))`; normalize = trim + удаление `:` и пробелов + lowercase (дефисы/подчёркивания сохраняются) (chain.rs:160–181). На экран — prefix8, полный hash — в syslog.

#### Scenario: Нормализация сырого значения
- **WHEN** сырое значение источника содержит `:`, пробелы и буквы в верхнем регистре
- **THEN** normalize удаляет `:` и пробелы, приводит к lowercase (дефисы/подчёркивания сохраняются), затем считается SHA256

### HID-004 — Fallback-политика

[[auth.host-identity-resolution|Разрешение идентичности хоста]] MUST соблюдать правило «Fallback-политика» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/host-identity/spec.md, requirement «Fallback-политика».

При отказе ВСЕХ источников политика fallback должна применяться так: `fallback="deny"` (дефолт) → `AllSourcesFailed` → отказ auth (fail-closed); `warn`/`allow` → host_id = `"unknown"` (host_id_hash = sha256("unknown")) — fail-open, серты под него не совпадут кроме wildcard (chain.rs:138–154).

#### Scenario: Все источники упали при дефолтной политике
- **WHEN** ни один источник не дал значения и `fallback="deny"`
- **THEN** возвращается `AllSourcesFailed` → отказ auth (fail-closed)

### HID-005 — Override-источник

[[auth.host-identity-resolution|Разрешение идентичности хоста]] MUST соблюдать правило «Override-источник» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/host-identity/spec.md, requirement «Override-источник».

При `sources` содержащем `override` И заданном `override`-значении враппер PAM-крейта должен вернуть hash от override-значения, минуя цепочку (lib.rs:55–101). Это основа clone-image bootstrap (`override="installation"`).

- Замечание о слоистости (нормативно): override реализован враппером PAM-крейта (`tessera/src/lib.rs`); в core-резолвере `Override` — намеренная no-op ветка (chain.rs:75). Прямое использование core `HostIdentityResolver` с `sources=["override"]` даёт пустой список → всегда fallback.

#### Scenario: Override задан в clone-image bootstrap
- **WHEN** `sources` содержит `override` и задано `override="installation"`
- **THEN** враппер PAM-крейта возвращает hash от `"installation"`, минуя цепочку источников

### HID-006 — Эксплуатационные правила

[[auth.host-identity-resolution|Разрешение идентичности хоста]] MUST соблюдать правило «Эксплуатационные правила» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/host-identity/spec.md, requirement «Эксплуатационные правила».

Эксплуатация должна следовать правилам ниже, чтобы устранить host-id drift:

- Hash для выпуска серта должен браться из живой системы (`tessera dump-host-id`, либо `journalctl -t tessera | grep 'probe selected'`), а не вычисляться вручную — устраняет drift.
- На VM/дешёвом железе DMI-значения часто фиктивны (`"0"`, `"1"`; sha256("1")=5feceb66…) — рекомендация: `sources=["machine_id"]` либо `override`.

#### Scenario: Hash для выпуска серта
- **WHEN** оператор готовит host-binding для выпуска серта
- **THEN** hash берётся из живой системы (`tessera dump-host-id`), а не вычисляется вручную

