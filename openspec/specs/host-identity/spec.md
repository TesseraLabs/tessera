# host-identity Specification

## Purpose

Вычисление идентичности машины (`host_id_hash`), против которой сверяется `pam_cert_host_binding`. Принцип: первый работающий источник побеждает; перебор источников при mismatch ЗАПРЕЩЁН (security).

Код: `crates/tessera_core/src/host_identity/` (chain.rs, source.rs, machine_id.rs, dmi.rs, hostname.rs, custom_command.rs), враппер `crates/pam_tessera/src/lib.rs::resolve_host_identity`.

## Requirements

### Requirement: Источники

Источники в `[host_identity].sources` ДОЛЖНЫ (MUST) быть из допустимого набора: `machine_id` (/etc/machine-id), `dmi_board_serial`, `dmi_system_uuid`, `dmi_system_serial` (sysfs DMI; алиасы board_serial/system_uuid/system_serial), `hostname` (/etc/hostname), `custom_command` (внешняя команда, timeout clamp 1..30s), `override` (фиксированное значение из `override`).

- ⚠ KNOWN GAP (docs): configuration.md:125 упоминает несуществующий `tpm_ek_pubhash`; clone-image.md:213 — несуществующие `dmi_product_serial`/`dmi_chassis_serial`.

#### Scenario: custom_command с большим таймаутом
- **WHEN** `custom_command` задан с таймаутом вне диапазона 1..30s
- **THEN** значение clamp'ится в 1..30s

### Requirement: First-working-wins, без перебора при mismatch

Резолвер ДОЛЖЕН (MUST) вернуть ПЕРВЫЙ источник, давший непустое нормализованное значение (chain.rs:114–157). Multi-source matching («хоть один совпал») НЕ ДОЛЖЕН (MUST NOT) реализовываться: weakest-link-wins даёт атакующему спуфить самый слабый источник (например, dmi в qemu) — зафиксировано в threat-model.md §4.10. Видимость drift'а — через `probe_all()` (диагностический лог всех источников при auth и старте демона), не через fallback.

#### Scenario: Несколько источников, mismatch
- **WHEN** первый источник даёт значение, не совпавшее с host_binding серта, а другой источник совпал бы
- **THEN** резолвер НЕ перебирает источники — возвращается только первый рабочий, mismatch ведёт к отказу

### Requirement: Нормализация и хеш

Хеш идентичности ДОЛЖЕН (MUST) вычисляться как `host_id_hash = lowercase_hex(SHA256(normalize(raw)))`; normalize = trim + удаление `:` и пробелов + lowercase (дефисы/подчёркивания сохраняются) (chain.rs:160–181). На экран — prefix8, полный hash — в syslog.

#### Scenario: Нормализация сырого значения
- **WHEN** сырое значение источника содержит `:`, пробелы и буквы в верхнем регистре
- **THEN** normalize удаляет `:` и пробелы, приводит к lowercase (дефисы/подчёркивания сохраняются), затем считается SHA256

### Requirement: Fallback-политика

При отказе ВСЕХ источников политика fallback ДОЛЖНА (MUST) применяться так: `fallback="deny"` (дефолт) → `AllSourcesFailed` → отказ auth (fail-closed); `warn`/`allow` → host_id = `"unknown"` (host_id_hash = sha256("unknown")) — fail-open, серты под него не совпадут кроме wildcard (chain.rs:138–154).

#### Scenario: Все источники упали при дефолтной политике
- **WHEN** ни один источник не дал значения и `fallback="deny"`
- **THEN** возвращается `AllSourcesFailed` → отказ auth (fail-closed)

### Requirement: Override-источник

При `sources` содержащем `override` И заданном `override`-значении враппер PAM-крейта ДОЛЖЕН (MUST) вернуть hash от override-значения, минуя цепочку (lib.rs:55–101). Это основа clone-image bootstrap (`override="installation"`).

- ⚠ Замечание (для контрибьюторов): в core-резолвере `Override` — no-op ветка (chain.rs:75); override работает только через враппер `tessera/src/lib.rs`. Прямое использование core `HostIdentityResolver` с `sources=["override"]` даст пустой список → всегда fallback.

#### Scenario: Override задан в clone-image bootstrap
- **WHEN** `sources` содержит `override` и задано `override="installation"`
- **THEN** враппер PAM-крейта возвращает hash от `"installation"`, минуя цепочку источников

### Requirement: Эксплуатационные правила

Эксплуатация ДОЛЖНА (MUST) следовать правилам ниже, чтобы устранить host-id drift:

- Hash для выпуска серта ДОЛЖЕН (MUST) браться из живой системы (`tessera dump-host-id`, либо `journalctl -t tessera | grep 'probe selected'`), а не вычисляться вручную — устраняет drift.
- На VM/дешёвом железе DMI-значения часто фиктивны (`"0"`, `"1"`; sha256("1")=5feceb66…) — рекомендация: `sources=["machine_id"]` либо `override`.

#### Scenario: Hash для выпуска серта
- **WHEN** оператор готовит host-binding для выпуска серта
- **THEN** hash берётся из живой системы (`tessera dump-host-id`), а не вычисляется вручную
