# daemon-lifecycle — delta (mrd-guard)

## ADDED Requirements

### Requirement: Startup-check — детект активного МРД

Startup-check pipeline ДОЛЖЕН (MUST) включать проверку `mac_mrd_active`:
probe состояния МРД (`Active` / `Inactive` / `Unknown`; реализация probe —
в коммерческом backend'е, открытая сборка ДОЛЖНА (MUST) возвращать `Unknown`).
Серьёзность записи определяется `[mac].runtime`:

| `[mac].runtime` | МРД `Active` | МРД `Unknown` | МРД `Inactive` |
|---|---|---|---|
| `required` | ERROR | WARN | INFO |
| `auto` | WARN | INFO | INFO |
| `disabled` | INFO | INFO | INFO |

ERROR подчиняется общему fail-closed-гейту: демон отказывается стартовать.
Проверка ДОЛЖНА (MUST) выполняться и в `tessera check` (общий pipeline).

#### Scenario: required на МРД-системе

- **WHEN** `[mac].runtime=required` и probe вернул `Active`
- **THEN** запись ERROR `mac_mrd_active`, демон не стартует

#### Scenario: auto на МРД-системе

- **WHEN** `[mac].runtime=auto` и probe вернул `Active`
- **THEN** запись WARN: конфигурация не поддерживается, демон стартует

#### Scenario: Открытая сборка

- **WHEN** открытая сборка (probe недоступен) и `[mac].runtime=auto`
- **THEN** запись INFO `mac_mrd_active` со статусом `Unknown`, старт не блокируется
