# logging-audit Delta Specification

## ADDED Requirements

### Requirement: Audit-события плагинов (target plugin.audit)

События плагинов ДОЛЖНЫ (MUST) идти в стабильный tracing-target `plugin.audit`:

| Событие | Поля | Когда |
|---|---|---|
| `plugin_loaded` | `name`, `plugin_version`, `kind`, `sha256` | успешная регистрация |
| `plugin_rejected` | `path`, `reason` (`signature` / `abi` / `kind` / `dlopen` / `init` / `missing` / `header`) | любой отказ загрузки |
| `plugin_inactive_file` | `path` | файл в каталоге плагинов, не названный конфигом |
| `plugin_panic` | `name`, `entry_point` | паника на FFI-границе |

#### Scenario: Отказ по подписи
- **WHEN** подпись .so не сходится ни с одним вшитым ключом
- **THEN** эмитится `plugin_rejected` с `path` и `reason=signature` в target `plugin.audit`
