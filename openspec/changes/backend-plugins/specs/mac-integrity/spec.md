# mac-integrity Delta Specification

## ADDED Requirements

### Requirement: ParsecBackend как плагин

Реальный МКЦ-enforcement ДОЛЖЕН (MUST) поставляться плагином `tessera_backend_parsec.so`
(kind backend.enforcement) и выбираться конфигом `[mac] backend = "parsec"`. SPI-trait
`MacBackend`, orchestrator, label-алгебра и StubBackend остаются в открытом ядре без
изменений; мост `PluginBackend` (trait поверх C-vtable) — открытый. При отсутствии,
невалидности или отказе плагина активен StubBackend; роли, требующие МКЦ, при StubBackend
отклоняются (правило change'а role-format). Compile-time feature `astra-mac` ДОЛЖНА (MUST)
быть удалена по завершении миграции.

#### Scenario: Astra-устройство с установленным плагином
- **WHEN** enterprise-пакет установлен и конфиг называет backend "parsec"
- **THEN** apply_session исполняется ParsecBackend'ом из плагина в процессе PAM-сессии

#### Scenario: Плагин не установлен на открытой системе
- **WHEN** конфиг не называет backend либо плагин отсутствует
- **THEN** активен StubBackend; вход по ролям без mac_mask работает, с mac_mask — отказ
