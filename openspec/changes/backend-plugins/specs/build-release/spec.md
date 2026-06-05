# build-release Delta Specification

## ADDED Requirements

### Requirement: Сборка с плагинами

Release-сборка ДОЛЖНА (MUST) инжектить список публичных ключей верификации плагинов на
этапе компиляции (`TESSERA_PLUGIN_PUBKEYS`); пайплайн открытого пакета собирает ОДИН
бинарь без enforcement-features. CI ДОЛЖЕН (MUST) собирать фикстурный тест-плагин и гонять
тесты загрузчика (подпись валид/битая/чужой ключ, ABI-несовпадение, malformed-заголовок,
panic-граница). Enterprise-пайплайн (tessera-enterprise) собирает `tessera_backend_parsec.so`,
подписывает его и пакует в .deb с зависимостью от открытого пакета. По завершении миграции
matrix-ветка `--features astra-mac` ДОЛЖНА (MUST) быть удалена.

#### Scenario: PR-сборка открытого репо
- **WHEN** открыт PR в tessera
- **THEN** собирается один бинарь, фикстурный плагин, тесты загрузчика зелёные без enterprise-кода
