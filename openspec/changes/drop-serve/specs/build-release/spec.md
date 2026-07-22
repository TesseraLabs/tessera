# Delta: build-release

## MODIFIED Requirements

### Requirement: Release job

`release` job ДОЛЖНА (MUST) только на тегах `v*` публиковать в draft GitHub
Release: (1) astra+ubuntu `.deb` агента enforcement; (2) бинарь `issuer` под
Linux, macOS и Windows, собранный как CLI с бэкендами PKCS#11, Vault и файловым
(`cli,pkcs11,vault,file`), с манифестом `SHA256SUMS`. Открытый бинарь `issuer` —
чистый CLI: локальный агент подписи и веб-кабинет выпуска поставляются отдельно
и в бинарь НЕ входят. Linux-бинарь `issuer` ДОЛЖЕН (MUST) собираться в
контейнере `astra-builder` (самый старый glibc среди целевых систем), чтобы
работать на Astra, Ubuntu и Debian по обратной совместимости glibc. `.deb` НЕ
содержит `issuer` (device-сторона поставляется отдельно от инструментов выпуска).

#### Scenario: Push тега
- **WHEN** пушится тег `v*`
- **THEN** публикуются astra+ubuntu `.deb` агента и бинари `issuer` (Linux/macOS/Windows, CLI-only) + `SHA256SUMS` в draft GitHub Release

#### Scenario: Linux-бинарь issuer на Astra и новее
- **WHEN** оператор запускает опубликованный Linux-бинарь `issuer` на Astra, Ubuntu или Debian
- **THEN** бинарь работает на всех трёх: собран против самого старого glibc (astra-builder), новее — обратная совместимость glibc
