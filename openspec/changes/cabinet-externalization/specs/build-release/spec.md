# build-release

## MODIFIED Requirements

### Requirement: Release job

`release` job ДОЛЖНА (MUST) только на тегах `v*` публиковать в draft GitHub
Release: (1) astra+ubuntu `.deb` агента enforcement; (2) бинарь `issuer`
под Linux, macOS и Windows, собранный с бэкендами PKCS#11 и Vault
(`cli,pkcs11,vault,serve`), с манифестом `SHA256SUMS`. Кабинет выпуска в
бинарь НЕ встраивается: `issuer serve` раздаёт внешний бандл, указанный
опцией `--cabinet-dir`. Linux-бинарь `issuer` ДОЛЖЕН (MUST) собираться в
контейнере `astra-builder` (самый старый glibc среди целевых систем), чтобы
работать на Astra, Ubuntu и Debian по обратной совместимости glibc. `.deb` НЕ
содержит `issuer` (device-сторона поставляется отдельно от инструментов выпуска).

#### Scenario: Push тега
- **WHEN** пушится тег `v*`
- **THEN** публикуются astra+ubuntu `.deb` агента и бинари `issuer` (Linux/macOS/Windows, без кабинета) + `SHA256SUMS` в draft GitHub Release

#### Scenario: Linux-бинарь issuer на Astra и новее
- **WHEN** оператор запускает опубликованный Linux-бинарь `issuer` на Astra, Ubuntu или Debian
- **THEN** бинарь работает на всех трёх: собран против самого старого glibc (astra-builder), новее — обратная совместимость glibc

#### Scenario: Запуск serve без бандла
- **WHEN** оператор запускает релизный `issuer serve` без `--cabinet-dir`
- **THEN** сервис стартует без ошибок и отдаёт локализованную страницу-заглушку с указанием опции
