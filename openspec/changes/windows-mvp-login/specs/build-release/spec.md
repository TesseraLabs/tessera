# build-release Specification

## MODIFIED Requirements

### Requirement: CI matrix

CI-пайплайн ДОЛЖЕН (MUST) собирать один открытый host в двух окружениях и
дополнительно проверять портируемость ядра под Windows:

| Таргет | Контейнер | Features | Тесты | Артефакт |
|---|---|---|---|---|
| ubuntu | ubuntu-22.04 | — | `cargo test --workspace` (debug) | open .deb |
| astra | astra-builder (GHCR) | — | `cargo nextest run --workspace` (debug) | open .deb |
| windows | windows-runner | — | `cargo test -p tessera_core -p tessera_proto -p pam_tessera` (debug) | — |

Тесты ДОЛЖНЫ (MUST) гоняться в debug; `.deb` ДОЛЖЕН (MUST) собираться в
release+LTO через dpkg-buildpackage. Обе Linux-ноги ДОЛЖНЫ (MUST) собирать
фикстурный runtime-плагин и прогонять loader/ABI contract tests. Открытый `.deb`
НЕ ДОЛЖЕН (MUST NOT) линковаться с libpdp. Official release CI ДОЛЖЕН (MUST)
отвергать пустой `TESSERA_PLUGIN_PUBKEYS`, чтобы `.deb` всегда содержал явный
trust store для подписанных runtime-плагинов.

Windows-нога ДОЛЖНА (MUST) собирать `openssl` с feature `vendored` и НЕ ДОЛЖНА
(MUST NOT) включать ГОСТ-тесты: движок загружается динамически и под Windows
отсутствует. Windows-нога артефактов не производит и `.deb` не собирает.
Регистрация Credential Provider на стенде автоматизации НЕ ПОДЛЕЖИТ (MUST NOT)
и остаётся ручным прогоном: сломанный провайдер делает машину недоступной для
входа.

#### Scenario: PR-сборка
- **WHEN** открыт PR
- **THEN** обе Linux-ноги собирают один host без enterprise feature, fixture-plugin tests зелёные, `.deb` собирается в release+LTO

#### Scenario: Портируемость ядра
- **WHEN** открыт PR, затрагивающий `tessera_core`, `tessera_proto` или `pam_tessera`
- **THEN** Windows-нога собирает эти крейты под `x86_64-pc-windows-msvc` и прогоняет их unit-тесты; падение ноги блокирует мерж

#### Scenario: Регресс платформенных гейтов
- **WHEN** в verify-путь ядра вносится безусловная зависимость от `nix`, `rustix`, `libc` или udev
- **THEN** Windows-нога падает на сборке, а не оставляет расхождение до ручного прогона на стенде
