---
id: build-release
kind: операция
context: platform
name: "Сборка и выпуск"
aliases:
  - "build-release"
relations:
  references:
    - issuance.leaf-certificate-issuance
    - runtime.monitor-daemon
anchors:
  code:
    - ".github/workflows/build.yml"
  test:
    - ".github/workflows/nightly.yml"
requirements:
  BLD-001:
    kind: операционное
    subjects:
      - platform.build-release
    origins:
      - "build-release::CI matrix"
    evidence:
      code:
        - ".github/workflows/build.yml"
  BLD-002:
    kind: операционное
    subjects:
      - platform.build-release
    origins:
      - "build-release::Версионный guardrail"
    evidence:
      code:
        - ".github/workflows/build.yml"
  BLD-003:
    kind: операционное
    subjects:
      - platform.build-release
    origins:
      - "build-release::Release job"
    evidence:
      code:
        - ".github/workflows/build.yml"
  BLD-004:
    kind: операционное
    subjects:
      - platform.build-release
    origins:
      - "build-release::Доставка на парк"
    evidence:
      code:
        - ".github/workflows/build.yml"
  BLD-005:
    kind: операционное
    subjects:
      - platform.build-release
    origins:
      - "build-release::Тестовое покрытие (evidence)"
    evidence:
      code:
        - ".github/workflows/build.yml"
  BLD-006:
    kind: операционное
    subjects:
      - platform.build-release
    origins:
      - "build-release::Nightly release-профиль тестов"
    evidence:
      code:
        - ".github/workflows/build.yml"
  BLD-007:
    kind: операционное
    subjects:
      - platform.build-release
    origins:
      - "build-release::Lint-гейт"
    evidence:
      code:
        - ".github/workflows/build.yml"
---
# Сборка и выпуск

Эта страница заменяет процедурную capability-спеку OpenSpec «build-release»: она
помещает каждое прежнее требование в адресуемую норму с владельцем, видом и
проверяемым происхождением. Под каждым нормативным предложением сохранены подробные условия, отрицательные
сценарии и rationale; они входят в ту же страницу и уточняют границы нормы.

### BLD-001 — CI matrix

[[platform.build-release|Сборка и выпуск]] MUST соблюдать правило «CI matrix» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/build-release/spec.md, requirement «CI matrix».

CI-пайплайн должен собирать один открытый host в двух окружениях и
дополнительно проверять портируемость ядра под Windows:

| Таргет | Контейнер | Features | Тесты | Артефакт |
|---|---|---|---|---|
| ubuntu | ubuntu-22.04 | — | `cargo test --workspace` (debug) | open .deb |
| astra | astra-builder (GHCR) | — | `cargo nextest run --workspace` (debug) | open .deb |
| windows | windows-runner | — | `cargo test -p tessera_core -p tessera_proto -p pam_tessera` (debug) | — |

Тесты должны гоняться в debug; `.deb` должен собираться в
release+LTO через dpkg-buildpackage. Обе Linux-ноги должны собирать
фикстурный runtime-плагин и прогонять loader/ABI contract tests. Открытый `.deb`
не должен линковаться с libpdp. Official release CI должен
отвергать пустой `TESSERA_PLUGIN_PUBKEYS`, чтобы `.deb` всегда содержал явный
trust store для подписанных runtime-плагинов.

Windows-нога должна собирать `openssl` с feature `vendored` и не должна
(не допускается) включать ГОСТ-тесты: движок загружается динамически и под Windows
отсутствует. Windows-нога артефактов не производит и `.deb` не собирает.
Регистрация Credential Provider на стенде автоматизации НЕ ПОДЛЕЖИТ (не допускается)
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

### BLD-002 — Версионный guardrail

[[platform.build-release|Сборка и выпуск]] MUST соблюдать правило «Версионный guardrail» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/build-release/spec.md, requirement «Версионный guardrail».

CI должен проверять `Cargo.toml` workspace version == `debian/changelog` top entry. Каждая новая changelog-запись должна иметь timestamp ПОЗЖЕ предыдущей — иначе lintian (только ubuntu-pipeline) валит build, а `release` job с `needs: build` на всю matrix пропускает релиз ЦЕЛИКОМ (инцидент v0.3.13: релиз без .deb).

#### Scenario: changelog с убывающим timestamp
- **WHEN** новая запись в `debian/changelog` имеет timestamp раньше предыдущей
- **THEN** lintian валит ubuntu-pipeline → `release` job с `needs: build` пропускает релиз целиком

### BLD-003 — Release job

[[platform.build-release|Сборка и выпуск]] MUST соблюдать правило «Release job» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/build-release/spec.md, requirement «Release job».

`release` job должна только на тегах `v*` публиковать в draft GitHub
Release: (1) astra+ubuntu `.deb` агента enforcement; (2) бинарь `issuer` под
Linux, macOS и Windows, собранный как CLI с бэкендами PKCS#11, Vault и файловым
(`cli,pkcs11,vault,file`), с манифестом `SHA256SUMS`. Открытый бинарь `issuer` —
чистый CLI: локальный агент подписи и веб-кабинет выпуска поставляются отдельно
и в бинарь НЕ входят. Linux-бинарь `issuer` должен собираться в
контейнере `astra-builder` (самый старый glibc среди целевых систем), чтобы
работать на Astra, Ubuntu и Debian по обратной совместимости glibc. `.deb` НЕ
содержит `issuer` (device-сторона поставляется отдельно от инструментов выпуска).

#### Scenario: Push тега
- **WHEN** пушится тег `v*`
- **THEN** публикуются astra+ubuntu `.deb` агента и бинари `issuer` (Linux/macOS/Windows, CLI-only) + `SHA256SUMS` в draft GitHub Release

#### Scenario: Linux-бинарь issuer на Astra и новее
- **WHEN** оператор запускает опубликованный Linux-бинарь `issuer` на Astra, Ubuntu или Debian
- **THEN** бинарь работает на всех трёх: собран против самого старого glibc (astra-builder), новее — обратная совместимость glibc

### BLD-004 — Доставка на парк

[[platform.build-release|Сборка и выпуск]] MUST соблюдать правило «Доставка на парк» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/build-release/spec.md, requirement «Доставка на парк».

Модуль должен попадать на машины через TMS-push либо вручную `dpkg -i` с USB; apt-repo/pull НЕ используется. Под жёсткой ЗПС (digsig_verif LSM) `.so` должен быть подписан (`security.ima` xattr) — иначе PAM-стек падает на mmap; подпись доставляется postinst-восстановлением xattr, приватный ключ только в CI.

#### Scenario: Жёсткая ЗПС (digsig_verif)
- **WHEN** хост под digsig_verif LSM
- **THEN** `.so` должен быть подписан (`security.ima` xattr), иначе PAM-стек падает на mmap; подпись восстанавливается postinst

### BLD-005 — Тестовое покрытие (evidence)

[[platform.build-release|Сборка и выпуск]] MUST соблюдать правило «Тестовое покрытие (evidence)» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/build-release/spec.md, requirement «Тестовое покрытие (evidence)».

Тестовый набор должен покрывать negative PAM-flow на фикстурах в CI: wrong-PIN→MAXTRIES, subject mismatch, revoked (±CRL), expired; happy-path RSA/ECDSA p12. (Информативно: на момент bootstrap спеки — ~360 тестов across core/cli/proto/pam; точное число дрейфует и не нормируется.)

#### Scenario: Negative PAM-flow в CI
- **WHEN** прогоняется CI
- **THEN** покрываются negative-сценарии (wrong-PIN→MAXTRIES, subject mismatch, revoked ±CRL, expired) и happy-path RSA/ECDSA p12

### BLD-006 — Nightly release-профиль тестов

[[platform.build-release|Сборка и выпуск]] MUST соблюдать правило «Nightly release-профиль тестов» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/build-release/spec.md, requirement «Nightly release-профиль тестов».

Тесты в release-профиле должны гоняться ежедневно workflow `.github/workflows/nightly.yml` (cron `17 2 * * *` UTC + `workflow_dispatch`, только в основном репо): та же matrix, что в build.yml (ubuntu stub / astra builder-контейнер), с теми же release-knobs, что у продового `.deb` (`CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1`, `CARGO_PROFILE_RELEASE_LTO=thin`) — release-only ошибки (кодоген, LTO, timing-чувствительные тесты) ловятся не позднее чем через сутки. `.deb` в nightly не собирается — это делает build.yml.

#### Scenario: Release-only регрессия
- **WHEN** изменение ломает тесты только в release-профиле (кодоген/LTO/timing)
- **THEN** ближайший nightly-прогон (ubuntu или astra) падает

Проверки, выполняемые вручную (runbook'и `tests/scripts/install-and-test.sh`, `vagrant/scripts/test-mac.sh`): ГОСТ end-to-end, реальный libpdp/parsec enforcement, полный flow с реальным USB/токеном, hook-security инварианты (no_new_privs/uid-drop/fd-leak, `#[ignore]` из-за RLIMIT_NPROC на GH-раннерах), vagrant E2E auth-flow. Их автоматизация — proposal [ci-hardening](../../changes/ci-hardening/).

### BLD-007 — Lint-гейт

[[platform.build-release|Сборка и выпуск]] MUST соблюдать правило «Lint-гейт» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/build-release/spec.md, requirement «Lint-гейт».

CI должен гонять на каждом push/PR в main workflow `lint.yml`: `cargo clippy --workspace --all-targets -- -D warnings` (toolchain из rust-toolchain.toml) и supply-chain job (`cargo deny check` по deny.toml + `cargo audit`).

Линт linux-only кода (`#[cfg(target_os = "linux")]` модули pam_tessera) проверяется ТОЛЬКО CI — локальный clippy на macOS эти модули не видит.

#### Scenario: PR с clippy-warning
- **WHEN** PR вносит код с clippy-предупреждением (включая linux-only модули)
- **THEN** job `clippy` падает (`-D warnings`), PR не мержится

