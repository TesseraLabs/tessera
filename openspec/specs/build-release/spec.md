# build-release Specification

## Purpose

CI/CD, packaging и тестовая инфраструктура: что гарантируется на каждом push/PR/теге, известные пробелы покрытия.

Файлы: `.github/workflows/build.yml`, `debian/`, `vagrant/`, `tests/scripts/`.
## Requirements
### Requirement: CI matrix

CI-пайплайн ДОЛЖЕН (MUST) гонять матрицу из двух таргетов:

| Таргет | Контейнер | Features | Тесты | Артефакт |
|---|---|---|---|---|
| ubuntu | ubuntu-22.04 | — (stub) | `cargo test --workspace` (debug) | stub .deb (НЕ для прода) |
| astra | astra-builder (GHCR) | astra-mac | `cargo nextest run --workspace --features astra-mac` (debug) | релизный .deb |

Тесты ДОЛЖНЫ (MUST) гоняться в debug (release-тесты ~510s vs ~60s); `.deb` ДОЛЖЕН (MUST) всегда собираться в release+LTO через dpkg-buildpackage (release-only ошибки компиляции ловятся в PR). astra-job ДОЛЖНА (MUST) проверять реальные символы libpdp.

#### Scenario: PR-сборка
- **WHEN** открыт PR
- **THEN** гоняются обе ветки матрицы (ubuntu stub + astra astra-mac), тесты в debug, `.deb` собирается в release+LTO

### Requirement: Версионный guardrail

CI ДОЛЖЕН (MUST) проверять `Cargo.toml` workspace version == `debian/changelog` top entry. Каждая новая changelog-запись ДОЛЖНА (MUST) иметь timestamp ПОЗЖЕ предыдущей — иначе lintian (только ubuntu-pipeline) валит build, а `release` job с `needs: build` на всю matrix пропускает релиз ЦЕЛИКОМ (инцидент v0.3.13: релиз без .deb).

#### Scenario: changelog с убывающим timestamp
- **WHEN** новая запись в `debian/changelog` имеет timestamp раньше предыдущей
- **THEN** lintian валит ubuntu-pipeline → `release` job с `needs: build` пропускает релиз целиком

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

### Requirement: Доставка на парк

Модуль ДОЛЖЕН (MUST) попадать на машины через TMS-push либо вручную `dpkg -i` с USB; apt-repo/pull НЕ используется. Под жёсткой ЗПС (digsig_verif LSM) `.so` ДОЛЖЕН (MUST) быть подписан (`security.ima` xattr) — иначе PAM-стек падает на mmap; подпись доставляется postinst-восстановлением xattr, приватный ключ только в CI.

#### Scenario: Жёсткая ЗПС (digsig_verif)
- **WHEN** хост под digsig_verif LSM
- **THEN** `.so` должен быть подписан (`security.ima` xattr), иначе PAM-стек падает на mmap; подпись восстанавливается postinst

### Requirement: Тестовое покрытие (evidence)

Тестовый набор ДОЛЖЕН (MUST) покрывать negative PAM-flow на фикстурах в CI: wrong-PIN→MAXTRIES, subject mismatch, revoked (±CRL), expired; happy-path RSA/ECDSA p12. (Информативно: на момент bootstrap спеки — ~360 тестов across core/cli/proto/pam; точное число дрейфует и не нормируется.)

#### Scenario: Negative PAM-flow в CI
- **WHEN** прогоняется CI
- **THEN** покрываются negative-сценарии (wrong-PIN→MAXTRIES, subject mismatch, revoked ±CRL, expired) и happy-path RSA/ECDSA p12

### Requirement: Nightly release-профиль тестов

Тесты в release-профиле ДОЛЖНЫ (MUST) гоняться ежедневно workflow `.github/workflows/nightly.yml` (cron `17 2 * * *` UTC + `workflow_dispatch`, только в основном репо): та же matrix, что в build.yml (ubuntu stub / astra builder-контейнер), с теми же release-knobs, что у продового `.deb` (`CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1`, `CARGO_PROFILE_RELEASE_LTO=thin`) — release-only ошибки (кодоген, LTO, timing-чувствительные тесты) ловятся не позднее чем через сутки. `.deb` в nightly не собирается — это делает build.yml.

#### Scenario: Release-only регрессия
- **WHEN** изменение ломает тесты только в release-профиле (кодоген/LTO/timing)
- **THEN** ближайший nightly-прогон (ubuntu или astra) падает

Проверки, выполняемые вручную (runbook'и `tests/scripts/install-and-test.sh`, `vagrant/scripts/test-mac.sh`): ГОСТ end-to-end, реальный libpdp/parsec enforcement, полный flow с реальным USB/токеном, hook-security инварианты (no_new_privs/uid-drop/fd-leak, `#[ignore]` из-за RLIMIT_NPROC на GH-раннерах), vagrant E2E auth-flow. Их автоматизация — proposal [ci-hardening](../../changes/ci-hardening/).

### Requirement: Lint-гейт

CI ДОЛЖЕН (MUST) гонять на каждом push/PR в main workflow `lint.yml`: `cargo clippy --workspace --all-targets -- -D warnings` (toolchain из rust-toolchain.toml) и supply-chain job (`cargo deny check` по deny.toml + `cargo audit`).

Линт linux-only кода (`#[cfg(target_os = "linux")]` модули pam_tessera) проверяется ТОЛЬКО CI — локальный clippy на macOS эти модули не видит.

#### Scenario: PR с clippy-warning
- **WHEN** PR вносит код с clippy-предупреждением (включая linux-only модули)
- **THEN** job `clippy` падает (`-D warnings`), PR не мержится

