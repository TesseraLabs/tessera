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

`release` job ДОЛЖНА (MUST) только на тегах `v*` публиковать astra+ubuntu `.deb` + admin-tools tarball в draft GitHub Release.

#### Scenario: Push тега
- **WHEN** пушится тег `v*`
- **THEN** публикуются astra+ubuntu `.deb` и admin-tools tarball в draft GitHub Release

### Requirement: Доставка на парк

Модуль ДОЛЖЕН (MUST) попадать на машины через TMS-push либо вручную `dpkg -i` с USB; apt-repo/pull НЕ используется. Под жёсткой ЗПС (digsig_verif LSM) `.so` ДОЛЖЕН (MUST) быть подписан (`security.ima` xattr) — иначе PAM-стек падает на mmap; подпись доставляется postinst-восстановлением xattr, приватный ключ только в CI.

#### Scenario: Жёсткая ЗПС (digsig_verif)
- **WHEN** хост под digsig_verif LSM
- **THEN** `.so` должен быть подписан (`security.ima` xattr), иначе PAM-стек падает на mmap; подпись восстанавливается postinst

### Requirement: Тестовое покрытие (evidence)

Тестовый набор ДОЛЖЕН (MUST) включать 362 объявленных теста (core 253 / cli 66 / proto 27 / pam 16). Negative PAM-flow на фикстурах в CI: wrong-PIN→MAXTRIES, subject mismatch, revoked (±CRL), expired; happy-path RSA/ECDSA p12.

#### Scenario: Negative PAM-flow в CI
- **WHEN** прогоняется CI
- **THEN** покрываются negative-сценарии (wrong-PIN→MAXTRIES, subject mismatch, revoked ±CRL, expired) и happy-path RSA/ECDSA p12

⚠ KNOWN GAP — НЕ проверяется автоматически:
1. ГОСТ end-to-end (фикстуры не закоммичены, `gost-tests` не в CI).
2. Реальный libpdp/parsec enforcement (CI только компилит; runtime — ручной test-mac.sh).
3. Полный flow с реальным USB/токеном (`#[ignore]`, ручной runbook `tests/scripts/install-and-test.sh`).
4. Hook-security инварианты (no_new_privs/uid-drop/fd-leak) — `#[ignore]` из-за RLIMIT_NPROC на GH-раннерах.
5. Release-профиль тестов (nightly workflow упомянут в комментарии, не существует).
6. Lint-гейт (clippy/cargo-deny/audit) на main отсутствует — живёт на неслитой ветке `fix/daemon-singleton-and-audit-trail` (37 коммитов, кандидат на ревью).
7. vagrant/README ссылается на test-happy/negative/gost/setup-mof-n скрипты — их НЕТ в репо (фантом; реально только test-mac.sh, bench-mac.sh).

### Requirement: Гигиена репозитория (зафиксированные хвосты)

Репозиторий ДОЛЖЕН (MUST) быть очищен от зафиксированных хвостов:

- `CertAuth-scopes-mofn/` — осиротевший сломанный worktree со старым снапшотом M-of-N; кандидат на удаление.
- `fix/usb-p12-asn1-fallback` — стало (26 коммитов позади main, фичи давно в main); мусор.
- Реальный кандидат на перенос — `fix/daemon-singleton-and-audit-trail` (lint workflow, unsafe-hardening, zbus 5). Требует решения человека.

#### Scenario: Осиротевший worktree
- **WHEN** в репозитории присутствует `CertAuth-scopes-mofn/` или устаревшая ветка `fix/usb-p12-asn1-fallback`
- **THEN** они помечаются кандидатами на удаление как мусор
