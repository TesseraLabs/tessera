# build-release Delta Specification

## MODIFIED Requirements

### Requirement: Тестовое покрытие (evidence)

Тестовый набор ДОЛЖЕН (MUST) покрывать negative PAM-flow на фикстурах в CI: wrong-PIN→MAXTRIES,
subject mismatch, revoked (±CRL), expired; happy-path RSA/ECDSA p12. Дополнительно автоматически
ДОЛЖНЫ (MUST) проверяться: ГОСТ end-to-end (nightly, закоммиченные фикстуры + `gost-tests`),
hook-security инварианты (nightly container-job), release-профиль тестов (nightly),
PKCS#11-путь против SoftHSM (nightly), MAC-runtime libpdp/parsec (weekly VM-прогон).
(Информативно: на момент bootstrap спеки — ~360 тестов across core/cli/proto/pam; точное число
дрейфует и не нормируется.)

#### Scenario: Negative PAM-flow в CI
- **WHEN** прогоняется CI
- **THEN** покрываются negative-сценарии (wrong-PIN→MAXTRIES, subject mismatch, revoked ±CRL, expired) и happy-path RSA/ECDSA p12

⚠ KNOWN GAP — НЕ проверяется автоматически (сокращённый список):
1. Полный flow с **реальным** USB/токеном (нет железа на hosted-раннерах) — ручной runbook
   `tests/scripts/install-and-test.sh`, обязательный пункт чек-листа релиза
   (JaCarta-2 GOST + Рутокен); SoftHSM-smoke покрывает PKCS#11-код, но не вендорские прошивки.
2. Vagrant-риг E2E-скриптов текущего auth-flow (помимо MAC-runtime) — нет.

## ADDED Requirements

### Requirement: Nightly release-профиль

Workflow `nightly.yml` ДОЛЖЕН (MUST): запускаться по schedule (ночь UTC, вне окна 08:00–19:00 МСК)
и вручную через `workflow_dispatch`; гонять тесты в **release-профиле** по той же matrix, что
build.yml (ubuntu: `cargo test --workspace --release`; astra: `cargo nextest run --workspace
--release` в astra-builder контейнере) с теми же release-knobs (codegen-units=1, LTO=thin) —
проверяется именно тот профиль, в котором собирается продовый `.deb`; иметь concurrency-группу
и щедрые `timeout-minutes` (release-компиляция тестов ~510s только на компиляцию). Падение
nightly ДОЛЖНО (MUST) оставлять видимый след (GitHub issue), а не только красный бейдж.

#### Scenario: Ночной прогон
- **WHEN** срабатывает schedule
- **THEN** обе ветки matrix гоняют тесты в release-профиле; release-only ошибки (кодоген, LTO, timing-чувствительные тесты) ловятся не позднее чем через сутки

#### Scenario: Падение nightly
- **WHEN** nightly-job завершился с ошибкой
- **THEN** создаётся/обновляется GitHub issue с ссылкой на прогон — сигнал не теряется

### Requirement: ГОСТ E2E в CI

GOST-фикстуры (CA → intermediate → leaf 2012-256/512, p12, отозванный leaf + CRL) ДОЛЖНЫ (MUST)
быть закоммичены в `tests/fixtures/gost/` и регенерируемы скриптом
`tests/scripts/gen-gost-fixtures.sh` (openssl + gost-engine; скрипт — источник правды).
Nightly astra-ветка ДОЛЖНА (MUST) гонять `--features gost-tests` (интеграционные `gost_*_real.rs`)
на этих фикстурах. Каталог фикстур ДОЛЖЕН (MUST) содержать README «тестовые ключи, не секреты».

#### Scenario: Регрессия ГОСТ-пути
- **WHEN** изменение ломает верификацию GOST-цепочки или challenge-response с GOST-ключом
- **THEN** nightly astra-job с `gost-tests` падает — регрессия видна не позднее чем через сутки, без ручного прогона

### Requirement: Hook-security инварианты в CI

Тесты hook-security (no_new_privs, uid-drop, fd-leak) ДОЛЖНЫ (MUST) гоняться в nightly
в выделенном container-job (root в контейнере: управляемый RLIMIT_NPROC, доступен uid-drop);
гейт — переменная окружения `TESSERA_HOOK_SECURITY_TESTS=1` вместо безусловного `#[ignore]`
(без маркера — skip с диагностикой).

#### Scenario: Прогон hook-security в nightly
- **WHEN** nightly-job выставляет маркер и поднимает RLIMIT_NPROC
- **THEN** инварианты no_new_privs/uid-drop/fd-leak проверяются реально (не skip), падение блокирует зелёный nightly

### Requirement: PKCS#11 smoke через SoftHSM

Nightly ДОЛЖЕН (MUST) гонять PKCS#11-путь (login, find_certificate, find_private_key_for_cert,
`C_Sign`, верификация) против softhsm2 с фикстурными RSA/ECDSA ключами
(`pkcs11_module=libsofthsm2.so`). GOST через SoftHSM НЕ эмулируется (нет GOST-механизмов) —
реальное железо остаётся в ручном чек-листе релиза.

#### Scenario: Регрессия PKCS#11-кода
- **WHEN** изменение ломает PKCS#11-flow (поиск объектов, подпись, перекодировку r||s)
- **THEN** softhsm-job nightly падает без участия физического токена

### Requirement: Периодический MAC-runtime прогон

`vagrant/scripts/test-mac.sh` (T1–T11, реальный libpdp/parsec enforcement) ДОЛЖЕН (MUST)
прогоняться автоматически не реже раза в неделю на Astra VM (vagrant-libvirt на hosted-раннере
с KVM либо self-hosted раннер — по итогам spike), с отчётом-артефактом прогона. Этот прогон
изолирован от nightly (не блокирует его) и от PR-пути.

#### Scenario: Регрессия MAC-enforcement
- **WHEN** изменение ломает runtime-применение МКЦ-метки (libpdp/parsec путь)
- **THEN** weekly MAC-job падает с отчётом — регрессия видна без ручного vagrant-прогона
