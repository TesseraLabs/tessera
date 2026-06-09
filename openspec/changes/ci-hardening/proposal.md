# Proposal: ci-hardening

## Why

build-release спека (требование «Тестовое покрытие (evidence)») перечисляет шесть пунктов
KNOWN GAP — то, что НЕ проверяется автоматически:

1. **ГОСТ end-to-end** — фикстуры `tests/fixtures/gost/` не закоммичены, feature `gost-tests`
   не включается в CI (gost-crypto/spec.md): весь ГОСТ-путь проверяется только вручную.
2. **Реальный libpdp/parsec enforcement** — CI только компилирует astra-таргет; runtime —
   ручной `vagrant/scripts/test-mac.sh` (T1–T11; tessera-enterprise mac-integrity спека).
3. **Hook-security инварианты** (no_new_privs, uid-drop, fd-leak) — `#[ignore]` из-за
   RLIMIT_NPROC=64 на shared-UID GH-раннерах (hooks/spec.md): security-критичные тесты
   верифицированы только вручную.
4. **Полный flow с реальным USB/токеном** — `#[ignore]`, ручной runbook
   `tests/scripts/install-and-test.sh`.
5. **Release-профиль тестов** — nightly workflow упомянут в комментарии build.yml, не существует
   (закрывается workflow'ом `nightly.yml`; этот change фиксирует его как требование спеки).

Каждый ручной пункт — это регрессия, которую CI молча пропустит. Для СЗИ с fail-closed
конвенциями «верифицировано один раз вручную» — недостаточный уровень evidence.

## What Changes

- **ГОСТ E2E в CI**: детерминированная генерация GOST-фикстур скриптом (gost-engine в
  astra-builder образе), коммит фикстур в `tests/fixtures/gost/`, прогон `--features gost-tests`
  в astra-ветке CI (nightly; в PR-ветке — по бюджету времени).
- **Hook-security инварианты в CI**: выделенный container-job (контейнер в GH Actions стартует
  от root → свой UID-неймспейс и управляемый RLIMIT_NPROC), снятие `#[ignore]` с тестов
  no_new_privs/uid-drop/fd-leak при наличии маркера окружения (env-гейт вместо безусловного ignore).
- **MAC-runtime автоматизация**: периодический (nightly/weekly) прогон `vagrant/scripts/test-mac.sh`
  на Astra VM — vagrant+libvirt на GH-раннере (KVM доступен на Linux-раннерах) либо self-hosted
  Astra-раннер; выбор — в design.md. Синхронно обновляется enterprise mac-integrity спека.
- **PKCS#11 smoke через SoftHSM**: автоматизируемая часть гэпа №4 — прогон PKCS#11-пути
  (RSA/ECDSA) против softhsm2 в CI; реальный USB/токен остаётся ручным runbook'ом,
  привязанным к чек-листу релиза (полное закрытие №4 — вне scope, честно остаётся KNOWN GAP).
- **Nightly release-профиль** — требование к существованию и содержимому `nightly.yml`
  (schedule+dispatch, release-профиль тестов, concurrency, щедрые таймауты).

## Capabilities

### Modified Capabilities

- `build-release`: требование «Тестовое покрытие (evidence)» — KNOWN GAP-список сокращается;
  новые требования: «ГОСТ E2E в CI», «Hook-security инварианты в CI», «Nightly release-профиль»,
  «PKCS#11 smoke через SoftHSM», «Периодический MAC-runtime прогон».
- `gost-crypto`: требование «Feature-флаги» — `gost-tests` включается в CI с закоммиченными
  фикстурами; снимается KNOWN GAP (testing).
- `hooks`: новое требование — hook-security инварианты проверяются автоматически в CI;
  снимается KNOWN GAP (testing).

## Impact

- `.github/workflows/`: `nightly.yml` (release-профиль + тяжёлые джобы), правки `build.yml`
  не требуются (PR-путь не замедляется — тяжёлое уходит в nightly).
- `tests/`: фикстуры `tests/fixtures/gost/` + скрипт генерации `tests/scripts/gen-gost-fixtures.sh`;
  env-гейт вместо `#[ignore]` в hook-security тестах; softhsm2-настройка для PKCS#11 smoke.
- `vagrant/`: возможная адаптация test-mac.sh под headless CI-прогон.
- tessera-enterprise: KNOWN GAP в `openspec/specs/mac-integrity/spec.md:95` обновляется
  отдельным изменением в том репо (здесь — только открытая часть).
- Время PR-CI не растёт: все новые джобы — nightly/weekly или отдельные container-джобы вне PR-пути.
