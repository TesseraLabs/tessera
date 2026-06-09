# Tasks: ci-hardening

## 1. Nightly release-профиль

- [ ] 1.1 Прогнать `nightly.yml` (создан 2026-06-09) вручную через workflow_dispatch, убедиться в зелёном прогоне обеих веток matrix (release-профиль, ubuntu+astra)
- [ ] 1.2 Шаг «упавший nightly → создать/обновить GitHub issue» (gh CLI при `failure()`), чтобы красный nightly не оставался незамеченным

## 2. ГОСТ E2E

- [ ] 2.1 `tests/scripts/gen-gost-fixtures.sh`: детерминированная генерация GOST-CA → intermediate → leaf 2012-256/512, p12-контейнеры, отозванный leaf + GOST-CRL (openssl+gost-engine); README в каталоге фикстур («тестовые ключи, не секреты»)
- [ ] 2.2 Закоммитить фикстуры в `tests/fixtures/gost/`; убедиться, что `gost_*_real.rs` тесты на них проходят локально (astra-builder контейнер)
- [ ] 2.3 Включить `--features gost-tests` в astra-ветку nightly; замерить длительность; решить open question про paths-фильтр для PR (изменения `src/gost/**`)

## 3. Hook-security инварианты

- [ ] 3.1 Перевести тесты no_new_privs/uid-drop/fd-leak с `#[ignore]` на env-гейт `TESSERA_HOOK_SECURITY_TESTS=1` (skip с диагностикой без маркера); локальная проверка под root-контейнером
- [ ] 3.2 Job `hook-security` в nightly: container от root, prlimit/ulimit -u перед прогоном, маркер выставлен; убедиться, что RLIMIT_NPROC-блокер снят

## 4. MAC-runtime (libpdp/parsec)

- [ ] 4.1 Spike: vagrant-libvirt на hosted GH-раннере — KVM доступен, влезает ли Astra box в диск, время прогона; зафиксировать выбор hosted vs self-hosted в design.md
- [ ] 4.2 Решить хостинг Astra box (GHCR OCI / Release-asset / self-hosted) с учётом лицензионных ограничений образа Astra
- [ ] 4.3 Weekly workflow: подъём VM → `vagrant/scripts/test-mac.sh` (T1–T11) → отчёт artifact'ом; адаптировать test-mac.sh под headless при необходимости
- [ ] 4.4 Обновить tessera-enterprise `openspec/specs/mac-integrity/spec.md:95` (KNOWN GAP testing) отдельным изменением в том репо

## 5. PKCS#11 smoke (SoftHSM)

- [ ] 5.1 Nightly-job softhsm2: инициализация токена, импорт фикстурных RSA/ECDSA ключа+серта, прогон PKCS#11-интеграционных тестов с `pkcs11_module=libsofthsm2.so` (login, find_certificate, C_Sign, верификация)
- [ ] 5.2 Чек-лист релиза: обязательный пункт «`tests/scripts/install-and-test.sh` прогнан на реальном железе (JaCarta-2 GOST + Рутокен)» — зафиксировать в docs/RELEASING или README релиз-процедуры

## 6. Спеки и документация

- [ ] 6.1 Синк дельт в main-спеки (`/opsx:sync` или archive): build-release (KNOWN GAP-список сокращён, новые требования), gost-crypto (gost-tests в CI), hooks (KNOWN GAP снят)
- [ ] 6.2 Обновить комментарий в build.yml («nightly workflow упомянут» → ссылка на существующий nightly.yml) и docs про CI-матрицу
