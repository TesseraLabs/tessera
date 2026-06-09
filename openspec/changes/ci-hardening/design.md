# Design: ci-hardening

## Context

CI сегодня: `build.yml` (matrix ubuntu stub / astra container, тесты в debug, .deb в release+LTO),
`lint.yml` (clippy -D warnings, cargo deny/audit). Пять направлений ручной верификации
перечислены KNOWN GAP'ами build-release спеки. Ограничения: PR-cycle быстрый (~3 мин ubuntu),
замедлять нельзя; shared GH-раннеры — RLIMIT_NPROC=64 на shared-UID, нет физических токенов,
нет ядра Astra/parsec; репо приватный (минуты Actions не бесплатны — тяжёлое не чаще nightly).

## Goals / Non-Goals

**Goals:**
- Перевести ГОСТ-путь, hook-security и release-профиль из «верифицировано вручную один раз»
  в «проверяется автоматически с известной периодичностью».
- MAC-runtime (libpdp/parsec) — автоматизированный периодический прогон с артефактом-отчётом.
- Не замедлить PR-путь и не раздуть стоимость Actions.

**Non-Goals:**
- Реальный USB/токен в CI (нет железа на hosted-раннерах) — остаётся ручным runbook'ом;
  закрывается компенсирующим softhsm2-smoke + чек-листом релиза.
- Коммерческий CI (tessera_mac_parsec FFI) — живёт в tessera-enterprise.
- Перестройка build.yml (кэши, matrix) — только дополнение новыми workflow/джобами.

## Decisions

1. **Тяжёлое — в nightly.yml, PR-путь не трогаем.** Nightly: schedule (ночь UTC, вне окна
   08:00–19:00 МСК) + workflow_dispatch; concurrency-группа; щедрые `timeout-minutes`.
   Состав: release-профиль тестов (обе ветки matrix), gost-tests, hook-security job.
   Альтернатива «всё в PR» отвергнута: +8–10 мин на каждый PR ради инвариантов, меняющихся
   редко; nightly ловит регрессию с лагом ≤24h — приемлемо для текущего темпа разработки.
2. **GOST-фикстуры: генерация скриптом, коммит в репо.** `tests/scripts/gen-gost-fixtures.sh`
   (openssl+gost-engine, доступен в astra-builder образе и любом Linux с libgost): корневой
   GOST-CA, intermediate, leaf 2012-256/512, p12-контейнеры, отозванный leaf + CRL.
   Коммитим артефакты (как существующие RSA/ECDSA фикстуры; ключи фикстурные, секретами не
   являются — каталог уже в allowlist tests/fixtures) — CI не зависит от наличия gost-engine
   на ubuntu-ветке; скрипт остаётся источником правды для регенерации. `--features gost-tests`
   гоняется в astra-ветке nightly (там gost-engine гарантирован); в PR — нет.
3. **Hook-security: env-гейт вместо `#[ignore]`.** Тесты переводятся с безусловного
   `#[ignore]` на проверку маркера `TESSERA_HOOK_SECURITY_TESTS=1` (skip с понятным сообщением
   без маркера). В nightly — job в контейнере (`container:` в GHA стартует процессом root,
   PID 1 в своём namespace): RLIMIT_NPROC поднимается `ulimit -u`/prlimit перед прогоном,
   uid-drop тестам доступен setuid (root в контейнере). Альтернатива self-hosted отвергнута
   для этого пункта: контейнера достаточно, инфраструктуру не плодим.
4. **MAC-runtime: vagrant+libvirt на hosted-раннере, weekly.** На GH Linux-раннерах доступен
   KVM (/dev/kvm) — vagrant-libvirt поднимает Astra VM из box'а; прогон test-mac.sh (T1–T11),
   отчёт — artifact. Открытые вопросы: где хостить Astra box (GHCR OCI-артефакт приватного
   репо — кандидат) и влезает ли образ в диск раннера (~14 GB свободных) — проверяется
   первой задачей; fallback — self-hosted раннер на выделенном гипервизоре (есть VBox-образ
   astra_1.8.4). Weekly, не nightly: прогон тяжёлый, MAC-слой меняется редко.
5. **SoftHSM2-smoke (компенсация гэпа №4).** Job (ubuntu, nightly): softhsm2 + импорт
   фикстурного RSA/ECDSA ключа/серта → прогон PKCS#11-пути (login, find, C_Sign, верификация)
   через существующие интеграционные тесты с `pkcs11_module=libsofthsm2.so`. GOST через
   softhsm не эмулируется (нет GOST-механизмов) — железные токены остаются в ручном runbook'е,
   привязка: пункт чек-листа релиза «install-and-test.sh прогнан на JaCarta+Рутокен».
6. **Маркер «ручное не забыто»**: KNOWN GAP №4 в спеке не снимается, а сужается до
   «реальное железо — ручной чек-лист релиза»; остальные пункты (1,2,4-hooks,5) из списка
   уходят.

## Risks / Trade-offs

- **Nightly зелёный, но никто не смотрит.** Митигация: упавший nightly создаёт/обновляет
  issue (actions: `gh issue` шаг при failure) — пассивный сигнал вместо тишины.
- **vagrant-libvirt на hosted — самая хрупкая часть** (диск, сеть box'а, время прогона).
  Поэтому она weekly, изолирована в свой workflow/job и не блокирует остальной nightly.
- **Закоммиченные GOST-ключи** могут смутить сканеры секретов. Митигация: README в каталоге
  фикстур («тестовые ключи, генерируются gen-gost-fixtures.sh, не секреты») + allowlist-паттерн.
- **Стоимость минут**: nightly ~30–40 мин/сутки + weekly ~1ч — в пределах разумного для
  приватного репо; concurrency cancel-in-progress предотвращает наложение.

## Open Questions

- Хостинг Astra box для vagrant-libvirt (GHCR OCI vs Release-asset vs self-hosted).
- Гонять ли gost-tests и в PR при изменениях `crates/tessera_core/src/gost/**`
  (paths-фильтр) — решить после замера длительности.
