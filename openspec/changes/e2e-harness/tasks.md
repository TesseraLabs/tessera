# Tasks: e2e-harness

## 1. Каркас раннера

- [ ] 1.1 Крейт `crates/xtask` как член workspace + alias `cargo xtask` в `.cargo/config.toml`; убедиться, что `cargo test --workspace` его не трогает и в `.deb` он не попадает
- [ ] 1.2 Модель реестра (serde): suite, кейс, шаги `run`/`expect_journal`/`expect_file`/`pause`, ожидания `exit_code`/`stdout_matches`/`stderr_matches`; вывод режима кейса из состава шагов
- [ ] 1.3 Загрузка профиля и `~/.config/tessera-e2e/stand.toml`; подстановка `{{…}}`; понятная ошибка с образцом файла при его отсутствии
- [ ] 1.3a Разрешение ссылок `op://` через `op read` на старте прогона (до первого кейса), значения только в памяти; недоступность хранилища — понятная ошибка, а не провал auth-кейсов; проверить, что разрешённые значения не попадают в отчёт и артефакты
- [ ] 1.4 Драйвер `docker` (exec, recreate) и драйвер `ssh` (одно соединение на шаг, без ControlMaster — лимит сессий Astra)
- [ ] 1.5 Матчинг `requires` кейса против `capabilities` профиля → `SKIP` с причиной
- [ ] 1.6 Исполнитель кейса: последовательные шаги, таймауты, teardown при любом исходе включая `Ctrl-C`; отдельная классификация провала teardown
- [ ] 1.7 Интерактивный `pause` (ok/fail/skip + `capture`) и режим `--non-interactive` со статусом `BLOCKED`

## 2. Отчёты и baseline

- [ ] 2.1 `report.json` + `report.md`, пять статусов, метаданные прогона (профиль, версия пакета, коммит)
- [ ] 2.2 Сбор артефактов для провалов: срез journald за время кейса, `/etc/tessera/*`, вывод `tessera check`, stdout/stderr шагов
- [ ] 2.3 Чтение и диff `BASELINE.md`; ненулевой код возврата при расхождении, а также при любом `ERROR` или провале teardown — независимо от baseline
- [ ] 2.4 `--update-baseline` как явная команда; отказ записывать в baseline `ERROR` и провал teardown; `runs/` в `.gitignore`
- [ ] 2.5 Провенанс пакета в отчёте: sha256 `.deb`, источник (локальный путь либо run id `build.yml`), коммит сборки; пометка «провенанс не установлен», когда коммит артефакта подтвердить нечем

## 3. Образы и хелперы

- [ ] 3.1 `tests/e2e/images/ubuntu.Dockerfile` (ubuntu:24.04 + systemd, udev, dosfstools); проверить `--privileged --cgroupns=host`, `systemctl is-system-running`
- [ ] 3.2 `tests/e2e/images/astra.Dockerfile` (astra/ubi18-systemd:1.8.5 + udev, dosfstools, parsec-base); хелпер поднятия `systemd-udevd` вручную вместо Astra-шного init
- [ ] 3.3 `tests/e2e/helpers/pam-drive.c` — раздельные коды по фазам; сборка в обоих образах
- [ ] 3.4 `tests/e2e/helpers/usb-loop.sh` — attach/detach/swap: loop + vfat + udev-правило `ID_BUS=usb`; идемпотентность, re-arm после teardown
- [ ] 3.5 `tests/e2e/helpers/ocsp-responder.sh` — запуск/остановка по pidfile (не `pkill -f`: паттерн самоматчит ssh-шелл)
- [ ] 3.6 Получение `.deb`: путь из `stand.toml` либо `gh run download` артефакта `build.yml`; проверка архитектуры под профиль и фиксация провенанса (см. 2.5) — при скачивании коммит берётся из метаданных прогона

## 4. Первый реестр — ubuntu-container

- [ ] 4.1 `10-install.yaml`: миграция `install-and-test.sh` и `test_integrate_pam.sh` в кейсы (раскладка, служба неактивна без конфига, integrate/unintegrate, purge)
- [ ] 4.2 `20-auth.yaml`: валидное удостоверение, неверный PIN, нет носителя, просроченный, чужой host_binding, чужой user_binding, битый p12, цепочка через intermediate
- [ ] 4.3 Первый полный прогон `--profile ubuntu-container`, разбор каждого результата глазами, заполнение `BASELINE.md`
- [ ] 4.4 `test_integrate_pam.sh` удалить после миграции. `install-and-test.sh` НЕ удалять: на него опираются `ci-hardening` (задача 5.2, чек-лист релиза) и `gost-pkcs11` (задача 4.1) как на единственный путь проверки вендорского железа — свести его к hardware-runbook'у (JaCarta-2 GOST, Рутокен), убрав то, что покрыто реестром, и сослаться на реестр в шапке. `test_build_deb.sh` и `verify-reproducible.sh` оставить на месте
- [ ] 4.5 Кейсы с реальным токеном (`mixed`, профиль `astra-vm`) — happy-path, wrong-PIN→MAXTRIES, removal-enforcement на обоих вендорах; после их появления и синхронной правки `ci-hardening` 5.2 и `gost-pkcs11` 4.1 решить судьбу runbook'а отдельно

## 5. Остальные suite'ы

- [ ] 5.1 `30-roles.yaml` — allowed_roles, роль вне списка, права роль-учётной записи
- [ ] 5.2 `40-revocation.yaml` — свежий CRL, просроченный CRL (fail-closed), OCSP, `crl_then_ocsp`, недоступность сети
- [ ] 5.3 `50-enforcement.yaml` — группы, sudoers, лимиты на сессии. **Заблокирован**: чтобы проверить применение прав, нужно выбрать роль, а вход по имени ролевой учётной записи не реализован (KNOWN GAP в `role-selection`, см. красные ROLE-001…004 в baseline). Кейсы, написанные сейчас, падали бы на выборе роли и не отличали бы «права не применились» от «роль не выбралась». Делать после перепроводки role-selection; сам enforcement — отдельный открытый change `linux-session-enforcement` (0/15)
- [ ] 5.4 `60-issuer.yaml` — выпуск, делегирование, `issuer serve` отдаёт кабинет, подпись реестра

## 6. Профиль astra-container

- [ ] 6.1 Поднять профиль, разобрать открытый вопрос: чем поднимать monitord без systemd и как ведёт себя `monitor_fail_mode` в этом режиме
- [ ] 6.2 Прогнать существующий реестр, зафиксировать расхождения с ubuntu-профилем в baseline
- [ ] 6.3 Приватный реестр в `tessera-ws/tests/e2e-private/` + свой baseline; проверить склейку через `--cases-dir`

## 7. Профиль astra-vm

- [x] 7.1 Профиль `astra-vm` заведён и прогнан (2026-08-10): 57 кейсов в baseline, красный только CONF-013 — тот же, что и в контейнере. Потребовало четырёх правок раннера (поле `sudo` у хоста, доставка потоком `tar` под root вместо `scp` из-за `nochmodx`, рабочий каталог стенда вместо `WORKDIR` образа, не-login оболочка против баннера Astra) и правки `install-package.sh` (сверка sha256 пакета вместо номера версии). Teardown по SSH с `--unintegrate` НЕ проверен — кейсы установки на профиле не гонялись, см. 7.1a
- [ ] 7.1a Идемпотентный teardown по SSH для suite установки: `integrate-pam.sh --unintegrate` для каждого затронутого сервиса ДО purge (postrm снимает только `@include tessera*`, оставляя `session required pam_tessera.so` на удалённый модуль → ломается sudo и вход), затем purge пакета, снос `/etc/tessera`, отвязка loop
- [ ] 7.2 Проверить восстановление PAM на путях провала, таймаута и `Ctrl-C`: намеренно прервать кейс после интеграции и убедиться, что sudo и вход остались работоспособными
- [ ] 7.3 `70-mac.yaml` — МКЦ на сессии, поведение на МРД-системе, ЗПС (только этот профиль)
- [ ] 7.4 `80-desktop.yaml` — выбор роли в fly-dm, извлечение носителя при активной сессии (`manual`/`mixed`)
- [ ] 7.5 Прогон полного реестра на VM, заполнение baseline профиля

## 8. Документация

- [ ] 8.1 `tests/e2e/README.md`: как добавить кейс, как запустить, что означает каждый статус, что делать с расхождением
- [ ] 8.2 Образец `stand.toml` с комментариями и ссылками `op://` вместо паролей
- [ ] 8.3 Пункт «прогон реестра» в чек-лист релиза

## 9. Трассируемость и покрытие спек

Реестр знает, на какую спеку смотрит каждый кейс (`requirement:`), но связь
ничем не проверяется, а вопрос «что из спек вообще не проверяется» до сих пор
требовал ручного пересчёта. На срезе 2026-08-10: 32 спеки, 338 сценариев,
29 кейсов, 23 спеки без единого кейса.

- [x] 9.1 Валидация `requirement:` при загрузке реестра: путь обязан существовать в `openspec/specs/`; спека, ещё не синкнутая из change'а, находится в `openspec/changes/*/specs/` и проходит с предупреждением; не найденная нигде — ошибка разбора, прогон не начинается
- [x] 9.2 `cargo xtask e2e-coverage` — сборка генерируемого участка `tests/e2e/COVERAGE.md` из реестра и спек; `--check` для CI, детерминированная сортировка
- [x] 9.3 Job `e2e-registry` в `lint.yml`: `cargo xtask e2e-coverage --check` без стенда
- [x] 9.4 Волна 1 — кейсы на `configuration` (13), `trust-chain-validation` (5), `pam-integration` (3), `pam-module-runtime` (4). Прогнаны на `ubuntu-container`, артефакт `af35b94`. CONF-013 красный намеренно: спека требует WARN на устаревший ключ логирования, продукт принимает его молча
- [x] 9.4a Строка `session` в тестовом сервисе `certauth` (`deploy-fixtures.sh`) — добавлена, весь реестр перепрогнан, расхождений нет
- [ ] 9.6a Пакет первичной настройки для стенда (удостоверение узла + подписанный манифест): без него успешный импорт и повторный импорт как no-op не проверяются, покрыты только отказные пути
- [ ] 9.4b Фикстура удостоверения, истёкшего в пределах `clock_skew_seconds`: существующая `expired_leaf.p12` просрочена на годы, сценарий «истёк в пределах допуска» ею не проверяется
- [x] 9.5 Волна 2 — `logging-audit` (3), `host-identity` (3), `hooks` (2), `session-monitoring` (1), `ipc-protocol` (1). Потребовала `helpers/setup/start-monitord.sh`: демон в контейнере поднимается drop-in'ом с `--no-dbus`, иначе не стартует без системной шины
- [ ] 9.5a Применение действия к сессии при извлечении носителя (блокировка, завершение) — упирается в logind, наблюдать только на профиле с настоящей системой. Демон обнаружение фиксирует, дальше идёт fail-closed путь с перезагрузкой, и в контейнере его проверять нельзя
- [x] 9.6 Волна 3 (сделана 2026-08-10: issuer-signing 4, device-tags 4, usb-media-pkcs12 3, cli-diagnostics 3, device-enrollment 2, licensing-distribution 1, challenge-response 1) — `issuer-signing`, `usb-media-pkcs12`, `challenge-response`, `cli-diagnostics`, `device-enrollment`, `device-tags`, `licensing-distribution`
- [ ] 9.7 Волна 4 — доборы сценариев уже затронутых спек (`cert-authentication-flow`, `revocation`, `role-selection`, `role-store`, `cert-issuance`)
- [ ] 9.8 Волна 5 — `gost-crypto` (gost-engine в образе), профиль `astra-vm` (`mac-integrity`, `fly-dm-greeter`, `clone-image-bootstrap`), профиль Windows. Разделы 6 и 7 этого файла — та же работа со стороны профилей
