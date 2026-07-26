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
- [ ] 5.3 `50-enforcement.yaml` — группы, sudoers, лимиты на сессии
- [ ] 5.4 `60-issuer.yaml` — выпуск, делегирование, `issuer serve` отдаёт кабинет, подпись реестра

## 6. Профиль astra-container

- [ ] 6.1 Поднять профиль, разобрать открытый вопрос: чем поднимать monitord без systemd и как ведёт себя `monitor_fail_mode` в этом режиме
- [ ] 6.2 Прогнать существующий реестр, зафиксировать расхождения с ubuntu-профилем в baseline
- [ ] 6.3 Приватный реестр в `tessera-ws/tests/e2e-private/` + свой baseline; проверить склейку через `--cases-dir`

## 7. Профиль astra-vm

- [ ] 7.1 Профиль и идемпотентный teardown по SSH: `integrate-pam.sh --unintegrate` для каждого затронутого сервиса ДО purge (postrm снимает только `@include tessera*`, оставляя `session required pam_tessera.so` на удалённый модуль → ломается sudo и вход), затем purge пакета, снос `/etc/tessera`, отвязка loop
- [ ] 7.2 Проверить восстановление PAM на путях провала, таймаута и `Ctrl-C`: намеренно прервать кейс после интеграции и убедиться, что sudo и вход остались работоспособными
- [ ] 7.3 `70-mac.yaml` — МКЦ на сессии, поведение на МРД-системе, ЗПС (только этот профиль)
- [ ] 7.4 `80-desktop.yaml` — выбор роли в fly-dm, извлечение носителя при активной сессии (`manual`/`mixed`)
- [ ] 7.5 Прогон полного реестра на VM, заполнение baseline профиля

## 8. Документация

- [ ] 8.1 `tests/e2e/README.md`: как добавить кейс, как запустить, что означает каждый статус, что делать с расхождением
- [ ] 8.2 Образец `stand.toml` с комментариями и ссылками `op://` вместо паролей
- [ ] 8.3 Пункт «прогон реестра» в чек-лист релиза
