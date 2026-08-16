# Baseline e2e

Зафиксированное состояние кейсов. Обновляется только явной командой `--update-baseline`.
Статусы `ERROR` и провалы teardown здесь не фиксируются.

## Чего в baseline нет и почему

Отсутствие строки — это «не прогонялось», а не «зелено». Профиль `astra-vm`
снят на 57 кейсах из 82, и шесть suite'ов в нём не участвовали. Полный прогон
профиля вернёт их разом, и без этой записи он читался бы как лавина регрессий:

- **INST (5), `10-install`** — идемпотентного teardown по SSH нет. `postrm`
  снимает только `@include tessera*`, оставляя `session required pam_tessera.so`
  на удалённый модуль, и машина теряет sudo и вход; пересоздать её нельзя.
  Записано в `openspec/changes/e2e-harness/tasks.md`, задачи 7.1 и 7.1a.
- **ISS (7), `60-issuer`** и **SIGN (4), `61-issuer-signing`** — подготовка
  `deploy-issuer` требует бинарь `issuer`, который раннер везёт в окружение как
  артефакт стенда (`[[artifacts]]` в `stand.toml`). В прогоне 2026-08-10 он не
  объявлялся: «помимо пакета в окружение ничего не везлось»
  (`runs/2026-08-10-astra-vm-af35b94/report.md`). Подготовка отдала бы `ERROR`.
- **TOK (4), `70-token-carrier`** — все кейсы требуют `hardware-token`, а
  профиль его намеренно не объявляет: USB-проброс в эту виртуальную машину не
  настроен (`profiles/astra-vm.toml`). Прогон дал бы `SKIP`, а не проверку.
- **MON (2), `23-monitord`** — подготовка `start-monitord` написана под
  окружение без D-Bus: она правит штатный юнит drop-in'ом `--no-dbus`, отключая
  ровно тот путь через logind, ради которого профиль и нужен, а снять drop-in
  на живой машине нечем — teardown у suite'ов нет. Отдельной записи о причине
  пропуска в репозитории нет, это восстановление по коду подготовки.
- **PAMI (3), `17-pam-integration`** — не прогонялся, причина не записана.
  Кейсы работают на временных файлах в `/tmp` и живой PAM-стек не трогают;
  препятствий, видимых по репозиторию, нет.
- **CLI-004…CLI-010 (7), `12-cli-diagnostics`** — написаны вместе с изменением
  `gost-engine-preload`, прогона ещё не было. Прогонять их на `.deb` из `main`
  бессмысленно как проверка: ГОСТ-шага префлайта там пока нет, поэтому
  CLI-004/005/006 на нём заведомо красные — это ожидаемое состояние «кейс
  написан раньше кода», а не регрессия. CLI-007 закрывает второй, уже
  существующий барьер (валидатор пути) и на `main` должен быть зелёным;
  расхождение здесь означало бы, что кейс воспроизводит не то. CLI-006 и
  CLI-008 требуют `gost-engine` и вне `astra-vm` дают `SKIP`. Первый
  осмысленный прогон — на сборке с этим изменением; до него ни одна из семи
  строк в таблицу ниже не попадает.

- **CLI-010 добавлен позже остальных** — по находке независимого ревью уже
  после первой правки шага: запись о неверной паре `mode`/`crypto_backend`
  выдавалась только когда разрешён ГОСТ, то есть проверка режима зависела от
  настройки ГОСТа, и обычная RSA/ECDSA-конфигурация с той же неработающей
  парой проходила префлайт молча. Кейс не прогонялся ни разу; на `.deb` из
  `main` он заведомо красный, потому что записи `pkcs11_openssl_unsupported`
  там ещё нет.

- **CLI-005 переписан по итогам ревью PR #94.** Прежнее ожидание — `exit 0` и
  `[WARN ] gost_engine_configured_unused` — закрепляло дефект: режим хелпера
  `gost-engine-unused` подставляет заведомо неисправный движок, а
  аутентификация грузит его по самому факту заданного пути, так что на такой
  машине не входит никто. Теперь кейс ждёт `[ERROR] gost_engine_load_failed` и
  `exit 1`. Прежнюю ветку (движок исправен, ГОСТ-подписи не разрешены →
  предупреждение и `exit 0`) проверяет новый CLI-008 на настоящем движке.

- **CLI-008 и CLI-009 опираются на новые режимы `config-mutate.sh`** —
  `gost-engine-unused-real` и `gost-pkcs11-openssl`. До первого прогона на
  стенде сами режимы тоже не проверены на живой системе: локально сверен
  только результат подстановки на `dist/config/config.toml.example`.

- **Изменение привилегированной загрузки конфигурации в CLI затрагивает весь
  реестр.** `tessera daemon`, `tessera check` и `tessera enroll` перешли на
  `load_privileged_validated_config`, поэтому на стенде, где `config.toml`,
  якоря, CRL, `pkcs11_module` или `gost_engine_path` лежат не под root или
  доступны на запись остальным, красными станут не только ГОСТ-кейсы, а все
  кейсы, которые дёргают эти команды. Такой результат — сигнал о правах на
  стенде, а не о дефекте продукта; проверять `sudo tessera check` до прогона.

| id | статус | дата | версия | профиль | комментарий |
|---|---|---|---|---|---|
| AUTH-001 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| AUTH-002 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| AUTH-003 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| CHAL-001 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| CLI-001 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| CLI-002 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| CLI-003 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| CONF-001 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| CONF-002 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| CONF-003 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| CONF-004 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| CONF-005 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| CONF-006 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| CONF-007 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| CONF-008 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| CONF-009 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| CONF-010 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| CONF-011 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| CONF-012 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| CONF-013 | FAIL | 2026-08-10 | 0.5.0-1 | astra-vm | Тот же красный, что и на ubuntu-container: спека требует WARN «deprecated and ignored» на `[logging].syslog_facility`, продукт принимает ключ молча. Расхождение спека↔код, одинаковое на обоих профилях |
| ENR-001 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| ENR-002 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| HOOK-001 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| HOOK-002 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| HOST-001 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| HOST-002 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| HOST-003 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| LIC-001 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| LOG-001 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| LOG-002 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| LOG-003 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| PMR-001 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| PMR-002 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| PMR-003 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| PMR-004 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| REV-001 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| REV-002 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| REV-003 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| REV-004 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| REV-005 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| REV-006 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| ROLE-001 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| ROLE-002 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| ROLE-004 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| ROLE-005 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| TAG-001 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| TAG-002 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| TAG-003 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| TAG-004 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| TRUST-001 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| TRUST-002 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| TRUST-003 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| TRUST-004 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| TRUST-005 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| USB-001 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| USB-002 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| USB-003 | PASS | 2026-08-10 | 0.5.0-1 | astra-vm |  |
| AUTH-001 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| AUTH-002 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container | Был красным на дефекте PAM_MAXTRIES (модуль отдавал 8 PAM_CRED_INSUFFICIENT вместо 11); закрыт изменением pam-maxtries-fix, проверено на артефакте сборки 83613888 |
| AUTH-003 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| CHAL-001 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| CLI-001 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| CLI-002 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| CLI-003 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| CONF-001 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| CONF-002 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| CONF-003 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| CONF-004 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| CONF-005 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| CONF-006 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| CONF-007 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| CONF-008 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| CONF-009 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| CONF-010 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| CONF-011 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| CONF-012 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| CONF-013 | FAIL | 2026-08-10 | 0.5.0-1 | ubuntu-container | Красный намеренно: спека configuration требует WARN «deprecated and ignored» на `[logging].syslog_facility`, продукт принимает ключ молча (ни в выводе `tessera check`, ни при `TESSERA_LOG=debug`). Администратор, задавший ключ, считает журналирование настроенным, а оно не настроено. Расхождение спека↔код не разведено |
| ENR-001 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| ENR-002 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| HOOK-001 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| HOOK-002 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| HOST-001 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| HOST-002 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| HOST-003 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| INST-001 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| INST-002 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| INST-003 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| INST-004 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| INST-005 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| ISS-001 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| ISS-002 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| ISS-003 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| ISS-004 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| ISS-005 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container | Сквозной кейс, вскрывший четыре дефекта совместимости выпуска и проверки: keyUsage/EKU листа, расходившиеся дефолты profile_version, непригодные рамки делегирования и требование роли. Все закрыты; зелёный с role-account-login |
| ISS-006 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| ISS-007 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| LIC-001 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| LOG-001 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| LOG-002 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| LOG-003 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| MON-001 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| MON-003 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| PAMI-001 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| PAMI-002 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| PAMI-003 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| PMR-001 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| PMR-002 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| PMR-003 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| PMR-004 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| REV-001 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| REV-002 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| REV-003 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| REV-004 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| REV-005 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| REV-006 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| ROLE-001 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container | Был красным до перепроводки role-selection: модуль спрашивал роль prompt'ом вместо вывода из имени учётной записи входа. Закрыт изменением role-account-login |
| ROLE-002 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container | Был красным до перепроводки role-selection: модуль спрашивал роль prompt'ом вместо вывода из имени учётной записи входа. Закрыт изменением role-account-login |
| ROLE-004 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container | Был красным до перепроводки role-selection: модуль спрашивал роль prompt'ом вместо вывода из имени учётной записи входа. Закрыт изменением role-account-login |
| ROLE-005 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| SIGN-001 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| SIGN-002 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| SIGN-003 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| SIGN-004 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| TAG-001 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| TAG-002 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| TAG-003 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| TAG-004 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| TOK-001 | SKIP | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| TOK-002 | SKIP | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| TOK-003 | SKIP | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| TOK-004 | SKIP | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| TRUST-001 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| TRUST-002 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| TRUST-003 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| TRUST-004 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| TRUST-005 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| USB-001 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| USB-002 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
| USB-003 | PASS | 2026-08-10 | 0.5.0-1 | ubuntu-container |  |
