# Покрытие спек e2e-реестром

Участок между маркерами `BEGIN GENERATED` и `END GENERATED` собирается командой
`cargo xtask e2e-coverage` — править его руками бессмысленно, следующая же
генерация сотрёт правку. Остальной текст рукописный.

Единица покрытия — сценарий спеки (`#### Scenario:`), а не спека целиком: спека
на 19 сценариев, к которой привязан один кейс, покрыта на один сценарий, а не
«покрыта». Связь даёт поле `requirement:` в кейсе.

<!-- BEGIN GENERATED -->
## Сводка

| | |
|---|---|
| Спек в `openspec/specs/` | 32 |
| Сценариев в них | 338 |
| Кейсов в реестре | 127 |
| Спек, к которым привязан хотя бы один кейс | 26 |
| Спек без единого кейса | 6 |

## Спеки, к которым привязаны кейсы

| Спека | Сценариев | Кейсов |
|---|---:|---:|
| configuration | 19 | 13 |
| device-enrollment | 5 | 13 |
| cli-diagnostics | 3 | 9 |
| revocation | 19 | 6 |
| cert-authentication-flow | 15 | 6 |
| trust-chain-validation | 14 | 5 |
| issuer-signing | 15 | 4 |
| pam-module-runtime | 9 | 4 |
| device-tags | 6 | 4 |
| role-selection | 19 | 3 |
| cert-issuance | 16 | 3 |
| logging-audit | 14 | 3 |
| usb-media-pkcs12 | 11 | 3 |
| pam-integration | 9 | 3 |
| host-identity | 6 | 3 |
| build-release | 10 | 2 |
| hooks | 7 | 2 |
| role-store | 13 | 1 |
| cert-scope-binding | 12 | 1 |
| issuance-journal | 12 | 1 |
| daemon-lifecycle | 10 | 1 |
| ipc-protocol | 10 | 1 |
| session-monitoring | 9 | 1 |
| gost-crypto | 7 | 1 |
| licensing-distribution | 5 | 1 |
| challenge-response | 4 | 1 |

## Спеки без кейсов

| Спека | Сценариев |
|---|---:|
| token-pkcs11 | 26 |
| windows-privileged-path | 10 |
| windows-removable-media | 8 |
| mac-integrity | 6 |
| clone-image-bootstrap | 5 |
| fly-dm-greeter | 4 |

## Спеки, ещё не синкнутые из предложений

На них ссылается кейсов: 32. Именно на столько сумма по таблицам выше меньше числа кейсов в сводке: строки в тех таблицах эти спеки получат, когда переедут в `openspec/specs/`.

| Спека | Предложение | Кейсов |
|---|---|---:|
| qr-login-method | online-approval | 15 |
| audit-chain | audit-chain | 6 |
| codes-operator-cli | codes-operator-cli | 5 |
| credential-packaging | issuer-key-generation | 2 |
| token-data-carrier | pkcs12-token-carrier | 2 |
| carrier-presence | token-presence-monitor | 1 |
| device-unenroll | codes-device-artifacts | 1 |
<!-- END GENERATED -->

## Чем проверять непокрытое

На существующих профилях, без новых стендов.

| Спека | Чем проверять |
|---|---|
| configuration | ubuntu-container: конфиг с лишним полем / битый / отсутствующий, наблюдать отказ |
| trust-chain-validation | ubuntu-container: фикстуры цепочек через pam-drive |
| logging-audit | ubuntu-container: `expect_journal` под identifier `pam_tessera` |
| issuer-signing | ubuntu-container: бинарь issuer уже доставляется в стенд |
| usb-media-pkcs12 | ubuntu-container: эмуляция носителя через `usb-loop.sh` |
| ipc-protocol | ubuntu-container: сокет демона |
| pam-integration | ubuntu-container: три режима control-flags в стеке |
| pam-module-runtime | ubuntu-container: pam-drive, panic guard на C-границе |
| session-monitoring | ubuntu-container: требует service-manager, он есть |
| hooks | ubuntu-container: скрипты стадий |
| host-identity | ubuntu-container: источники идентичности узла |
| device-tags | ubuntu-container |
| device-enrollment | ubuntu-container |
| licensing-distribution | ubuntu-container: проверка артефактов пакета, рядом с 10-install |
| challenge-response | ubuntu-container: round-trip подписи на фикстуре |
| cli-diagnostics | ubuntu-container: `tessera check` |
| gost-crypto | нужен gost-engine в образе — доработка `ubuntu.Dockerfile` |
| token-pkcs11 | частично SoftHSM2 в образе; остальное — `hardware-token`, только живое железо |
| clone-image-bootstrap | нужен профиль `astra-vm` (эталонный образ) |
| mac-integrity | нужен профиль `astra-vm` (capability `mac`) |
| fly-dm-greeter | нужен профиль `astra-vm` (capability `graphics`) |
| windows-privileged-path | профиля Windows нет вовсе |
| windows-removable-media | профиля Windows нет вовсе |

## Волны

Порядок задан ценой ошибки: сначала то, чей отказ пускает не того или молча
отключает защиту.

**Волна 0 — механика.** Без неё матрица устареет к следующему PR.
- Валидация поля `requirement:` в раннере: ссылка обязана иметь ровно вид
  `openspec/specs/<имя>/spec.md`. Если файла по нему ещё нет, спека ищется по
  имени в `openspec/changes/*/specs/` — это способ разрешить ссылку на спеку,
  ещё не синкнутую из предложения, а не вторая допустимая форма записи.
  Всё остальное — ошибка разбора реестра, не молчание.
- Сборка генерируемого участка этого файла командой `cargo xtask e2e-coverage`;
  проверка в CI (`--check`), что закоммиченная версия совпадает со сгенерированной.

**Волна 1 — фундамент отказа. Сделана 2026-08-10.** `configuration` (13 кейсов),
`trust-chain-validation` (5), `pam-integration` (3), `pam-module-runtime` (4).
Прогнано на `ubuntu-container`, пакет из сборки `af35b94`.

**Волна 2 — наблюдаемость и границы. Сделана 2026-08-10.** `logging-audit` (3),
`host-identity` (3), `hooks` (2), `session-monitoring` (1), `ipc-protocol` (1).

Волна 2 потребовала двух доработок стенда, и обе меняют условия всего реестра:
строка `session` в тестовом сервисе `certauth` (без неё фазы сессии до модуля
не доходят — пустой стек PAM завершает успехом сам) и запуск демона с
`--no-dbus` через drop-in к юниту (без системной шины демон не стартует, потому
что действия над сессией идут через logind).

Остаётся непроверенным на контейнерных профилях: применение действия к сессии
при извлечении носителя — оно упирается в logind, и наблюдать его надо на
профиле с настоящей системой. Сценарий «удостоверение истекло в пределах
допуска часов» требует фикстуры, просроченной на минуты, а имеющаяся
просрочена на годы.

**Волна 3 — выпуск и носитель. Сделана 2026-08-10.** `issuer-signing` (4),
`device-tags` (4), `usb-media-pkcs12` (3), `cli-diagnostics` (3),
`device-enrollment` (2), `licensing-distribution` (1), `challenge-response` (1).

Непокрытым осознанно осталось: успешный импорт пакета первичной настройки и
повторный импорт как no-op — для них нужен собранный пакет с удостоверением
узла и подписанным манифестом, а его сборка относится к стороне выпуска, не к
проверяемому устройству.

Из волны 3 удалён кейс регистрации сессии в демоне: снаружи она ненаблюдаема,
и проверка зеленела от фоновых записей журнала. Плавающий кейс хуже
отсутствующего — он тратит разбор и создаёт видимость покрытия.

**Волна 4 — доборы существующих спек.** Сценарии `cert-authentication-flow`,
`revocation`, `role-selection`, `role-store`, `cert-issuance`, оставшиеся без
кейсов.

**Волна 5 — новые окружения.** Профиль `astra-vm` заведён 2026-08-10 и прогнан:
57 кейсов существующего реестра на настоящей Astra 1.8.4, красный только
CONF-013 — тот же, что и в контейнере. Осталось: кейсы `mac-integrity` и
`fly-dm-greeter`, ради которых профиль и нужен, `clone-image-bootstrap`,
`gost-crypto` (gost-engine в образе), профиль Windows.

Прогон на живой машине идёт по SSH, соединение открывается на каждый шаг
(мультиплексирование выключено: Astra ограничивает число сессий), поэтому он
на порядок медленнее контейнерного — час против минут. Контейнер остаётся
контуром на каждый день, машина — для того, чего в контейнере нет вовсе:
мандатного контроля, настоящего logind, графического входа.

**Прогоны на машине только последовательные.** Контейнер прощает параллельные
запуски, живая машина — нет: они делят один `/etc/tessera/config.toml` и одни
loop-устройства, и результаты обоих становятся недостоверными. Первый снятый
baseline профиля пришлось выбросить именно поэтому.
