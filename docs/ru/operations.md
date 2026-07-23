# Runbook эксплуатации Tessera

Для дежурного администратора Astra Linux SE, обслуживающего парк
машин с установленным `tessera`. Здесь собрано то, что делают на
дежурстве, — сгруппировано по поводу запуска:

- **регулярно, по расписанию** — мониторинг (§1), ежедневное
  обновление CRL (§2.2), бэкап конфигурации (§4);
- **по событию** — обновление CA (§2.1), изменение области
  сертификата (§2.3), раскатка клонированного образа (§2.4),
  ротация `gost-engine` после обновления Astra (§5);
- **при аварии** — инциденты безопасности, потеря токена, отказ
  демона: вынесены в [troubleshooting.md](troubleshooting.md) (§3).

Где у операции есть срок или триггер, он указан в поле **Когда**.
Логи, МКЦ и экстренный контакт — в конце (§6–§8).

## 1. Мониторинг

> Отдельного health-файла у демона **нет** — сигналы живости:
> systemd-состояние юнита (`Type=notify` + `sd_notify`), наличие
> IPC-сокета и записи в журнале.

### 1.1 systemd-сервис

```bash
systemctl is-active tessera
```

Ожидание: `active`. Любое другое значение — алерт. Юнит работает в
режиме `Type=notify`: systemd сам видит, что демон жив, и
перезапускает его по `Restart=`-политике.

### 1.2 Сокет

```bash
test -S /run/tessera/monitord.sock && echo OK || echo FAIL
```

### 1.3 Журнал

Свежие ошибки демона за интервал опроса:

```bash
journalctl -u tessera --since '5 min ago' -p err --no-pager -q
```

Пустой вывод — норма; любая строка — повод посмотреть руками.

### 1.4 Шаблон для Zabbix UserParameter

`UserParameter=<key>,<command>` — одна строка на ключ (перенос строки
Zabbix не разрешает):

```ini
UserParameter=tessera.active,systemctl is-active tessera
UserParameter=tessera.socket,test -S /run/tessera/monitord.sock && echo 1 || echo 0
```

### 1.5 Шаблон для Prometheus textfile collector

`/var/lib/node_exporter/textfile_collector/tessera.prom`:

```
# HELP tessera_up 1 if monitord is active.
# TYPE tessera_up gauge
tessera_up <0|1>
# HELP tessera_socket_present 1 if the IPC socket exists.
# TYPE tessera_socket_present gauge
tessera_socket_present <0|1>
```

Скрипт обновления (cron каждые 30 сек):

```bash
#!/usr/bin/env bash
set -e
UP=$([[ "$(systemctl is-active tessera)" == "active" ]] && echo 1 || echo 0)
SOCK=$([[ -S /run/tessera/monitord.sock ]] && echo 1 || echo 0)
TMP=$(mktemp)
{
    echo "# HELP tessera_up 1 if monitord is active."
    echo "# TYPE tessera_up gauge"
    echo "tessera_up $UP"
    echo "# HELP tessera_socket_present 1 if the IPC socket exists."
    echo "# TYPE tessera_socket_present gauge"
    echo "tessera_socket_present $SOCK"
} > "$TMP"
mv "$TMP" /var/lib/node_exporter/textfile_collector/tessera.prom
```

## 2. Операции с сертификатами и CRL

### 2.1 Обновление CA-сертификата

**Когда:** за 6 месяцев до истечения текущего CA.

**Как:**

1. Сгенерировать новый CA в HSM или защищённом сегменте.
2. Подписать новый CA старым (cross-sign) для плавного перехода.
3. Распространить новый `chain.pem` на каждое устройство:
   - на USB-носители (Mode A) — обновить `certs/chain.pem`;
   - в `/etc/tessera/ca/bundle.pem` (через apt-репозиторий
     организации или ansible/puppet).
4. Перевыпустить пользовательские сертификаты новой CA-парой,
   сохраняя в них корректные расширения `pam_cert_host_binding` и
   `pam_cert_user_binding` (см. [cert-issuance.md](cert-issuance.md)).
5. После полного перехода — отозвать старый CA через CRL и удалить
   из `[trust].anchors`.

**Проверка:**

```bash
openssl x509 -in /etc/tessera/ca/bundle.pem -noout -enddate
```

### 2.2 Обновление CRL

**Когда:** ежедневно через cron / systemd timer.

**Как:**

systemd timer (`/etc/systemd/system/tessera-crl-update.timer`):

```
[Unit]
Description=tessera daily CRL refresh

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Service (`/etc/systemd/system/tessera-crl-update.service`):

```
[Unit]
Description=tessera CRL refresh

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/tessera-crl-fetch
```

`/usr/local/sbin/tessera-crl-fetch` — скрипт, скачивающий CRL по
подписанному HTTP-каналу или с CA-шары и атомарно перезаписывающий
`/etc/tessera/crl/*.crl`.

**Проверка:**

```bash
ls -la /etc/tessera/crl/
openssl crl -in /etc/tessera/crl/staff.crl -noout -lastupdate -nextupdate
```

### 2.3 Изменение области действия сертификата

**Когда:** при добавлении/удалении пользователя или машины из
области действия конкретного сертификата.

Так как авторизация описана в самих X.509-расширениях
(`pam_cert_host_binding`, `pam_cert_user_binding`), отдельной
конфигурации обновлять не нужно. Жизненный цикл — через УЦ:

1. Отозвать текущий сертификат через CRL (процедура отзыва —
   [troubleshooting.md §8](troubleshooting.md#8-инциденты-безопасности)).
2. Перевыпустить сертификат с обновлёнными списками в расширениях
   (рецепты `openssl.cnf` — в [cert-issuance.md](cert-issuance.md)).
3. Распространить новый сертификат на USB/токен пользователя.
4. Обновить CRL на endpoints (см. §2.2).

`monitord` перечитывать конфиг не требуется — изменения вступают в
силу при следующем `pam_sm_authenticate`.

### 2.4 Раскатка клонированного образа

**Когда:** установили один эталонный АРМ, сняли образ, разворачиваете
по парку. На каждой железке `machine_id` / DMI / hostname уникальны и
отличаются от эталонного.

**Полный workflow:** [docs/clone-image.md](clone-image.md) — bootstrap
эталона, `finish-bootstrap.sh` на клоне, выпуск per-host сертификата,
Ansible-выкатка, troubleshooting.

Краткий контур для дежурного:

1. Эталон: `[host_identity].sources = ["override"]` +
   bootstrap-cert с `host_binding = "installation"`.
2. Клон → boot → bootstrap auth работает.
3. На каждом АРМ-е: `sudo /usr/share/tessera/finish-bootstrap.sh`
   (или Ansible с `--non-interactive`). Flip + дамп host_id на USB.
4. CA-админ выписывает per-host сертификат по `hash_hex` из строки
   `active_under_current_config=yes` (CA-инструментом; поставляется
   отдельно, см. [clone-image.md §6.1](clone-image.md)).
5. USB с новым `.p12` возвращается на АРМ — bootstrap
   больше не используется, работает per-host цепочка.

## 3. Действия при инцидентах

Все инциденты и troubleshooting вынесены в единый справочник —
**[docs/troubleshooting.md](troubleshooting.md)**:

- [§8 Инциденты безопасности](troubleshooting.md#8-инциденты-безопасности): компрометация cert, потеря токена, CA worst-case, DIGSIG
- [§2 USB и токены](troubleshooting.md#2-usb-и-токены): USBGuard, ЗПС, потеря/блокировка токена
- [§3 monitord и daemon](troubleshooting.md#3-monitord-и-daemon): failed-старт, недоступный сокет
- [§4 PAM-стек и lockout](troubleshooting.md#4-pam-стек-и-lockout): replay из rescue.target, `Logout requested but session has no logind id`
## 4. Backup и restore конфигурации

### 4.1 Что бэкапить

- `/etc/tessera/` (config, ca/, crl/);
- `/var/lib/tessera/` (root-owned policy/enrollment material и persistent state демона);
- `/etc/pam.d/` (с резервными копиями `.bak.*`).

### 4.2 Что НЕ бэкапить

- `/run/tessera/` — runtime (сокет, `sessions.json`,
  `daemon.lock`), создаётся директивой `RuntimeDirectory=tessera`
  юнита при каждом старте демона.
- `/var/cache/tessera/` — зарезервировано под кэши,
  восстанавливается при работе.

### 4.3 Команды

Backup:

```bash
sudo tar --acls --xattrs -czf /backup/tessera-$(date +%F).tgz \
    /etc/tessera /var/lib/tessera /etc/pam.d
gpg --encrypt --recipient backup@example.test \
    /backup/tessera-$(date +%F).tgz
```

Restore:

```bash
gpg --decrypt /backup/tessera-2026-05-01.tgz.gpg \
    | sudo tar -xzC /
sudo systemctl reload tessera
```

## 5. Ротация `gost-engine` при обновлении Astra

### 5.1 Когда

После `apt upgrade`, в логах указано обновление пакета `gost-engine` или
`libgost-engine`.

### 5.2 Что проверить

```bash
openssl engine gost -t
# Сразу после обновления должен показывать [ available ].
pamtester sudo alice authenticate
# Smoke-тест аутентификации после обновления.
```

### 5.3 Откат

Если обновление сломало совместимость:

```bash
apt install gost-engine=<previous-version>
apt-mark hold gost-engine
sudo systemctl restart tessera
```

## 6. Логи: где искать, что искать

### 6.1 monitord

```bash
sudo journalctl -u tessera
sudo journalctl -u tessera -g 'tessera.monitord'
```

> Имя `tessera.monitord` сохраняется как операционный ABI: им
> пользуются журнал-агрегаторы и шаблоны journalctl-фильтров. Сам
> бинарь и unit называются `tessera`, но `tracing target` и
> путь к Unix-сокету (`/run/tessera/monitord.sock`) остаются
> историческими — переименование сломало бы фильтры в проде.

Отдельных таргетов вида `tessera.monitord.start` / `.removal` / `.lock`
**нет**: у демона один таргет `tessera.monitord` со свободным текстом
сообщения. Исход и детали события лежат в тексте сообщения и полях
`key=value`, а не в имени таргета. Основные таргеты демона и примеры
реальных сообщений (дословно из журнала):

- `tessera.monitord` — жизненный цикл демона, udev-события, grace-окно,
  диспетчеризация действий:
  - `starting` — старт демона;
  - `grace window expired, dispatching action` (поле `serial=…`) —
    grace-окно после извлечения носителя истекло, действие уходит
    в action-runner;
  - `grace cancelled` (`serial=…`) — носитель вернули в grace-окне,
    действие отменено;
  - `session target updated` (`session_id=…`, `new_target=…`) —
    `pam_sm_open_session` прислал реальный `XDG_SESSION_ID`, запись
    сессии в реестре обновлена с placeholder-цели на `LogindSession`.
- `tessera.mount` — монтирование и очистка stale-точек под
  mountpoint-base.
- `tessera.daemon.singleton` — singleton-замок `daemon.lock`.
- `tessera.fly_dm_greeter` — перерисовка wallpaper-баннера.
- `tessera.startup_check` — стартовая валидация конфигурации.
- `role.audit` — события ролевого стора (`role_deny`,
  `role_session_open` с полем `reason=…`); таргет **без** префикса
  `tessera.`.

**Извлечение носителя из сессии без logind id.** В 0.4.0 действие
не «дропается» (строки `USB-removal action dropped` нет) — оно
завершается fail-closed перезагрузкой хоста. Это ERROR-строка
(поле `action=Lock` или `Logout`):

```
ERROR tessera.monitord: ALERT: USB-removal Logout has no logind id; failing closed with reboot session_id=… target=… pam_user=… pam_service=…
```

Следом идёт INFO-подсказка (текст начинается с
`tip: pam_sm_open_session pushes XDG_SESSION_ID to monitord`) о том,
что нужно поправить порядок `pam_systemd.so` / `pam_tessera.so` в
session-фазе. Разбор причины и починка —
[troubleshooting.md §4](troubleshooting.md#4-pam-стек-и-lockout).

### 6.2 cdylib (PAM-модуль)

```bash
sudo tail -f /var/log/auth.log
sudo journalctl -t pam_tessera
```

> PAM-модуль пишет в syslog (facility `auth`) под идентификатором
> процесса `pam_tessera` — отсюда фильтр `-t pam_tessera`, а не
> `-t tessera`. На journald-хостах строки видны и в
> `journalctl -t pam_tessera`, и в `/var/log/auth.log`.

Отдельных таргетов вида `tessera.auth.success` / `.fail.<reason>` или
`tessera.cert_scope.*` **нет** — исход аутентификации и причина отказа
лежат в тексте сообщения и полях (`error=…`, `reason=…`), а не в имени
таргета. Основные таргеты модуля:

- `tessera.auth` — вход и итог `pam_sm_authenticate`:
  - `authentication failed` (WARN, поле `error=…` несёт категорию
    отказа);
  - `host identity unresolved` (ERROR, `error=…`).
- `tessera.flow` — пошаговая трасса flow:
  - `usb devices/partitions enumerated` (`count=…`);
  - `trying USB candidate` (`devnode=…`, `vid=…`, `pid=…`, `fs_type=…`);
  - `candidate mounted` (`devnode=…`, `mountpoint=…`);
  - `no .p12 on this partition, trying next` (`mountpoint=…`, `missing=…`);
  - `cert chain validated`;
  - `auth result: success (pkcs12)` — успех PKCS#12-пути.
- `tessera.session` — `pam_sm_open_session` / `pam_sm_close_session`:
  - `open_session: running session_open hooks` (`session_id=…`, `pam_user=…`);
  - `close_session: running session_close hooks` (`session_id=…`).
- `role.audit` — ролевой отказ/выдача: `role_deny` с полем `reason=…`
  (`not_found` / `not_covered` / `backend_unavailable` /
  `mask_exceeds_ceiling` / `syntax`), `role_session_open`.

### 6.3 Полезные `grep`-фильтры

```bash
# Все неуспешные аутентификации за сутки:
sudo journalctl -t pam_tessera --since="1 day ago" \
    | grep -F 'authentication failed'

# Все ролевые отказы (реестр role-store):
sudo journalctl -t pam_tessera | grep -F 'role_deny'

# События извлечения USB, по которым сработало действие:
sudo journalctl -u tessera | grep -F 'grace window expired, dispatching action'

# Fail-closed перезагрузки из-за отсутствия logind id:
sudo journalctl -u tessera | grep -F 'failing closed with reboot'

# Пошаговая трасса подбора раздела на multi-partition носителе:
sudo journalctl -t pam_tessera \
    | grep -E 'trying USB candidate|candidate mounted|no \.p12 on this partition'

# Сессии/отказы конкретного пользователя (ролевой аудит):
sudo journalctl -t pam_tessera | grep -E 'role_(deny|session_open)' | grep alice
```

### 6.4 Что не логируется (по политике)

- PIN-коды и парольные фразы — `<redacted>`.
- Полные DN сертификатов на уровне `info` — отображаются только CN.
  На уровне `debug` — полный DN.
- Полное содержимое X.509-расширений `pam_cert_host_binding` /
  `pam_cert_user_binding` — на уровне `info` логируется только
  совпавшая запись; полный список — на уровне `debug`.

## 7. МКЦ (MAC integrity)

Активация мандатного контроля целостности — опциональный шаг,
выполняется оператором вручную после установки пакета. По
умолчанию демон `tessera.service` работает как `tessera` без
`CAP_MAC_ADMIN`/`PARSEC_CAP_CHMAC`. Активация — три шага оператора:

1. установить drop-in
   `/usr/share/tessera/systemd/mac-integrity.conf.example` в
   `/etc/systemd/system/tessera.service.d/`;
2. установить парный PAM-стек
   `/usr/share/tessera/pam.d/tessera.example` в `/etc/pam.d/tessera`
   (использует `pam_parsec_cap.so` + `pam_parsec_mac.so`);
3. выдать демону `PARSEC_CAP_CHMAC` через `usercaps -m "+3" tessera`
   плюс `pdpl-user --ilevel 63 tessera`.

Полная процедура активации, проверки и отката описана в
[docs/install.md §«МКЦ (MAC integrity) — опциональная активация»](install.md#мкц-mac-integrity--опциональная-активация).

**Состояние сессий.** Реестр `sessions.json` лежит на tmpfs
(`/run/tessera/sessions.json`, `RuntimeDirectory=`). Реестр
обнуляется при перезагрузке — так и задумано: sshd/login/sudo-процессы,
держащие эти сессии, всё равно умирают при reboot. Singleton-замок
`daemon.lock` живёт рядом с `sessions.json` (fallback —
`/var/lib/tessera/daemon/`); постоянное состояние демона —
wallpaper-backup в `/var/lib/tessera/daemon/`. Родитель
`/var/lib/tessera/` остаётся root-owned, потому что в нём также лежат
доверенные роли, теги и enrollment material.

## 8. Экстренный контакт

Для конфиденциальных сообщений о безопасности — см. контакты в
[README.md](../../README.md#безопасность-и-сообщения-об-уязвимостях).
