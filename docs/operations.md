# Runbook эксплуатации Tessera

Этот документ — операционный runbook для администратора Astra Linux SE,
обслуживающего парк машин с установленным `tessera`. Каждый
инцидент описан по схеме «симптом → диагностика → действие → проверка».

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

### 1.4 Snippet для Zabbix UserParameter

```ini
UserParameter=tessera.active,
    systemctl is-active tessera
UserParameter=tessera.socket,
    test -S /run/tessera/monitord.sock && echo 1 || echo 0
```

### 1.5 Snippet для Prometheus textfile collector

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

## 2. Регулярные операции

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

1. Отозвать текущий сертификат через CRL (см. §3.1).
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
- `/var/lib/tessera/` (если есть persistent state);
- `/etc/pam.d/` (с резервными копиями `.bak.*`).

### 4.2 Что НЕ бэкапить

- `/run/tessera/` — runtime (сокет, `sessions.json`,
  `daemon.lock`), восстанавливается systemd-tmpfiles при загрузке.
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

Полезные теги:

- `tessera.monitord.start` — запуск.
- `tessera.monitord.removal` — udev REMOVE-события.
- `tessera.monitord.reinsert` — отмена в grace-окне.
- `tessera.monitord.lock` — отправка `LockSession` к logind.
- `tessera.monitord.reload` — reload конфига.
- `USB-removal action dropped` (WARN, 0.3.10+) — action не отправлен,
  потому что в сессии нет logind id. См. §3.6.1.
- `pushed logind session target to monitord` (INFO, `tessera.session`,
  0.3.10+) — `pam_sm_open_session` успешно проксировал `XDG_SESSION_ID`
  в monitord; норма для logind-сессии.

### 6.2 cdylib (PAM-модуль)

```bash
sudo tail -f /var/log/auth.log
sudo journalctl -t tessera
```

Полезные теги:

- `tessera.auth.start` — начало `pam_sm_authenticate`.
- `tessera.auth.success` — успех.
- `tessera.auth.fail.<reason>` — отказ; `<reason>` — категория.
- `tessera.cert_scope.host_mismatch` — `host_id_hash` не входит
  в `pam_cert_host_binding`.
- `tessera.cert_scope.user_mismatch` — `pam_user` не входит в
  `pam_cert_user_binding`.
- `tessera.session.open` — открыта сессия.
- `tessera.session.close` — закрыта сессия.

### 6.3 Полезные `grep`-фильтры

```bash
# Все отказы за сутки:
sudo journalctl -t tessera --since="1 day ago" | grep -F 'auth.fail'

# Все события извлечения USB:
sudo journalctl -u tessera | grep -F 'monitord.removal'

# Все mismatch'и cert scope (host/user binding):
sudo journalctl -t tessera | grep -E 'cert_scope\.(host|user)_mismatch'

# Сессии конкретного пользователя:
sudo journalctl -t tessera | grep -E 'pam_user[=:]"alice"'
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
выполняется оператором вручную после установки пакета. Демон
`tessera.service` работает как `tessera` без
`CAP_MAC_ADMIN`/`PARSEC_CAP_CHMAC`, пока оператор не установит
шипованный drop-in
`/usr/share/tessera/systemd/mac-integrity.conf.example` в
`/etc/systemd/system/tessera.service.d/`, парный PAM-стек
`/usr/share/tessera/pam.d/tessera.example` в
`/etc/pam.d/tessera` (использует `pam_parsec_cap.so` +
`pam_parsec_mac.so`) и не выдаст `PARSEC_CAP_CHMAC` через
`usercaps -m "+3" tessera` плюс `pdpl-user --ilevel 63 tessera`.
Полная процедура активации, проверки и отката описана в
[docs/install.md §«МКЦ (MAC integrity) — опциональная активация»](install.md#мкц-mac-integrity--опциональная-активация).

**Состояние сессий.** Реестр `sessions.json` лежит на tmpfs
(`/run/tessera/sessions.json`, `RuntimeDirectory=`). Volatile
across reboot — это by design: sshd/login/sudo-процессы, держащие
эти сессии, всё равно умирают на reboot. Singleton-замок
`daemon.lock` живёт рядом с `sessions.json` (fallback —
`/var/lib/tessera/`); постоянное состояние — wallpaper-backup в
`/var/lib/tessera/`.

## 8. Emergency contact

Для конфиденциальных сообщений о безопасности — см. контакты в
[README.md](../README.md#безопасность-и-сообщения-об-уязвимостях).

## CLA automation

External-contributor CLA flow is enforced by `.github/workflows/cla.yml`
(CLA Assistant Lite). Reference: design spec
`docs/superpowers/specs/2026-06-04-cla-automation-design.md`.

- **Signatures:** stored in the private repo `RoboNET/cla-signatures`,
  file `signatures/version-1/cla.json`. Never edit manually.
- **Token:** secret `CLA_SIGNATURES_PAT` (fine-grained PAT, contents:write
  on `cla-signatures` only) expires yearly — renew in GitHub Developer
  settings and update via `gh secret set CLA_SIGNATURES_PAT --repo
  RoboNET/tessera`. Symptom of expiry: CLA workflow run fails with a
  401/403 on the signatures repo.
- **Updating the CLA text:** bump **Document version** in
  `docs/cla/CLA-individual.md`, change `path-to-signatures` in the workflow
  to `signatures/version-2/cla.json` — the bot will re-request signatures
  from everyone on their next PR.
- **Corporate CLA:** executed manually via e-mail (see
  `docs/cla/CLA-corporate.md`); after execution add the designated GitHub
  accounts to the `allowlist` input in `.github/workflows/cla.yml`.
- **Legal status:** the CLA text is a draft pending lawyer review; schedule
  review before any certification round or external partner due
  diligence. Re-signing mechanism above covers text upgrades.
- **Pending first external PR:** the flow has not yet been exercised
  end-to-end, and the CLA check is not yet a required status check on
  `main`. When the first external PR arrives: verify the bot blocks and
  unblocks correctly (including the `Full name:` line in the signing
  comment), confirm the signature lands in `cla-signatures`, then add the
  exact check name to branch protection as a required status check.
