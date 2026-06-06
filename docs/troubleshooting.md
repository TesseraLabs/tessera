# Troubleshooting `tessera`

Единый справочник по диагностике. Разделы:

- [§1 Cert/auth-ошибки](#1-tessera-ошибки)
- [§2 USB и токены](#2-usb-и-токены)
- [§3 monitord и daemon](#3-monitord-и-daemon)
- [§4 PAM-стек и lockout](#4-pam-стек-и-lockout)
- [§5 МКЦ (Astra strict-mode)](#5-мкц-astra-strict-mode)
- [§6 fly-dm и greeter](#6-fly-dm-и-greeter)
- [§7 Clone-image / golden image](#7-clone-image--golden-image)
- [§8 Инциденты безопасности](#8-инциденты-безопасности)
- [§9 Backup / recovery](#9-backup--recovery)
- [§10 Установка / `gost-engine`](#10-установка--gost-engine)

Для каждого кейса: симптом → диагностика → фикс. Команды
журналирования универсальны:

```bash
sudo journalctl -u tessera --since '5 min ago'
sudo journalctl -t tessera | tail -50
sudo tail -f /var/log/auth.log
```

---

## 1. Cert/auth-ошибки

### `host_binding mismatch`

**Симптом:** PAM отказывает с `HostNotAllowed` или
`HostExtensionMissing`. С 0.3.6 на banner'е (TTY/sshd/sudo):

```
Сертификат выпущен для другого банкомата.
host_id_hash этой машины: <hex>
источник host_id: DmiBoardSerial
Передайте администратору для перевыпуска.
```

**Диагностика:**

```bash
# Что ответил каждый сконфигурированный источник host_identity
sudo journalctl -t tessera | grep 'host_identity: probe' | tail -20
# probe ok      source=MachineId raw=abc... host_id_hash_prefix=a1b2c3d4 host_id_hash=<full sha256 hex>
# probe error   source=DmiBoardSerial error="ENOENT"
# probe selected source=MachineId (first successful) host_id_hash_prefix=a1b2c3d4

# Что зашито в сертификате
openssl x509 -in /etc/tessera/<atm>.pem -noout -text \
    | grep -A1 '2\.25\.183976554325829274683049824615098'
```

**Фикс:** перевыпустить cert CA-инструментом
с правильным `host_id_hash`. **НЕ** считать hash вручную
через `sha256sum /etc/machine-id` — source-of-truth определяется
развёрнутым `[host_identity].sources`. См.
[architecture.md](architecture.md#host-identity-chain).

### `user_binding mismatch`

**Симптом:** цепь cert валидна, конкретный user отвергается
`UserNotAllowed` / `UserExtensionMissing`.

**Диагностика:**

```bash
openssl x509 -in /tmp/ca/alice.pem -noout -text \
    | grep -A1 '2\.25\.215438916728501023845629178354627'
```

**Фикс:** перевыпустить cert с правильным `pam_cert_user_binding`.

### `Authentication failed (PAM_AUTH_ERR)` сразу

**Симптом:** `pamtester` сразу отказывает, без задержки.

**Диагностика:**

```bash
sudo tail -f /var/log/auth.log &
pamtester sudo alice authenticate
```

В журнале искать `tessera.auth.fail.<reason>`. Список причин —
[architecture.md](architecture.md#fail-closed-rules).

### Сертификат не принимается на банкомате (общий чек-лист)

С 0.3.6 PAM выводит на экран `PAM_TEXT_INFO` с диагностикой для
несовпадения `host_binding` и неверного PIN. Смотреть на экран **и**
в syslog:

```bash
# Реальный host_id_hash этой машины
sudo journalctl -t tessera | grep 'host_id resolved' | tail -1

# Пошаговая трасса (mount → discovery → envelope → chain → результат)
sudo journalctl -t tessera --since '5 min ago' \
    | grep -E 'tessera\.(flow|host_identity)'
```

Сверять с реестром выпуска (`atm-registry.tsv` на админ-машине):

- `host_id_hash` в логе ≠ значение в cert → cert выпущен для другого
  АРМ. Перевыпустить.
- В логе нет `host_id resolved` → resolver не отработал. Проверить
  `[host_identity].sources` в `config.toml`.
- `PAM_TEXT_INFO` «Пароль .p12 неверный. Этот сертификат выпущен
  для host_id_hash=…, пользователь=…» → user вставил флешку другого
  инженера. Если cert закодирован legacy-форматом — короткое
  сообщение «Пароль .p12 неверный»; читать на админ-машине:

```bash
openssl pkcs12 -in service.p12 -nokeys -nomacver -passin pass: \
    | openssl x509 -noout -text
```

### `revocation: ocsp unavailable`

**Симптом:** при `[trust.revocation] mode = "ocsp"` отказ
`OCSP unavailable`.

**Фикс:** проверить сетевую доступность OCSP-ответчика. Офлайн-контур
— `mode = "crl"` с локальным CRL.

---

## 2. USB и токены

### `usb_wait_seconds истёк`

**Симптом:** `pamtester` ждёт ~10 с, потом `usb medium not found`.

**Фикс:** проверить `lsblk`, что USB смонтирован и виден. Бóльшее
окно — увеличить `usb_wait_seconds` в `config.toml` (см.
[configuration.md](configuration.md#общие-параметры)).

### `pcscd not running`

**Симптом:** PKCS#11-токен (Рутокен) не виден в `pkcs11-tool -L`.

```bash
sudo systemctl enable --now pcscd
sudo systemctl status pcscd
pcsc_scan          # должен показать вставленный токен
```

### `Token PIN locked`

**Симптом:** `pkcs11-tool` возвращает `CKR_PIN_LOCKED`.

**Фикс:** разблокировать SO-PIN'ом, переинициализировать user-PIN
через `pkcs11-tool --init-pin`.

### 14-секундная тишина после `trying USB candidate`

**Симптом** (0.3.5 и старше): между `trying USB candidate
devnode=/dev/sdb1` и завершением модуля 10–30 с без логов. На USB
Ventoy / multi-partition.

**Причина:** в 0.3.5 нет per-candidate logging — модуль итерировал
партиции без вывода. Длительность = число партиций × таймаут.

**Фикс:** обновиться до 0.3.6+ — добавлено пошаговое INFO:

```
INFO tessera.flow: candidate mounted devnode="/dev/sdb1"
INFO tessera.flow: p12 not found at <path>, skipping candidate
INFO tessera.flow: trying USB candidate devnode="/dev/sdb2"
```

### USB-токен заблокирован USBGuard или ЗПС

**Симптом:** auth падает с `AUTHINFO_UNAVAIL` сразу после вставки:

```
tessera: WARN  tessera.flow: usb device found ...
tessera: WARN  tessera.auth: authentication failed
              error=mount: mount(2) failed: Operation not permitted
```

**Диагностика:**

```bash
# USBGuard
sudo usbguard list-devices              # столбец "block" → токен заблокирован
sudo usbguard list-rules
journalctl -u usbguard.service -n 30 --no-pager

# ЗПС
sudo astra-digsig-control status        # "ВКЛЮЧЕНО"/"НЕАКТИВНО"
sudo dmesg | grep -i digsig | tail
```

**Фикс — USBGuard:**

```bash
sudo usbguard append-rule \
    'allow id 0aca:1234 name "Rutoken ECP" hash "ABC..."'
# либо вписать правило в /etc/usbguard/rules.conf:
sudo systemctl restart usbguard
```

Чтобы daemon не стартовал до USBGuard:

```bash
sudo mkdir -p /etc/systemd/system/tessera.service.d
sudo tee /etc/systemd/system/tessera.service.d/usbguard.conf <<EOF
[Unit]
After=usbguard.service
Wants=usbguard.service
EOF
sudo systemctl daemon-reload
```

**Фикс — ЗПС:** см. §10 ниже.

### USB-токен утерян / заблокирован — user не может войти

**By-design.** `tessera` — жёсткий второй фактор: без валидного
токена с правильными расширениями user **не пройдёт** PAM-стек,
куда модуль интегрирован. Альтернативного пути auth нет.

**ДО первого внедрения админ должен:**

1. Сохранить локальный root-shell с выключенным `tessera` или
   sudoers-правило для админа без второго фактора — иначе
   блокировка единственного токена выводит машину из строя.
2. Готовить **резервные** сертификаты: каждому privileged user —
   две физические флешки, обе подписаны CA, обе с одинаковым
   `pam_cert_user_binding`.
3. Документировать SLA на перевыпуск утерянного cert.

**Что произойдёт при потере токена:**

- Все попытки auth → `PAM_AUTHINFO_UNAVAIL` после `usb_wait_seconds`.
- `monitord` работает, но не регистрирует активных сессий —
  `on_usb_removed` не сработает.

**При блокировке USBGuard / ЗПС:** то же + строки ошибки в
`auth.log`. Держать админ-канал (SSH key-only auth без
`tessera`-цепочки) до валидации развёртывания.

---

## 3. monitord и daemon

### `monitord not reachable`

**Симптом:** PAM отказывает `monitord unavailable` или зависает.

```bash
sudo systemctl status tessera
sudo journalctl -xeu tessera -n 200
sudo ls -la /run/tessera/
```

**Типовые причины:**

- сокет `/run/tessera/monitord.sock` не создан → проверить
  `RuntimeDirectory=tessera` в юните;
- права на `/run/tessera/` неверны → должно быть
  `drwxr-x--- root root` (0750);
- `config.toml` повреждён → запустить вручную:
  `sudo /usr/bin/tessera` и читать диагностический вывод.

### monitord не запускается

**Симптом:** `systemctl status tessera` показывает `failed`.

```bash
sudo journalctl -xeu tessera -n 200
```

**Типовые причины:**

- занятый сокет: `lsof /run/tessera/monitord.sock`;
- нет прав на `/run/tessera/`: `ls -la`, должно быть `0750 root:root`;
- повреждённый `config.toml`: запустить вручную `sudo /usr/bin/tessera`;
- отсутствие `gost-engine`: `openssl engine gost -t`.

---

## 4. PAM-стек и lockout

### Замок-аут после неудачной правки PAM

**Симптом:** ни один user не может войти, рут-shell тоже.

**Recovery:**

1. Перезагрузить в single-user mode: на GRUB добавить к строке ядра
   `systemd.unit=rescue.target init=/bin/bash`.
2. Перемонтировать `/` в rw: `mount -o remount,rw /`.
3. Откатить `/etc/pam.d/*` из бекапов `*.bak.<TS>`:
   ```bash
   ls /etc/pam.d/*.bak.* | tail
   cp /etc/pam.d/sudo.bak.20260501T103000Z /etc/pam.d/sudo
   ```
4. `systemctl reboot`.

### `tessera` в `/etc/pam.d/login` не находится

**Симптом:** после правки login отказывает `Module is unknown` или
не стартует.

```bash
ls -la /lib/security/pam_tessera.so
test -f /lib/security/pam_tessera.so && echo "module installed"
sudo ldd /lib/security/pam_tessera.so | grep -i 'not found'
```

- `not found` → недостающая зависимость (`libparsec-mic.so.3` на
  старых сборках). Обновиться до 0.3.7+ — там
  `cargo:rustc-link-lib=parsec-mic` в `build.rs`.
- Файл отсутствует → `dpkg -l tessera`. Возможно прерванная
  установка → `sudo dpkg --configure -a`.

### `Logout requested but session has no logind id`

**Симптом** (0.3.10+): извлечение USB корректно детектится в
journald (`grace window expired, dispatching action`), но logout не
происходит:

```
WARN tessera.monitord: USB-removal action dropped: session has no logind id action=Logout target=Tty("/dev/tty1") ...
INFO tessera.monitord: tip: pam_sm_open_session pushes XDG_SESSION_ID ...
```

**Причина:** на момент `pam_sm_open_session` `XDG_SESSION_ID` не был
в PAM-environment — monitord-запись осталась с placeholder-target'ом
(`Tty` / `Display` / `Unknown`), захваченным на auth-фазе.
Action-runner не может вызвать `terminate_session` без logind id.

**Action-runner fallback (0.3.10):**

| Конфигурация              | Без logind id                              |
|---------------------------|--------------------------------------------|
| `action = "lock"`         | Дропается с WARN; сессия остаётся открытой |
| `action = "logout"`       | Дропается с WARN; сессия остаётся открытой |
| `action = "shutdown"`     | Срабатывает — `power_off` не требует logind|
| `action = "hook"`         | Срабатывает — hook получает SESSION_ID env |

**Причина 1 (типичная, 0.3.11 и старше — pre-fix):** `@include tessera*`
включал `session required pam_tessera.so` внутри snippet'а, и сниппет
оказывался выше `@include common-session` (где `pam_systemd.so`).
`sm_open_session` срабатывал раньше `pam_systemd`. В 0.3.12
session-фаза вынесена из snippet'ов в отдельную строку, которую
`integrate-pam.sh` ставит ПОСЛЕ `@include common-session`. Демон
0.3.12+ валит на старте `ERROR pam_stack_session_misorder` если
порядок неправильный.

Проверка:

```bash
sudo tessera check 2>&1 | grep pam_stack_session
# OR:
sudo grep -nE 'session.*(pam_systemd|tessera)|@include[[:space:]]+(common-session|tessera)' \
    /etc/pam.d/login /etc/pam.d/fly-dm
```

Фикс — переинтегрировать через 0.3.12+ скрипт:

```bash
sudo /usr/share/tessera/integrate-pam.sh --unintegrate /etc/pam.d/login
sudo /usr/share/tessera/integrate-pam.sh --mode=<your-mode> /etc/pam.d/login
sudo systemctl restart tessera
```

**Причина 2:** `pam_systemd.so` отсутствует в `session`-фазе сервиса.
Startup-check выдаёт INFO `pam_stack_session_no_systemd`. Фикс —
восстановить штатный шаблон `dpkg-reconfigure libpam-runtime`,
прогнать `integrate-pam.sh`.

**Причина 3:** консольная сессия без systemd (sysvinit, OpenRC).
`pam_systemd` не загружен, `XDG_SESSION_ID` физически не создаётся.
До реализации TTY-based logout fallback:

- `[on_usb_removed].action = "shutdown"` (грубо, но работает);
- или `"hook"` со скриптом — `pkill -KILL -u <pam_user>` / `chvt 1`;
- или включить systemd на хосте.

**Verify фикса:**

```bash
sudo journalctl -u tessera -f &
# залогиниться, дождаться:
#   INFO tessera.session: pushed logind session target to monitord
#   target=LogindSession { id: "..." }
# извлечь USB:
#   INFO tessera.monitord: grace window expired, dispatching action
```

---

## 5. МКЦ (Astra strict-mode)

### `pam_parsec_mac(login:account): Can't obtain required data`

**Симптом:** `tessera` отработал успешно, но через несколько
секунд `pam_parsec_mac` валит login в `account`-фазе:

```
pam_parsec_mac(login:account): Can't obtain required data.
Did you forget add pam_parsec_mac to "auth" stack?
```

`pam_parsec_mac.so` хранит PAM data между фазами: auth-инстанс
пишет, account/session читают. Появляется когда auth-инстанс **не
выполнился**, хотя в файле формально присутствует.

**Причина 1 (наиболее частая, integrate-pam.sh < 0.3.8):** наш
`@include tessera-only` оказался ПЕРЕД `auth required
pam_parsec_mac.so`. `tessera-only` использует
`auth [success=done default=die] pam_tessera.so` — `success=done`
обрывает auth-стек на успехе, pam_parsec_mac в auth не успевает
положить data.

Проверка:

```bash
sudo grep -n -E 'tessera|parsec_mac' /etc/pam.d/login /etc/pam.d/fly-dm
```

Если номер строки `@include tessera*` **меньше** номера
`auth ... pam_parsec_mac.so` — это оно.

Фикс:

```bash
# integrate-pam.sh >= 0.3.8 расставляет правильно сам
sudo /usr/share/tessera/integrate-pam.sh --unintegrate /etc/pam.d/login
sudo /usr/share/tessera/integrate-pam.sh --mode=cert-only /etc/pam.d/login
# повторить для fly-dm
```

**Причина 2:** МКЦ-ядро выключено (`parsec.mac=0` в GRUB), а
`pam_parsec_mac.so` в `/etc/pam.d/login`. У модуля нет MAC data —
account валится. См. следующий кейс.

**Причина 3:** МКЦ-ядро включено, но `service` не имеет MAC-уровня.

```bash
sudo /sbin/pdpl-user service
sudo ls /etc/parsec/macdb/$(id -u service)
```

Если `pdpl-user` показывает только `0:0:0x0:0x0` без записи в
`/etc/parsec/macdb/<uid>`:

```bash
sudo /sbin/pdpl-user --ilevel 63 service
sudo systemctl restart fly-dm
```

### `parsec.mac=0` + `pam_parsec_mac` в стеке

**Симптом:** МКЦ-ядро отключено через GRUB (`parsec.mac=0`), но
`/etc/pam.d/login` содержит `pam_parsec_mac.so` в auth/account/session.
Модуль ждёт MAC data, которой не существует — login deny.

```bash
cat /proc/cmdline | tr ' ' '\n' | grep parsec
cat /sys/module/parsec/parameters/strict_mode    # N = выключен
sudo astra-strictmode-control status             # НЕАКТИВНО
```

**(А) МКЦ нужен** — включить ядро:

```bash
# /etc/default/grub
GRUB_CMDLINE_LINUX_DEFAULT="... parsec.mac=1 parsec.max_ilev=63 ..."
sudo update-grub
sudo reboot
sudo /sbin/pdpl-user --ilevel 63 service
```

**(Б) МКЦ не нужен** — убрать `pam_parsec_mac.so`, поставить
`runtime = "disabled"`:

```toml
[mac]
runtime        = "disabled"
cert_integrity = "ignored"
```

```bash
for f in /etc/pam.d/login /etc/pam.d/fly-dm; do
    sudo sed -i.bak 's|^\(\s*\(auth\|account\|session\).*pam_parsec_mac\.so\)|# disabled МКЦ off: \1|' "$f"
done
sudo systemctl restart tessera fly-dm
```

См. [install.md §8.5](install.md) — матрица PAM-стеков с/без МКЦ.

### `unknown field 'enabled', expected one of ... 'runtime'`

**Симптом:** daemon не стартует, TOML parse error:

```
failed to load monitord config from /etc/tessera/config.toml:
unknown field `enabled`, expected one of `cert_integrity`,
`fallback_max_integrity`, `warn_on_homedir_label_mismatch`, `runtime`
```

**Причина:** legacy-поле `[mac].enabled = true` из 0.3.0–0.3.6.
С 0.3.7 удалено, заменено на `[mac].runtime`.

```toml
# было
[mac]
enabled        = true
cert_integrity = "optional"

# стало (для МКЦ-ядра ВКЛ)
[mac]
runtime        = "required"     # или "auto"
cert_integrity = "optional"

# или (для МКЦ-ядра ВЫКЛ)
[mac]
runtime        = "disabled"
cert_integrity = "ignored"
```

### WARN `mac_caps_missing` / `pdp_set_fd rc=-1`

**Симптом:** при старте daemon:

```
WARN mac.audit: F_event="mac_caps_missing" F_detail="PARSEC_CAP_CHMAC not present in effective set"
WARN mac.audit: F_event="mac_sessions_file_label_warning" F_error="parsec error: op=pdp_set_fd rc=-1"
```

**Не блокирующие.** Daemon стартует и работает. Означает что не
удалось выставить МКЦ-метку на `sessions.json`. Auth-flow не
затрагивает.

Чтобы убрать (опционально):

```bash
sudo /sbin/usercaps -m "+3" tessera
sudo cp /usr/share/tessera/systemd/mac-integrity.conf.example \
    /etc/systemd/system/tessera.service.d/mac-integrity.conf
sudo systemctl daemon-reload
sudo systemctl restart tessera
```

### `dmi_board_serial = 0` (VM), hash меняется при пересборке VM

**Симптом:** на VirtualBox/QEMU `/sys/class/dmi/id/board_serial` пуст
или `0`. Resolver делает fallback на `machine_id`, но при пересборке
VM `machine-id` тоже может измениться → cert с зашитым hash
перестаёт валидироваться.

```bash
cat /sys/class/dmi/id/board_serial   # 0 или пусто = непригоден
sudo journalctl -t tessera | grep 'host_identity:' | tail -10
```

Для дев/тестов:

```toml
[host_identity]
sources  = ["override"]
fallback = "deny"
override = "test-vm-stable-id"
```

В production на железных АРМ `dmi_board_serial` обычно валиден.

---

## 6. fly-dm и greeter

### fly-dm не показывает host_id на экране входа

**Симптом:** на login fly-dm не видно `host_id` — ни через
`PAM_TEXT_INFO`, ни через стоковое «Добро пожаловать в %n».

**Причина:** на Astra с МКЦ-3 fly-modern theme
(`libfly-dm_greet_modern.so`) hardcoded'но подставляет в headline
«Усиленный уровень защищенности». GreetString и PAM-сообщения
игнорируются.

**Фикс — wallpaper banner (0.3.19+):**

```toml
# /etc/tessera/config.toml
[fly_dm_greeter]
update_wallpaper = true
```

Если на хосте сильное затемнение / blur скрывает текст:

```ini
# /etc/X11/fly-dm/fly-modern/settings.ini
[background]
color_overlay=0,0,0,30

[background][blur]
enable=false
```

```bash
sudo systemctl restart tessera     # перерисует banner
sudo systemctl restart fly-dm           # подхватит новый JPG
```

Полный набор опций, baseline и реализация — [fly-dm-greeter.md](fly-dm-greeter.md).

**Cargo-cult-подходы (удалены в 0.3.19):**

- `greeter-show-messages = true` в `/etc/X11/fly-dm/fly-dmrc` — KDM/LightDM
  legacy ключ, fly-qdm 2.15+ не парсит.
- `/etc/X11/fly-dm/override/GreetString.desktop` — fly-modern на МКЦ-3
  GreetString игнорирует, headline занят МКЦ-статусом.

### Wallpaper не обновляется

- Демон не имеет прав на `wallpaper_target`: `ls -l` источника. Демон
  под root, права 0644 достаточно.
- Шрифт не найден: WARN `fly_dm_greeter_font_missing`. Поставить
  `fonts-dejavu-core`.
- Текст не видно: `color_overlay` слишком плотный, blur включён —
  см. fix выше.

---

## 7. Clone-image / golden image

### `dump-host-id`: все источники пусты

**Симптом:** TSV содержит только `status=empty` или `status=error`,
exit ≠ 0.

**Причины:**

- **`dmi_board_serial = 0`** — типично для VM (KVM/VMware без SMBIOS
  override). Фикс: SMBIOS-strings в гипервизоре или
  `--sources machine_id`.
- **`machine_id` пустой** — очищен перед клонированием, systemd не
  сгенерировал на первой загрузке. Фикс:
  `systemd-machine-id-setup && systemctl restart tessera`.
- **`custom_command` exit ≠ 0** — путь/permissions скрипта, см.
  `reason` в TSV.

### USB не появляется во время `--usb`

`finish-bootstrap.sh` / `dump-host-id --usb` ретраит ~30 с. Если
флешка не определилась:

- `lsblk` параллельно;
- FS из allowlist (`vfat`/`exfat`/`ext4`/`ntfs`);
- использовать fallback в `/var/lib/tessera/`.

### `active_under_current_config=no` для всех строк

Бывает если `--sources` указали несуществующие источники (опечатка).
`tessera check` обычно ловит, но если прошло — проверить
`[host_identity].sources` в `config.toml`.

### Bootstrap-cert отвергается на клоне

- Trust anchor не попал в образ: `tessera check` покажет
  `trust_anchor_missing`.
- `host_binding` в cert не равен строке `override` — пересобрать
  bootstrap-cert с `--mode bootstrap`.
- `[host_identity].override` ≠ `host_binding` в cert — обычно
  `installation` с обеих сторон, синхронизировать.

### Повторный flip после замены материнки

`dmi_board_serial` изменился → `host_id_hash` другой → per-host cert
больше не валиден.

1. Восстановить bootstrap-state: `config.toml` →
   `sources = ["override"]`, `override = "installation"`.
2. Положить bootstrap-cert на USB.
3. Запустить `finish-bootstrap.sh` повторно — новый TSV-дамп с
   новым `host_id_hash`.
4. Выпустить новый per-host cert (см. [clone-image.md §6](clone-image.md)).

`finish-bootstrap.sh` не делает шаги 1–2 автоматически — сознательно
(требуется решение оператора + физическая флешка).

---

## 8. Инциденты безопасности

### Компрометация сертификата пользователя

**Симптом:** уведомление от user / SOC.

1. Внести серийник в CRL УЦ.
2. Перевыпустить и опубликовать CRL.
3. Обновить CRL на endpoints (см. [operations.md §2.2](operations.md);
   ускоренная процедура — `systemctl start tessera-crl-update.service`).
4. Проверить журнал:
   ```bash
   sudo journalctl -u tessera -g 'revoked' -n 100
   ```
5. Сообщить пользователю; организовать выпуск нового сертификата.

### Потеря токена

1. Revoke серийника (см. выше).
2. Дождаться propagation CRL.
3. Выпустить replacement-токен с новым сертификатом, корректно
   проставив `pam_cert_host_binding` и `pam_cert_user_binding`
   (см. [cert-issuance.md](cert-issuance.md)).

### Утрата CA private key (worst-case)

1. **Немедленно** прекратить новые выпуски.
2. Объявить инцидент Critical; задействовать ИБ.
3. Disaster recovery — отдельный sub-runbook
   `docs/operations-disaster-recovery.md` (создаётся организацией;
   объём — 10–20 страниц).
4. Подготовить новый CA из cold-storage backup'а или перевыпустить
   с нуля.
5. Координированное обновление всех endpoints.
6. Опубликовать инцидент через `security@...` и в
   [changelog.md](changelog.md) секции `Security`.

### DIGSIG `enforce` без подписи на `pam_tessera.so`

**Симптом:** `PAM unable to dlopen(pam_tessera.so)` или
`DIGSIG: blocked unsigned ELF` в `dmesg`. На production-Astra с
включённым `astra-digsig-control` в enforce-режиме.

```bash
sudo astra-digsig-control status   # ВКЛЮЧЕНО = enforce
sudo dmesg | grep -i digsig | grep tessera
```

**Два варианта:**

1. Подписать `.deb` через Astra-партнёрский CI/CD (`bsign` ключом из
   `/etc/digsig/keys/`). Стандартный pipeline для production.
2. Временно перевести в logging-only:
   ```bash
   sudo astra-digsig-control logging
   ```
   **Не для production** — syslog забьётся `DIGSIG: NOT_ELF_SIGNED`.

См. [threat-model.md §3.7](threat-model.md).

---

## 9. Backup / recovery

См. [operations.md §4](operations.md) — что бэкапить, что не бэкапить,
команды.

---

## 10. Установка / `gost-engine`

### `gost-engine not loaded`

**Симптом:** `openssl engine gost -t` выводит
`engine "gost" not found` или `dynamic` без `[ available ]`.

```bash
sudo apt install --reinstall gost-engine
sudo systemctl restart pcscd
openssl engine gost -t
```
