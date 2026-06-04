# Установка Tessera на Astra Linux SE

Этот документ — пошаговый сценарий установки и базовой настройки
`tessera` на чистой машине Astra Linux SE 1.7+. Каждый раздел
заканчивается командой проверки. Если проверка не прошла — читать
раздел «Что делать, если…» в конце документа.

> Все команды выполняются от имени `root` или с `sudo`. На время
> правки PAM-стека держите открытый рут-shell в **другом** терминале.
> Если PAM-стек собьёт авторизацию, второй терминал — единственный
> способ откатить изменения.

## 1. Подготовка машины

### 1.1 Проверка ОС

```bash
cat /etc/astra_version 2>/dev/null || cat /etc/os-release
```

Ожидаемый вывод: версия `1.7.5` или новее. На других редакциях
Astra Linux (Орёл, Воронеж, Смоленск 1.7+) сценарий идентичен. На
Ubuntu/Debian — best-effort, без ГОСТ.

### 1.2 Проверка ядра

```bash
uname -r
```

Ожидание: `5.15.0-93-generic` или новее (необходимо для корректной
доставки udev-событий извлечения USB).

### 1.3 Установка системных зависимостей

```bash
sudo apt update
sudo apt install -y \
    libpam0g \
    libssl3 \
    libudev1 \
    libdbus-1-3 \
    libsystemd0 \
    pcsc-lite \
    pcscd \
    opensc-pkcs11 \
    gost-engine \
    pamtester
```

Точные имена пакетов соответствуют репозиторию Astra SE 1.7. На
Ubuntu 22.04 пакета `gost-engine` в основном репозитории нет — его
надо собирать из исходников или брать из стороннего PPA, и в этом
случае ГОСТ-функционал работать не будет (см. README, раздел
«Поддерживаемые ОС»).

### 1.4 Проверка `gost-engine`

```bash
openssl engine gost -t
```

Ожидание: вывод содержит `[ available ]` и список доступных
алгоритмов, в том числе `id-GostR3411-2012-256` (Streebog-256) и
`gost2012_256` (ГОСТ 34.10-2012-256).

### Verification (раздел 1)

```bash
openssl dgst -engine gost -md_gost12_256 /etc/hostname
```

Ожидание: 64-символьный шестнадцатеричный хеш в выводе. Если получили
`engine "gost" set.` без хеша — `gost-engine` подключился, но что-то
пошло не так с алгоритмом; вероятно, версия `gost-engine` рассинхронна
с системным OpenSSL. См. раздел «Что делать, если…».

### 1.5 Preflight: USBGuard и Astra ЗПС (DIGSIG)

Перед установкой полезно убедиться, что окружение не заблокирует ни
сам токен на USB-шине, ни запуск `pam_tessera.so` /
`tessera` через ЭЦП-контроль.

#### USBGuard

Если на хосте установлен USBGuard в режиме `block`, USB-токен должен
быть в allowlist — иначе ядро не отдаст устройство `udev`'у, и
`tessera` не увидит его.

```bash
sudo systemctl is-active usbguard          # active / inactive / not-found
sudo usbguard list-devices 2>/dev/null     # столбец "block" → токен заблокирован
```

Разрешить конкретный токен (по vid:pid или по hash) — отдельным
правилом в `/etc/usbguard/rules.conf`:

```
allow id 0aca:0030 name "Rutoken ECP" hash "ABC..."
```

После правки правил — `sudo systemctl reload usbguard`. Подробности
по runtime-аспекту (порядок старта `monitord` относительно USBGuard)
— в [docs/operations.md §3.5](operations.md).

#### Astra ЗПС / DIGSIG (`astra-digsig-control`)

В production-развёртывании на Astra SE требуется одно из двух:

1. **`astra-digsig-control`** переведён в `logging-only`-режим
   (модуль не блокирует выполнение неподписанных ELF, но шумит в
   `/var/log/syslog` сообщениями `DIGSIG: NOT_ELF_SIGNED`); либо
2. бинари `pam_tessera.so` и `tessera` подписаны
   через сервис подписи Astra-партнёра (`bsign` GPG-ключом из
   доверенной связки в `/etc/digsig/keys/`) — обычно это шаг сборки
   `.deb` в Astra-CI.

```bash
sudo astra-digsig-control status     # ВКЛЮЧЕНО / НЕАКТИВНО / logging-only
sudo dmesg | grep -i digsig | tail   # видны ли отказы по подписи
```

В режиме `enforce` без валидной подписи PAM-аутентификация не
проходит — `pam_tessera.so` просто не загружается. См. также
[docs/threat-model.md §3.7](threat-model.md).

## 2. Установка `.deb`

### 2.1 Скачивание

```bash
# Ссылка на релиз — placeholder; заменить на реальный URL после
# публикации v0.1.1 (обычно — GitHub Releases или внутренний репозиторий
# Astra Linux).
wget https://example.test/releases/tessera_0.1.1-1_amd64.deb
wget https://example.test/releases/tessera_0.1.1-1_amd64.deb.sha256
wget https://example.test/releases/tessera_0.1.1-1_amd64.deb.streebog256
```

### 2.2 Проверка SHA-256

```bash
sha256sum -c tessera_0.1.1-1_amd64.deb.sha256
```

Ожидание: `tessera_0.1.1-1_amd64.deb: OK`.

### 2.3 Проверка Streebog-256

```bash
./scripts/verify-checksums.sh \
    tessera_0.1.1-1_amd64.deb \
    checksums/checksums.txt
```

Скрипт описан в [scripts/verify-checksums.sh](../scripts/verify-checksums.sh)
и проверяет обе суммы (SHA-256 и Streebog-256). См.
[configuration.md](configuration.md) для подробностей.

### 2.4 Установка

```bash
sudo apt install ./tessera_0.3.0-1_amd64.deb
# или legacy 0.1.x:
# sudo apt install ./tessera_0.1.1-1_amd64.deb
```

> Начиная с 0.2.0 бинарь `tessera-monitord` переименован в
> `tessera`. Daemon-режим запускается как `tessera daemon`;
> systemd-юнит `tessera.service` уже использует новое имя.

`apt` подтянет недостающие зависимости (`libgost-engine | gost-engine`,
`libpkcs11-helper1`, `librtpkcs11ecp`).

### 2.4½ Предполётная проверка (`tessera check`)

Перед `systemctl restart tessera` или при первой установке прогоните
preflight: он валидирует `config.toml` и доносит ВСЕ потенциальные
мисконфиги в одном проходе — без открытия сокета и без рестарта demon'а.

```bash
sudo tessera check
```

Что проверяется:

- **PAM-стек.** Сканирует `/etc/pam.d/{login,fly-dm,fly-dm-np,sshd,sudo,su}`
  и валит ERROR в двух случаях:
  1. `@include tessera-*` стоит ПЕРЕД `auth required pam_parsec_mac.so`
     (на Astra SE это убивает account-фазу с «Can't obtain required data»).
     Check id: `pam_stack_misorder`.
  2. (0.3.12+) `session required pam_tessera.so` стоит ПЕРЕД
     `pam_systemd.so` / `@include common-session` —
     `XDG_SESSION_ID` ещё не доступен на момент `pam_sm_open_session`,
     `UpdateSessionTarget` не отправляется, monitord не умеет вызвать
     logind Logout/Lock при извлечении USB. Check id:
     `pam_stack_session_misorder`. Обе ошибки подсказывают команду фикса
     через `integrate-pam.sh`. Хелсчек для session-фазы пишет
     `pam_stack_session_ok` (INFO) при корректном порядке или
     `pam_stack_session_no_systemd` (INFO) если в стеке вообще нет
     pam_systemd — типично для sysvinit/OpenRC хостов.
- **`[mac].runtime` vs ядро.** `runtime=required` без активного
  `parsec_strict_mode()=1` — ERROR (`required` в strict-mode без МКЦ
  ядра делает demon бесполезным). `auto` + отсутствующее ядро — WARN
  (тихий fallback на `StubBackend`, MAC НЕ enforced). `disabled` — INFO.
- **Trust anchors / intermediates.** Каждый путь из `[trust].anchors`
  и `[trust].intermediates` должен существовать, быть непустым и
  содержать хотя бы один `-----BEGIN CERTIFICATE-----` маркер. Иначе
  ERROR — demon не может валидировать ни одной цепочки.
- **`/etc/tessera/ca/`.** WARN, если world-writable
  (`mode & 0o002 != 0`).
- **`PARSEC_CAP_CHMAC`.** Если МКЦ ядро активно и `[mac].runtime ≠ disabled`,
  но у процесса нет capability — WARN: метки на `sessions.json` не лягут.
- **`host_identity`-источники.** По одной INFO/WARN строке на каждый
  настроенный источник (`machine_id`, `dmi_*`, `hostname`,
  `custom_command`) — видно сразу, что резолвится и что падает.

Exit-код: **0** — только INFO/WARN; **1** — есть хотя бы один ERROR. Тот
же check выполняется demon'ом на старте: при наличии ERROR boot
обрывается, в `journalctl -u tessera` останутся структурные
сообщения с `target=tessera.startup_check` для каждой проверки.

### 2.4¾ Сценарий клонированного образа (golden image → терминал)

Если устанавливаете на множество терминалов через клон одного образа,
полный end-to-end workflow вынесен в отдельный документ:
**[docs/clone-image.md](clone-image.md)** — bootstrap-cert на эталоне,
`finish-bootstrap.sh` на каждом клоне, `dump-host-id` для CA-админа,
выпуск per-host сертификата, troubleshooting, Ansible-выкатка.

Tldr — два инструмента, поставляемых в `.deb`:

- `tessera dump-host-id [--output FILE | --usb]` — пробует
  все известные `host_identity`-источники, пишет TSV-отчёт. Столбец
  `active_under_current_config=yes` отмечает источник, который daemon
  реально использует сейчас. `--usb` автоматически монтирует первую
  USB-флешку r/w и пишет `host-ids-<hostname>-<UTC>.tsv`.
- `/usr/share/tessera/finish-bootstrap.sh` — single-pass переход
  с bootstrap-state на production: rewrite `config.toml`
  (`sources = ["override"]` → `["dmi_board_serial", "machine_id"]`),
  `tessera check`, restart daemon, дамп host_id'ов на USB.
  Идемпотент. Флаги — см. [clone-image.md §4.2](clone-image.md).

### 2.5 Проверка systemd-юнита

```bash
systemctl status tessera
```

Ожидание: `Active: active (running)`. Если `inactive (dead)` —
запустить вручную:

```bash
sudo systemctl enable --now tessera
```

### Verification (раздел 2)

```bash
tessera --version
test -d /run/tessera && echo "runtime dir OK"
test -S /run/tessera/monitord.sock && echo "socket OK"
```

Ожидание: версия `0.3.0` (или `0.1.1` для legacy), обе строки `OK`.

## 3. Создание тестового CA (ГОСТ)

> Тестовый CA пригоден только для лабораторного развёртывания. Для
> production используется внешний УЦ — см.
> [docs/operations.md](operations.md).

### 3.1 Каталог

```bash
mkdir -p /tmp/ca && cd /tmp/ca
```

### 3.2 Ключ CA

```bash
openssl genpkey -engine gost -algorithm gost2012_256 \
    -pkeyopt paramset:A -out ca.key
chmod 0600 ca.key
```

### 3.3 Сертификат CA

```bash
openssl req -new -x509 -engine gost -key ca.key \
    -out ca.pem -days 3650 \
    -subj "/CN=tessera Test CA/O=Test/OU=Internal" \
    -addext "extendedKeyUsage=clientAuth" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
```

### 3.4 Проверка

```bash
openssl x509 -in ca.pem -text -noout | head -30
```

Ожидаемая строка: `Signature Algorithm: GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)`.

### Verification (раздел 3)

```bash
openssl verify -CAfile ca.pem ca.pem
```

Ожидание: `ca.pem: OK`.

## 4. Создание тестового пользователя

### 4.1 Ключ alice

```bash
openssl genpkey -engine gost -algorithm gost2012_256 \
    -pkeyopt paramset:A -out alice.key
chmod 0600 alice.key
```

### 4.2 CSR

```bash
openssl req -new -engine gost -key alice.key -out alice.csr \
    -subj "/CN=Alice/UID=alice"
```

### 4.3 Подпись CSR

```bash
openssl x509 -req -engine gost -in alice.csr \
    -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out alice.pem -days 365 \
    -extfile <(printf "extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\n")
```

### 4.4 Упаковка в P12

```bash
openssl pkcs12 -export -engine gost -inkey alice.key -in alice.pem \
    -out alice.p12 -name alice -passout pass:test
chmod 0600 alice.p12
```

### Verification (раздел 4)

```bash
openssl pkcs12 -in alice.p12 -nokeys -passin pass:test \
    | openssl x509 -noout -subject
```

Ожидание: `subject=CN=Alice, UID=alice` (точный порядок RDN зависит
от версии OpenSSL).

## 5. Подготовка USB-носителя (режим `pkcs12` / Mode A)

> Mode A: ключ хранится в `.p12` на USB-носителе, защищён парольной
> фразой. Для production выбирать Mode B (PKCS#11-токен).

### 5.1 Форматирование

`tessera` ищет `.p12` на **любой** партиции с FS из allowlist
(`vfat`, `exfat`, `ext4`, `ntfs`). Метка партиции значения не имеет —
защита обеспечивается на уровне расшифровки `.p12` пользовательским
паролем и валидации цепочки сертификатов модулем доверия. Лимит на
число перебираемых партиций задаётся параметром `max_usb_partitions`
в `config.toml` (по умолчанию 8, диапазон 1..=64).

> Начиная с 0.3.5: если на USB-флешке несколько разделов и часть
> содержит посторонние файлы с именем, совпадающим с
> `pkcs12_path_pattern` (типично для Apple-форматированных носителей
> и USB с несколькими партициями), `tessera` распознаёт их как
> «не PKCS#12» по ASN.1-конверту (без запроса PIN) и продолжает
> искать настоящий `.p12` на следующих разделах. Ошибки, требующие
> пароля (неверный PIN / MAC verify / decrypt / chain), по-прежнему
> fail-closed без перебора.

Типовой рецепт (`sdX1` — раздел USB-носителя из вывода `lsblk | grep -i usb`):

```bash
# ВНИМАНИЕ: команда УНИЧТОЖАЕТ данные на устройстве /dev/sdX1.
# Поддерживаемые FS: vfat, exfat, ext4, ntfs.
sudo mkfs.ext4 /dev/sdX1
sudo mount /dev/sdX1 /mnt/usb
sudo install -m 0600 service.p12 /mnt/usb/service.p12
sudo umount /mnt/usb
```

Если флешка отформатирована без таблицы разделов (FS лежит прямо на
whole-device), это тоже работает: `tessera` читает `ID_FS_TYPE`
udev и монтирует whole-device напрямую.

### 5.2 Layout

```
/mnt/usb/
├─ certs/
│   ├─ user.p12
│   └─ chain.pem
└─ tessera.marker
```

### 5.3 Копирование

```bash
sudo mkdir -p /mnt/usb/certs
sudo cp /tmp/ca/alice.p12  /mnt/usb/certs/user.p12
sudo cp /tmp/ca/ca.pem     /mnt/usb/certs/chain.pem
sudo touch /mnt/usb/tessera.marker
sudo umount /mnt/usb
```

### Verification (раздел 5)

```bash
sudo mount /dev/sdX1 /mnt/usb
ls -la /mnt/usb/certs/
sudo umount /mnt/usb
```

Ожидание: оба файла присутствуют, размер > 0.

## 6. Подготовка Рутокен ЭЦП 2.0 (режим `pkcs11` / Mode B)

### 6.1 Установка драйвера

```bash
sudo apt install librtpkcs11ecp
```

### 6.2 Проверка слота

```bash
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so -L
```

Ожидание: вывод вида `Slot 0 (0x...): ...` с моделью токена.

### 6.3 Инициализация (только для нового, неинициализированного токена)

```bash
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so \
    --init-token --label "alice-token" \
    --so-pin '12345678'
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so \
    --init-pin --so-pin '12345678' --pin '1234567890'
```

### 6.4 Импорт ключа и сертификата

```bash
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so \
    --login --pin '1234567890' \
    --write-object alice.pem --type cert --label alice --id 01
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so \
    --login --pin '1234567890' \
    --write-object alice.p12 --type privkey --label alice --id 01
```

### Verification (раздел 6)

```bash
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so \
    --pin '1234567890' -O
```

Ожидание: в выводе присутствуют `Private Key Object` и
`Certificate Object` с `label=alice`.

## 7. Авторизация: расширения сертификата

Привязка «какой пользователь на каком хосте» живёт в самом
сертификате. PAM-модуль читает два X.509 v3 расширения leaf-сертификата:

- `pam_cert_host_binding` (OID `2.25.183976554325829274683049824615098`)
  — список разрешённых хостов;
- `pam_cert_user_binding` (OID `2.25.215438916728501023845629178354627`)
  — список разрешённых PAM-пользователей.

Готовые рецепты `openssl.cnf` для выпуска сертификатов с правильными
расширениями приведены в [cert-issuance.md](cert-issuance.md).

### Verification (раздел 7)

```bash
openssl x509 -in /tmp/ca/alice.pem -noout -text \
    | grep -E '2\.25\.(183976554325829274683049824615098|215438916728501023845629178354627)'
```

Ожидание: обе строки с дотированными OID присутствуют в выводе.

## 8. Правка `/etc/pam.d/*`

PAM-stack editing вынесен в отдельный документ —
**[docs/pam-integration.md](pam-integration.md)**:

- `integrate-pam.sh` и поставочный snippet
- Two-include pattern (0.3.12+) и порядок `pam_systemd.so`
- fly-dm (зачем + применение + screen-locker)
- Три режима: `2fa` / `optional` / `cert-only` с lockout-warning
- sudo, login, sshd
- PAM-стек с учётом МКЦ → [mac-integrity.md](mac-integrity.md)
- Безопасность правки + recovery

> **ВАЖНО.** Перед правкой PAM открыть второй рут-shell.
> Detail — [pam-integration.md §1](pam-integration.md).

### Verification (раздел 8)

```bash
pamtester sudo alice authenticate
sudo tessera check
```

Ожидание: `Authentication successful` (при вставленном USB или токене).
`tessera check` ловит ошибки порядка PAM-стека (например
`pam_stack_session_misorder`).
## 9. Smoke-тест через `pamtester`

### 9.1 Авторизация

```bash
pamtester sudo alice authenticate
```

Положительный результат: `pamtester: successfully authenticated`.

### 9.2 Сессия

```bash
pamtester sudo alice open_session
pamtester sudo alice close_session
```

Положительный результат: оба вызова возвращают `pamtester: successfully ...`.

### 9.3 Negative-тест: извлечь USB

В одном терминале запустить:

```bash
pamtester sudo alice authenticate
```

Сразу после ввода извлечь USB. Ожидание: `monitord` пишет в журнал:

```bash
sudo journalctl -u tessera -n 20 -g 'medium absent'
```

## 10. Troubleshooting

Полный справочник по диагностике — **[docs/troubleshooting.md](troubleshooting.md)**:

- Cert/auth-ошибки (`host_binding mismatch`, `user_binding mismatch`, общий чек-лист)
- USB и токены (`pcscd`, `Token PIN locked`, USBGuard, ЗПС)
- monitord и daemon (`monitord not reachable`, `failed`-старт)
- PAM-стек и lockout (`Logout requested but session has no logind id`, recovery из rescue.target)
- МКЦ (`pam_parsec_mac: Can't obtain required data`, `parsec.mac=0`, `mac_caps_missing`, `dmi_board_serial = 0`)
- fly-dm и greeter (wallpaper не виден) — см. также [fly-dm-greeter.md](fly-dm-greeter.md)
- Clone-image / golden image (`dump-host-id` пуст, повторный flip) — см. также [clone-image.md](clone-image.md)
- Инциденты безопасности (компрометация cert, потеря токена, CA worst-case, DIGSIG)
- Установка / `gost-engine`
## 11. Хосты без systemd: SysV init

Пакет ставит **оба** init-варианта: `tessera.service` (systemd)
и `/etc/init.d/tessera` (SysV). На systemd-хостах SysV-скрипт
трогать не нужно. На non-systemd:

```bash
sudo update-rc.d tessera defaults
sudo service tessera start
```

Подробности (caveats, отсутствие logind logout) —
[pam-integration.md §10](pam-integration.md#10-хосты-без-systemd-sysv-init).
## Дальнейшие шаги

- [docs/configuration.md](configuration.md) — справочник по всем
  параметрам `config.toml`.
- [docs/cert-issuance.md](cert-issuance.md) — выпуск сертификатов с
  расширениями `pam_cert_host_binding` и `pam_cert_user_binding`.
- [docs/operations.md](operations.md) — runbook эксплуатации и
  процедуры incident response.
- [docs/threat-model.md](threat-model.md) — модель угроз и какие
  атаки модуль защищает.

## МКЦ (MAC integrity) — опциональная активация

Полная активация МКЦ (capability демону, шипованный PAM-стек,
systemd drop-in, per-user MNKC, защита `config.toml` через ilevel=63,
verify, откат) — отдельный документ:
**[docs/mac-integrity.md](mac-integrity.md)**.

Краткий путь:

1. `astra-strictmode-control enable` + reboot.
2. `usercaps -m "+3" tessera` + `pdpl-user --ilevel 63 tessera`.
3. Скопировать `tessera.example` и `mac-integrity.conf.example`
   из `/usr/share/tessera/` в `/etc/pam.d/` и
   `/etc/systemd/system/tessera.service.d/`.
4. `pdpl-user --ilevel 63 <pam_user>` для каждого end-user.
5. `[mac].cert_integrity = "required"` + `runtime = "required"`,
   restart daemon.

Default (`cert_integrity = "ignore"`, `runtime = "disabled"`)
— production-готов без активации МКЦ. Ничего настраивать не надо.
