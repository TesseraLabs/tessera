# Развёртывание парка АРМ через клонированный образ

Runbook end-to-end: от подготовки эталонного образа до per-host
сертификата на каждом боевом АРМ. Сценарий применим, когда один
образ Astra SE раскатывается на десятки/сотни машин (типично — парк
банкоматов), и `host_id` каждого АРМ известен только после первого
бута на реальном железе.

> Документы рядом:
> - [install.md](install.md) — пошаговая установка `tessera` (выполняется на эталоне).
> - [configuration.md](configuration.md) — справочник по `config.toml`.
> - [cert-issuance.md](cert-issuance.md) — структура и выпуск сертификатов.
> - [operations.md](operations.md) — runbook эксплуатации.

## 1. Зачем bootstrap-режим

Сертификат `tessera` привязан к `host_id_hash` АРМ-а
(расширение `pam_cert_host_binding`). При клонировании эталона:

- `machine_id` совпадает у всех клонов (если не сброшен на первой загрузке);
- `dmi_board_serial` уникален у каждой железки;
- `hostname` назначается оператором/Ansible.

Эталонный образ не может содержать per-host сертификат — его не
существует на момент сборки. Решение: bootstrap-сертификат с
фиксированным `host_binding = "installation"` + `config.toml`,
который резолвит `host_id` в это же значение через
`[host_identity].sources = ["override"]`. Bootstrap проходит auth
на любой машине, развёрнутой из образа. После первого бута оператор
переводит АРМ на реальный источник (`dmi_board_serial` /
`machine_id`) и снимает дамп — теперь известен настоящий
`host_id_hash`, по которому CA выпускает per-host сертификат.

## 2. Подготовка эталонного образа

Шаги выполняются один раз, на эталонной машине, до снятия образа.

### 2.1 Установка `tessera`

См. [install.md §1–§8](install.md). Все секции выполняются
полностью, кроме персонального USB-носителя (раздел 5):
вместо per-user/.p12 на эталон кладётся **bootstrap-цепочка**.

### 2.2 Bootstrap-сертификат

Выпускается CA-инструментами в bootstrap-режиме (см. §6.1).
Сертификат должен содержать расширения:

- `pam_cert_host_binding = "installation"` (строка-маркер, **не** хеш);
- `pam_cert_user_binding = <service_user>`;
- стандартные `extendedKeyUsage = clientAuth, emailProtection`.

`emailProtection` требует не `tessera`, а **штатный валидатор Astra**
(openssl `CMS_verify`) — без этого EKU он отвергает цепочку
(см. [cert-issuance.md](cert-issuance.md)).

### 2.3 `config.toml` на эталоне

```toml
# /etc/tessera/config.toml (фрагмент)

[host_identity]
sources = ["override"]
override = "installation"

[fly_dm_greeter]
update_wallpaper = true     # см. §2.4
```

`sources = ["override"]` + `override = "installation"` заставляет
демон резолвить `host_id` в строку `installation` на любой клон-машине
— ровно то, что зашито в bootstrap-cert.

### 2.4 Wallpaper-баннер (опционально, рекомендуется на МКЦ-3)

На production fly-qdm 2.15+ под МКЦ-3 fly-modern theme hardcoded'но
рендерит `"Усиленный уровень защищенности"` в headline место —
PAM_TEXT_INFO с `host_id` **не виден** в greeter UI. Workaround:
впечатать `host_id` прямо в JPG-фон, на который смотрит
`[background].path` в `/etc/X11/fly-dm/fly-modern/settings.ini`.

Включается одной строкой в `config.toml`:

```toml
[fly_dm_greeter]
update_wallpaper = true
```

Дефолты (все переопределяемые):

| Поле                  | Значение                                                |
|-----------------------|---------------------------------------------------------|
| `wallpaper_target`    | `/usr/share/wallpapers/fly-default-light.jpg`           |
| `wallpaper_backup`    | `/var/lib/tessera/wallpaper.orig.jpg`              |
| `wallpaper_font`      | `/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf`  |
| `wallpaper_font_size` | `64`                                                    |
| `wallpaper_text_color`| `#000000`                                               |
| `wallpaper_gravity`   | `south`                                                 |
| `wallpaper_offset_x`  | `0`                                                     |
| `wallpaper_offset_y`  | `120`                                                   |
| `template_ru`         | `Банкомат %n  host_id={host_id_short} ({source})`       |
| `template_en`         | `ATM %n  host_id={host_id_short} ({source})`            |

При каждом старте `tessera.service`:

1. Первый раз: `cp wallpaper_target → wallpaper_backup` (one-time оригинал).
2. Открывает `wallpaper_backup` как source.
3. Рендерит `template_ru`/`template_en` (по locale) с подстановкой
   `{host_id_short}` (первые 8 hex), `{source}`, `%n` (hostname).
4. Atomic save → `wallpaper_target`.

Демон **не редактирует** `settings.ini` (operator/ansible управляет
`blur`, `color_overlay`, `path`). На эталоне baseline:

```ini
# /etc/X11/fly-dm/fly-modern/settings.ini
[background]
path=/usr/share/wallpapers/fly-default-light.jpg
color_overlay=0,0,0,30

[background][blur]
enable=false
```

При сильном `color_overlay` или включённом blur текст невидим —
снизить alpha и отключить blur перед снятием образа.

### 2.5 Validation эталона

```bash
sudo tessera check
```

Должен вернуть exit 0. На эталоне в журнале демона ожидаемы INFO
`fly-dm wallpaper update finished` (target `tessera.fly_dm_greeter`)
и `host_identity: probe selected` с `source=Override`.

### 2.6 Снятие образа

Стандартный путь (`dd`, Clonezilla, vSphere template — на усмотрение
интегратора). До снятия:

- остановить `tessera.service` (`systemctl stop tessera`);
- очистить `/var/lib/tessera/sessions.json` (опционально, не критично);
- **не очищать** `/etc/machine-id` — после flip-а он перестанет
  использоваться, но до этого момента нужен консистентный override.

## 3. Раскатка клона на боевой АРМ

Клон загружается, bootstrap-цепочка действует — auth работает.
`host_id` всё ещё `installation` на каждой машине.

> На этом этапе **не выпускать** per-host сертификаты:
> `host_id_hash` ещё не известен.

## 4. Flip → production: `finish-bootstrap.sh`

Единственная команда, которую оператор запускает на каждом АРМ-е
после первого бута:

```bash
sudo /usr/share/tessera/finish-bootstrap.sh
```

### 4.1 Что делает скрипт

Atomic, single-pass:

1. **Rewrite `config.toml`**:
   - `[host_identity].sources = ["override"]` → `["dmi_board_serial", "machine_id"]` (default);
   - строка `override = "..."` комментируется (`#override = "..."`).
   - Backup → `/etc/tessera/config.toml.bak.<UTC-ISO8601>`.
2. **Валидирует** новый конфиг: `tessera check`. Если ERROR —
   rollback бекапа, exit ≠ 0.
3. **Рестарт** `tessera.service`, ждёт `is-active=active` до 30 с.
4. **Снимает дамп**: `tessera dump-host-id --usb` с ретраями
   (до 60 с на появление USB, опрос каждые 5 с). Fallback: TSV в
   `/var/lib/tessera/host-ids-<hostname>-<UTC>.tsv`.

### 4.2 Флаги

| Флаг                          | Назначение                                                                                                                          |
|-------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| `--non-interactive`           | Пропустить подтверждения. Для Ansible.                                                                                              |
| `--sources "A,B"`             | Заменить production-список источников. Или переменная `POST_INSTALL_SOURCES`. Default: `dmi_board_serial,machine_id`.               |
| `--no-restart`                | Только rewrite + check, без restart. Для dry-run.                                                                                   |
| `--no-dump`                   | Пропустить шаг 4. Если оператор сам снимет дамп позже.                                                                              |

### 4.3 Идемпотентность

Скрипт детектит `sources = ["override"]` в текущем `config.toml`:

- есть → выполняет полный pipeline;
- нет → exit 0 без изменений (АРМ уже flipped).

Безопасно перезапускать в любой Ansible-выкатке.

### 4.4 Формат TSV-дампа

Колонки:

```
source  status  hash_hex  hash_prefix  raw  normalized  active_under_current_config  reason
```

Одна строка на каждый **известный** источник (не только настроенные):
`machine_id`, `dmi_board_serial`, `dmi_system_uuid`,
`dmi_system_serial`, `hostname`, плюс `custom_command` (если в
конфиге). Строка с `active_under_current_config=yes` — тот источник,
что демон **сейчас** использует. Из неё CA-админ берёт `hash_hex`.

`status` ∈ {`ok`, `err`}. `reason` поясняет `err` (пустое значение,
`dmi_board_serial = 0` в VM, `custom_command exited 1` и т.п.).

Exit ≠ 0 у `dump-host-id`, если **все** известные источники вернули
пустое/ошибку — однозначный сигнал «не выписывать сертификат, пока
не починен вход».

## 5. Возврат флешки на эталонную сторону

Оператор физически приносит USB CA-админу (или передаёт TSV через
безопасный канал — это просто хеши, не секреты).

## 6. CA-сторона: выпуск per-host сертификата

### 6.1 CA-инструменты

CA-инструменты (настройка PKI, выпуск сертификатов в режимах
per-host / wildcard / bootstrap, подготовка USB-носителя)
**не входят** в `.deb` и в этот репозиторий — они не должны
лежать на боевых АРМ. Поставляются отдельно; хранятся на
CA-машине (HSM/Vault host).

### 6.2 Выпуск

Админ читает из TSV строку `active_under_current_config=yes`,
берёт `hash_hex` и выпускает per-host сертификат CA-инструментом.

Сертификат получает расширения:

- `pam_cert_host_binding = <host_id_hash>` (привязка к АРМ-у);
- `pam_cert_user_binding = service`;
- `pam_cert_max_integrity = <level>` если применимо (МКЦ).

### 6.3 Упаковка на USB

Готовый `.p12` упаковывается на флешку оператора CA-инструментом:
старые `.p12` удаляются, новый пишется с правами `0600`,
носитель размонтируется.

**Enrollment-пакет (теги + первый bundle).** Рядом с per-host `.p12` CA
кладёт на тот же возврат USB **enrollment-пакет** — для устройства,
которому при раскатке нужны теги (групповое делегирование) и/или база ролей.
Это контракт CA-стороны (формат — change `device-enrollment`):

- **managed** (с сервером): подписанный `manifest.toml` (Ed25519) с тегами
  устройства, базой ролей и CRL-пином + сам файл CRL. Подпись и монотонный
  `bundle_version` (anti-rollback) — те же, что у `role-store`; теги/роли/CRL
  не секретны → едут открыто (PIN защищает только `.p12`).
- **standalone** (без сервера): файл тегов + срезы ролей под правами ФС
  (`root:root`, dir `0755`, файлы `0644`), без подписи.

Теги/bundle не секретны и доступа сами по себе не дают — доступ по-прежнему
через PIN-защищённый `.p12`; имена тегов Engine не интерпретирует (generic-данные,
обработка единообразная без хардкода ключей). Кривой/битый пакет → импорт
отвергается fail-closed, устройство остаётся в прежнем состоянии.

### 6.4 Назначение тегов — серверная сторона

Устройство **принимает** теги из доверенного источника, но не **решает** их
сам (иначе обход рамок делегирования). Маппинг `hash_hex → теги` —
ответственность Control inventory (или оператора при установке): из TSV-дампа
(`hash_hex`) сервер/оператор выбирает теги устройства (`region`, `class`, …)
и кладёт их в подписанный manifest (managed) или в standalone-файл. Произвольный
локальный конфиг тегов на устройстве **не принимается** как источник.

## 7. Возврат флешки на АРМ

Оператор втыкает USB обратно в боевой АРМ.

- bootstrap-cert на флешке стирается шагом 6.3;
- per-host cert проходит auth → `host_binding` matches `host_id_hash`;
- bootstrap-цепочка в trust store **остаётся валидной** (на случай
  повторного flip-а после смены железа), но cert на USB её больше
  не использует.

**Импорт enrollment-пакета (если есть).** Если CA положил на возврат
enrollment-пакет (§6.3), после `finish-bootstrap` импортируем его:

```bash
# managed (подписанный manifest) — ключ верификации задаётся флагом
tessera enroll --import /run/media/usb --manifest-pubkey /etc/tessera/ca/manifest.pub
# standalone (без сервера)
tessera enroll --standalone --import /run/media/usb
```

Импорт атомарен и идемпотентен: повтор того же `bundle_version` — no-op,
меньший — reject (anti-rollback), больший — применяется. После успешного
импорта автоматически запускается `tessera check`; провал → откат, exit ≠ 0
(fail-closed). Отчёт печатает `host_id` (prefix8), serial серта,
`bundle_version`, режим; событие `device_enrolled` уходит в audit. Без тегов
групповой делегированный вход отвергается (fail-closed), per-host вход по
серту работает.

### 7.1 Verification на АРМ

```bash
journalctl -u tessera -g 'host_identity: probe' -n 20
journalctl -u tessera -g 'host_binding' -n 20
journalctl -u tessera -g 'device_enrolled' -n 5
```

Первая команда — должна показывать `probe selected source=dmi_board_serial`
(или то, что выставлено в `--sources`), **не** `override`. Вторая —
`host_binding match` на следующей auth-сессии.

## 8. Troubleshooting

Clone-specific кейсы (`dump-host-id` пуст, USB не появляется,
`active_under_current_config=no`, bootstrap-cert отвергается,
повторный flip после замены материнки, wallpaper не обновляется)
— см. [troubleshooting.md §7 Clone-image / golden image](troubleshooting.md#7-clone-image--golden-image).
## 9. Ansible-выкатка

Минимальный playbook-фрагмент:

```yaml
- name: Finish bootstrap on cloned ATM
  ansible.builtin.command:
    cmd: /usr/share/tessera/finish-bootstrap.sh --non-interactive --no-dump
  register: finish
  changed_when: "'no changes' not in finish.stdout"

- name: Fetch host_id dump
  ansible.builtin.command:
    cmd: tessera dump-host-id --output /tmp/host-ids.tsv
  changed_when: false

- name: Pull TSV to control node
  ansible.builtin.fetch:
    src: /tmp/host-ids.tsv
    dest: ./host-ids/{{ inventory_hostname }}.tsv
    flat: true
```

Дальше TSV-файлы агрегируются на CA-машине, per-host сертификаты
выпускаются CA-инструментом в цикле, готовые `.p12` распространяются
обратно (на USB-носителе или через защищённый канал на АРМ).

## 10. См. также

- [install.md §2.4¾](install.md) — короткая врезка про tooling.
- [install.md §8.5.1](install.md) — wallpaper baseline в деталях.
- [cert-issuance.md](cert-issuance.md) — расширения сертификатов,
  per-host vs wildcard vs bootstrap.
- [operations.md §2.4](operations.md) — место этого workflow в
  runbook эксплуатации.
- [configuration.md](configuration.md) — `[host_identity]`,
  `[fly_dm_greeter]` поля целиком.
