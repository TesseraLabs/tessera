# Выпуск сертификатов: host_binding и user_binding

## Введение

Авторизация «какой пользователь на каком хосте» закодирована в двух
X.509-расширениях leaf-сертификата, которые PAM-модуль проверяет на
этапе аутентификации:

- `pam_cert_host_binding`
- `pam_cert_user_binding`

Когда оба расширения присутствуют — они и только они определяют
область действия сертификата. Список `[[user_mapping]]` в
`config.toml` остался как **legacy fallback** для сертификатов,
выпущенных без расширения `pam_cert_user_binding`; на новые выпуски
расширения должны проставляться УЦ всегда (см. `docs/threat-model.md`,
mandatory-extension policy).

Этот документ описывает синтаксис расширений и приводит готовые рецепты
для `openssl.cnf`, по которым сертификат можно выпустить штатным
`openssl x509 -req`.

## OID-таблица

| Имя расширения | Дотированный OID | ASN.1 синтаксис |
|---|---|---|
| `pam_cert_host_binding` | `2.25.183976554325829274683049824615098` | `extnValue ::= SEQUENCE OF UTF8String` |
| `pam_cert_user_binding` | `2.25.215438916728501023845629178354627` | `extnValue ::= SEQUENCE OF UTF8String` |
| `pam_cert_allowed_roles` | `2.25.185305973969816596290730578528098241367` | `extnValue ::= SEQUENCE OF UTF8String` |

OID размещены в нерегистрируемой ветке `2.25.<UUID>` (RFC 4530), что
гарантирует уникальность без обращения к внешнему реестру. Эти значения
зафиксированы в коде (`tessera_core::x509::oids`) и являются частью
on-the-wire X.509-контракта — менять их нельзя.

## Семантика

Каждая запись `UTF8String` в `pam_cert_host_binding` интерпретируется
так:

| Запись | Значение |
|---|---|
| `*` | разрешено на любом хосте |
| `sha256:<HEX>` | разрешено только на хосте, чей `host_id_hash` совпадает с указанным шестидесятичетырёхсимвольным lowercase-hex (case-insensitive) |
| Любая другая UTF-8 строка | строка интерпретируется как «сырое» `machine_id` и сравнение идёт через SHA-256 от строки |

В `pam_cert_user_binding` запись либо `*` (любой PAM-пользователь), либо
точное имя пользователя (case-sensitive — Linux usernames регистрозависимы).

Для авторизации сертификата на конкретном хосте/пользователе нужна
**хотя бы одна совпавшая запись** в каждом из двух расширений.

## Сценарий 1 — рабочая станция: один хост, один пользователь

Рабочее место конкретного оператора. Сертификат можно использовать
только на машине с известным `machine_id` и только для конкретного
PAM-пользователя.

```ini
# openssl.cnf — фрагмент
[ user_exts ]
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature
extendedKeyUsage       = clientAuth
subjectAltName         = email:ivanov@example.org

# Хост: SHA-256 от machine-id операторской АРМ
2.25.183976554325829274683049824615098 = ASN1:SEQUENCE:hb_one
# Пользователь: единственное имя
2.25.215438916728501023845629178354627 = ASN1:SEQUENCE:ub_one

[ hb_one ]
e0 = UTF8String:sha256:a1b2c3d4e5f6...64charsTotal...

[ ub_one ]
e0 = UTF8String:ivanov
```

Команда выпуска:

```sh
openssl req -new -key user.key -subj "/CN=Иванов" \
    -reqexts user_exts -config openssl.cnf -out user.csr
openssl x509 -req -in user.csr -CA int.pem -CAkey int.key \
    -CAcreateserial -days 365 -sha256 \
    -extfile openssl.cnf -extensions user_exts -out user.pem
```

## Сценарий 2 — оператор терминалов: несколько хостов, один пользователь

```ini
[ hb_three_hosts ]
e0 = UTF8String:sha256:1111111111111111111111111111111111111111111111111111111111111111
e1 = UTF8String:sha256:2222222222222222222222222222222222222222222222222222222222222222
e2 = UTF8String:sha256:3333333333333333333333333333333333333333333333333333333333333333

[ ub_operator ]
e0 = UTF8String:operator
```

## Сценарий 3 — мобильный администратор: любой хост, точный пользователь

```ini
[ hb_any ]
e0 = UTF8String:*

[ ub_admin ]
e0 = UTF8String:admin
```

`*` в host_binding позволяет сертификату работать на любой машине; в
user_binding по-прежнему остаётся жёсткое ограничение на имя
пользователя.

## Проверка выпущенного сертификата

```sh
openssl x509 -in user.pem -noout -text
```

В выводе должны присутствовать обе строки с дотированными OID:

```
2.25.183976554325829274683049824615098:
    0...sha256:a1b2c3d4...
2.25.215438916728501023845629178354627:
    0...ivanov
```

## Таблица проверки

| Запись | Совпадает с… |
|---|---|
| `*` | любым хостом / любым пользователем |
| `sha256:<HEX>` | хостом, чей `host_id_hash` равен `HEX` (без учёта регистра) |
| `<raw>` (host_binding) | хостом, чей `host_id_hash` равен `sha256(raw)` |
| `<name>` (user_binding) | PAM-пользователем с точным именем `<name>` |
| Расширение отсутствует | **отказ** (`HostExtensionMissing` / `UserExtensionMissing`) |
| Расширение пустое или DER-битое | **отказ** (`*ExtensionMalformed`) |
| Записи есть, но ни одна не совпала | **отказ** (`HostNotAllowed` / `UserNotAllowed`) |

См. также [`docs/configuration.md`](configuration.md).

## Расширение `MAX_INTEGRITY` (МКЦ Astra, 0.3.0+)

`MAX_INTEGRITY` — non-critical X.509 v3-расширение, кодирующее
максимальную метку целостности `(level, categories)`, до которой
сертификат может быть допущен на хосте Astra SE с включённым
strict-mode.

OID: `2.25.273824307386008814506455310913083078403`

Структура (DER):

```asn1
IntegrityLabel ::= SEQUENCE {
    level       INTEGER (-128..127),
    categories  BIT STRING DEFAULT ''B
}
```

Семантика на сервере:

- При `open_session` PAM-модуль выбирает эффективную метку как
  `intersect(cert, runtime_caps, fallback?)`.
- `cert_integrity = "required"` → сертификат без расширения отвергается.
- `cert_integrity = "optional"` → отсутствие расширения допускается;
  если задан `[mac.fallback_max_integrity]`, применяется он.
- `cert_integrity = "ignore"` → расширение игнорируется.

См. `docs/configuration.md` §«MAC integrity» и `docs/threat-model.md`
§«Privilege-escalation via MAC label».

Готовые шаблоны openssl.cnf для тестовых сертификатов:
`tests/fixtures/leaf-{l2-c01,l1-empty,no-ext,l3,malformed,l0-fullcats}.cnf`.
Генерация — `tests/fixtures/setup-mac-fixtures.sh`.

Пример строки в `openssl.cnf` для `level=2, categories={0}`:

```ini
2.25.273824307386008814506455310913083078403 = critical,DER:30:06:02:01:02:03:02:00:01
```

DER здесь — три TLV: `SEQUENCE`, `INTEGER 2`, `BIT STRING '01'B`.

## Расширение `allowed_roles` (выбор роли на логине, role-format)

`pam_cert_allowed_roles` — non-critical X.509 v3-расширение, перечисляющее
`role_id`, которые leaf-сертификат имеет право активировать на логине
(`user+role`). Семантика авторизационная: запрошенная роль покрыта, если
её `role_id` присутствует в списке.

OID: `2.25.185305973969816596290730578528098241367`

Структура (DER) — та же, что у host/user binding:

```asn1
extnValue ::= SEQUENCE OF UTF8String
```

Каждая `UTF8String` — это `role_id`, обязан матчить `^[a-z][a-z0-9-]{0,15}$`.
Список разбирается строго fail-closed: при некорректном DER **или** любой
строке, не проходящей regex `role_id`, всё расширение считается malformed
(не пропуск одной строки), список ролей пуст → запрошенная роль не покрыта
→ отказ (audit `cert_allowed_roles_parse_failed`). Отсутствие расширения =
сертификат не даёт ролей (при `roles.enforce = require` — отказ входа; при
`warn` — лог и пропуск, миграционный режим).

Семантика на сервере: см. `docs/configuration.md` §«roles» и дельта-спеку
`role-selection`. Извлечение — только из верифицированного серта
(`VerifiedX509`), как у `max_integrity`.

Фрагмент `openssl.cnf` через `ASN1:SEQUENCE` (две роли — `oper`, `serv`):

```ini
# Роли, которые серт может активировать на логине
2.25.185305973969816596290730578528098241367 = ASN1:SEQUENCE:allowed_roles

[ allowed_roles ]
e0 = UTF8String:oper
e1 = UTF8String:serv
```

Эквивалент одной DER-строкой (`SEQUENCE { UTF8String "oper", UTF8String "serv" }`):

```ini
2.25.185305973969816596290730578528098241367 = DER:30:0c:0c:04:6f:70:65:72:0c:04:73:65:72:76
```

DER здесь: `SEQUENCE` (30 0c) → `UTF8String "oper"` (0c 04 6f 70 65 72) →
`UTF8String "serv"` (0c 04 73 65 72 76). Расширение non-critical (без
префикса `critical,`).

## Workflow для клонированных образов

Полный end-to-end runbook (эталон → клон → flip → выпуск per-host) —
в **[docs/clone-image.md](clone-image.md)**. Здесь — только CA-сторона:
как читать TSV-дамп и что попадает в выпускаемый сертификат.

### TSV-дамп от оператора

Оператор после `finish-bootstrap.sh` присылает CA-админу файл
`host-ids-<hostname>-<UTC>.tsv` (с USB или через защищённый канал).
Колонки:

```
source  status  hash_hex  hash_prefix  raw  normalized  active_under_current_config  reason
```

Одна строка на каждый **известный** источник (не только настроенные
в `[host_identity].sources`): `machine_id`, `dmi_board_serial`,
`dmi_system_uuid`, `dmi_system_serial`, `hostname`, плюс
`custom_command` (если configured).

Строка с `active_under_current_config=yes` — это тот источник,
который daemon **сейчас** использует. Только её `hash_hex` идёт
в сертификат.

### Выпуск per-host сертификата

`hash_hex` подаётся в CA-инструмент выпуска (см.
[clone-image.md §6.1](clone-image.md) — CA-инструменты поставляются
отдельно, не в этом репозитории).

Cert получает `pam_cert_host_binding = <hash_hex>`,
`pam_cert_user_binding = <service_user>` и стандартный
`extendedKeyUsage = clientAuth, emailProtection` (`emailProtection`
требует штатный валидатор Astra — openssl `CMS_verify`; сам
`tessera` этот EKU не проверяет). На МКЦ-АРМ
дополнительно `pam_cert_max_integrity` (см. §«Поле MaxIntegrity»).

Готовый `.p12` упаковывается на ту же флешку CA-инструментом
и возвращается на АРМ.

### Pre-flight checks

`tessera dump-host-id` (вызываемый внутри `finish-bootstrap.sh`
или вручную) выходит с **ненулевым кодом**, если ни один источник
не отдал непустое значение. Это однозначный сигнал «не выписывайте
сертификат, пока не починён вход» — типичные причины: пустые
DMI-поля в VM, очищенный `machine_id`, неработающий `custom_command`.
См. [clone-image.md §8](clone-image.md) — troubleshooting.

### Ручной дамп (без скрипта)

После уже состоявшегося flip-а:

- `tessera dump-host-id --usb` — на USB-флешку;
- `tessera dump-host-id --output /tmp/host.tsv` — в файл;
- `tessera dump-host-id` (без флагов) — в stdout.

