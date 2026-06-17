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
| `pam_cert_profile_version` | `2.25.107983357797077476746994938370032043240` | `extnValue ::= INTEGER` (**critical**) |
| `pam_cert_delegation_constraints` | `2.25.242193075883906031821745064285793775511` | `SEQUENCE { requireTags, allowRoles, maxLevel, maxTtl }` (**critical**, только `CA=TRUE`) |

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

## Расширение `profile_version` (version-gate, tags-delegation)

`pam_cert_profile_version` — **critical** X.509 v3-расширение, несущее
целочисленную версию формата серта. Engine знает `max_supported_profile_version`
(конфиг `[trust].max_supported_profile_version`, дефолт `0`); серт **любого**
звена цепи с версией выше → reject всей цепи (fail-closed version-gate). Это
второй слой защиты от эволюции формата: непонятый critical-OID отвергается по
RFC, а понятый, но более новый профиль — version-gate'ом.

OID: `2.25.107983357797077476746994938370032043240`

Структура (DER):

```asn1
extnValue ::= INTEGER
```

Извлечение — только из верифицированного серта (`VerifiedX509`). Malformed (не
INTEGER) или отрицательное значение → reject (audit `profile_version_rejected`).
Отсутствие расширения = baseline (версия `0`), допускается.

Фрагмент `openssl.cnf` для версии `1`:

```ini
2.25.107983357797077476746994938370032043240 = critical,ASN1:INTEGER:1
```

Эквивалент DER-строкой (`INTEGER 1`): `critical,DER:02:01:01`.

## Расширение `delegation_constraints` (рамки делегирования, tags-delegation)

`pam_cert_delegation_constraints` — **critical** X.509 v3-расширение, валидное
**только на серте с `basicConstraints CA=TRUE`** (на листе → malformed → reject).
Объявляет конверт делегирования выпускающего CA: на какую группу устройств (по
тегам), какие роли, потолок уровня и TTL он вправе выпускать. Гарантия
проверяется на устройстве офлайн против собственных подписанных тегов, по
логическому И/MIN ко **всем** CA-звеньям цепи (misissued дочерний CA не
вырывается из родительского конверта).

OID: `2.25.242193075883906031821745064285793775511`

Структура (DER):

```asn1
DelegationConstraints ::= SEQUENCE {
    requireTags  SEQUENCE OF SEQUENCE { key UTF8String, value UTF8String },
    allowRoles   SEQUENCE OF UTF8String,   -- каждый — валидный role_id
    maxLevel     INTEGER,                  -- потолок МКЦ-уровня (-128..127)
    maxTtl       INTEGER                   -- потолок срока звена, секунды
}
```

Семантика на устройстве: `device.tags ⊇ requireTags` (generic-сравнение пар,
без хардкода имён ключей); запрошенная роль ∈ `allowRoles`; запрошенный уровень
`≤ maxLevel`; срок дочернего звена `≤ maxTtl`. Любое нарушение → reject (audit
`delegation_denied`; инженеру — обобщённая причина). Извлечение — только из
`VerifiedX509`; malformed или невалидный `role_id` → reject.

Фрагмент `openssl.cnf` через `ASN1:SEQUENCE` (CA для `region=north`, роли
`oper`/`serv`, уровень ≤ 5, TTL ≤ 14400 с):

```ini
# Только на CA-серте (basicConstraints CA:TRUE)
2.25.242193075883906031821745064285793775511 = critical,ASN1:SEQUENCE:deleg

[ deleg ]
field1 = SEQUENCE:require_tags
field2 = SEQUENCE:allow_roles
field3 = INTEGER:5            # maxLevel
field4 = INTEGER:14400        # maxTtl

[ require_tags ]
t0 = SEQUENCE:tag_region

[ tag_region ]
key = UTF8String:region
val = UTF8String:north

[ allow_roles ]
r0 = UTF8String:oper
r1 = UTF8String:serv
```

Эквивалент DER-строкой:

```ini
2.25.242193075883906031821745064285793775511 = critical,DER:30:28:30:11:30:0f:0c:06:72:65:67:69:6f:6e:0c:05:6e:6f:72:74:68:30:0c:0c:04:6f:70:65:72:0c:04:73:65:72:76:02:01:05:02:02:38:40
```

DER: `SEQUENCE`(30 28){ `SEQUENCE`(30 11) requireTags { `SEQUENCE`(30 0f){
`UTF8String "region"`, `UTF8String "north"` } }, `SEQUENCE`(30 0c) allowRoles {
`UTF8String "oper"`, `UTF8String "serv"` }, `INTEGER 5`(02 01 05),
`INTEGER 14400`(02 02 38 40) }.

**Монотонное сужение.** Дочерний CA ДОЛЖЕН выпускать конверт ⊆ родительского
(больше `requireTags`, подмножество `allowRoles`, не больший `maxLevel`/`maxTtl`)
— ранний отказ и ясность; но безопасность не зависит от честности звеньев:
Engine применяет рамки каждого CA по И, так что более широкий дочерний конверт
не расширяет права. Пример сужения: родитель `requireTags{region:north}`,
`allowRoles{oper,serv,admin}`, `maxLevel:7`; дочерний регион-CA
`requireTags{region:north,site:hq}`, `allowRoles{oper,serv}`, `maxLevel:5`.

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

