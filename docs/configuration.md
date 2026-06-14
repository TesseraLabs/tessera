# Справочник конфигурации Tessera

Этот документ — справочник по основному конфигурационному файлу
`tessera`:

- `/etc/tessera/config.toml` — основная конфигурация модуля и
  демона `tessera`.

Авторизация «какой пользователь на каком хосте» живёт в самом
сертификате — в X.509-расширениях `pam_cert_host_binding` и
`pam_cert_user_binding`. Когда расширение `pam_cert_user_binding`
присутствует на leaf-сертификате, оно полностью определяет, под каким
PAM-пользователем разрешено залогиниться, а массив `[[user_mapping]]`
из этого файла **игнорируется**. `[[user_mapping]]` оставлен в схеме
как legacy-fallback — он применяется только для тех сертификатов,
которые выпущены без расширения `pam_cert_user_binding`. См.
[docs/cert-issuance.md](cert-issuance.md).

Каждое поле описано в формате «тип → значение по умолчанию →
допустимые значения → влияние на поведение → security implication».
Все поля валидируются при загрузке через
`tessera_core::config::ValidatedConfig::try_from`
(см. [`crates/tessera_core/src/config/validated.rs`](../crates/tessera_core/src/config/validated.rs)
и [`crates/tessera_core/src/config/raw.rs`](../crates/tessera_core/src/config/raw.rs)).
Несуществующие поля или неверные типы — ошибка загрузки → fail-closed.

> Все примеры используют тестовые данные (`alice@example.test`,
> `BANKOMAT-001`, `ca-test.example`). Никаких реальных CA, паролей
> или клиентских хостов в этом документе нет.

## Файл `/etc/tessera/config.toml`

Полный поставочный пример лежит в
[`dist/config/config.toml.example`](../dist/config/config.toml.example).
Этот пример проверяется регрессионным тестом
`crates/tessera_core/tests/dist_examples_parse.rs` — он гарантирует,
что пример действительно валидируется через `ValidatedConfig::try_from`.

### Глобальные параметры

| Поле                       | Тип                | Default     | Допустимые значения                                            | Влияние                                                       | Security implication                                                                 |
|----------------------------|--------------------|-------------|----------------------------------------------------------------|---------------------------------------------------------------|--------------------------------------------------------------------------------------|
| `crypto_backend`           | строка             | —           | `"openssl"`, `"pkcs11_native"`                                 | Какой бэкенд считает подписи и хеши.                          | `"openssl"` обязателен для ГОСТ через `gost-engine`.                                 |
| `mode`                     | строка             | —           | `"pkcs12"`, `"pkcs11"`                                         | Где живёт ключ пользователя.                                  | `"pkcs11"` — non-extractable ключ; `"pkcs12"` — программная защита.                  |
| `pkcs11_module`            | путь               | —           | абсолютный путь к `.so`                                        | Какой PKCS#11-модуль используется.                            | Обязателен в `mode = "pkcs11"`.                                                      |
| `pkcs11_token_label`       | строка             | `None`      | `≤ 64` байт без NUL                                            | Фильтр по `CKA_LABEL` токена.                                 | Защищает от случайного выбора чужого токена на машине.                               |
| `pkcs11_object_label`      | строка             | `None`      | `≤ 64` байт без NUL                                            | Фильтр по `CKA_LABEL` объекта (cert/privkey).                 | Аналогично, защита от выбора неправильного объекта.                                  |
| `pkcs11_max_pin_attempts`  | целое              | `3`         | `1..=5`                                                        | Сколько раз модуль предложит ввести PIN.                      | Слишком много → анти-paranoia; слишком мало → плохой UX.                             |
| `pkcs11_locking_mode`      | строка             | `"os"`      | `"os"`, `"mutex"`                                              | Стратегия блокировок PKCS#11.                                 | Зависит от поставляемого PKCS#11-модуля (см. документацию вендора).                  |
| `pkcs11_pin_prompt`        | строка             | `"Введите PIN токена: "` | UTF-8, непустая, `≤ 128` байт                     | Текст приглашения PIN на PKCS#11-пути.                        | Локализация UX, не безопасности.                                                     |
| `pkcs11_slot_wait_seconds` | целое              | `10`        | `0..=60`                                                       | Сколько секунд ждать вставки токена.                          | `0` — не ждать; UX vs. удобство.                                                     |
| `pkcs11_allow_extractable_keys` | булево        | `false`     | `true`, `false`                                                | Принимать ли ключи с `CKA_EXTRACTABLE = TRUE`.                | `false` (default) — отказ (fail-closed): extractable-ключ ломает инвариант режима B. `true` — только WARN `pkcs11_extractable_key`; включать осознанно. |
| `pkcs12_path_pattern`      | строка             | `"certs/user.p12"` | относительный путь от mountpoint USB, опц. `${user}`     | Где искать `.p12` на USB-носителе (поддерживает `${user}`).   | Только относительный путь; `..`/`.` сегменты и абсолютные пути отклоняются валидатором. |
| `pkcs12_pin_prompt`        | строка             | `"Smart-card PIN: "` | UTF-8, непустая, `≤ 128` байт                         | Текст приглашения для пароля `.p12`.                          | Локализация UX.                                                                      |
| `gost_engine_path`         | путь               | `None`      | абсолютный путь к `.so`                                        | Явный путь к `gost-engine`. По умолчанию — поиск по id.       | `None` — engine ищется через `OPENSSL_ENGINES`.                                      |
| `usb_wait_seconds`         | целое              | `10`        | `0..=300`                                                      | Сколько секунд ждать USB-носителя.                            | UX. На `0` — fail-fast.                                                              |
| `usb_allowed_devices`      | массив строк       | `[]`        | строки `"vid:pid"`, по 4 hex-цифры (формат lsusb), напр. `["0951:1666"]` | Allow-list USB-устройств, рассматриваемых как носитель `.p12`; пустой/отсутствующий = любое USB block-устройство. | Гигиена против случайных/посторонних флешек, НЕ граница доверия: VID/PID подделываются, доверие даёт только расшифровка `.p12` + валидация цепочки. |
| `max_usb_partitions`       | целое              | `8`         | `1..=64`                                                       | Максимум партиций, перебираемых при поиске `.p12`.            | Защита от DoS: физический атакующий не сможет навязать огромное число mount/umount.  |
| `on_usb_removed`           | строка             | `"lock"`    | `"lock"`, `"logout"`, `"hook"`, `"shutdown"`                   | Действие при подтверждённом извлечении USB.                   | `"shutdown"` уместен для банкоматов; `"lock"` — для рабочих станций.                 |
| `usb_removed_grace_seconds`| целое              | `0`         | `0..=300`                                                      | Окно отмены: реинсерт того же серийника отменяет действие.    | Защищает от ложных срабатываний; на банкоматах ставить `0`.                          |
| `suspend_grace_seconds`    | целое              | `0`         | `0..=600`                                                      | Окно после resume, в котором USB-removal игнорируется.        | Хабы во время suspend часто шумят; `30` секунд — типовое значение.                   |
| `monitor_fail_mode`        | строка             | `"strict"`  | `"strict"`, `"permissive"`                                     | Пробрасывать ли нефатальные ошибки IPC с `monitord` вызывающему коду (`strict`) или глотать с WARN (`permissive`). | `DeviceGone`/`Unauthorized` фатальны всегда; транспортные сбои monitord не отменяют успех auth (см. architecture.md §13). |

> **Авторизация (host + user) описана в самом сертификате через X.509
> v3 расширения** `pam_cert_host_binding` и `pam_cert_user_binding`.
> Этот файл содержит только trust + identity + monitor + hooks; см.
> [cert-issuance.md](cert-issuance.md) для выпуска сертификатов с
> нужными расширениями.

#### Значения `on_usb_removed`

| Значение     | Действие при подтверждённом извлечении USB                                                | Типовой сценарий                     |
|--------------|-------------------------------------------------------------------------------------------|--------------------------------------|
| `"lock"`     | `LockSession` через D-Bus к logind для **этой** сессии. Хост продолжает работать.          | Рабочая станция оператора.            |
| `"logout"`   | `TerminateSession` для **этой** сессии. Хост продолжает работать, остальные сессии целы. | Киоски, банкоматы (если хост не выключаем). |
| `"hook"`     | Запускается внешний исполняемый файл, заданный в `monitor.on_usb_removed_hook_path`.       | Сложные сценарии (audit + custom action). |
| `"shutdown"` | `PowerOff` через D-Bus к logind — выключение хоста.                                       | Банкоматы / выделенные АРМ.            |

При `"hook"` секция `[monitor]` должна содержать
`on_usb_removed_hook_path = "/абсолютный/путь"`. Валидатор отказывает
в загрузке конфига при `on_usb_removed = "hook"` без `hook_path`.

### Секция `[monitor]`

| Поле                         | Тип    | Default | Допустимые значения | Влияние                                                              | Security implication                                            |
|------------------------------|--------|---------|----------------------|----------------------------------------------------------------------|------------------------------------------------------------------|
| `on_usb_removed_hook_path`   | путь   | `None`  | абсолютный путь      | Исполняемый файл для `on_usb_removed = "hook"`. Валиден **только** при этом значении `on_usb_removed`. | Исполняется от root; путь проверяется на небезопасные права.     |
| `idle_timeout_seconds`       | целое  | `30`    | `1..=3600`           | Idle-таймаут IPC-соединения с monitord.                              | Анти-DoS: висящие соединения закрываются.                        |
| `max_concurrent_connections` | целое  | `64`    | `1..=4096`           | Максимум одновременных IPC-соединений к monitord.                    | Анти-DoS: ограничивает расход ресурсов демона.                   |

### Секция `[trust]`

| Поле                            | Тип        | Default | Допустимые значения                | Влияние                                                | Security implication                                              |
|---------------------------------|------------|---------|------------------------------------|--------------------------------------------------------|-------------------------------------------------------------------|
| `anchors`                       | список путей | —     | `≥ 1` PEM-файл                     | Корневые CA доверия.                                   | Корень доверия. Должны быть `0640 root:root`.                     |
| `intermediates`                 | список путей | `[]`  | PEM-файлы                          | Промежуточные CA (опционально).                        | Снимает нагрузку с поиска цепи.                                   |
| `max_chain_depth`               | целое      | `5`     | `1..=16`                           | Максимальная глубина X.509-цепи.                       | Анти-DoS.                                                         |
| `clock_skew_seconds`            | целое      | `0`     | `0..=600`                          | Допустимое отклонение часов при проверке `notBefore`/`notAfter`. | Слишком много — атакующий с устаревшим сертификатом.   |
| `allowed_signature_algorithms`  | список строк | `[]`  | OID или имена                      | Whitelist подписей. Пустой/опущенный — подменяется безопасным дефолтом: `sha256/384/512WithRSAEncryption`, `ecdsa-with-SHA256/384/512` (без SHA-1 и без ГОСТ). | Запрет SHA-1/MD5/слабых RSA действует и без явной настройки; ГОСТ требует явного opt-in. |

Записи сравниваются **точно** (без подстрок) с OpenSSL display-формой алгоритма
сертификата (см. `pre_validate_end_entity` в
[`crates/tessera_core/src/x509/pre_validate.rs`](../crates/tessera_core/src/x509/)):

- RSA: `"sha256WithRSAEncryption"`, `"sha384WithRSAEncryption"`, `"sha512WithRSAEncryption"`
- ECDSA: `"ecdsa-with-SHA256"`, `"ecdsa-with-SHA384"`, `"ecdsa-with-SHA512"`
- ГОСТ Р 34.10-2012-256: `"id-tc26-signwithdigest-gost3410-12-256"`
- ГОСТ Р 34.10-2012-512: `"id-tc26-signwithdigest-gost3410-12-512"`

### Секция `[trust.revocation]`

| Поле                       | Тип       | Default  | Допустимые значения                                       | Влияние                                                  | Security implication                                                  |
|----------------------------|-----------|----------|-----------------------------------------------------------|----------------------------------------------------------|------------------------------------------------------------------------|
| `mode`                     | строка    | `"none"` | `"none"`, `"crl"`, `"ocsp"`, `"crl_then_ocsp"`           | Какие источники отзыва используются.                     | `"none"` — отзыв не проверяется (НЕ для production).                  |
| `crl_paths`                | список путей | `[]` | PEM/DER-файлы                                             | Локальные CRL.                                           | Обязательны при `mode = "crl"`.                                       |
| `crl_max_age_hours`        | целое     | `None`   | `1..=8760` (часы)                                         | Максимальный возраст CRL от `thisUpdate` до отказа.      | Не задан — свежесть CRL не проверяется; не рекомендуется.             |
| `ocsp_responder_url`       | строка URL | —       | `http://…` / `https://…`                                 | Адрес OCSP-responder'а. ОБЯЗАТЕЛЕН при `mode ∈ {ocsp, crl_then_ocsp}`. AIA из серта не извлекается. | Единственный источник адреса — конфиг (предсказуемость офлайн-аудита). |
| `ocsp_timeout_seconds`     | целое     | `5`      | `1..=30`                                                  | Общий deadline одного OCSP-обмена (connect+write+read).  | Бюджет логина = (глубина цепи − 1) × таймаут.                         |
| `ocsp_cache_ttl_seconds`   | целое     | `3600`   | `0..=86400`                                               | Верхний предел жизни кэш-записи (`0` = кэш выключен).     | Кэш ограничивает сетевые вызовы; запись валидна до `min(nextUpdate, mtime+ttl)`. |

**Семантика режимов отзыва:**

| `mode`           | Поведение |
|------------------|-----------|
| `none`           | Отзыв не проверяется; компенсация — короткий TTL leaf-сертов (deployment-политика). |
| `crl`            | Strict offline CRL: просроченная/отсутствующая покрывающая CRL → отказ. |
| `ocsp`           | Каждый non-anchor серт цепочки проверяется через OCSP; CRL-store не участвует. |
| `crl_then_ocsp`  | Сначала CRL: свежая CRL, чей issuer DN покрывает серт, даёт статус без сетевого вызова; иначе OCSP обязателен. |

> **Fail-closed в OCSP-режимах.** Недоступность responder'а, таймаут,
> статус `unknown`, непроверяемая подпись ответа, окно `thisUpdate/nextUpdate`
> вне допуска (с учётом `clock_skew_seconds`) → **отказ аутентификации**
> (`PAM_AUTH_ERR`). Деградации «WARN и пропустить» в OCSP-режимах нет —
> кто хочет мягкость, выбирает `none` или нестрогий CRL.
>
> **Zero-egress контурам (банкоматы) OCSP не включать** — там нет сети до
> responder'а; их режим `none` + короткий TTL либо offline `crl`. OCSP —
> для сегментов с сетью (офисные АРМ, стенды заказчиков). `ocsp_*`-ключи
> при `mode ∈ {none, crl}` отвергаются валидацией (не могут молча
> игнорироваться). Кэш — `/var/cache/tessera/ocsp/*.der`, каталог создаёт
> postinst пакета.

### Секция `[trust.pinning]`

| Поле                       | Тип       | Default  | Допустимые значения                | Влияние                                                | Security implication                                                  |
|----------------------------|-----------|----------|-------------------------------------|--------------------------------------------------------|------------------------------------------------------------------------|
| `enabled`                  | bool      | `false`  | `true`, `false`                    | Включает pinning по SPKI корневых CA.                   | Защита от компрометации УЦ.                                           |
| `allowed_root_spki_sha256` | список строк | `[]`  | 64-символьные lower-case hex       | Список разрешённых SPKI-хешей корней.                   | Любой корень не из списка отвергается.                                |

### Секция `[host_identity]`

| Поле                            | Тип        | Default          | Допустимые значения                                                       | Влияние                                                           | Security implication                                              |
|---------------------------------|------------|------------------|---------------------------------------------------------------------------|-------------------------------------------------------------------|--------------------------------------------------------------------|
| `sources`                       | список строк | —              | `"machine_id"`, `"dmi_board_serial"`, `"dmi_system_uuid"`, `"dmi_system_serial"`, `"hostname"`, `"custom_command"`, `"override"` | Цепочка источников `host_id`. Первый непустой выигрывает.       | Чем стабильнее источник, тем сильнее host-binding.                |
| `fallback`                      | строка     | `"deny"`         | `"deny"`, `"warn"`, `"allow"`                                             | Что делать, если все источники пустые.                             | На production — только `"deny"`.                                  |
| `override`                      | строка     | `None`           | UTF-8, без перевода строк                                                 | Жёстко заданное значение `host_id` (для тестов).                  | НЕ использовать на production.                                    |
| `custom_command`                | путь       | `None`           | абсолютный путь к скрипту                                                 | Скрипт, печатающий `host_id` в stdout.                             | Скрипт исполняется от `root`. Должен быть `0750 root:root`.       |
| `custom_command_timeout_seconds`| целое      | `5`              | `1..=30`                                                                  | Таймаут на исполнение `custom_command`.                            | Анти-DoS.                                                         |

Реализация цепочки — в
[`crates/tessera_core/src/host_identity/chain.rs`](../crates/tessera_core/src/host_identity/chain.rs).
Поведение `fallback = "deny"` гарантирует fail-closed: если ни один
источник не дал значения, аутентификация не проходит.

### Секция `[[user_mapping]]` (legacy fallback)

> **Только для сертификатов без расширения `pam_cert_user_binding`.**
> Если на leaf-сертификате расширение `pam_cert_user_binding` присутствует,
> массив `[[user_mapping]]` **полностью игнорируется** — авторизацию
> определяет сам сертификат. На новые выпуски расширение должно
> проставляться всегда (mandatory-extension policy, см.
> [docs/threat-model.md §3.8](threat-model.md)).

Массив таблиц. Каждая запись — пара «PAM-пользователь → критерий
сертификата».

| Поле               | Тип    | Default | Допустимые значения              | Влияние                                                  | Security implication                                                |
|--------------------|--------|---------|-----------------------------------|----------------------------------------------------------|----------------------------------------------------------------------|
| `pam_user`         | строка | —       | UNIX-имя пользователя             | Какой UNIX-пользователь предъявляется PAM-стеку.         | Должен быть локальный аккаунт.                                       |
| `cert_subject_cn`  | строка | `None`  | значение `CN` из subject-DN       | Сопоставление по `CN`.                                   | Один из трёх критериев должен быть установлен.                       |
| `cert_san_email`   | строка | `None`  | RFC822-имя из SAN                  | Сопоставление по `subjectAltName`.                       | Точная строка, без regex.                                            |
| `cert_san_upn`     | строка | `None`  | UPN-имя из SAN OtherName           | Сопоставление по UPN (Microsoft AD).                     | Применимо для смешанных AD-сред.                                     |

> Ровно одно из `cert_subject_cn`/`cert_san_email`/`cert_san_upn` должно
> быть установлено в каждой записи. Невыполнение — ошибка валидации.

### Секция `[logging]`

| Поле                | Тип    | Default  | Допустимые значения                                       | Влияние                                                | Security implication                                                  |
|---------------------|--------|----------|-----------------------------------------------------------|--------------------------------------------------------|------------------------------------------------------------------------|
| `level`             | строка | —        | `"error"`, `"warn"`, `"info"`, `"debug"`, `"trace"`       | Уровень детализации журнала **демона**. Переменная окружения `TESSERA_LOG` имеет приоритет над этим полем. | `"trace"` — отладка; не оставлять на production.                       |
| `syslog_facility`   | строка | опционален | `"auth"`, `"authpriv"`, `"user"`, `"daemon"`              | **Deprecated, игнорируется.** PAM-модуль пишет в syslog facility `auth` фиксированно. Поле валидируется (`local0..7` не поддержаны — ошибка загрузки), но на runtime не влияет; при наличии ключа в журнал выдаётся WARN «deprecated and ignored». | Не влияет на поведение.                                                |
| `journald_priority` | bool   | опционален | `true`, `false`                                           | **Deprecated, игнорируется.** При наличии ключа — WARN «deprecated and ignored». | Не влияет на поведение.                                                |

> PIN-коды и пароли никогда не логируются. Полные DN сертификатов
> логируются на уровне `debug` и выше; на `info` и ниже — только CN.

### Секция `[roles]`

Управляет выбором роли на логине и базой ролей устройства (см.
[`docs/cert-issuance.md`](cert-issuance.md) — расширение `pam_cert_allowed_roles`).

| Поле                         | Тип    | Default                  | Допустимые значения            | Влияние                                                                 | Security implication                                                  |
|------------------------------|--------|--------------------------|---------------------------------|--------------------------------------------------------------------------|------------------------------------------------------------------------|
| `enforce`                    | строка | `"false"`                | `"false"`, `"warn"`, `"require"` | Этап миграции enforcement ролей.                                        | `"false"` — роли не проверяются (поведение v0.3.19); `"require"` — полный fail-closed. |
| `dir`                        | путь   | `/var/lib/tessera/roles` | абсолютный путь к каталогу       | Каталог базы ролей (срезы `<role>.toml`).                                | `root:root`, каталог `0755`, файлы `0644`.                            |
| `default_session_ttl_seconds`| целое  | `43200` (12 ч)           | секунды                          | TTL сессии, когда ни удостоверение, ни роль его не задают.               | Бессрочной сессии не возникает — потолок всегда конечен.             |

**Семантика `enforce`:**

| Значение    | Поведение |
|-------------|-----------|
| `"false"`   | Суффикс/prompt не запрашиваются, покрытие не проверяется — вход работает как в v0.3.19. |
| `"warn"`    | Роль проверяется, несоответствие логируется, но во входе не отказывается (миграционный режим). |
| `"require"` | Полный enforcement: роль обязательна и должна быть покрыта удостоверением. |

> **Fail-closed при `enforce = "require"`.** Пустая или невалидная база
> ролей при `require` приводит к отказу входов, требующих роль, с
> диагностикой «роли не настроены».

**Выбор роли на логине.** Дефолтной роли нет — роль указывается явно,
двумя DM-агностичными способами: суффиксом имени учётки
`<user>+<role>` (например `ssh ivanov+serv@device`) либо текстовым
PAM-prompt, если суффикс не задан. Без указания роли (и при
невозможности показать prompt) вход отклоняется. Модуль канонизирует
PAM_USER — переписывает имя на каноническое (`ivanov`) до остальных
модулей стека; символ `+` запрещён в канонических именах учёток.

### Секция `[[hooks]]`

Массив таблиц. Каждый хук — внешняя команда, исполняемая в стадии
жизненного цикла. Полная реализация — в
[`crates/tessera_core/src/hooks/`](../crates/tessera_core/src/hooks/).

| Поле               | Тип        | Default | Допустимые значения                                                                                  | Влияние                                                  | Security implication                                                                  |
|--------------------|------------|---------|-------------------------------------------------------------------------------------------------------|----------------------------------------------------------|----------------------------------------------------------------------------------------|
| `stage`            | строка     | —       | `"pre_auth"`, `"post_auth_success"`, `"session_open"`, `"session_close"`, `"usb_removed"`             | На какой стадии жизненного цикла вызывается хук.         | Хуки исполняются с sandbox-ограничениями (см. [docs/threat-model.md](threat-model.md)). |
| `command`          | список строк | —    | `[ "/usr/local/sbin/foo", "arg" ]`, первый элемент — абсолютный путь                                  | Argv хука. Передаётся **буквально**, placeholder'ы в argv НЕ подставляются. | Динамика передаётся только через `env` — argv injection невозможен.   |
| `timeout_seconds`  | целое      | `10`    | `1..=120`                                                                                             | Таймаут исполнения.                                      | Хук убивается через `SIGKILL` по истечении.                                            |
| `on_failure`       | строка     | `None`  | `"warn"`, `"ignore"`; любое иное значение → abort                                                     | Что делать при ненулевом коде возврата хука.             | Default: abort (deny) для `pre_auth` (там `"warn"` тоже принудительно abort); `"warn"` для остальных стадий. |
| `run_as`           | строка     | `None`  | UNIX-имя                                                                                              | UID, под которым запускается хук.                        | По умолчанию — `root`. Снижение привилегий — лучшая практика.                          |
| `env`              | таблица    | `{}`    | строки `{ KEY = "literal ${placeholder}" }`                                                          | Переменные окружения, передаваемые хуку.                  | База: whitelist `PATH`/`HOME`/`USER`/`LOGNAME`/`LANG` + все `TESSERA_*`-переменные; кастомные ключи могут их переопределить. |

Подстановка `${...}` работает **только в значениях `env`** — `command`
исполняется буквально (см.
[`crates/tessera_core/src/hooks/fork_exec.rs`](../crates/tessera_core/src/hooks/fork_exec.rs)).
Кроме того, хук всегда получает готовый набор переменных
`TESSERA_STAGE`, `TESSERA_USER`, `TESSERA_SERVICE`, `TESSERA_HOST_ID`,
`TESSERA_HOST_ID_HASH`, `TESSERA_HOST_ID_SOURCE`, `TESSERA_CERT_CN`,
`TESSERA_CERT_SERIAL`, `TESSERA_USB_SERIAL`, `TESSERA_USB_VID_PID`,
`TESSERA_SESSION_ID` (пустая строка, если значение недоступно).

Допустимые placeholder'ы для значений `env` (см.
[`crates/tessera_core/src/hooks/placeholder.rs`](../crates/tessera_core/src/hooks/placeholder.rs)):

- `${pam_user}` — UNIX-пользователь.
- `${pam_service}` — PAM-сервис.
- `${host_id}` / `${host_id_hash}` / `${host_id_source}` — вычисленный
  `host_id`, его SHA-256 и имя источника.
- `${cert_cn}` — Common-Name сертификата.
- `${cert_serial}` — серийник сертификата (hex).
- `${usb_serial}` / `${usb_vid_pid}` — данные USB-носителя.
- `${session_id}` — UUID PAM-сессии.

Пример: динамические данные — через `env`, не через argv:

```toml
[[hooks]]
stage           = "post_auth_success"
command         = ["/usr/local/sbin/audit-login"]
timeout_seconds = 5
on_failure      = "warn"
env             = { AUDIT_USER = "${pam_user}", AUDIT_SERIAL = "${cert_serial}" }
```

### Секция `[fly_dm_greeter]` (0.3.19+)

Опциональная. Контролирует wallpaper writer для fly-dm — впечатывает
`host_id` в JPG-фон, на который указывает `[background].path` в
`/etc/X11/fly-dm/fly-modern/settings.ini`. Workaround для МКЦ-3
fly-modern theme, где PAM_TEXT_INFO не пробрасывается в UI.

| Поле                    | Тип    | Default                                                       | Описание                                                                 |
|-------------------------|--------|---------------------------------------------------------------|--------------------------------------------------------------------------|
| `update_wallpaper`      | bool   | `false`                                                       | Включить wallpaper writer.                                               |
| `wallpaper_target`      | path   | `/usr/share/wallpapers/fly-default-light.jpg`                 | JPG, который daemon перерисовывает.                                      |
| `wallpaper_backup`      | path   | `/var/lib/tessera/wallpaper.orig.jpg`                    | Куда сохраняется one-time оригинал источника.                            |
| `wallpaper_font`        | path   | `/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf`        | TrueType шрифт для рендера.                                              |
| `wallpaper_font_size`   | int    | `64`                                                          | Размер шрифта в пунктах.                                                 |
| `wallpaper_text_color`  | string | `"#000000"`                                                   | Цвет в hex (`#RRGGBB`).                                                  |
| `wallpaper_gravity`     | enum   | `"south"`                                                     | `north` / `south` / `east` / `west` / `center` — якорь позиционирования. |
| `wallpaper_offset_x`    | int    | `0`                                                           | Горизонтальное смещение в пикселях от gravity-якоря.                     |
| `wallpaper_offset_y`    | int    | `120`                                                         | Вертикальное смещение в пикселях от gravity-якоря (для `south` — вверх). |
| `template_ru`           | string | `"Банкомат %n  host_id={host_id_short} ({source})"`           | Шаблон для ru locale.                                                    |
| `template_en`           | string | `"ATM %n  host_id={host_id_short} ({source})"`                | Шаблон для en locale.                                                    |

Подстановки в template'е: `{host_id_short}` (первые 8 hex sha256),
`{source}` (имя источника — `MachineId`, `DmiBoardSerial` ...), `%n`
(hostname). Поведение, baseline для `settings.ini`, troubleshooting
— см. **[fly-dm-greeter.md](fly-dm-greeter.md)**.

Legacy-поле `update_greet_string` (0.3.16–0.3.18) — переписывало
`/etc/X11/fly-dm/override/GreetString.desktop`. На production
МКЦ-3 fly-modern игнорируется (no-op). Сохранено для обратной
совместимости, но НЕ работает на банкоматах. Использовать
`update_wallpaper` вместо.

### Секция `[[trust_override]]`

Массив таблиц. Каждая запись — переопределение `[trust]` для
ограниченного набора `host_id`.

| Поле               | Тип        | Default | Допустимые значения        | Влияние                                                | Security implication                                                  |
|--------------------|------------|---------|-----------------------------|--------------------------------------------------------|------------------------------------------------------------------------|
| `when_host_id_in`  | список строк | —     | список `host_id`            | На каких машинах применять override.                    | Должен быть непустым.                                                  |
| `anchors`          | список путей | `[]`  | PEM-файлы                   | Какие корни доверия использовать вместо основных.       | Сужает доверие на конкретных машинах.                                  |
| `intermediates`    | список путей | `[]`  | PEM-файлы                   | Какие промежуточные использовать.                       | Аналогично.                                                            |

### Worked example: минимальная валидная конфигурация

```toml
crypto_backend = "openssl"
mode           = "pkcs12"
pkcs12_path_pattern = "certs/${user}.p12"  # относительно mountpoint USB

usb_wait_seconds         = 10
on_usb_removed           = "lock"
usb_removed_grace_seconds = 5
suspend_grace_seconds    = 30
monitor_fail_mode        = "strict"

[trust]
anchors = ["/etc/tessera/ca/bundle.pem"]

[trust.revocation]
mode = "none"

[host_identity]
sources  = ["machine_id", "hostname"]
fallback = "deny"

[[user_mapping]]
pam_user        = "alice"
cert_subject_cn = "Alice"

[logging]
level = "info"
```

## Авторизация в сертификате

Привязка сертификата к хостам и пользователям полностью описывается
двумя X.509 v3 расширениями leaf-сертификата:

- `pam_cert_host_binding` (OID `2.25.183976554325829274683049824615098`)
  — `SEQUENCE OF UTF8String`, каждая запись — либо `*`, либо
  `sha256:<HEX>`, либо «сырое» значение `machine_id` (тогда сравнение
  идёт через SHA-256 от строки).
- `pam_cert_user_binding` (OID `2.25.215438916728501023845629178354627`)
  — `SEQUENCE OF UTF8String`, каждая запись — либо `*`, либо точное
  имя PAM-пользователя.

Для авторизации сертификата на конкретном `host_id` / `pam_user`
требуется **хотя бы одна совпавшая запись в каждом** из расширений.
Отсутствие любого из расширений, повреждённое DER-кодирование или
полное отсутствие совпадений — отказ (`PAM_AUTH_ERR`).

Подробности и готовые рецепты `openssl.cnf` — в
[cert-issuance.md](cert-issuance.md).

## Типовые сценарии

### 3.1 Банкомат — оффлайн, CRL с TTL, USB обязателен

Свойства: машина в железной коробке, нет Интернета, ключ — на токене,
извлечение USB → немедленное завершение сессии (без grace).

```toml
crypto_backend = "openssl"
mode           = "pkcs11"
pkcs11_module  = "/usr/lib/librtpkcs11ecp.so"
pkcs11_max_pin_attempts = 3
pkcs11_slot_wait_seconds = 5

usb_wait_seconds         = 5
on_usb_removed           = "shutdown"   # банкомат — выключаемся
usb_removed_grace_seconds = 0           # без отмены
suspend_grace_seconds    = 0
monitor_fail_mode        = "strict"

[trust]
anchors = ["/etc/tessera/ca/bankomat-ca.pem"]
allowed_signature_algorithms = [
    "1.2.643.7.1.1.3.2",   # ГОСТ-2012-256
]

[trust.revocation]
mode             = "crl"
crl_paths        = ["/etc/tessera/crl/bankomat.crl"]
crl_max_age_hours = 72

[trust.pinning]
enabled = true
allowed_root_spki_sha256 = [
    "ee0bd4f3a3c8e21d4a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f"
]

[host_identity]
sources  = ["dmi_board_serial", "machine_id"]
fallback = "deny"

[[user_mapping]]
pam_user      = "operator"
cert_san_upn  = "operator@bankomat.example.test"

[logging]
level = "warn"
```

Обоснование выбора:

- `mode = "pkcs11"` + `librtpkcs11ecp.so`: ключ non-extractable.
- `on_usb_removed = "shutdown"`: банкомат не должен оставаться
  включённым с разлоченной сессией.
- `usb_removed_grace_seconds = 0`: на банкомате не может быть «вынул и
  передумал».
- `mode = "crl"` с `crl_max_age_hours = 72`: трое суток — компромисс
  между UX (CRL обновляется ежедневно) и безопасностью.
- `host_identity.sources = ["dmi_board_serial", ...]`: материнская
  плата привязана к корпусу, замена → новый `host_id` → требуется
  перевыпустить сертификат с новым значением в
  `pam_cert_host_binding`.
- `pinning.enabled = true`: компрометация УЦ не открывает все
  банкоматы автоматически.

### 3.2 Рабочая станция в защищённом контуре — CRL, ГОСТ-токен

```toml
crypto_backend = "openssl"
mode           = "pkcs11"
pkcs11_module  = "/usr/lib/librtpkcs11ecp.so"
pkcs11_token_label = "STAFF"
pkcs11_max_pin_attempts = 3
pkcs11_slot_wait_seconds = 10

usb_wait_seconds         = 10
on_usb_removed           = "lock"
usb_removed_grace_seconds = 30
suspend_grace_seconds    = 60
monitor_fail_mode        = "strict"

[trust]
anchors = ["/etc/tessera/ca/staff-ca.pem"]
intermediates = ["/etc/tessera/ca/staff-int.pem"]
allowed_signature_algorithms = [
    "1.2.643.7.1.1.3.2",  # ГОСТ-2012-256
    "1.2.643.7.1.1.3.3",  # ГОСТ-2012-512
]

[trust.revocation]
mode               = "crl"
crl_paths          = ["/etc/tessera/crl/staff.crl"]
crl_max_age_hours  = 24

[host_identity]
sources  = ["machine_id", "hostname"]
fallback = "deny"

[[user_mapping]]
pam_user        = "staff"
cert_subject_cn = "Staff Operator"

[logging]
level = "info"

[[hooks]]
stage           = "post_auth_success"
command         = ["/usr/local/sbin/audit-login"]
timeout_seconds = 5
on_failure      = "warn"
run_as          = "audit"
env             = { AUDIT_USER = "${pam_user}", AUDIT_SERIAL = "${cert_serial}" }
```

Обоснование:

- `usb_removed_grace_seconds = 30`: пользователь может вытащить
  токен, чтобы что-то перевставить, и продолжить работу.
- `mode = "crl"` + `crl_max_age_hours = 24`: единственный
  поддерживаемый источник отзыва; свежесть CRL контролируется TTL.
- `[[hooks]]` для аудита: сторонняя система аудита получает событие
  «вход» (данные — через `env`, argv передаётся буквально).

### 3.3 Тестовое окружение — `mode = "pkcs12"`, без revocation

```toml
crypto_backend = "openssl"
mode           = "pkcs12"
pkcs12_path_pattern = "certs/${user}.p12"  # относительно mountpoint USB
pkcs12_pin_prompt   = "PKCS#12 password: "

usb_wait_seconds         = 5
on_usb_removed           = "lock"
usb_removed_grace_seconds = 5
suspend_grace_seconds    = 0
monitor_fail_mode        = "permissive"

[trust]
anchors = ["/etc/tessera/ca/test-ca.pem"]

[trust.revocation]
mode = "none"

[host_identity]
sources  = ["hostname"]
fallback = "warn"

[[user_mapping]]
pam_user        = "alice"
cert_subject_cn = "Alice"

[logging]
level = "debug"
```

Обоснование:

- `mode = "pkcs12"`: чтобы не возиться с реальным токеном на тестах.
- `monitor_fail_mode = "permissive"`: monitord падает на dev-машинах
  чаще, чем на production.
- `level = "debug"`: всё видно, для отладки.
- `revocation.mode = "none"`: тесты не должны зависеть от внешних
  сервисов.

> **Эту конфигурацию нельзя использовать на production.** Маркер: в
> комментарии к файлу пишется `# TEST CONFIG — DO NOT DEPLOY`.

## MAC integrity (Astra МКЦ, 0.3.0+)

Секция `[mac]` опциональна. На сборке без feature `astra-mac` (Debian,
Ubuntu, Astra без strict-mode) присутствие секции не запрещено — но
`cert_integrity = "required"` отвергается на этапе загрузки конфига:
stub-бэкенд не может применить метки и не должен молча пропускать
аутентификацию, которая обязалась их применять.

### Поля

| Поле                              | Тип           | По умолчанию | Описание                                                                                                  |
|-----------------------------------|---------------|--------------|-----------------------------------------------------------------------------------------------------------|
| `cert_integrity`                  | enum          | `"optional"` | Один из `required` / `optional` / `ignore`. См. ниже.                                                     |
| `fallback_max_integrity.level`    | int (-128..127) | —          | Уровень fallback-метки, если расширение `MAX_INTEGRITY` отсутствует и `cert_integrity = "optional"`.       |
| `fallback_max_integrity.categories` | string (hex или CSV) | —    | Битовая маска категорий для fallback. Пустая строка = `''B`.                                              |
| `runtime`                         | enum          | `"auto"`     | Один из `required` / `auto` / `disabled`. См. ниже (0.3.7+).                                              |
| `warn_on_homedir_label_mismatch`  | bool          | `true`       | Логировать `homedir_label_above_session_cap` при расхождении.                                             |

### Семантика `cert_integrity`

- **`required`** — сертификат обязан содержать `MAX_INTEGRITY`. Если
  расширения нет или DER битый, аутентификация отклоняется
  (`mac_required_no_label` / `mac_parse_failed`).
- **`optional`** — расширение применяется при наличии. Если его нет:
  - есть `[mac.fallback_max_integrity]` → применяется fallback;
  - нет fallback → шаг применения метки пропускается (логируется
    `mac_label_skipped`).
- **`ignore`** — расширение распарсивается для диагностики
  (`mac_label_parsed`), но не применяется. Безопасно для миграции
  парка машин без runtime МКЦ.

### Семантика `runtime` (0.3.7+)

Compile-time feature `astra-mac` решает, **может ли** бинарь линковаться
с libpdp. Поле `runtime` решает, **будет ли** бинарь действительно
использовать настоящий backend в текущем процессе. Это важно для
смешанного парка: один и тот же `.deb` ставится и на машины с МКЦ,
и без, а поведение управляется через `config.toml`.

- **`required`** — обязателен `ParsecBackend` + активное МКЦ-ядро
  (`parsec_strict_mode() == 1`). Если ядро не активно, аутентификация
  отклоняется с событием `mac_runtime_required` (ERROR). Требует
  собранный с `astra-mac` бинарь — иначе конфиг отвергается на старте.
- **`auto`** *(default)* — на старте сессии пробуется
  `parsec_strict_mode`; если активен — настоящий `ParsecBackend`, иначе
  fallback на `StubBackend` с одноразовым событием
  `mac_runtime_fallback` (WARN). Подходит для дев-машин и смешанного
  парка.
- **`disabled`** — всегда `StubBackend`, даже если бинарь собран с
  `astra-mac`. Используется на банкоматах без МКЦ-ядра, чтобы
  гарантированно не вызывать `pdp_*`. Логируется событие
  `mac_runtime_disabled` (INFO).

Валидация конфига:

- `runtime = "disabled"` + `cert_integrity = "required"` отвергается
  на старте (логически несовместимо: stub не может прочитать или
  выставить метку, которую требует cert-политика).
- `runtime = "required"` в бинаре без `astra-mac` отвергается на
  старте.

### Эффективная метка

При `open_session` выбирается:

```
effective = intersect(cert_label, runtime_caps)
```

где `runtime_caps` — потолок, который libpdp возвращает из
`ipdp_get_caps()`. Уровень эффективной метки — `min(cert.level,
caps.level)`; категории — `cert.categories & caps.categories`. Если
после пересечения `effective.level < cert.level` — пишется событие
`mac_level_intersected`; аналогично для категорий.

### Полный пример

```toml
[mac]
cert_integrity = "optional"

[mac.fallback_max_integrity]
level = 0
categories = ""
```

См. `docs/threat-model.md` §«Privilege-escalation via MAC label» и
`docs/cert-issuance.md` §«MAX_INTEGRITY».

## Дальнейшее чтение

- [docs/install.md](install.md) — пошаговая установка.
- [docs/architecture.md](architecture.md) — модель доверия и
  IPC-протокол.
- [docs/threat-model.md](threat-model.md) — каждое поле через призму
  угроз.
- [docs/operations.md](operations.md) — как менять конфиг на работающей
  машине без обрыва сессий.
