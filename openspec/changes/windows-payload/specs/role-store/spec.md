# role-store — delta (windows-payload)

## MODIFIED Requirements

### Requirement: Формат среза роли

Срез роли ДОЛЖЕН (MUST) быть TOML-файлом `/var/lib/tessera/roles/<role>.toml` со схемой:
`role` (id, `^[a-z][a-z0-9-]{0,15}$`), `version` (u32), `os` (`astra|linux|windows`),
`name` (строка UI/аудита), `level` (u8, порядок в UI; на Astra соответствует уровню МКЦ),
`description` (опц.), `[payload]` (содержимое зависит от `os`), `[session]` (опц.).
`name` — одна строка (локализация — YAGNI, не закладывается). Поля `[session]` —
закрытый whitelist: `max_ttl` (duration) и ресурсные лимиты сессии `memory_max`, `tasks_max`,
`cpu_weight`, `io_weight` (маппятся в systemd per-session лимиты через `pam_set_data`
до pam_systemd). Для `os = "windows"` в `[session]` ДОЛЖЕН (MUST) допускаться только
`max_ttl` (TOML-ключ `max_ttl_seconds`); systemd-специфичные поля (`memory_max`, `tasks_max`, `cpu_weight`, `io_weight`)
ДОЛЖНЫ (MUST) отвергаться ошибкой валидации — ресурсные лимиты Windows живут в
`[payload.windows.limits]`. Парсинг ДОЛЖЕН (MUST) быть строгим (`deny_unknown_fields`):
неизвестные поля и битые типы — ошибка валидации; границы парсера: файл ≤ 64 KiB, база
≤ 256 ролей (превышение = ошибка валидации, не молчаливое усечение). `role` ДОЛЖЕН (MUST)
совпадать с именем файла и неизменяем (переименование = новая роль). Роли несравнимы: ядро
НЕ ДОЛЖНО (MUST NOT) сравнивать роли или уровни «больше/меньше».

Содержимое `[payload]` для `os = "windows"` — вложенная секция `[payload.windows]`
(все поля опциональны; пустая секция валидна):

- `groups` — список локальных групп для инъекции в токен сессии: имена групп SAM
  и/или SID-строки (`S-1-…`). Элементы ДОЛЖНЫ (MUST) быть непустыми строками;
  строка с префиксом `S-1-` ДОЛЖНА (MUST) быть синтаксически валидным SID
  (`S-1-<число>` и далее дефис-разделённые числа). Резолв имени в SID — задача
  адаптера в runtime, не валидации схемы.
- `integrity_level` — уровень целостности токена сессии; закрытый whitelist
  строк `untrusted|low|medium|high`. Иные значения ДОЛЖНЫ (MUST) отвергаться
  ошибкой валидации. Значение `system` в словаре роли отсутствует намеренно.
- `privileges_remove` — список имён привилегий к отзыву из токена сессии.
  Каждый элемент ДОЛЖЕН (MUST) быть непустой строкой вида `Se…Privilege`
  (префикс `Se`, суффикс `Privilege`); семантика — только сужение: выдачу
  привилегий срез выражать НЕ ДОЛЖЕН (MUST NOT).
- `[payload.windows.limits]` — ресурсные лимиты сессии: `memory_max`
  (строка-размер в конвенции `[session].memory_max`, напр. `512M`) и
  `process_max` (u32).

Кросс-ОС правила ДОЛЖНЫ (MUST) быть симметричны: для `os = "windows"`
допускается только секция `windows` (поля `mac_mask`, `groups`, `sudo_role`,
`limits`, `selinux` верхнего уровня отвергаются); для `os = "astra"` и
`os = "linux"` секция `windows` отвергается. Секция ДОЛЖНА (MUST) парситься
и валидироваться целиком в открытой сборке (формат открыт всегда);
до появления Windows-адаптера секция parse-only — enforcement отсутствует.

#### Scenario: Неизвестное поле в файле роли
- **WHEN** срез содержит поле, отсутствующее в схеме
- **THEN** срез отвергается с ошибкой валидации и audit-событием; остальные роли базы продолжают работать

#### Scenario: Срез чужой ОС
- **WHEN** `os` среза не совпадает с ОС устройства (файл скопирован с другой платформы)
- **THEN** срез отвергается, audit-событие; роль считается отсутствующей

#### Scenario: role не совпадает с именем файла
- **WHEN** `serv.toml` содержит `role = "oper"`
- **THEN** срез отвергается с ошибкой валидации

#### Scenario: Валидный Windows-срез с полным payload
- **WHEN** срез с `os = "windows"` несёт `[payload.windows]` с `groups`, `integrity_level = "medium"`, `privileges_remove` и `[payload.windows.limits]`
- **THEN** срез валиден и загружается (в любой сборке; enforcement не требуется для валидности)

#### Scenario: Секция windows в Linux-срезе
- **WHEN** срез с `os = "linux"` содержит `[payload.windows]`
- **THEN** срез отвергается с ошибкой валидации (payload не принадлежит объявленной ОС)

#### Scenario: Linux-поля в Windows-срезе
- **WHEN** срез с `os = "windows"` содержит `groups`, `sudo_role`, `limits` или `selinux` на верхнем уровне `[payload]`, либо `mac_mask`
- **THEN** срез отвергается с ошибкой валидации

#### Scenario: Невалидный integrity_level
- **WHEN** срез с `os = "windows"` содержит `integrity_level = "s4u-custom"`
- **THEN** срез отвергается с ошибкой валидации (значение вне whitelist)

#### Scenario: Синтаксически битый SID в groups
- **WHEN** элемент `groups` начинается с `S-1-`, но не является валидным SID (например `S-1-abc`)
- **THEN** срез отвергается с ошибкой валидации

#### Scenario: systemd-поля session в Windows-срезе
- **WHEN** срез с `os = "windows"` содержит `[session]` с `memory_max` или `tasks_max`
- **THEN** срез отвергается с ошибкой валидации; `[session]` с одним `max_ttl_seconds` — валиден

#### Scenario: Отзыв привилегии с опечаткой
- **WHEN** `privileges_remove` содержит строку без префикса `Se` или суффикса `Privilege` (например `ShutdownPriv`)
- **THEN** срез отвергается с ошибкой валидации
