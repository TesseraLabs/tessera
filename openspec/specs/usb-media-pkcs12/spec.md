# usb-media-pkcs12 Specification

## Purpose

Носитель PKCS#12 на USB-флешке: обнаружение устройства, монтирование, поиск и парсинг `.p12`, PIN-цикл, обращение с секретами. Граница доверия — расшифровка .p12 + валидация цепочки, НЕ метка/имя носителя.

Код: `crates/tessera_core/src/{usb,mount,mount_guard.rs,discovery.rs,pkcs12,secret.rs}`, оркестрация `flow.rs::authenticate_pkcs12`.

## Requirements

### Requirement: Обнаружение USB

Обнаружение ДОЛЖНО (MUST) быть двухфазным: сначала перечислить уже подключённые USB block-устройства (subsystem `block` + `ID_BUS=="usb"`); если пусто — блокироваться на udev `add`-событиях до `usb_wait_seconds` (дефолт 10, валидируется в 0..=300) (linux_impl.rs). Таймаут → `UsbError::Timeout`. Не-Linux → `UnsupportedPlatform` (fail-closed).

Top-level ключ `usb_allowed_devices` (список строк `"vid:pid"`, по 4 hex-цифры — формат lsusb, например `["0951:1666"]`) задаёт allow-list устройств: при непустом списке обнаружение ДОЛЖНО (MUST) отбрасывать устройства, чьи `(vid, pid)` не входят в список; пустой/отсутствующий список = фильтра нет. Невалидный формат записи — ошибка валидации конфига (config/validated.rs). Фильтр — гигиена против случайных устройств, НЕ граница доверия (VID/PID подделываются): доверие остаётся за расшифровкой .p12 + цепочкой.

#### Scenario: Нет уже подключённых USB
- **WHEN** на момент старта auth подключённых USB block-устройств нет
- **THEN** обнаружение блокируется на udev `add`-событиях до `usb_wait_seconds`; по таймауту → `UsbError::Timeout`

#### Scenario: VID/PID вне allow-list
- **WHEN** задан непустой `usb_allowed_devices` и подключено устройство с `(vid, pid)` вне списка
- **THEN** устройство не попадает в кандидаты; при отсутствии других кандидатов до таймаута → `UsbError::Timeout`

### Requirement: Выбор партиций

Whole-device с FS → ровно один кандидат. Whole-disk без FS → резолвер ДОЛЖЕН (MUST) перечислить партиции (DEVTYPE=partition), natural-sort (`sda2`<`sda10`), отобрать ВСЕ с FS из allowlist; метка ФС ДОЛЖНА (MUST) игнорироваться (label не даёт безопасности — решение 0.3.3). Кандидатов > `max_usb_partitions` (дефолт 8, 1..=64) → `TooManyPartitions` (fail-closed против many-partition DoS) (linux_impl.rs:134–234, partition.rs:57–74).

#### Scenario: Слишком много партиций
- **WHEN** число кандидатов-партиций превышает `max_usb_partitions`
- **THEN** возвращается `TooManyPartitions` (fail-closed против many-partition DoS)

### Requirement: Mount — hardened, RO

FS allowlist: `vfat, exfat, ext4, ntfs` (ntfs только потому что RO). Mount ДОЛЖЕН (MUST) идти с `NOSUID|NODEV|NOEXEC|RO|NOATIME`; FS вне allowlist или без fs_type ДОЛЖНА (MUST) отвергаться ДО mount(2) (mount/usb.rs:25,169–211). Mountpoint: `/run/tessera/mounts/<sid>[-seq]`.

#### Scenario: FS вне allowlist
- **WHEN** партиция имеет fs_type не из allowlist либо fs_type не определён
- **THEN** она отвергается ДО вызова mount(2)

### Requirement: MountGuard RAII

На Drop guard ДОЛЖЕН (MUST): umount с `MNT_DETACH` (lazy) → rmdir; при `EBUSY` от rmdir — ретраи (5 попыток × 100 мс: lazy umount может финализироваться асинхронно), затем WARN; ошибки — WARN, не паника (mount_guard.rs). Drop не выполняется при crash PAM-процесса, поэтому остатки под `/run/tessera/mounts/` ДОЛЖЕН (MUST) подбирать startup-cleanup демона (см. [daemon-lifecycle](../daemon-lifecycle/spec.md)): `/run` — tmpfs и чистится только на reboot, а устройство работает неделями. Базовый каталог — константа `mount::usb::MOUNTPOINT_BASE`, общая для PAM-модуля и демона.

#### Scenario: Drop guard при ошибке umount
- **WHEN** на Drop guard umount или rmdir завершается ошибкой
- **THEN** эмитится WARN, паники не происходит

#### Scenario: rmdir EBUSY после lazy umount
- **WHEN** после umount rmdir возвращает `EBUSY`
- **THEN** rmdir ретраится до 5 раз с паузой 100 мс; при исчерпании — WARN, остаточный каталог подберёт startup-cleanup демона

- Замечание (тех-долг): `RealMountOps::mount` — no-op placeholder; фактический mount делает `NixMounter`, guard только adopt'ит (mount_guard.rs).

### Requirement: Поиск .p12

Поиск ДОЛЖЕН (MUST) идти ровно по `<mount>/<pkcs12_path_pattern>` (дефолт `certs/user.p12`; `${user}` поддержан; валидация: относительный путь без `..`). Глоба `*.p12`/`*.pfx` НЕТ. Лимиты: `.p12` ≤ 10 MiB, `chain.pem` ≤ 1 MiB (discovery.rs).

#### Scenario: Файла по точному пути нет
- **WHEN** по пути `<mount>/<pkcs12_path_pattern>` файла нет
- **THEN** глоб-поиск `*.p12`/`*.pfx` НЕ выполняется — кандидат отсутствует

- Замечание (осознанная граница дизайна): путь `certs/chain.pem` фиксирован и намеренно не следует за `pkcs12_path_pattern` — интермедиаты опциональны, и выдача кладёт их в фиксированное место носителя (discovery.rs:106).

### Requirement: ASN.1 envelope pre-check (anti-oracle инвариант)

Перед PIN ДОЛЖЕН (MUST) выполняться `validate_p12_envelope` — структурная проверка внешнего ASN.1-конверта БЕЗ пароля (без MAC, без дешифровки). Перебор партиций допустим ТОЛЬКО до касания пароля:
- продолжать к следующей партиции: `P12NotFound`, `P12EnvelopeError::Asn1`;
- НЕ перебирать (fail-closed, нет PIN/chain-oracle): wrong PIN / MAC fail / decrypt fail / chain fail / host|user binding mismatch (flow.rs:466–578).

Error precedence при отказе всех партиций: `P12Envelope` предпочитается `P12NotFound` (информативнее).

#### Scenario: multi-partition носитель с мусорным файлом
- **WHEN** на первой партиции файл с верным именем, но не PKCS#12 (типично Apple-форматированные флешки)
- **THEN** envelope-fail → umount, переход к следующей партиции без касания PIN

### Requirement: Парсинг PKCS#12 и PIN-цикл

`from_p12`: `Pkcs12::from_der` → `parse2(pin)`; приватный ключ ДОЛЖЕН (MUST) храниться как PKCS#8 DER в `Zeroizing`. Классификация ошибки parse2 по строкам OpenSSL: `mac verify`/`wrong password`/`bad decrypt`/`invalid mac` → WrongPin; иначе Corrupt (pkcs12/mod.rs:63–133).

PIN-retry: максимум **3 попытки (захардкожено)** (flow.rs:582); WrongPin → следующая попытка; MissingKey/MissingCert/Corrupt → немедленный выход без ретрая; исчерпание → `PAM_MAXTRIES`. Текст prompt'а ДОЛЖЕН (MUST) браться из `pkcs12_pin_prompt`; при отсутствии в конфиге — дефолт `"Smart-card PIN: "`. PIN — `SecretString` (zeroize); PIN и байты p12 НЕ ДОЛЖНЫ (MUST NOT) логироваться. Wrong-PIN НИЧЕГО не лочит (USB RO, счётчика нет) — отличие от PKCS#11.

#### Scenario: Исчерпание PIN-попыток
- **WHEN** введён неверный PIN три раза подряд
- **THEN** возвращается `PAM_MAXTRIES`; PIN и байты p12 при этом не логируются

#### Scenario: Операторский pkcs12_pin_prompt
- **WHEN** в конфиге задан непустой `pkcs12_pin_prompt`
- **THEN** PIN-цикл PKCS#12-пути показывает именно его вместо дефолтного `"Smart-card PIN: "`
- Замечание (осознанная граница дизайна): классификация WrongPin опирается на строки сообщений OpenSSL; незнакомое сообщение (новая версия/локаль OpenSSL) консервативно уходит в Corrupt — то есть в немедленный выход без ретрая, fail-closed деградация вместо лишних PIN-попыток.

### Requirement: Диагностика wrong-PIN

При исчерпании PIN, если cert лежит в нешифрованном SafeBag (issuance v2+), он ДОЛЖЕН (MUST) извлекаться без пароля и показывать host/user-binding («не та флешка vs не тот PIN»); cert при этом НЕ валидируется против anchor — только диагностика (pkcs12/mod.rs:176–182).

#### Scenario: Cert в нешифрованном SafeBag после исчерпания PIN
- **WHEN** PIN-попытки исчерпаны, а cert лежит в нешифрованном SafeBag (issuance v2+)
- **THEN** cert извлекается без пароля, показывается host/user-binding для диагностики; против anchor он не валидируется
