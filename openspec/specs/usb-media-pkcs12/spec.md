# usb-media-pkcs12 Specification

## Purpose

Носитель PKCS#12 на USB-флешке: обнаружение устройства, монтирование, поиск и парсинг `.p12`, PIN-цикл, обращение с секретами. Граница доверия — расшифровка .p12 + валидация цепочки, НЕ метка/имя носителя.

Код: `crates/tessera_core/src/{usb,mount,mount_guard.rs,discovery.rs,pkcs12,secret.rs}`, оркестрация `flow.rs::authenticate_pkcs12`.

## Requirements

### Requirement: Обнаружение USB

Обнаружение ДОЛЖНО (MUST) быть двухфазным: сначала перечислить уже подключённые USB block-устройства (subsystem `block` + `ID_BUS=="usb"`); если пусто — блокироваться на udev `add`-событиях до `usb_wait_seconds` (дефолт 10) (linux_impl.rs:37–118). Таймаут → `UsbError::Timeout`. Не-Linux → `UnsupportedPlatform` (fail-closed).

- ⚠ KNOWN GAP: VID/PID-фильтр поддержан кодом, но в проде жёстко `None` и конфиг-ключа НЕТ (entry.rs:207). Если whitelisting по VID/PID — заявленная фича, она не выведена оператору.
- ⚠ KNOWN GAP (docs): configuration.md:55 заявляет диапазон `usb_wait_seconds` 0..=300 — в коде верхней границы нет.

#### Scenario: Нет уже подключённых USB
- **WHEN** на момент старта auth подключённых USB block-устройств нет
- **THEN** обнаружение блокируется на udev `add`-событиях до `usb_wait_seconds`; по таймауту → `UsbError::Timeout`

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

На Drop guard ДОЛЖЕН (MUST): umount с `MNT_DETACH` (lazy) → rmdir; ошибки — WARN, не паника (mount_guard.rs:112–152).

#### Scenario: Drop guard при ошибке umount
- **WHEN** на Drop guard umount или rmdir завершается ошибкой
- **THEN** эмитится WARN, паники не происходит

- ⚠ KNOWN GAP (открытый баг, May 25): sticky mount — при удержании mount чем-либо rmdir падает EBUSY, каталог остаётся; при crash PAM-процесса Drop не выполняется. Предложенный (не реализованный) фикс: poll-after-umount + startup-cleanup остатков в демоне. `/run` tmpfs чистится только на reboot, а банкомат работает неделями.
- Замечание (тех-долг): `RealMountOps::mount` — no-op placeholder; фактический mount делает `NixMounter`, guard только adopt'ит (mount_guard.rs:126–138).

### Requirement: Поиск .p12

Поиск ДОЛЖЕН (MUST) идти ровно по `<mount>/<pkcs12_path_pattern>` (дефолт `certs/user.p12`; `${user}` поддержан; валидация: относительный путь без `..`). Глоба `*.p12`/`*.pfx` НЕТ. Лимиты: `.p12` ≤ 10 MiB, `chain.pem` ≤ 1 MiB (discovery.rs).

#### Scenario: Файла по точному пути нет
- **WHEN** по пути `<mount>/<pkcs12_path_pattern>` файла нет
- **THEN** глоб-поиск `*.p12`/`*.pfx` НЕ выполняется — кандидат отсутствует

- ⚠ Замечание: `certs/chain.pem` захардкожен и не следует за `pkcs12_path_pattern` (discovery.rs:106).

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

PIN-retry: максимум **3 попытки (захардкожено)** (flow.rs:582); WrongPin → следующая попытка; MissingKey/MissingCert/Corrupt → немедленный выход без ретрая; исчерпание → `PAM_MAXTRIES`. PIN — `SecretString` (zeroize); PIN и байты p12 НЕ ДОЛЖНЫ (MUST NOT) логироваться. Wrong-PIN НИЧЕГО не лочит (USB RO, счётчика нет) — отличие от PKCS#11.

#### Scenario: Исчерпание PIN-попыток
- **WHEN** введён неверный PIN три раза подряд
- **THEN** возвращается `PAM_MAXTRIES`; PIN и байты p12 при этом не логируются

- ⚠ KNOWN GAP: `pkcs12_pin_prompt` — мёртвый конфиг: парсится/валидируется, но prompt захардкожен `"Smart-card PIN: "` (pkcs12/mod.rs:208). Реализовать проброс либо задокументировать как no-op.
- ⚠ Замечание (хрупкость): классификация WrongPin по строкам сообщений OpenSSL может сломаться при смене версии/локали — незнакомое сообщение уйдёт в Corrupt (без ретрая).

### Requirement: Диагностика wrong-PIN

При исчерпании PIN, если cert лежит в нешифрованном SafeBag (issuance v2+), он ДОЛЖЕН (MUST) извлекаться без пароля и показывать host/user-binding («не та флешка vs не тот PIN»); cert при этом НЕ валидируется против anchor — только диагностика (pkcs12/mod.rs:176–182).

#### Scenario: Cert в нешифрованном SafeBag после исчерпания PIN
- **WHEN** PIN-попытки исчерпаны, а cert лежит в нешифрованном SafeBag (issuance v2+)
- **THEN** cert извлекается без пароля, показывается host/user-binding для диагностики; против anchor он не валидируется
