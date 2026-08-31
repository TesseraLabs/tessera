---
id: usb-pkcs12-carrier
kind: операция
context: auth
name: "PKCS#12 на USB-носителе"
aliases:
  - "usb-media-pkcs12"
relations:
  references:
    - auth.carrier
    - auth.credential
anchors:
  code:
    - "crates/pam_tessera/src/volume_flow.rs"
  test:
    - "tests/e2e/cases/24-usb-media.yaml"
requirements:
  USB-001:
    kind: операционное
    subjects:
      - auth.usb-pkcs12-carrier
    origins:
      - "usb-media-pkcs12::Обнаружение USB"
    evidence:
      code:
        - "crates/pam_tessera/src/volume_flow.rs"
  USB-002:
    kind: инвариант
    subjects:
      - auth.usb-pkcs12-carrier
    origins:
      - "usb-media-pkcs12::Выбор партиций"
    evidence:
      test:
        - "tests/e2e/cases/24-usb-media.yaml"
  USB-003:
    kind: операционное
    subjects:
      - auth.usb-pkcs12-carrier
    origins:
      - "usb-media-pkcs12::Mount — hardened, RO"
    evidence:
      code:
        - "crates/pam_tessera/src/volume_flow.rs"
  USB-004:
    kind: операционное
    subjects:
      - auth.usb-pkcs12-carrier
    origins:
      - "usb-media-pkcs12::MountGuard RAII"
    evidence:
      code:
        - "crates/pam_tessera/src/volume_flow.rs"
  USB-005:
    kind: операционное
    subjects:
      - auth.usb-pkcs12-carrier
    origins:
      - "usb-media-pkcs12::Поиск .p12"
    evidence:
      code:
        - "crates/pam_tessera/src/volume_flow.rs"
  USB-006:
    kind: операционное
    subjects:
      - auth.usb-pkcs12-carrier
    origins:
      - "usb-media-pkcs12::ASN.1 envelope pre-check (anti-oracle инвариант)"
    evidence:
      code:
        - "crates/pam_tessera/src/volume_flow.rs"
  USB-007:
    kind: инвариант
    subjects:
      - auth.usb-pkcs12-carrier
    origins:
      - "usb-media-pkcs12::Парсинг PKCS#12 и PIN-цикл"
    evidence:
      test:
        - "tests/e2e/cases/24-usb-media.yaml"
  USB-008:
    kind: инвариант
    subjects:
      - auth.usb-pkcs12-carrier
    origins:
      - "usb-media-pkcs12::Диагностика wrong-PIN"
    evidence:
      test:
        - "tests/e2e/cases/24-usb-media.yaml"
---
# PKCS#12 на USB-носителе

Эта страница заменяет процедурную capability-спеку OpenSpec «usb-media-pkcs12»: она
помещает каждое прежнее требование в адресуемую норму с владельцем, видом и
проверяемым происхождением. Под каждым нормативным предложением сохранены подробные условия, отрицательные
сценарии и rationale; они входят в ту же страницу и уточняют границы нормы.

### USB-001 — Обнаружение USB

[[auth.usb-pkcs12-carrier|PKCS#12 на USB-носителе]] MUST соблюдать правило «Обнаружение USB» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/usb-media-pkcs12/spec.md, requirement «Обнаружение USB».

Обнаружение должно быть двухфазным: сначала перечислить уже подключённые USB block-устройства (subsystem `block` + `ID_BUS=="usb"`); если пусто — блокироваться на udev `add`-событиях до `usb_wait_seconds` (дефолт 10, валидируется в 0..=300) (linux_impl.rs). Таймаут → `UsbError::Timeout`. Не-Linux → `UnsupportedPlatform` (fail-closed).

Top-level ключ `usb_allowed_devices` (список строк `"vid:pid"`, по 4 hex-цифры — формат lsusb, например `["0951:1666"]`) задаёт allow-list устройств: при непустом списке обнаружение должно отбрасывать устройства, чьи `(vid, pid)` не входят в список; пустой/отсутствующий список = фильтра нет. Невалидный формат записи — ошибка валидации конфига (config/validated.rs). Фильтр — гигиена против случайных устройств, НЕ граница доверия (VID/PID подделываются): доверие остаётся за расшифровкой .p12 + цепочкой.

#### Scenario: Нет уже подключённых USB
- **WHEN** на момент старта auth подключённых USB block-устройств нет
- **THEN** обнаружение блокируется на udev `add`-событиях до `usb_wait_seconds`; по таймауту → `UsbError::Timeout`

#### Scenario: VID/PID вне allow-list
- **WHEN** задан непустой `usb_allowed_devices` и подключено устройство с `(vid, pid)` вне списка
- **THEN** устройство не попадает в кандидаты; при отсутствии других кандидатов до таймаута → `UsbError::Timeout`

### USB-002 — Выбор партиций

[[auth.usb-pkcs12-carrier|PKCS#12 на USB-носителе]] MUST соблюдать правило «Выбор партиций» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/usb-media-pkcs12/spec.md, requirement «Выбор партиций».

Whole-device с FS → ровно один кандидат. Whole-disk без FS → резолвер должен перечислить партиции (DEVTYPE=partition), natural-sort (`sda2`<`sda10`), отобрать ВСЕ с FS из allowlist; метка ФС должна игнорироваться (label не даёт безопасности — решение 0.3.3). Кандидатов > `max_usb_partitions` (дефолт 8, 1..=64) → `TooManyPartitions` (fail-closed против many-partition DoS) (linux_impl.rs:134–234, partition.rs:57–74).

#### Scenario: Слишком много партиций
- **WHEN** число кандидатов-партиций превышает `max_usb_partitions`
- **THEN** возвращается `TooManyPartitions` (fail-closed против many-partition DoS)

### USB-003 — Mount — hardened, RO

[[auth.usb-pkcs12-carrier|PKCS#12 на USB-носителе]] MUST соблюдать правило «Mount — hardened, RO» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/usb-media-pkcs12/spec.md, requirement «Mount — hardened, RO».

FS allowlist: `vfat, exfat, ext4, ntfs` (ntfs только потому что RO). Mount должен идти с `NOSUID|NODEV|NOEXEC|RO|NOATIME`; FS вне allowlist или без fs_type должна отвергаться ДО mount(2) (mount/usb.rs:25,169–211). Mountpoint: `/run/tessera/mounts/<sid>[-seq]`.

#### Scenario: FS вне allowlist
- **WHEN** партиция имеет fs_type не из allowlist либо fs_type не определён
- **THEN** она отвергается ДО вызова mount(2)

### USB-004 — MountGuard RAII

[[auth.usb-pkcs12-carrier|PKCS#12 на USB-носителе]] MUST соблюдать правило «MountGuard RAII» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/usb-media-pkcs12/spec.md, requirement «MountGuard RAII».

На Drop guard должен: umount с `MNT_DETACH` (lazy) → rmdir; при `EBUSY` от rmdir — ретраи (5 попыток × 100 мс: lazy umount может финализироваться асинхронно), затем WARN; ошибки — WARN, не паника (mount_guard.rs). Drop не выполняется при crash PAM-процесса, поэтому остатки под `/run/tessera/mounts/` должен подбирать startup-cleanup демона (см. [daemon-lifecycle](../daemon-lifecycle/spec.md)): `/run` — tmpfs и чистится только на reboot, а устройство работает неделями. Базовый каталог — константа `mount::usb::MOUNTPOINT_BASE`, общая для PAM-модуля и демона.

#### Scenario: Drop guard при ошибке umount
- **WHEN** на Drop guard umount или rmdir завершается ошибкой
- **THEN** эмитится WARN, паники не происходит

#### Scenario: rmdir EBUSY после lazy umount
- **WHEN** после umount rmdir возвращает `EBUSY`
- **THEN** rmdir ретраится до 5 раз с паузой 100 мс; при исчерпании — WARN, остаточный каталог подберёт startup-cleanup демона

- Замечание (тех-долг): `RealMountOps::mount` — no-op placeholder; фактический mount делает `NixMounter`, guard только adopt'ит (mount_guard.rs).

### USB-005 — Поиск .p12

[[auth.usb-pkcs12-carrier|PKCS#12 на USB-носителе]] MUST соблюдать правило «Поиск .p12» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/usb-media-pkcs12/spec.md, requirement «Поиск .p12».

Поиск должен идти ровно по `<mount>/<pkcs12_path_pattern>` (дефолт `certs/user.p12`; `${user}` поддержан; валидация: относительный путь без `..`). Глоба `*.p12`/`*.pfx` НЕТ. Лимиты: `.p12` ≤ 10 MiB, `chain.pem` ≤ 1 MiB (discovery.rs).

#### Scenario: Файла по точному пути нет
- **WHEN** по пути `<mount>/<pkcs12_path_pattern>` файла нет
- **THEN** глоб-поиск `*.p12`/`*.pfx` НЕ выполняется — кандидат отсутствует

- Замечание (осознанная граница дизайна): путь `certs/chain.pem` фиксирован и намеренно не следует за `pkcs12_path_pattern` — интермедиаты опциональны, и выдача кладёт их в фиксированное место носителя (discovery.rs:106).

### USB-006 — ASN.1 envelope pre-check (anti-oracle инвариант)

[[auth.usb-pkcs12-carrier|PKCS#12 на USB-носителе]] MUST соблюдать правило «ASN.1 envelope pre-check (anti-oracle инвариант)» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/usb-media-pkcs12/spec.md, requirement «ASN.1 envelope pre-check (anti-oracle инвариант)».

Перед PIN должен выполняться `validate_p12_envelope` — структурная проверка внешнего ASN.1-конверта БЕЗ пароля (без MAC, без дешифровки). Перебор партиций допустим ТОЛЬКО до касания пароля:
- продолжать к следующей партиции: `P12NotFound`, `P12EnvelopeError::Asn1`;
- НЕ перебирать (fail-closed, нет PIN/chain-oracle): wrong PIN / MAC fail / decrypt fail / chain fail / host|user binding mismatch (flow.rs:466–578).

Error precedence при отказе всех партиций: `P12Envelope` предпочитается `P12NotFound` (информативнее).

#### Scenario: multi-partition носитель с мусорным файлом
- **WHEN** на первой партиции файл с верным именем, но не PKCS#12 (типично Apple-форматированные флешки)
- **THEN** envelope-fail → umount, переход к следующей партиции без касания PIN

### USB-007 — Парсинг PKCS#12 и PIN-цикл

[[auth.usb-pkcs12-carrier|PKCS#12 на USB-носителе]] MUST соблюдать правило «Парсинг PKCS#12 и PIN-цикл» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/usb-media-pkcs12/spec.md, requirement «Парсинг PKCS#12 и PIN-цикл».

`from_p12`: `Pkcs12::from_der` → `parse2(pin)`; приватный ключ должен храниться как PKCS#8 DER в `Zeroizing`. Классификация ошибки parse2 по строкам OpenSSL: `mac verify`/`wrong password`/`bad decrypt`/`invalid mac` → WrongPin; иначе Corrupt (pkcs12/mod.rs:63–133).

PIN-retry: максимум **3 попытки (захардкожено)** (flow.rs:582); WrongPin → следующая попытка; MissingKey/MissingCert/Corrupt → немедленный выход без ретрая; исчерпание → `PAM_MAXTRIES`. Текст prompt'а должен браться из `pkcs12_pin_prompt`; при отсутствии в конфиге — дефолт `"Smart-card PIN: "`. PIN — `SecretString` (zeroize); PIN и байты p12 не должны логироваться. Wrong-PIN НИЧЕГО не лочит (USB RO, счётчика нет) — отличие от PKCS#11.

#### Scenario: Исчерпание PIN-попыток
- **WHEN** введён неверный PIN три раза подряд
- **THEN** возвращается `PAM_MAXTRIES`; PIN и байты p12 при этом не логируются

#### Scenario: Операторский pkcs12_pin_prompt
- **WHEN** в конфиге задан непустой `pkcs12_pin_prompt`
- **THEN** PIN-цикл PKCS#12-пути показывает именно его вместо дефолтного `"Smart-card PIN: "`
- Замечание (осознанная граница дизайна): классификация WrongPin опирается на строки сообщений OpenSSL; незнакомое сообщение (новая версия/локаль OpenSSL) консервативно уходит в Corrupt — то есть в немедленный выход без ретрая, fail-closed деградация вместо лишних PIN-попыток.

### USB-008 — Диагностика wrong-PIN

[[auth.usb-pkcs12-carrier|PKCS#12 на USB-носителе]] MUST соблюдать правило «Диагностика wrong-PIN» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/usb-media-pkcs12/spec.md, requirement «Диагностика wrong-PIN».

При исчерпании PIN, если cert лежит в нешифрованном SafeBag (issuance v2+), он должен извлекаться без пароля и показывать host/user-binding («не та флешка vs не тот PIN»); cert при этом НЕ валидируется против anchor — только диагностика (pkcs12/mod.rs:176–182).

#### Scenario: Cert в нешифрованном SafeBag после исчерпания PIN
- **WHEN** PIN-попытки исчерпаны, а cert лежит в нешифрованном SafeBag (issuance v2+)
- **THEN** cert извлекается без пароля, показывается host/user-binding для диагностики; против anchor он не валидируется

