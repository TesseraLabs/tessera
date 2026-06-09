# configuration Specification

## Purpose

Схема `/etc/tessera/config.toml`, pipeline RawConfig→ValidatedConfig, семантика перечитывания. Источник истины — `config/raw.rs` + `config/validated.rs` (docs/configuration.md содержит 17 задокументированных расхождений — см. KNOWN GAP внизу).

## Requirements

### Requirement: Fail-closed загрузка + deny_unknown_fields

Невалидный/непарсящийся конфиг ДОЛЖЕН (MUST) приводить: PAM-сторона → `PAM_AUTHINFO_UNAVAIL` на всех фазах; демон → отказ старта; `check` → exit FAILURE. Все секции `#[serde(deny_unknown_fields)]` — неизвестное поле = ошибка (включая legacy `[mac].enabled`, `update_greet_string`) (config/mod.rs:15–25, raw.rs:8).

#### Scenario: Невалидный конфиг
- **WHEN** конфиг не парсится или содержит неизвестное поле
- **THEN** PAM возвращает `PAM_AUTHINFO_UNAVAIL`, демон отказывается стартовать, `check` завершается с exit FAILURE

### Requirement: Семантика перечитывания

PAM-cdylib ДОЛЖЕН (MUST) перечитывать конфиг с диска на КАЖДЫЙ вызов `pam_sm_*` (изменения применяются на следующем auth без рестартов). Демон читает конфиг ОДИН раз при старте — изменения требуют `systemctl restart tessera`. SIGHUP/hot-reload НЕТ.

#### Scenario: Перечитывание на стороне PAM
- **WHEN** конфиг изменён на диске и происходит новый вызов `pam_sm_*`
- **THEN** PAM-cdylib читает свежий конфиг и применяет изменения без рестарта

### Requirement: Ключевые top-level поля

Каждое значение поля ДОЛЖНО (MUST) соответствовать своему default и диапазону из таблицы ниже; нарушение диапазона = ошибка валидации конфига.

| Поле | Default | Диапазон |
|---|---|---|
| `crypto_backend` | обязательно | openssl \| pkcs11_native |
| `mode` | обязательно | pkcs12 \| pkcs11 |
| `pkcs12_path_pattern` | `certs/user.p12` | relative, без `..`, `${user}` |
| `usb_wait_seconds` | 10 | 0..=300 |
| `usb_allowed_devices` | `[]` | список `"vid:pid"`, по 4 hex-цифры (lsusb-формат); пустой = фильтра нет (см. [usb-media-pkcs12](../usb-media-pkcs12/spec.md)) |
| `max_usb_partitions` | 8 | 1..=64 |
| `on_usb_removed` | lock | lock\|logout\|hook\|shutdown |
| `usb_removed_grace_seconds` / `suspend_grace_seconds` | 0 | ≤600 только через [monitor] |
| `monitor_fail_mode` | strict | strict\|permissive |
| `pkcs11_module` | — | обязателен при mode=pkcs11 |
| `pkcs11_max_pin_attempts` | 3 | 1..=5 |
| `pkcs11_slot_wait_seconds` | 10 | 0..=60 |
| `pkcs11_pin_prompt` | «Введите PIN токена: » | ≤128 байт |
| `pkcs11_allow_extractable_keys` | false | bool; true = WARN вместо отказа для `CKA_EXTRACTABLE=TRUE` (см. [token-pkcs11](../token-pkcs11/spec.md)) |
| `pkcs12_pin_prompt` | «Smart-card PIN: » | непустой, ≤128 байт; применяется в PIN-prompt PKCS#12-пути |
| `gost_engine_path` | — | только при openssl; readable файл |

#### Scenario: Поле вне диапазона
- **WHEN** значение top-level поля выходит за указанный диапазон (например `max_usb_partitions=100`)
- **THEN** валидация конфига завершается ошибкой

### Requirement: Секции

Каждая секция конфига ДОЛЖНА (MUST) валидироваться по описанным ниже правилам полей и диапазонов; неизвестные или невалидные значения отвергаются.

- `[monitor]`: socket_path, state_file_path, timeout_ms (2000, 100..=60000), fail_mode (`degraded`→Permissive; при отсутствии — fallback на legacy top-level `monitor_fail_mode`, validated.rs:1137–1152), on_usb_removed (+`on_usb_removed_hook_path`: обязателен при `on_usb_removed="hook"`, абсолютный путь, ЗАПРЕЩЁН в не-hook режиме — raw.rs:282–285, validated.rs:1166–1183), grace-поля (≤600), idle_timeout_seconds (30, 1..=3600), max_concurrent_connections (64, 1..=4096). Последние два пробрасываются в accept-loop через `AcceptConfig::from_monitor` (см. [ipc-protocol](../ipc-protocol/spec.md)).
- `[trust]`: anchors (непустой список — пустые anchors отклоняются валидацией конфига (`TrustError::AnchorsEmpty`); конструктор verifier'а дублирует проверку как defense-in-depth; каждый файл — PEM с BEGIN CERTIFICATE), intermediates, max_chain_depth (5, 1..=16), clock_skew_seconds (0, ≤600), allowed_signature_algorithms (пусто/опущено = безопасный дефолт `DEFAULT_SIGNATURE_ALGORITHMS`: SHA-256/384/512 RSA + ECDSA, без SHA-1 и GOST; GOST — только явный opt-in; см. [trust-chain-validation](../trust-chain-validation/spec.md)).
- `[trust.revocation]`: mode (none|crl). Значения `ocsp`/`crl_then_ocsp` и ключи `ocsp_responder_url`/`ocsp_timeout_seconds`/`ocsp_cache_ttl_seconds` принимаются парсером, но валидация завершается ошибкой «OCSP is not implemented» до реализации `openspec/changes/ocsp-support` (см. [revocation](../revocation/spec.md)). `crl_max_age_hours` (опционален, 1..=8760) пробрасывается в runtime как `crl_max_age` (`RevocationSection` → `RevocationConfig`). `is_file`-проверка CRL — только при mode=crl.
- `[trust.pinning]`: enabled (false), allowed_root_spki_sha256 (64 hex, валидируется только при enabled).
- `[[trust_override]]`: when_host_id_in (непустой) + anchors/intermediates.
- `[host_identity]`: sources (обязателен, непустой, без дублей), fallback (deny), override, custom_command (absolute) + timeout (clamp 1..30).
- `[[user_mapping]]`: pam_user (`^[a-z_][a-z0-9_-]{0,31}$`, без дублей) + ровно один из cert_subject_cn/cert_san_email/cert_san_upn. Legacy fallback при отсутствии user_binding ext.
- `[logging]`: level (trace..error; применяется демоном к tracing-фильтру после загрузки конфига, env `TESSERA_LOG` приоритетнее — см. [logging-audit](../logging-audit/spec.md)); syslog_facility (deprecated, ignored + WARN при валидации; значение всё ещё валидируется: auth|authpriv|user|daemon, прочие — включая local0..7 — отклоняются) и journald_priority (deprecated, ignored + WARN) в ValidatedConfig не пробрасываются.
- `[[hooks]]` — см. [hooks](../hooks/spec.md).
- `[mac]` — см. [mac-integrity](../mac-integrity/spec.md). Дефолты: cert_integrity=**optional**, runtime=auto.
- `[fly_dm_greeter]` — см. [fly-dm-greeter](../fly-dm-greeter/spec.md).

#### Scenario: Пустой [trust].anchors
- **WHEN** `[trust].anchors` — пустой список
- **THEN** валидация конфига завершается ошибкой («trust.anchors must not be empty»)

#### Scenario: Deprecated-ключ [logging] присутствует
- **WHEN** в `[logging]` задан `syslog_facility` (допустимое значение) или `journald_priority`
- **THEN** конфиг валиден, при валидации эмитится WARN «deprecated and ignored» (target `tessera.config`); на runtime значения не влияют

#### Scenario: on_usb_removed_hook_path вне hook-режима
- **WHEN** в `[monitor]` задан `on_usb_removed_hook_path`, но `on_usb_removed` не равен `hook`
- **THEN** валидация секции завершается ошибкой (поле запрещено в не-hook режиме — иначе оно бы молча игнорировалось в runtime)

#### Scenario: hook-режим без on_usb_removed_hook_path
- **WHEN** `on_usb_removed = "hook"`, а `on_usb_removed_hook_path` не задан или не абсолютный
- **THEN** валидация секции завершается ошибкой

### Requirement: Права на config.toml

Код НЕ ДОЛЖЕН (MUST NOT) проверять права config.toml (проверок нет); защита — DAC + (на Astra strict) МКЦ ilevel=63 из postinst. World-writable проверяется только для `/etc/tessera/ca/` (startup-check).

#### Scenario: Права config.toml не проверяются
- **WHEN** выполняется загрузка конфига и startup-check
- **THEN** права самого config.toml не инспектируются; world-writable проверяется только для `/etc/tessera/ca/`

### Requirement: KNOWN GAP — сводка расхождений docs/configuration.md ↔ код

Документация ДОЛЖНА (MUST) быть синхронизирована с кодом: 17 расхождений зафиксировано на момент bootstrap (источник: openspec/.bootstrap-notes/code-config.md §РАСХОЖДЕНИЯ; часть уже закрыта — например `[logging].level` теперь применяется демоном). Критичные из оставшихся: hooks-плейсхолдеры в `command` не работают (только в `env`); стадия `post_auth_failure` не существует; `on_failure` принимает warn|ignore (всё прочее тихо → Abort); `tpm_ek_pubhash` не существует; revocation-поля теряются.

#### Scenario: Расхождение docs ↔ код
- **WHEN** docs/configuration.md описывает поведение, отсутствующее в коде (одно из 17 зафиксированных расхождений)
- **THEN** это считается дефектом документации, требующим синхронизации с кодом
