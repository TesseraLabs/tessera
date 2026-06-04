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
| `usb_wait_seconds` | 10 | ⚠ верхней границы нет (док врёт про 0..=300) |
| `max_usb_partitions` | 8 | 1..=64 |
| `on_usb_removed` | lock | lock\|logout\|hook\|shutdown |
| `usb_removed_grace_seconds` / `suspend_grace_seconds` | 0 | ≤600 только через [monitor] |
| `monitor_fail_mode` | strict | strict\|permissive |
| `pkcs11_module` | — | обязателен при mode=pkcs11 |
| `pkcs11_max_pin_attempts` | 3 | 1..=5 |
| `pkcs11_slot_wait_seconds` | 10 | 0..=60 |
| `pkcs11_pin_prompt` | «Введите PIN токена: » | ≤128 байт |
| `pkcs12_pin_prompt` | — | ⚠ мёртвое поле (не применяется) |
| `gost_engine_path` | — | только при openssl; readable файл |

#### Scenario: Поле вне диапазона
- **WHEN** значение top-level поля выходит за указанный диапазон (например `max_usb_partitions=100`)
- **THEN** валидация конфига завершается ошибкой

### Requirement: Секции

Каждая секция конфига ДОЛЖНА (MUST) валидироваться по описанным ниже правилам полей и диапазонов; неизвестные или невалидные значения отвергаются.

- `[monitor]`: socket_path, state_file_path, timeout_ms (2000, 100..=60000), fail_mode (`degraded`→Permissive), on_usb_removed (+hook_path: обязателен при hook, ЗАПРЕЩЁН в не-hook), grace-поля (≤600), idle_timeout_seconds (30, 1..=3600), max_concurrent_connections (64, 1..=4096). ⚠ Последние два не доходят до accept-loop (см. [ipc-protocol](../ipc-protocol/spec.md)).
- `[trust]`: anchors (PEM с BEGIN CERTIFICATE; ⚠ непустота НЕ enforced на уровне конфига — пустой список ловится только конструктором verifier'а), intermediates, max_chain_depth (5, 1..=16; ⚠ док: 1..=10), clock_skew_seconds (0, ≤600; ⚠ док-default 60), allowed_signature_algorithms (пусто = без ограничений, fail-open).
- `[trust.revocation]`: mode (none|crl|ocsp|crl_then_ocsp). ⚠ crl_max_age_hours / ocsp_* парсятся и ТЕРЯЮТСЯ (не доходят до runtime). `is_file`-проверка CRL — только при mode=crl.
- `[trust.pinning]`: enabled (false), allowed_root_spki_sha256 (64 hex, валидируется только при enabled).
- `[[trust_override]]`: when_host_id_in (непустой) + anchors/intermediates.
- `[host_identity]`: sources (обязателен, непустой, без дублей), fallback (deny), override, custom_command (absolute) + timeout (clamp 1..30).
- `[[user_mapping]]`: pam_user (`^[a-z_][a-z0-9_-]{0,31}$`, без дублей) + ровно один из cert_subject_cn/cert_san_email/cert_san_upn. Legacy fallback при отсутствии user_binding ext.
- `[logging]`: level (trace..error), syslog_facility (auth|authpriv|user|daemon; ⚠ local0..7 НЕ поддержаны), journald_priority.
- `[[hooks]]` — см. [hooks](../hooks/spec.md).
- `[mac]` — см. [mac-integrity](../mac-integrity/spec.md). Дефолты: cert_integrity=**optional** (⚠ док: ignore), runtime=auto.
- `[fly_dm_greeter]` — см. [fly-dm-greeter](../fly-dm-greeter/spec.md).

#### Scenario: hook_path вне hook-режима
- **WHEN** в `[monitor]` задан `hook_path`, но `on_usb_removed` не равен `hook`
- **THEN** валидация секции завершается ошибкой (поле запрещено в не-hook режиме)

### Requirement: Права на config.toml

Код НЕ ДОЛЖЕН (MUST NOT) проверять права config.toml (проверок нет); защита — DAC + (на Astra strict) МКЦ ilevel=63 из postinst. World-writable проверяется только для `/etc/tessera/ca/` (startup-check).

#### Scenario: Права config.toml не проверяются
- **WHEN** выполняется загрузка конфига и startup-check
- **THEN** права самого config.toml не инспектируются; world-writable проверяется только для `/etc/tessera/ca/`

### Requirement: KNOWN GAP — сводка расхождений docs/configuration.md ↔ код

Документация ДОЛЖНА (MUST) быть синхронизирована с кодом: 17 расхождений зафиксировано (источник: openspec/.bootstrap-notes/code-config.md §РАСХОЖДЕНИЯ). Критичные: hooks-плейсхолдеры в `command` не работают (только в `env`); стадия `post_auth_failure` не существует; `on_failure` принимает warn|ignore (всё прочее тихо → Abort); `tpm_ek_pubhash` не существует; revocation-поля теряются; `[logging].level` демоном игнорируется (env `TESSERA_LOG`).

#### Scenario: Расхождение docs ↔ код
- **WHEN** docs/configuration.md описывает поведение, отсутствующее в коде (одно из 17 зафиксированных расхождений)
- **THEN** это считается дефектом документации, требующим синхронизации с кодом
