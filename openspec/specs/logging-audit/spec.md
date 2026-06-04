# logging-audit Specification

## Purpose

Структурное логирование (tracing) и стабильные audit-события. Что логируется, куда, что НИКОГДА не попадает в логи.

Код: `crates/tessera_core/src/logging.rs` (заглушка), `tessera_cli/src/logging.rs`, `tessera_core/src/mac/audit.rs`.

## Requirements

### Requirement: Назначение вывода

Демон/CLI ДОЛЖНЫ (MUST) писать tracing в stderr → journald (под systemd); уровень — из env `TESSERA_LOG` (default info). PAM-сторона инициализируется через `logging::init_once` в entry.rs.

#### Scenario: Вывод под systemd
- **WHEN** демон/CLI запущены под systemd
- **THEN** tracing пишется в stderr и попадает в journald; уровень берётся из `TESSERA_LOG` (default info)

- ⚠ KNOWN GAP: `init_syslog` в core — no-op заглушка; `[logging].level/syslog_facility/journald_priority` парсятся и валидируются, но применяющего их subscriber-кода не обнаружено (демон уровень берёт из env). Конфиг-секция фактически декоративна — синхронизировать код либо docs.

### Requirement: Стабильные tracing-targets

`tessera.auth`, `tessera.flow`, `tessera.usb`, `tessera.host_identity`, `tessera.hook.*` (start/finish/timeout/failed/stdout/stderr), `tessera.startup_check`, `tessera.monitord`, `tessera.fly_dm_greeter`, `mac.audit`. Имена ДОЛЖНЫ (MUST) считаться API для журнальных grep'ов операторов.

#### Scenario: Стабильность target-имён
- **WHEN** оператор грепает журнал по tracing-target (например `tessera.auth`)
- **THEN** имя target неизменно как часть API и продолжает совпадать

### Requirement: Audit-события МКЦ (target mac.audit)

Набор событий ДОЛЖЕН (MUST) оставаться стабильным: mac_skipped, mac_runtime_required, mac_runtime_fallback, mac_runtime_disabled, cert_lacks_max_integrity_ext, integrity_applied, integrity_capped_below_user_mnkc, homedir_label_above_session_cap, mac_apply_failed, mac_caps_missing, mac_user_unknown, mac_fallback_used, cert_max_integrity_categories_above_32bit, cert_max_integrity_parse_failed (rate-limit 60s/256fp), mac_socket_label_set, mac_sessions_file_label_warning. Канонические поля `F_*` (audit.rs).

#### Scenario: Эмиссия audit-события
- **WHEN** происходит МКЦ-событие (например cert_lacks_max_integrity_ext)
- **THEN** оно пишется в target `mac.audit` со стабильным именем и каноническими полями `F_*`

- ⚠ KNOWN GAP (docs): `mac_runtime_detected` из mac-integrity.md:324 не существует; fly-dm события `wallpaper_rendered`/`wallpaper_backup_created`/`fly_dm_greeter_font_missing` не существуют (реально — один INFO с `?outcome`).

### Requirement: Секреты — никогда в логах

Система НЕ ДОЛЖНА (MUST NOT) логировать: PIN/пароли, байты .p12, приватные ключи, CKA_ID/key-байты (только длины/hex-префиксы). Env-значения хуков санитайзятся от control-байтов. Wrong-PIN логируется как категория ошибки + счётчик попыток.

#### Scenario: PIN не попадает в лог
- **WHEN** пользователь вводит неверный PIN
- **THEN** в лог пишется категория ошибки и счётчик попыток, но не сам PIN

### Requirement: host_identity видимость

`probe_all` ДОЛЖЕН (MUST) логировать все источники (raw + hash + selected) при каждом auth и старте демона — операторская диагностика drift'а без изменения policy резолюции.

#### Scenario: Логирование источников при auth
- **WHEN** происходит auth или старт демона
- **THEN** `probe_all` логирует все источники (raw + hash + selected) без влияния на резолюцию policy
