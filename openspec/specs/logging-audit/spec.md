# logging-audit Specification

## Purpose

Структурное логирование (tracing) и стабильные audit-события. Что логируется, куда, что НИКОГДА не попадает в логи.

Код: `crates/tessera_core/src/logging.rs` (типы `LogLevel`/`SyslogFacility`), `tessera_cli/src/logging.rs`, `tessera_core/src/mac/audit.rs`.

## Requirements

### Requirement: Назначение вывода

Демон/CLI ДОЛЖНЫ (MUST) писать tracing в stderr → journald (под systemd). Уровень фильтра ДОЛЖЕН (MUST) определяться приоритетом: env `TESSERA_LOG` > `[logging].level` из конфига > `info`. Демон инициализирует tracing до загрузки конфига (чтобы ошибки загрузки были видны) с фильтром за reload-layer, и после успешной загрузки применяет `[logging].level` через `logging::apply_config_level` (no-op при заданном `TESSERA_LOG`) (tessera_cli/src/logging.rs, daemon/mod.rs). PAM-сторона инициализируется через `logging::init_once` в entry.rs и пишет в syslog facility `auth` фиксированно (by design).

`[logging].syslog_facility` и `[logging].journald_priority` — deprecated: ДОЛЖНЫ (MUST) приниматься парсером для обратной совместимости, игнорироваться на runtime и вызывать WARN «deprecated and ignored» при валидации конфига; в `ValidatedConfig` не пробрасываются (см. [configuration](../configuration/spec.md)).

#### Scenario: Вывод под systemd
- **WHEN** демон/CLI запущены под systemd
- **THEN** tracing пишется в stderr и попадает в journald

#### Scenario: Уровень из конфига
- **WHEN** env `TESSERA_LOG` не задана и в конфиге `[logging].level = "debug"`
- **THEN** после загрузки конфига демон применяет уровень `debug` к живому tracing-фильтру

#### Scenario: env приоритетнее конфига
- **WHEN** задана env `TESSERA_LOG` (любое значение) и в конфиге задан `[logging].level`
- **THEN** действует фильтр из `TESSERA_LOG`; значение из конфига не применяется

#### Scenario: Deprecated-ключи logging
- **WHEN** конфиг содержит `syslog_facility` и/или `journald_priority`
- **THEN** загрузка успешна, эмитится WARN «deprecated and ignored»; на назначение вывода и приоритеты ключи не влияют

### Requirement: Стабильные tracing-targets

`tessera.auth`, `tessera.flow`, `tessera.config` (validated.rs, deprecated-ключи), `tessera.usb`, `tessera.mount` (mount_guard.rs), `tessera.crl` (crl/store.rs), `tessera.pkcs11`, `tessera.pkcs12` (pkcs12/mod.rs), `tessera.ipc` (ipc/), `tessera.host_identity`, `tessera.host_binding`, `tessera.hook.*` (start/finish/timeout/failed/stdout/stderr), `tessera.self_check`, `tessera.startup_check`, `tessera.session`, `tessera.monitord`, `tessera.daemon.singleton` (событие `daemon_already_running`), `tessera.fly_dm_greeter`, `tessera.panic` (pam_tessera/panic_guard.rs), `mac.audit`. Имена ДОЛЖНЫ (MUST) считаться API для журнальных grep'ов операторов.

#### Scenario: Стабильность target-имён
- **WHEN** оператор грепает журнал по tracing-target (например `tessera.auth`)
- **THEN** имя target неизменно как часть API и продолжает совпадать

### Requirement: Audit-события МКЦ (target mac.audit)

Набор событий ДОЛЖЕН (MUST) оставаться стабильным: mac_skipped, mac_runtime_required, mac_runtime_fallback, mac_runtime_disabled, cert_lacks_max_integrity_ext, integrity_applied, integrity_capped_below_user_mnkc, homedir_label_above_session_cap, mac_apply_failed, mac_caps_missing, mac_user_unknown, mac_fallback_used, cert_max_integrity_categories_above_32bit, cert_max_integrity_parse_failed (rate-limit 60s/256fp), mac_socket_label_set, mac_sessions_file_label_warning. Канонические поля `F_*` (audit.rs).

#### Scenario: Эмиссия audit-события
- **WHEN** происходит МКЦ-событие (например cert_lacks_max_integrity_ext)
- **THEN** оно пишется в target `mac.audit` со стабильным именем и каноническими полями `F_*`

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

### Requirement: Audit-события ролей (target role.audit)

События ролей ДОЛЖНЫ (MUST) идти в стабильный tracing-target `role.audit` со структурными
полями. Обязательный словарь событий:

| Событие | Поля | Когда |
|---|---|---|
| `role_session_open` | `user` (канон), `role`, `role_version`, `method` (cert/code), `ttl` | успешное открытие сессии |
| `role_deny` | `user`, `requested_role`, `reason` (`not_found` / `not_covered` / `backend_unavailable` / `mask_exceeds_ceiling` / `syntax`) | любой отказ по роли |
| `role_slice_invalid` | `path`, `error` | срез отвергнут валидацией (standalone: per-роль) |
| `bundle_rejected` | `reason` (`signature` / `rollback` / `hash_mismatch`), `bundle_version` | managed: отказ всей базы (severity critical) |
| `bundle_baseline_established` | `bundle_version` | первый манифест после потери персиста (TOFU) |
| `cert_allowed_roles_parse_failed` | `subject` | malformed расширение (fail-closed) |

Канон имени и запрошенная роль — всегда отдельные поля (не склейка `user+role`); сырая
введённая строка логируется только в `role_deny reason=syntax`.

#### Scenario: Отказ по непокрытой роли
- **WHEN** запрошенная роль не входит в allowed_roles серта
- **THEN** эмитится `role_deny` с `user`, `requested_role`, `reason=not_covered` в target `role.audit`

#### Scenario: Отказ базы в managed
- **WHEN** манифест отвергнут (rollback)
- **THEN** эмитится `bundle_rejected` severity critical с `reason=rollback` и обеими версиями в полях
