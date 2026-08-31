---
id: logging-audit
kind: операция
context: runtime
name: "Журналирование и аудит"
aliases:
  - "logging-audit"
relations:
  references:
    - runtime.monitor-daemon
    - auth.credential-revoked
anchors:
  code:
    - "crates/tessera_core/src/audit/mod.rs"
  test:
    - "tests/e2e/cases/22-logging-audit.yaml"
requirements:
  LOG-001:
    kind: операционное
    subjects:
      - runtime.logging-audit
    origins:
      - "logging-audit::Назначение вывода"
    evidence:
      code:
        - "crates/tessera_core/src/audit/mod.rs"
  LOG-002:
    kind: операционное
    subjects:
      - runtime.logging-audit
    origins:
      - "logging-audit::Стабильные tracing-targets"
    evidence:
      code:
        - "crates/tessera_core/src/audit/mod.rs"
  LOG-003:
    kind: операционное
    subjects:
      - runtime.logging-audit
    origins:
      - "logging-audit::Audit-события МКЦ (target mac.audit)"
    evidence:
      code:
        - "crates/tessera_core/src/audit/mod.rs"
  LOG-004:
    kind: инвариант
    subjects:
      - runtime.logging-audit
    origins:
      - "logging-audit::Секреты — никогда в логах"
    evidence:
      test:
        - "tests/e2e/cases/22-logging-audit.yaml"
  LOG-005:
    kind: операционное
    subjects:
      - runtime.logging-audit
    origins:
      - "logging-audit::host_identity видимость"
    evidence:
      code:
        - "crates/tessera_core/src/audit/mod.rs"
  LOG-006:
    kind: операционное
    subjects:
      - runtime.logging-audit
    origins:
      - "logging-audit::Audit-события ролей (target role.audit)"
    evidence:
      code:
        - "crates/tessera_core/src/audit/mod.rs"
  LOG-007:
    kind: операционное
    subjects:
      - runtime.logging-audit
    origins:
      - "logging-audit::Audit-события делегирования и тегов"
    evidence:
      code:
        - "crates/tessera_core/src/audit/mod.rs"
  LOG-008:
    kind: операционное
    subjects:
      - runtime.logging-audit
    origins:
      - "logging-audit::Audit-событие device_enrolled"
    evidence:
      code:
        - "crates/tessera_core/src/audit/mod.rs"
---
# Журналирование и аудит

Эта страница заменяет процедурную capability-спеку OpenSpec «logging-audit»: она
помещает каждое прежнее требование в адресуемую норму с владельцем, видом и
проверяемым происхождением. Под каждым нормативным предложением сохранены подробные условия, отрицательные
сценарии и rationale; они входят в ту же страницу и уточняют границы нормы.

### LOG-001 — Назначение вывода

[[runtime.logging-audit|Журналирование и аудит]] MUST соблюдать правило «Назначение вывода» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/logging-audit/spec.md, requirement «Назначение вывода».

Демон/CLI должны писать tracing в stderr → journald (под systemd). Уровень фильтра должен определяться приоритетом: env `TESSERA_LOG` > `[logging].level` из конфига > `info`. Демон инициализирует tracing до загрузки конфига (чтобы ошибки загрузки были видны) с фильтром за reload-layer, и после успешной загрузки применяет `[logging].level` через `logging::apply_config_level` (no-op при заданном `TESSERA_LOG`) (tessera_cli/src/logging.rs, daemon/mod.rs). PAM-сторона инициализируется через `logging::init_once` в entry.rs и пишет в syslog facility `auth` фиксированно (by design).

`[logging].syslog_facility` и `[logging].journald_priority` — deprecated: должны приниматься парсером для обратной совместимости, игнорироваться на runtime и вызывать WARN «deprecated and ignored» при валидации конфига; в `ValidatedConfig` не пробрасываются (см. [configuration](../configuration/spec.md)).

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

### LOG-002 — Стабильные tracing-targets

[[runtime.logging-audit|Журналирование и аудит]] MUST соблюдать правило «Стабильные tracing-targets» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/logging-audit/spec.md, requirement «Стабильные tracing-targets».

`tessera.auth`, `tessera.flow`, `tessera.config` (validated.rs, deprecated-ключи), `tessera.usb`, `tessera.mount` (mount_guard.rs), `tessera.crl` (crl/store.rs), `tessera.pkcs11`, `tessera.pkcs12` (pkcs12/mod.rs), `tessera.ipc` (ipc/), `tessera.host_identity`, `tessera.host_binding`, `tessera.hook.*` (start/finish/timeout/failed/stdout/stderr), `tessera.self_check`, `tessera.startup_check`, `tessera.session`, `tessera.monitord`, `tessera.daemon.singleton` (событие `daemon_already_running`), `tessera.fly_dm_greeter`, `tessera.panic` (pam_tessera/panic_guard.rs), `mac.audit`. Имена должны считаться API для журнальных grep'ов операторов.

#### Scenario: Стабильность target-имён
- **WHEN** оператор грепает журнал по tracing-target (например `tessera.auth`)
- **THEN** имя target неизменно как часть API и продолжает совпадать

### LOG-003 — Audit-события МКЦ (target mac.audit)

[[runtime.logging-audit|Журналирование и аудит]] MUST соблюдать правило «Audit-события МКЦ (target mac.audit)» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/logging-audit/spec.md, requirement «Audit-события МКЦ (target mac.audit)».

Набор событий должен оставаться стабильным: mac_skipped, mac_runtime_required, mac_runtime_fallback, mac_runtime_disabled, cert_lacks_max_integrity_ext, integrity_applied, integrity_capped_below_user_mnkc, homedir_label_above_session_cap, mac_apply_failed, mac_caps_missing, mac_user_unknown, mac_fallback_used, cert_max_integrity_categories_above_32bit, cert_max_integrity_parse_failed (rate-limit 60s/256fp), mac_socket_label_set, mac_sessions_file_label_warning. Канонические поля `F_*` (audit.rs).

#### Scenario: Эмиссия audit-события
- **WHEN** происходит МКЦ-событие (например cert_lacks_max_integrity_ext)
- **THEN** оно пишется в target `mac.audit` со стабильным именем и каноническими полями `F_*`

### LOG-004 — Секреты — никогда в логах

[[runtime.logging-audit|Журналирование и аудит]] MUST соблюдать правило «Секреты — никогда в логах» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/logging-audit/spec.md, requirement «Секреты — никогда в логах».

Система не должна логировать: PIN/пароли, байты .p12, приватные ключи, CKA_ID/key-байты (только длины/hex-префиксы). Env-значения хуков санитайзятся от control-байтов. Wrong-PIN логируется как категория ошибки + счётчик попыток.

#### Scenario: PIN не попадает в лог
- **WHEN** пользователь вводит неверный PIN
- **THEN** в лог пишется категория ошибки и счётчик попыток, но не сам PIN

### LOG-005 — host_identity видимость

[[runtime.logging-audit|Журналирование и аудит]] MUST соблюдать правило «host_identity видимость» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/logging-audit/spec.md, requirement «host_identity видимость».

`probe_all` должен логировать все источники (raw + hash + selected) при каждом auth и старте демона — операторская диагностика drift'а без изменения policy резолюции.

#### Scenario: Логирование источников при auth
- **WHEN** происходит auth или старт демона
- **THEN** `probe_all` логирует все источники (raw + hash + selected) без влияния на резолюцию policy

### LOG-006 — Audit-события ролей (target role.audit)

[[runtime.logging-audit|Журналирование и аудит]] MUST соблюдать правило «Audit-события ролей (target role.audit)» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/logging-audit/spec.md, requirement «Audit-события ролей (target role.audit)».

События ролей должны идти в стабильный tracing-target `role.audit` со структурными
полями. Обязательный словарь событий:

| Событие | Поля | Когда |
|---|---|---|
| `role_session_open` | `user` (канон), `role`, `role_version`, `method` (cert/code), `ttl` | успешное открытие сессии |
| `role_deny` | `user`, `requested_role`, `reason` (`not_found` / `not_covered` / `backend_unavailable` / `mask_exceeds_ceiling` / `syntax` / `system_account`) | любой отказ по роли |
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

`system_account` означает, что учётная запись входа признана системной по uid и
ролью быть не может. Диагностика этого отказа не должна сообщать,
присутствует ли в хранилище срез с таким именем: это дало бы оракул наличия
роли до предъявления удостоверения — ровно тот, ради отсутствия которого ранняя
проверка существования роли и была отвергнута.

### LOG-007 — Audit-события делегирования и тегов

[[runtime.logging-audit|Журналирование и аудит]] MUST соблюдать правило «Audit-события делегирования и тегов» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/logging-audit/spec.md, requirement «Audit-события делегирования и тегов».

Engine должен эмитить audit-события для решений делегирования и применения тегов:
`delegation_denied` (звено-виновник serial, нарушенная проверка: tags/role/level/ttl/version,
снимок `device.tags`), `tag_manifest_applied` (`device_id`, `bundle_version`),
`profile_version_rejected` (serial, версия серта, `max_supported`). Причина отказа, показываемая
инженеру, должна быть обобщённой; полный вектор причин должен попадать только в
audit (не раскрываем структуру рамок до аутентификации).

#### Scenario: Отказ по конверту делегирования
- **WHEN** цепь отвергнута из-за несоответствия `device.tags` конверту
- **THEN** эмитится `delegation_denied` с serial звена-виновника и снимком `device.tags`, инженеру — обобщённая причина

#### Scenario: Применение манифеста тегов
- **WHEN** применён новый подписанный манифест с тегами устройства
- **THEN** эмитится `tag_manifest_applied` с `device_id` и `bundle_version`

### LOG-008 — Audit-событие device_enrolled

[[runtime.logging-audit|Журналирование и аудит]] MUST соблюдать правило «Audit-событие device_enrolled» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/logging-audit/spec.md, requirement «Audit-событие device_enrolled».

Engine должен эмитить audit-событие `device_enrolled` после успешного импорта
enrollment-пакета: host_id prefix8, поле serial per-host серта, применённый `bundle_version`,
режим (standalone/managed). Событие должно попадать в локальный hash-chain журнал
(audit-visibility); выгрузка в Control — best-effort при связности.

Поле serial должно оставаться пустым, пока серийник не приходит из источника, покрытого
подписью. Вывести его из самого `.p12` при импорте нельзя: каким сертификатом устройство будет
аутентифицироваться, решает совпадение с закрытым ключом контейнера, а ключ без пароля не
прочесть — и пароля на этом шаге нет. Всё, что читается из контейнера без пароля, — это его
раскладка и метки, выбранные тем, кто контейнер собрал; пакет при этом читается до проверки
подписи манифеста, а в режиме standalone подписи нет вовсе. Событие долговременно и читается при
разборе инцидента, поэтому пустое поле должно предпочитаться догадке.

#### Scenario: Успешный enrollment
- **WHEN** enrollment-пакет импортирован и `tessera check` прошёл
- **THEN** эмитится `device_enrolled` с host_id prefix8, полем serial, bundle_version и режимом

#### Scenario: Серийник не заверен подписью
- **WHEN** серийник per-host серта доступен только из самого `.p12`, который на этом шаге ничем не заверен
- **THEN** поле serial пустое; событие эмитится с остальными полями, импорт не прерывается

