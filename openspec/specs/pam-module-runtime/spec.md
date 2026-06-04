# pam-module-runtime Specification

## Purpose

Поведение PAM-cdylib за пределами auth-фазы: panic-защита, acct_mgmt, open/close session, захват XDG_SESSION_ID, передача AuthContext между фазами, FFI conv.

Код: `crates/pam_tessera/src/` (panic_guard.rs, entry.rs, session.rs, xdg_capture.rs, data_handle.rs, pam_conv.rs).

## Requirements

### Requirement: Panic guard на каждой C-границе

Каждый `pam_sm_*` ДОЛЖЕН (MUST) быть обёрнут в `catch_unwind`; паника ДОЛЖНА (MUST) логироваться ERROR и возвращать `PAM_AUTHINFO_UNAVAIL`, никогда не разворачиваясь в C (UB-защита) (panic_guard.rs:13–23).

#### Scenario: Паника внутри pam_sm_*
- **WHEN** код внутри `pam_sm_*` паникует
- **THEN** `catch_unwind` ловит панику, логирует ERROR и возвращает `PAM_AUTHINFO_UNAVAIL`, не разворачивая стек в C

### Requirement: acct_mgmt — проверка истечения серта

`pam_sm_acct_mgmt` ДОЛЖЕН (MUST): при отсутствии AuthContext → `PAM_AUTHINFO_UNAVAIL`; при `now > cert_not_after` → `PAM_ACCT_EXPIRED` (13); иначе `PAM_SUCCESS` (lib.rs:126–133).

#### Scenario: Сертификат истёк
- **WHEN** AuthContext присутствует и `now > cert_not_after`
- **THEN** возвращается `PAM_ACCT_EXPIRED` (13)

- ⚠ KNOWN GAP: docs/architecture.md:191 обещает допуск `clock_skew_seconds` в acct_mgmt — код делает голое сравнение без допуска.
- Замечание: `cert_not_after = None` → SUCCESS (fail-open по этому полю).

### Requirement: open_session — MAC pipeline + hooks, fail-closed

`pam_sm_open_session` ДОЛЖЕН (MUST): загрузить конфиг (ошибка → AUTHINFO_UNAVAIL) → получить AuthContext (нет → AUTHINFO_UNAVAIL) → выполнить MAC-pipeline (`run_open_session_pipeline`, см. [mac-integrity](../mac-integrity/spec.md)) → XDG capture → `session_open` hooks (fatal → `PAM_SESSION_ERR`) (entry.rs:325–426).

#### Scenario: MAC-отказ — cleanup реестра
- **WHEN** MAC-pipeline вернул ошибку
- **THEN** перед возвратом ДОЛЖЕН (MUST) вызываться `monitor.close_session(session_id, "mac_denied")`, чтобы не оставить «активную» запись в реестре; ошибка cleanup — только WARN, не маскирует root cause (session.rs:200–211)

### Requirement: close_session — fail-open

`pam_sm_close_session` ДОЛЖЕН (MUST) всегда возвращать `PAM_SUCCESS`: ошибка загрузки конфига и ошибки `session_close` hooks логируются, но не блокируют logout (entry.rs:442–488). Асимметрия с open задокументирована и intended.

#### Scenario: Ошибка в session_close hook
- **WHEN** при logout падает загрузка конфига или `session_close` hook
- **THEN** ошибка логируется, но `pam_sm_close_session` всё равно возвращает `PAM_SUCCESS` — logout не блокируется

- Замечание: close_session НЕ шлёт `SessionClose` в monitord — очистка реестра идёт через logind `SessionRemoved` (см. [session-monitoring](../session-monitoring/spec.md)).

### Requirement: setcred — no-op

`pam_sm_setcred` ДОЛЖЕН (MUST) быть no-op, всегда `PAM_SUCCESS`.

#### Scenario: Вызов setcred
- **WHEN** PAM вызывает `pam_sm_setcred`
- **THEN** ничего не делается и возвращается `PAM_SUCCESS`

### Requirement: Захват XDG_SESSION_ID (two-include pattern)

Модуль ДОЛЖЕН (MUST) в `pam_sm_open_session` читать `XDG_SESSION_ID` из PAM-окружения и пушить `UpdateSessionTarget{LogindSession}` в monitord (entry.rs:369–397, xdg_capture.rs). Модуль вызывается дважды за логин:
1. из `@include tessera*` ДО `pam_systemd` → XDG NULL → `Skipped` (no-op);
2. из отдельной строки `session required pam_tessera.so` ПОСЛЕ `@include common-session` → push.

Любой IPC-сбой здесь ДОЛЖЕН (MUST) только логироваться WARN — auth-вердикт необратим (fail-open by design). Без корректного порядка PAM-стека removal-action Logout/Lock не получит logind id (см. [pam-integration](../pam-integration/spec.md)).

#### Scenario: Второй вызов с валидным XDG_SESSION_ID
- **WHEN** `pam_sm_open_session` вызван после `@include common-session` и `XDG_SESSION_ID` доступен
- **THEN** модуль читает id и пушит `UpdateSessionTarget{LogindSession}` в monitord; IPC-сбой логируется WARN и не меняет вердикт

История: реализовано в v0.3.13 (первый рабочий .deb — v0.3.14); релизы 0.3.10–0.3.12 выпускались на ложном отчёте субагента о реализации (PAM-сторона была пустой).

### Requirement: AuthContext между фазами

AuthContext (session_id, cert_cn/serial/not_after/ident/max_integrity, usb_serial/vid_pid, pam_service, host_id/source, authenticated_at, home_dir) ДОЛЖЕН (MUST) передаваться через `pam_set_data` с cleanup-коллбеком без утечек: неуспех `pam_set_data` → box возвращается и дропается (data_handle.rs:84–124).

#### Scenario: Неуспех pam_set_data
- **WHEN** `pam_set_data` возвращает ошибку при сохранении AuthContext
- **THEN** box с AuthContext возвращается и дропается, утечки памяти не происходит

### Requirement: PIN через PAM conv — обращение с секретом

`prompt_pin` ДОЛЖЕН (MUST) использовать `PAM_PROMPT_ECHO_OFF`; буфер ответа PAM ДОЛЖЕН (MUST) перезаписываться нулями ДО free даже при UTF-8-ошибке; результат — `SecretString` (zeroize) (pam_conv.rs:98–160). `show_info` (PAM_TEXT_INFO) — best-effort.

#### Scenario: Запрос PIN с затиранием буфера
- **WHEN** `prompt_pin` запрашивает PIN, в т.ч. при UTF-8-ошибке в ответе
- **THEN** используется `PAM_PROMPT_ECHO_OFF`, буфер ответа затирается нулями до free, результат отдаётся как `SecretString`
