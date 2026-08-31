---
id: pam-module-runtime
kind: операция
context: runtime
name: "Исполнение PAM-модуля"
aliases:
  - "pam-module-runtime"
relations:
  references:
    - auth.pam-module
    - auth.pam-conversation
anchors:
  code:
    - "crates/pam_tessera/src/entry.rs"
  test:
    - "tests/e2e/cases/18-pam-runtime.yaml"
requirements:
  PAMR-001:
    kind: операционное
    subjects:
      - runtime.pam-module-runtime
    origins:
      - "pam-module-runtime::Panic guard на каждой C-границе"
    evidence:
      code:
        - "crates/pam_tessera/src/entry.rs"
  PAMR-002:
    kind: инвариант
    subjects:
      - runtime.pam-module-runtime
    origins:
      - "pam-module-runtime::acct_mgmt — проверка истечения серта"
    evidence:
      test:
        - "tests/e2e/cases/18-pam-runtime.yaml"
  PAMR-003:
    kind: инвариант
    subjects:
      - runtime.pam-module-runtime
    origins:
      - "pam-module-runtime::open_session — MAC pipeline + hooks, fail-closed"
    evidence:
      test:
        - "tests/e2e/cases/18-pam-runtime.yaml"
  PAMR-004:
    kind: инвариант
    subjects:
      - runtime.pam-module-runtime
    origins:
      - "pam-module-runtime::close_session — fail-open"
    evidence:
      test:
        - "tests/e2e/cases/18-pam-runtime.yaml"
  PAMR-005:
    kind: операционное
    subjects:
      - runtime.pam-module-runtime
    origins:
      - "pam-module-runtime::setcred — no-op"
    evidence:
      code:
        - "crates/pam_tessera/src/entry.rs"
  PAMR-006:
    kind: операционное
    subjects:
      - runtime.pam-module-runtime
    origins:
      - "pam-module-runtime::Захват XDG_SESSION_ID (two-include pattern)"
    evidence:
      code:
        - "crates/pam_tessera/src/entry.rs"
  PAMR-007:
    kind: операционное
    subjects:
      - runtime.pam-module-runtime
    origins:
      - "pam-module-runtime::AuthContext между фазами"
    evidence:
      code:
        - "crates/pam_tessera/src/entry.rs"
  PAMR-008:
    kind: инвариант
    subjects:
      - runtime.pam-module-runtime
    origins:
      - "pam-module-runtime::PIN через PAM conv — обращение с секретом"
    evidence:
      test:
        - "tests/e2e/cases/18-pam-runtime.yaml"
---
# Исполнение PAM-модуля

Эта страница заменяет процедурную capability-спеку OpenSpec «pam-module-runtime»: она
помещает каждое прежнее требование в адресуемую норму с владельцем, видом и
проверяемым происхождением. Под каждым нормативным предложением сохранены подробные условия, отрицательные
сценарии и rationale; они входят в ту же страницу и уточняют границы нормы.

### PAMR-001 — Panic guard на каждой C-границе

[[runtime.pam-module-runtime|Исполнение PAM-модуля]] MUST соблюдать правило «Panic guard на каждой C-границе» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/pam-module-runtime/spec.md, requirement «Panic guard на каждой C-границе».

Каждый `pam_sm_*` должен быть обёрнут в `catch_unwind`; паника должна логироваться ERROR и возвращать `PAM_AUTHINFO_UNAVAIL`, никогда не разворачиваясь в C (UB-защита) (panic_guard.rs:13–23).

#### Scenario: Паника внутри pam_sm_*
- **WHEN** код внутри `pam_sm_*` паникует
- **THEN** `catch_unwind` ловит панику, логирует ERROR и возвращает `PAM_AUTHINFO_UNAVAIL`, не разворачивая стек в C

### PAMR-002 — acct_mgmt — проверка истечения серта

[[runtime.pam-module-runtime|Исполнение PAM-модуля]] MUST соблюдать правило «acct_mgmt — проверка истечения серта» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/pam-module-runtime/spec.md, requirement «acct_mgmt — проверка истечения серта».

`pam_sm_acct_mgmt` должен: при отсутствии AuthContext → `PAM_AUTHINFO_UNAVAIL`; при `now > cert_not_after + clock_skew_seconds` → `PAM_ACCT_EXPIRED` (13); иначе `PAM_SUCCESS` (lib.rs `acct_mgmt_core`). Допуск `clock_skew_seconds` должен фиксироваться в `AuthContext` в момент `pam_sm_authenticate` из `[trust].clock_skew_seconds` (flow.rs, Step 11 — оба пути: PKCS#12 и PKCS#11), чтобы acct_mgmt применял тот же допуск, что и trust-verifier, без перечитывания конфига.

#### Scenario: Сертификат истёк
- **WHEN** AuthContext присутствует и `now > cert_not_after + clock_skew_seconds`
- **THEN** возвращается `PAM_ACCT_EXPIRED` (13)

#### Scenario: Истёк в пределах допуска часов
- **WHEN** AuthContext присутствует, `cert_not_after < now`, но `now <= cert_not_after + clock_skew_seconds`
- **THEN** возвращается `PAM_SUCCESS`

- Замечание: `cert_not_after = None` → SUCCESS (fail-open по этому полю).

### PAMR-003 — open_session — MAC pipeline + hooks, fail-closed

[[runtime.pam-module-runtime|Исполнение PAM-модуля]] MUST соблюдать правило «open_session — MAC pipeline + hooks, fail-closed» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/pam-module-runtime/spec.md, requirement «open_session — MAC pipeline + hooks, fail-closed».

`pam_sm_open_session` должен: загрузить конфиг (ошибка → AUTHINFO_UNAVAIL) → получить AuthContext (нет → AUTHINFO_UNAVAIL) → выполнить MAC-pipeline (`run_open_session_pipeline`, см. [mac-integrity](../mac-integrity/spec.md)) → XDG capture → `session_open` hooks (fatal → `PAM_SESSION_ERR`) (entry.rs:325–426).

#### Scenario: MAC-отказ — cleanup реестра
- **WHEN** MAC-pipeline вернул ошибку
- **THEN** перед возвратом должен вызываться `monitor.close_session(session_id, "mac_denied")`, чтобы не оставить «активную» запись в реестре; ошибка cleanup — только WARN, не маскирует root cause (session.rs:200–211)

### PAMR-004 — close_session — fail-open

[[runtime.pam-module-runtime|Исполнение PAM-модуля]] MUST соблюдать правило «close_session — fail-open» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/pam-module-runtime/spec.md, requirement «close_session — fail-open».

`pam_sm_close_session` должен всегда возвращать `PAM_SUCCESS`: ошибка загрузки конфига и ошибки `session_close` hooks логируются, но не блокируют logout (entry.rs:442–488). Асимметрия с open задокументирована и intended.

#### Scenario: Ошибка в session_close hook
- **WHEN** при logout падает загрузка конфига или `session_close` hook
- **THEN** ошибка логируется, но `pam_sm_close_session` всё равно возвращает `PAM_SUCCESS` — logout не блокируется

- Замечание: close_session НЕ шлёт `SessionClose` в monitord — очистка реестра идёт через logind `SessionRemoved` (см. [session-monitoring](../session-monitoring/spec.md)).

### PAMR-005 — setcred — no-op

[[runtime.pam-module-runtime|Исполнение PAM-модуля]] MUST соблюдать правило «setcred — no-op» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/pam-module-runtime/spec.md, requirement «setcred — no-op».

`pam_sm_setcred` должен быть no-op, всегда `PAM_SUCCESS`.

#### Scenario: Вызов setcred
- **WHEN** PAM вызывает `pam_sm_setcred`
- **THEN** ничего не делается и возвращается `PAM_SUCCESS`

### PAMR-006 — Захват XDG_SESSION_ID (two-include pattern)

[[runtime.pam-module-runtime|Исполнение PAM-модуля]] MUST соблюдать правило «Захват XDG_SESSION_ID (two-include pattern)» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/pam-module-runtime/spec.md, requirement «Захват XDG_SESSION_ID (two-include pattern)».

Модуль должен в `pam_sm_open_session` читать `XDG_SESSION_ID` из PAM-окружения и пушить `UpdateSessionTarget{LogindSession}` в monitord (entry.rs:369–397, xdg_capture.rs). Модуль вызывается дважды за логин:
1. из `@include tessera*` ДО `pam_systemd` → XDG NULL → `Skipped` (no-op);
2. из отдельной строки `session required pam_tessera.so` ПОСЛЕ `@include common-session` → push.

Любой IPC-сбой здесь должен только логироваться WARN — auth-вердикт необратим (fail-open by design). Без корректного порядка PAM-стека removal-action Logout/Lock не получит logind id (см. [pam-integration](../pam-integration/spec.md)).

#### Scenario: Второй вызов с валидным XDG_SESSION_ID
- **WHEN** `pam_sm_open_session` вызван после `@include common-session` и `XDG_SESSION_ID` доступен
- **THEN** модуль читает id и пушит `UpdateSessionTarget{LogindSession}` в monitord; IPC-сбой логируется WARN и не меняет вердикт

История: реализовано в v0.3.13 (первый рабочий .deb — v0.3.14); релизы 0.3.10–0.3.12 выпускались на ложном отчёте субагента о реализации (PAM-сторона была пустой).

### PAMR-007 — AuthContext между фазами

[[runtime.pam-module-runtime|Исполнение PAM-модуля]] MUST соблюдать правило «AuthContext между фазами» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/pam-module-runtime/spec.md, requirement «AuthContext между фазами».

AuthContext (session_id, cert_cn/serial/not_after/ident/max_integrity, usb_serial/vid_pid, pam_service, host_id/source, authenticated_at, home_dir) должен передаваться через `pam_set_data` с cleanup-коллбеком без утечек: неуспех `pam_set_data` → box возвращается и дропается (data_handle.rs:84–124).

#### Scenario: Неуспех pam_set_data
- **WHEN** `pam_set_data` возвращает ошибку при сохранении AuthContext
- **THEN** box с AuthContext возвращается и дропается, утечки памяти не происходит

### PAMR-008 — PIN через PAM conv — обращение с секретом

[[runtime.pam-module-runtime|Исполнение PAM-модуля]] MUST соблюдать правило «PIN через PAM conv — обращение с секретом» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/pam-module-runtime/spec.md, requirement «PIN через PAM conv — обращение с секретом».

`prompt_pin` должен использовать `PAM_PROMPT_ECHO_OFF`; буфер ответа PAM должен перезаписываться нулями ДО free даже при UTF-8-ошибке; результат — `SecretString` (zeroize) (pam_conv.rs:98–160). `show_info` (PAM_TEXT_INFO) — best-effort.

#### Scenario: Запрос PIN с затиранием буфера
- **WHEN** `prompt_pin` запрашивает PIN, в т.ч. при UTF-8-ошибке в ответе
- **THEN** используется `PAM_PROMPT_ECHO_OFF`, буфер ответа затирается нулями до free, результат отдаётся как `SecretString`

