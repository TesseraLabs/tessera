---
id: certificate-authentication
kind: операция
context: auth
name: "Сертификатная аутентификация"
aliases:
  - "cert-authentication-flow"
relations:
  references:
    - auth.pam-module
    - auth.credential
    - auth.carrier
    - auth.trust-chain
anchors:
  code:
    - "crates/pam_tessera/src/flow.rs"
  test:
    - "tests/e2e/cases/20-auth.yaml"
requirements:
  AFLOW-001:
    kind: операционное
    subjects:
      - auth.certificate-authentication
    origins:
      - "cert-authentication-flow::Порядок шагов pam_sm_authenticate"
    evidence:
      code:
        - "crates/pam_tessera/src/flow.rs"
  AFLOW-002:
    kind: инвариант
    subjects:
      - auth.certificate-authentication
    origins:
      - "cert-authentication-flow::Режимы аутентификации"
    evidence:
      test:
        - "tests/e2e/cases/20-auth.yaml"
  AFLOW-003:
    kind: операционное
    subjects:
      - auth.certificate-authentication
    origins:
      - "cert-authentication-flow::Greeter-баннер перед prompt"
    evidence:
      code:
        - "crates/pam_tessera/src/flow.rs"
  AFLOW-004:
    kind: инвариант
    subjects:
      - auth.certificate-authentication
    origins:
      - "cert-authentication-flow::PKCS#12 путь (порядок проверок)"
    evidence:
      test:
        - "tests/e2e/cases/20-auth.yaml"
  AFLOW-005:
    kind: операционное
    subjects:
      - auth.certificate-authentication
    origins:
      - "cert-authentication-flow::PKCS#11 путь"
    evidence:
      code:
        - "crates/pam_tessera/src/flow.rs"
  AFLOW-006:
    kind: операционное
    subjects:
      - auth.certificate-authentication
    origins:
      - "cert-authentication-flow::Маппинг FlowError → PAM-код"
    evidence:
      code:
        - "crates/pam_tessera/src/flow.rs"
  AFLOW-007:
    kind: операционное
    subjects:
      - auth.certificate-authentication
    origins:
      - "cert-authentication-flow::Mount живёт только в auth-фазе"
    evidence:
      code:
        - "crates/pam_tessera/src/flow.rs"
  AFLOW-008:
    kind: инвариант
    subjects:
      - auth.certificate-authentication
    origins:
      - "cert-authentication-flow::Fail-closed резюме auth"
    evidence:
      test:
        - "tests/e2e/cases/20-auth.yaml"
  AFLOW-009:
    kind: операционное
    subjects:
      - auth.certificate-authentication
    origins:
      - "cert-authentication-flow::Допуск к учётной записи — только из удостоверения"
    evidence:
      code:
        - "crates/pam_tessera/src/flow.rs"
---
# Сертификатная аутентификация

Эта страница заменяет процедурную capability-спеку OpenSpec «cert-authentication-flow»: она
помещает каждое прежнее требование в адресуемую норму с владельцем, видом и
проверяемым происхождением. Под каждым нормативным предложением сохранены подробные условия, отрицательные
сценарии и rationale; они входят в ту же страницу и уточняют границы нормы.

### AFLOW-001 — Порядок шагов pam_sm_authenticate

[[auth.certificate-authentication|Сертификатная аутентификация]] MUST соблюдать правило «Порядок шагов pam_sm_authenticate» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/cert-authentication-flow/spec.md, requirement «Порядок шагов pam_sm_authenticate».

Модуль должен выполнять в `pam_sm_authenticate` строго упорядоченную последовательность: init logging → парсинг argv (только `config=<path>`, дефолт `/etc/tessera/config.toml`) → загрузка+валидация конфига → self_check → чтение PAM_USER → резолюция host identity → DI-граф → генерация session_id (32 hex из OS RNG, формат `sess-<hex>`) → `flow::authenticate` (entry.rs:119–260).

#### Scenario: Ошибка на инфраструктурном шаге
- **WHEN** ошибка загрузки конфига, self_check, host identity, DI или RNG
- **THEN** возврат `PAM_AUTHINFO_UNAVAIL` (9), fail-closed; для RNG намеренно нет SystemTime-fallback (entry.rs:95–110)

#### Scenario: PAM_SERVICE/PAM_TTY недоступны
- **WHEN** не удаётся прочитать PAM_SERVICE или PAM_TTY
- **THEN** fallback `"unknown"` / `SessionTarget::Unknown`, auth продолжается (fail-open — только метаданные)

### AFLOW-002 — Режимы аутентификации

[[auth.certificate-authentication|Сертификатная аутентификация]] MUST соблюдать правило «Режимы аутентификации» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/cert-authentication-flow/spec.md, requirement «Режимы аутентификации».

Модуль должен поддерживать ровно два режима: `mode = "pkcs12"` и `mode = "pkcs11"` (validated.rs:227–233). Семантики «2fa / optional / cert-only» должны реализовываться control-flags в `/etc/pam.d/*` (см. [pam-integration](../pam-integration/spec.md)), а НЕ аргументами модуля. Единственный распознаваемый аргумент модуля — `config=`.

#### Scenario: mode=pkcs11 + crypto_backend=openssl
- **WHEN** в конфиге `mode="pkcs11"` и `crypto_backend="openssl"`
- **THEN** `Pkcs11OpensslEngineNotImplemented` → `PAM_AUTHINFO_UNAVAIL` (engine-путь для токенов не реализован, flow.rs:405–418)

### AFLOW-003 — Greeter-баннер перед prompt

[[auth.certificate-authentication|Сертификатная аутентификация]] MUST соблюдать правило «Greeter-баннер перед prompt» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/cert-authentication-flow/spec.md, requirement «Greeter-баннер перед prompt».

Модуль должен перед любым prompt'ом показать через `PAM_TEXT_INFO` баннер `"Это устройство: host_id=<prefix8> (source=...)"` (flow.rs:394–400). Показ best-effort и не должен влиять на вердикт.

#### Scenario: Показ баннера перед prompt
- **WHEN** начинается аутентификация и host identity резолвлена
- **THEN** через `PAM_TEXT_INFO` показывается баннер `"Это устройство: host_id=<prefix8> (source=...)"` до любого prompt'а; сбой показа не влияет на вердикт

### AFLOW-004 — PKCS#12 путь (порядок проверок)

[[auth.certificate-authentication|Сертификатная аутентификация]] MUST соблюдать правило «PKCS#12 путь (порядок проверок)» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/cert-authentication-flow/spec.md, requirement «PKCS#12 путь (порядок проверок)».

`authenticate_pkcs12` должен выполнять: pre_auth hooks → wait_for_usb → per-partition loop (mount→discover→envelope) → PIN-loop (3 попытки, хардкод) → challenge-response → сборка цепи (p12-chain + `certs/chain.pem`) → trust verify → host_binding (обязателен) → user_binding/legacy mapping → AuthContext → post_auth_success hooks → monitord SessionOpen (non-fatal) (flow.rs:430–762).

#### Scenario: host_binding нарушен
- **WHEN** ни один дескриптор `pam_cert_host_binding` не совпал с host_id_hash
- **THEN** WARN + on-screen диагностика «Сертификат выпущен для другого устройства…» → `FlowError::CertScope` → `PAM_AUTH_ERR` (7), fail-closed (flow.rs:631–655)

#### Scenario: monitord недоступен при SessionOpen
- **WHEN** `monitor.open_session` вернул ошибку на auth-пути
- **THEN** только WARN, auth-вердикт не меняется (flow.rs:742–747)

Недоступность monitord на этом call-site не должна менять auth-вердикт даже при `monitor_fail_mode="strict"`: фатальны (меняют вердикт) только `DEVICE_GONE` и `UNAUTHORIZED` (`ipc/failmode.rs`); уведомление monitord идёт после уже состоявшегося успеха аутентификации, транспортные ошибки IPC — non-fatal. `strict`/`permissive` управляют лишь тем, пробрасывает ли `FailModeWrapper` нефатальные ошибки IPC вызывающему коду.

### AFLOW-005 — PKCS#11 путь

[[auth.certificate-authentication|Сертификатная аутентификация]] MUST соблюдать правило «PKCS#11 путь» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/cert-authentication-flow/spec.md, requirement «PKCS#11 путь».

`authenticate_pkcs11` должен зеркалить PKCS#12 без USB/mount: wait_for_token (polling 200ms) → read_token_serial → PIN-loop (`pkcs11_max_pin_attempts`) → find_certificate (по `pkcs11_object_label`) → find_private_key_for_cert (по CKA_ID) → подпись НА токене → trust verify (цепь только из config-intermediates) → host_binding → user auth → `drop(session)` = C_Logout до возврата (flow.rs:912–1107).

#### Scenario: Успешная аутентификация через токен
- **WHEN** токен присутствует, PIN верный, найдены сертификат и приватный ключ, подпись на токене и trust verify прошли
- **THEN** host_binding и user auth выполняются, сессия закрывается через `drop(session)` (C_Logout) до возврата управления

- Design-граница: intermediates с токена НЕ снимаются — trust-цепь строится только из anchors/intermediates конфига (flow.rs:1000–1009); носитель не участвует в формировании доверия, источник trust-материала — администрируемый конфиг.

### AFLOW-006 — Маппинг FlowError → PAM-код

[[auth.certificate-authentication|Сертификатная аутентификация]] MUST соблюдать правило «Маппинг FlowError → PAM-код» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/cert-authentication-flow/spec.md, requirement «Маппинг FlowError → PAM-код».

Модуль должен различать классы ошибок (flow.rs:189–229):

| Класс | PAM rc |
|---|---|
| Usb / Mount / Discovery / P12Envelope / Pkcs11-инфраструктура | 9 PAM_AUTHINFO_UNAVAIL |
| MaxTries / PinLocked / MaxAttemptsExceeded | 11 PAM_MAXTRIES |
| Pkcs12 / Crypto / Trust / Mapping | 6 PAM_PERM_DENIED |
| Conv / CertScope / PreAuthHook / PostAuthHook / прочие Pkcs11 | 7 PAM_AUTH_ERR |
| Internal | 4 PAM_SYSTEM_ERR |

Числовые значения должны соответствовать `<security/pam_appl.h>`, а не
представлению о них: `PAM_MAXTRIES` = 11, `PAM_CRED_INSUFFICIENT` = 8. Утверждения
в тестах должны содержать имя константы рядом с числом, чтобы расхождение
имени и значения было заметно при чтении.

#### Scenario: Маппинг класса ошибки в PAM-код
- **WHEN** `flow::authenticate` завершился `FlowError` (например, MaxTries)
- **THEN** возвращается соответствующий классу PAM rc (для MaxTries — 11 PAM_MAXTRIES), а не единый PAM_AUTH_ERR

#### Scenario: Исчерпание попыток PIN отличимо от недоступности данных
- **WHEN** бюджет попыток PIN исчерпан
- **THEN** приложение получает 11 PAM_MAXTRIES и может прекратить дальнейшие запросы, а не 8 PAM_CRED_INSUFFICIENT, означающий проблему с доступом к данным аутентификации

### AFLOW-007 — Mount живёт только в auth-фазе

[[auth.certificate-authentication|Сертификатная аутентификация]] MUST соблюдать правило «Mount живёт только в auth-фазе» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/cert-authentication-flow/spec.md, requirement «Mount живёт только в auth-фазе».

`pam_sm_authenticate` должен дропать MountGuard сразу после успешного auth (entry.rs) — USB размонтируется по завершении auth-фазы. Re-mount в session-фазе ОТСУТСТВУЕТ by design и не планируется: после auth `.p12` больше не нужен (ключ уже использован для challenge, контекст аутентификации передаётся в open_session через pam_data).

#### Scenario: Размонтирование USB после успешного auth
- **WHEN** auth-фаза завершилась успешно
- **THEN** MountGuard дропается сразу (entry.rs), USB размонтируется; `pam_sm_open_session` носитель не перемонтирует

### AFLOW-008 — Fail-closed резюме auth

[[auth.certificate-authentication|Сертификатная аутентификация]] MUST соблюдать правило «Fail-closed резюме auth» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/cert-authentication-flow/spec.md, requirement «Fail-closed резюме auth».

Модуль должен быть fail-closed: config load, self_check, host identity, RNG, PIN-исчерпание, challenge, trust, host_binding, user-авторизация, fatal hooks. должен быть fail-open (метаданные/диагностика): PAM_SERVICE/PAM_TTY, mkdir mountpoint, show_info, извлечение `cert_max_integrity` (ошибка парса → audit + None), monitord open_session.

#### Scenario: Сбой на критическом шаге
- **WHEN** падает один из критических шагов (config load, self_check, host identity, RNG, challenge, trust, host_binding, user-авторизация или fatal hook)
- **THEN** auth отклоняется (fail-closed)

#### Scenario: Сбой на метаданном шаге
- **WHEN** падает шаг метаданных/диагностики (PAM_SERVICE/PAM_TTY, mkdir mountpoint, show_info, извлечение `cert_max_integrity`, monitord open_session)
- **THEN** auth продолжается (fail-open), сбой только логируется

### AFLOW-009 — Допуск к учётной записи — только из удостоверения

[[auth.certificate-authentication|Сертификатная аутентификация]] MUST соблюдать правило «Допуск к учётной записи — только из удостоверения» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/cert-authentication-flow/spec.md, requirement «Допуск к учётной записи — только из удостоверения».

Допуск к учётной записи входа должен решаться исключительно
расширением `pam_cert_allowed_roles` верифицированного удостоверения:
`PAM_USER` (он же запрошенная роль) входит в список → допуск, иначе отказ
fail-closed.

Иных источников допуска существовать не должно. В частности,
конфигурация устройства не должна содержать механизма, разрешающего
вход по признакам удостоверения (CN, SAN), которые выпускающий не предназначал
для допуска. Рамки несёт удостоверение; путь, где их назначает ограничиваемая
сторона, подрывает саму модель.

Отсутствие расширения — отказ, а не откат к иному механизму: удостоверение,
не называющее ролей, не даёт доступа ни к одной.

#### Scenario: Роль вне списка удостоверения
- **WHEN** `PAM_USER = admin`, а `allowed_roles` удостоверения содержит только `oper` и `serv`
- **THEN** вход отклоняется fail-closed, audit deny

#### Scenario: Удостоверение без allowed_roles
- **WHEN** удостоверение не несёт расширения `allowed_roles`
- **THEN** вход отклоняется; отката к конфигурации устройства не существует

#### Scenario: Malformed allowed_roles
- **WHEN** расширение присутствует, но DER некорректен
- **THEN** вход отклоняется fail-closed — список считается пустым, а не игнорируется

