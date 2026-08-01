# cert-authentication-flow Specification

## Purpose

Оркестрация аутентификации в `pam_sm_authenticate`: от загрузки конфига до выдачи PAM-кода. Два пути — PKCS#12 (USB-носитель) и PKCS#11 (аппаратный токен). Описывает intended-поведение v0.4.0.

Код: `crates/pam_tessera/src/entry.rs`, `crates/pam_tessera/src/flow.rs`.
## Requirements
### Requirement: Порядок шагов pam_sm_authenticate

Модуль ДОЛЖЕН (MUST) выполнять в `pam_sm_authenticate` строго упорядоченную последовательность: init logging → парсинг argv (только `config=<path>`, дефолт `/etc/tessera/config.toml`) → загрузка+валидация конфига → self_check → чтение PAM_USER → резолюция host identity → DI-граф → генерация session_id (32 hex из OS RNG, формат `sess-<hex>`) → `flow::authenticate` (entry.rs:119–260).

#### Scenario: Ошибка на инфраструктурном шаге
- **WHEN** ошибка загрузки конфига, self_check, host identity, DI или RNG
- **THEN** возврат `PAM_AUTHINFO_UNAVAIL` (9), fail-closed; для RNG намеренно нет SystemTime-fallback (entry.rs:95–110)

#### Scenario: PAM_SERVICE/PAM_TTY недоступны
- **WHEN** не удаётся прочитать PAM_SERVICE или PAM_TTY
- **THEN** fallback `"unknown"` / `SessionTarget::Unknown`, auth продолжается (fail-open — только метаданные)

### Requirement: Режимы аутентификации

Модуль ДОЛЖЕН (MUST) поддерживать ровно два режима: `mode = "pkcs12"` и `mode = "pkcs11"` (validated.rs:227–233). Семантики «2fa / optional / cert-only» ДОЛЖНЫ (MUST) реализовываться control-flags в `/etc/pam.d/*` (см. [pam-integration](../pam-integration/spec.md)), а НЕ аргументами модуля. Единственный распознаваемый аргумент модуля — `config=`.

#### Scenario: mode=pkcs11 + crypto_backend=openssl
- **WHEN** в конфиге `mode="pkcs11"` и `crypto_backend="openssl"`
- **THEN** `Pkcs11OpensslEngineNotImplemented` → `PAM_AUTHINFO_UNAVAIL` (engine-путь для токенов не реализован, flow.rs:405–418)

### Requirement: Greeter-баннер перед prompt

Модуль ДОЛЖЕН (MUST) перед любым prompt'ом показать через `PAM_TEXT_INFO` баннер `"Это устройство: host_id=<prefix8> (source=...)"` (flow.rs:394–400). Показ best-effort и НЕ ДОЛЖЕН (MUST NOT) влиять на вердикт.

#### Scenario: Показ баннера перед prompt
- **WHEN** начинается аутентификация и host identity резолвлена
- **THEN** через `PAM_TEXT_INFO` показывается баннер `"Это устройство: host_id=<prefix8> (source=...)"` до любого prompt'а; сбой показа не влияет на вердикт

### Requirement: PKCS#12 путь (порядок проверок)

`authenticate_pkcs12` ДОЛЖЕН (MUST) выполнять: pre_auth hooks → wait_for_usb → per-partition loop (mount→discover→envelope) → PIN-loop (3 попытки, хардкод) → challenge-response → сборка цепи (p12-chain + `certs/chain.pem`) → trust verify → host_binding (обязателен) → user_binding/legacy mapping → AuthContext → post_auth_success hooks → monitord SessionOpen (non-fatal) (flow.rs:430–762).

#### Scenario: host_binding нарушен
- **WHEN** ни один дескриптор `pam_cert_host_binding` не совпал с host_id_hash
- **THEN** WARN + on-screen диагностика «Сертификат выпущен для другого устройства…» → `FlowError::CertScope` → `PAM_AUTH_ERR` (7), fail-closed (flow.rs:631–655)

#### Scenario: monitord недоступен при SessionOpen
- **WHEN** `monitor.open_session` вернул ошибку на auth-пути
- **THEN** только WARN, auth-вердикт не меняется (flow.rs:742–747)

Недоступность monitord на этом call-site НЕ ДОЛЖНА (MUST NOT) менять auth-вердикт даже при `monitor_fail_mode="strict"`: фатальны (меняют вердикт) только `DEVICE_GONE` и `UNAUTHORIZED` (`ipc/failmode.rs`); уведомление monitord идёт после уже состоявшегося успеха аутентификации, транспортные ошибки IPC — non-fatal. `strict`/`permissive` управляют лишь тем, пробрасывает ли `FailModeWrapper` нефатальные ошибки IPC вызывающему коду.

### Requirement: PKCS#11 путь

`authenticate_pkcs11` ДОЛЖЕН (MUST) зеркалить PKCS#12 без USB/mount: wait_for_token (polling 200ms) → read_token_serial → PIN-loop (`pkcs11_max_pin_attempts`) → find_certificate (по `pkcs11_object_label`) → find_private_key_for_cert (по CKA_ID) → подпись НА токене → trust verify (цепь только из config-intermediates) → host_binding → user auth → `drop(session)` = C_Logout до возврата (flow.rs:912–1107).

#### Scenario: Успешная аутентификация через токен
- **WHEN** токен присутствует, PIN верный, найдены сертификат и приватный ключ, подпись на токене и trust verify прошли
- **THEN** host_binding и user auth выполняются, сессия закрывается через `drop(session)` (C_Logout) до возврата управления

- Design-граница: intermediates с токена НЕ снимаются — trust-цепь строится только из anchors/intermediates конфига (flow.rs:1000–1009); носитель не участвует в формировании доверия, источник trust-материала — администрируемый конфиг.

### Requirement: Маппинг FlowError → PAM-код

Модуль ДОЛЖЕН (MUST) различать классы ошибок (flow.rs:189–229):

| Класс | PAM rc |
|---|---|
| Usb / Mount / Discovery / P12Envelope / Pkcs11-инфраструктура | 9 PAM_AUTHINFO_UNAVAIL |
| MaxTries / PinLocked / MaxAttemptsExceeded | 11 PAM_MAXTRIES |
| Pkcs12 / Crypto / Trust / Mapping | 6 PAM_PERM_DENIED |
| Conv / CertScope / PreAuthHook / PostAuthHook / прочие Pkcs11 | 7 PAM_AUTH_ERR |
| Internal | 4 PAM_SYSTEM_ERR |

Числовые значения ДОЛЖНЫ (MUST) соответствовать `<security/pam_appl.h>`, а не
представлению о них: `PAM_MAXTRIES` = 11, `PAM_CRED_INSUFFICIENT` = 8. Утверждения
в тестах ДОЛЖНЫ (MUST) содержать имя константы рядом с числом, чтобы расхождение
имени и значения было заметно при чтении.

#### Scenario: Маппинг класса ошибки в PAM-код
- **WHEN** `flow::authenticate` завершился `FlowError` (например, MaxTries)
- **THEN** возвращается соответствующий классу PAM rc (для MaxTries — 11 PAM_MAXTRIES), а не единый PAM_AUTH_ERR

#### Scenario: Исчерпание попыток PIN отличимо от недоступности данных
- **WHEN** бюджет попыток PIN исчерпан
- **THEN** приложение получает 11 PAM_MAXTRIES и может прекратить дальнейшие запросы, а не 8 PAM_CRED_INSUFFICIENT, означающий проблему с доступом к данным аутентификации

### Requirement: Mount живёт только в auth-фазе

`pam_sm_authenticate` ДОЛЖЕН (MUST) дропать MountGuard сразу после успешного auth (entry.rs) — USB размонтируется по завершении auth-фазы. Re-mount в session-фазе ОТСУТСТВУЕТ by design и не планируется: после auth `.p12` больше не нужен (ключ уже использован для challenge, контекст аутентификации передаётся в open_session через pam_data).

#### Scenario: Размонтирование USB после успешного auth
- **WHEN** auth-фаза завершилась успешно
- **THEN** MountGuard дропается сразу (entry.rs), USB размонтируется; `pam_sm_open_session` носитель не перемонтирует

### Requirement: Fail-closed резюме auth

Модуль ДОЛЖЕН (MUST) быть fail-closed: config load, self_check, host identity, RNG, PIN-исчерпание, challenge, trust, host_binding, user-авторизация, fatal hooks. ДОЛЖЕН (MUST) быть fail-open (метаданные/диагностика): PAM_SERVICE/PAM_TTY, mkdir mountpoint, show_info, извлечение `cert_max_integrity` (ошибка парса → audit + None), monitord open_session.

#### Scenario: Сбой на критическом шаге
- **WHEN** падает один из критических шагов (config load, self_check, host identity, RNG, challenge, trust, host_binding, user-авторизация или fatal hook)
- **THEN** auth отклоняется (fail-closed)

#### Scenario: Сбой на метаданном шаге
- **WHEN** падает шаг метаданных/диагностики (PAM_SERVICE/PAM_TTY, mkdir mountpoint, show_info, извлечение `cert_max_integrity`, monitord open_session)
- **THEN** auth продолжается (fail-open), сбой только логируется

### Requirement: Допуск к учётной записи — только из удостоверения

Допуск к учётной записи входа ДОЛЖЕН (MUST) решаться исключительно
расширением `pam_cert_allowed_roles` верифицированного удостоверения:
`PAM_USER` (он же запрошенная роль) входит в список → допуск, иначе отказ
fail-closed.

Иных источников допуска существовать НЕ ДОЛЖНО (MUST NOT). В частности,
конфигурация устройства НЕ ДОЛЖНА (MUST NOT) содержать механизма, разрешающего
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

