# token-pkcs11 Specification

## Purpose

Аппаратные токены через PKCS#11 (Rutoken, JaCarta-2 GOST, ESMART): приватный ключ неизвлекаем, подпись `C_Sign` на устройстве (режим B).

Код: `crates/tessera_core/src/token/pkcs11/` (backend, session, pin_loop, cert_lookup, key_lookup, mechanism, sign, info, waiter, locking).

## Requirements

### Requirement: Загрузка модуля

`Pkcs11Backend::load(pkcs11_module)`: файла нет → `ModulePathMissing`; dlopen-fail → `ModuleLoadFailed`; `C_Initialize(CKF_OS_LOCKING_OK)` fail → `InitFailed`. Модуль ДОЛЖЕН (MUST) грузиться сразу при построении IO — конфиг-ошибки всплывают ДО касания USB/PIN (backend.rs:72–101, flow.rs:877–893).

#### Scenario: Неверный путь к модулю
- **WHEN** `pkcs11_module` указывает на несуществующий файл
- **THEN** при построении IO возвращается `ModulePathMissing` — ещё до касания USB/PIN

### Requirement: Выбор слота/токена и ожидание

`find_slot`: только слоты с токеном; `pkcs11_token_label` (опц.) сверяется с CK_TOKEN_INFO.label (trim trailing spaces). `wait_for_token` ДОЛЖЕН (MUST) поллить каждые 200 ms до `pkcs11_slot_wait_seconds` (дефолт 10, 0..=60, 0 = не ждать); таймаут → `TokenWaitTimeout` (backend.rs:121–187, waiter.rs).

#### Scenario: Токен не появился за окно ожидания
- **WHEN** за `pkcs11_slot_wait_seconds` ни в одном слоте не появился токен
- **THEN** возвращается `TokenWaitTimeout`

### Requirement: PIN-сессия

Демон ДОЛЖЕН (MUST) открывать RW-сессию (JaCarta-2 GOST требует RW даже для C_Sign) + `login(User, pin)`. PIN — `SecretString`. Retry до `pkcs11_max_pin_attempts` (дефолт 3, 1..=5): `CKR_PIN_INCORRECT` → следующая попытка; `CKR_PIN_LOCKED` → немедленный short-circuit + ALERT-лог → `PAM_MAXTRIES` (токен лочит себя сам — PUK). Prompt ДОЛЖЕН (MUST) браться из `pkcs11_pin_prompt` (дефолт «Введите PIN токена: »). Drop сессии ДОЛЖЕН (MUST) делать `C_Logout` до возврата (session.rs, pin_loop.rs:89–125).

#### Scenario: Токен заблокирован
- **WHEN** `login` возвращает `CKR_PIN_LOCKED`
- **THEN** немедленный short-circuit + ALERT-лог → `PAM_MAXTRIES` (без дальнейших попыток)

### Requirement: Поиск объектов

`find_certificate`: `CKO_CERTIFICATE`+`CKC_X_509`, опц. `CKA_LABEL == pkcs11_object_label`; ПЕРВЫЙ кандидат с валидным X.509 DER в `CKA_VALUE`. Поиск НЕ ДОЛЖЕН (MUST NOT) выбирать по subject CN — привязка к pam_user делается через binding/mapping. `find_private_key_for_cert`: `CKO_PRIVATE_KEY` с `CKA_ID == cert.CKA_ID` (cert_lookup.rs, key_lookup.rs).

#### Scenario: Несколько сертификатов на токене
- **WHEN** на токене несколько объектов `CKO_CERTIFICATE` (с учётом фильтра `pkcs11_object_label`, если задан)
- **THEN** берётся ПЕРВЫЙ кандидат с валидным X.509 DER в `CKA_VALUE` (не по subject CN); приватный ключ ищется по `CKA_ID == cert.CKA_ID`

### Requirement: Non-extractable инвариант (режим B)

Ключ с `CKA_EXTRACTABLE == TRUE` ДОЛЖЕН (MUST) отклоняться с `ExtractableKeyRejected` (fail-closed; в сообщении — тип ключа и hex-префикс `CKA_ID`, без ключевого материала) — дефолтное поведение при `pkcs11_allow_extractable_keys = false`. При явном операторском opt-in `pkcs11_allow_extractable_keys = true` модуль ДОЛЖЕН (MUST) логировать WARN `pkcs11_extractable_key` и продолжать. Ошибка маппится на PAM как прочие pkcs11-ошибки auth-пути (`PAM_AUTH_ERR`) (key_lookup.rs, error.rs).

#### Scenario: Extractable-ключ при дефолтной политике
- **WHEN** `CKA_EXTRACTABLE == TRUE` и `pkcs11_allow_extractable_keys = false` (дефолт)
- **THEN** возвращается `ExtractableKeyRejected` → `PAM_AUTH_ERR`; аутентификация не продолжается

#### Scenario: Extractable-ключ при операторском opt-in
- **WHEN** `CKA_EXTRACTABLE == TRUE` и `pkcs11_allow_extractable_keys = true`
- **THEN** WARN `pkcs11_extractable_key`, работа продолжается

### Requirement: Механизмы подписи

Выбор механизма подписи ДОЛЖЕН (MUST) быть таким: RSA → `Sha256RsaPkcsPss` (salt 32, MGF1-SHA256); EC P-256/P-384 → `EcdsaSha256/384` (raw r||s перекодируется в DER); GOSTR3410 → `MechanismNotSupported` (см. KNOWN GAP в [challenge-response](../challenge-response/spec.md)). Верификация — публичным ключом ИЗ серта, не из заявленного токеном (sign.rs:119–125).

#### Scenario: GOST-ключ на токене
- **WHEN** ключ токена имеет тип GOSTR3410
- **THEN** возвращается `MechanismNotSupported`

### Requirement: Locking mode

Режим блокировки ДОЛЖЕН (MUST) определяться `pkcs11_locking_mode`: `os` (дефолт) — конкурентные вызовы разрешены; `mutex` — каждый cryptoki-вызов под process-global Mutex (legacy JaCarta-2 GOST, игнорирующие CKF_OS_LOCKING_OK) (locking.rs:78–87).

#### Scenario: Legacy-токен без OS-locking
- **WHEN** `pkcs11_locking_mode = mutex`
- **THEN** каждый cryptoki-вызов оборачивается process-global Mutex

### Requirement: Token serial как ключ removal-enforcement

`read_token_serial` (CK_TOKEN_INFO.serialNumber, trimmed; пусто → `TokenSerialMissing`) ДОЛЖЕН (MUST) читаться рано и занимать `AuthContext.usb_serial` — monitord матчит removal по нему (info.rs:27–36, flow.rs:959–961,1051).

#### Scenario: Пустой serial токена
- **WHEN** `CK_TOKEN_INFO.serialNumber` после trim пуст
- **THEN** возвращается `TokenSerialMissing`
