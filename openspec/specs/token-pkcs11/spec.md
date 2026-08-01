# token-pkcs11 Specification

## Purpose

Аппаратные токены через PKCS#11 (Rutoken, JaCarta-2 GOST, ESMART): приватный ключ неизвлекаем, подпись `C_Sign` на устройстве (режим B).

Код: `crates/tessera_core/src/token/pkcs11/` (backend, session, pin_loop, cert_lookup, key_lookup, mechanism, sign, info, waiter, locking).
## Requirements
### Requirement: Загрузка модуля

`Pkcs11Backend::load(pkcs11_module)`: файла нет → `ModulePathMissing`; dlopen-fail → `ModuleLoadFailed`; `C_Initialize(CKF_OS_LOCKING_OK)` fail → `InitFailed`. Модуль ДОЛЖЕН (MUST) грузиться сразу при построении IO — конфиг-ошибки всплывают ДО касания USB/PIN (backend.rs:72–101, flow.rs:877–893).

Контекст PKCS#11 ДОЛЖЕН (MUST) быть процесс-глобальным и разделяемым по пути модуля: на каждый путь в процессе выполняется ровно один успешный `C_Initialize`, сколько бы раз ни вызывался `load`. Повторный `load` того же модуля ДОЛЖЕН (MUST) переиспользовать живой контекст. Создание контекста ДОЛЖНО (MUST) быть сериализовано процесс-глобально независимо от `pkcs11_locking_mode` бэкенда: существуют провайдеры, роняющие процесс при конкурентном `C_Initialize` вопреки объявленному `CKF_OS_LOCKING_OK`.

Ответ `CKR_CRYPTOKI_ALREADY_INITIALIZED` на `C_Initialize` ДОЛЖЕН (MUST) трактоваться как успех, а контекст — помещаться в реестр. Реестр является кэшем, а не носителем корректности: провайдер может быть уже инициализирован тем, кого реестр не видит — посторонним потребителем PKCS#11 в том же процессе либо предыдущим экземпляром модуля, чьи статики исчезли при `dlclose` (libpam выгружает модули на `pam_end`, а в долгоживущем процессе это происходит после каждой попытки входа). Присвоение чужой инициализации безопасно ровно потому, что `C_Finalize` не вызывается — отнять её у владельца невозможно.

`C_Finalize` НЕ ДОЛЖЕН (MUST NOT) вызываться: контекст живёт до конца процесса. Финализация — процесс-глобальная операция над общим `dlopen`, поэтому она деинициализировала бы провайдера и у посторонних потребителей PKCS#11 в том же процессе (`pam_pkcs11`, `sshd` с `PKCS11Provider`), которые не имеют способа это обнаружить.

#### Scenario: Неверный путь к модулю
- **WHEN** `pkcs11_module` указывает на несуществующий файл
- **THEN** при построении IO возвращается `ModulePathMissing` — ещё до касания USB/PIN

#### Scenario: Повторная загрузка того же модуля
- **WHEN** `load` вызывается второй раз для того же пути, пока первый бэкенд жив
- **THEN** переиспользуется уже инициализированный контекст, повторного `C_Initialize` не происходит

#### Scenario: Конкурентная загрузка из нескольких нитей
- **WHEN** несколько нитей одновременно вызывают `load` для одного пути модуля
- **THEN** ровно одна выполняет `C_Initialize`, остальные получают тот же контекст, процесс не падает

#### Scenario: Загрузка после освобождения всех бэкендов
- **WHEN** последний бэкенд для пути уничтожен и `load` вызывается снова
- **THEN** переиспользуется тот же контекст, повторного `C_Initialize` не происходит и `C_Finalize` не вызывался

#### Scenario: Состояние логина не переживает аутентификацию
- **WHEN** аутентификация завершилась (успехом или отказом) и сессия уничтожена
- **THEN** выполнен `C_Logout`, и следующая аутентификация в том же процессе начинается с незалогиненного токена — иначе в долгоживущем процессе (slave-процесс дисплея `fly-dm` живёт весь uptime) следующая попытка получила бы доступ к приватным объектам без предъявления PIN

#### Scenario: Два разных модуля в одном процессе
- **WHEN** в процессе загружаются два разных пути модуля
- **THEN** каждый получает свой контекст и свой `C_Initialize`

#### Scenario: Токен уже залогинен кем-то другим
- **WHEN** `C_Login` возвращает `CKR_USER_ALREADY_LOGGED_IN` (остаточный логин после неудачного `C_Logout` либо логин соседа по процессу)
- **THEN** выполняется `C_Logout` и `C_Login` повторяется с предъявленным PIN — вход не отказывается, но и не принимается по чужому логину: PIN проверяется провайдером как обычно, неверный даёт `PinIncorrect`

#### Scenario: Провайдер уже инициализирован кем-то извне реестра
- **WHEN** `C_Initialize` возвращает `CKR_CRYPTOKI_ALREADY_INITIALIZED` (сосед по процессу или предыдущий экземпляр модуля после `dlclose`)
- **THEN** это считается успехом, контекст помещается в реестр и аутентификация продолжается — а не отвергается с `InitFailed`

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

Режим блокировки ДОЛЖЕН (MUST) задаваться `pkcs11_locking_mode`: `mutex` (дефолт) — каждый cryptoki-вызов под process-global Mutex; `os` — конкурентные вызовы разрешены, выбирается оператором явно и осознанно (locking.rs:78–87).

Режим ПРИНАДЛЕЖИТ (MUST) контексту, а не отдельному хендлу: бэкенды, разделяющие один путь модуля, разделяют и режим. При расхождении запросов ДОЛЖЕН (MUST) побеждать более строгий — `mutex`; ослабление до `os` из-за того, что кто-то загрузился первым, НЕ ДОПУСКАЕТСЯ (MUST NOT), иначе конфигурация, запросившая защиту, молча её не получит. Расхождение ДОЛЖНО (MUST) логироваться.

Дефолтом ЯВЛЯЕТСЯ (MUST) `mutex`, потому что провайдеры, объявляющие `CKF_OS_LOCKING_OK` и при этом не выдерживающие конкурентных вызовов, встречаются не только среди legacy: на `rtpkcs11ecp` 2.14.1 конкурентный `C_Initialize` роняет процесс через `std::terminate`. Стоимость дефолта — один неконтендящийся `parking_lot::Mutex` на вызов (≈ 20 нс), пренебрежимая на фоне `C_Sign`.

#### Scenario: Дефолтная конфигурация
- **WHEN** `pkcs11_locking_mode` не задан в конфиге
- **THEN** применяется `mutex` и каждый cryptoki-вызов сериализуется

#### Scenario: Legacy-токен без OS-locking
- **WHEN** `pkcs11_locking_mode = mutex`
- **THEN** каждый cryptoki-вызов оборачивается process-global Mutex

#### Scenario: Оператор явно выбрал конкурентность
- **WHEN** `pkcs11_locking_mode = os` и другой режим для этого пути модуля не запрашивался
- **THEN** пользовательский мьютекс не берётся, вызовы идут параллельно

#### Scenario: Расхождение режимов на общем контексте
- **WHEN** контекст создан в режиме `os`, а следующий `load` того же пути запрашивает `mutex`
- **THEN** режим контекста повышается до `mutex` и расхождение логируется — запросивший защиту её получает

### Requirement: Token serial как ключ removal-enforcement

`read_token_serial` (CK_TOKEN_INFO.serialNumber, trimmed; пусто → `TokenSerialMissing`) ДОЛЖЕН (MUST) читаться рано и занимать `AuthContext.usb_serial` — monitord матчит removal по нему (info.rs:27–36, flow.rs:959–961,1051).

#### Scenario: Пустой serial токена
- **WHEN** `CK_TOKEN_INFO.serialNumber` после trim пуст
- **THEN** возвращается `TokenSerialMissing`

### Requirement: PIN-сессия на разделяемом контексте

PIN-сессия ДОЛЖНА (MUST) учитывать, что состояние логина в PKCS#11 принадлежит «приложению», то есть одному `C_Initialize`, а не отдельной сессии: на процесс-глобальном контексте логин переживает сессию и разделяется с посторонними потребителями провайдера в том же процессе.

`C_Login`, ответивший `CKR_USER_ALREADY_LOGGED_IN`, НЕ ДОЛЖЕН (MUST NOT) трактоваться как успех: PIN в этом случае не предъявлялся провайдеру, и принять такой ответ означало бы пустить в систему по чужому логину. Вместо этого ДОЛЖЕН (MUST) выполняться `C_Logout` с повторным `C_Login` — тогда PIN проверяется честно, а вход не оказывается сломанным до перезагрузки машины.

`C_Logout` при уничтожении сессии ДОЛЖЕН (MUST) быть гарантированным, а его отказ — повторяться и логироваться на уровне ошибки с указанием последствия: в долгоживущем процессе остаточный логин означает и доступ к приватным объектам без PIN, и отказ следующей попытки входа.

#### Scenario: Остаточный логин от предыдущей попытки
- **WHEN** предыдущая аутентификация в этом процессе завершилась с неудавшимся `C_Logout`, и начинается новая
- **THEN** новая попытка не отказывается: выполняется `C_Logout` и повторный `C_Login` с предъявленным PIN

#### Scenario: Снять остаточный логин не удалось
- **WHEN** при остаточном логине `C_Logout` отказал
- **THEN** возвращается `LogoutFailed` и сессия не выдаётся: PIN проверить не удалось, значит аутентификации не было

#### Scenario: Неверный PIN при остаточном логине
- **WHEN** токен уже залогинен, а предъявленный PIN неверен
- **THEN** после `C_Logout` повторный `C_Login` возвращает `PinIncorrect` — чужой логин не даёт входа

