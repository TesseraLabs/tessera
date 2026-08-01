## MODIFIED Requirements

### Requirement: PKCS#12 путь (порядок проверок)

`authenticate_pkcs12` ДОЛЖЕН (MUST) выполнять: pre_auth hooks → получение конверта из выбранного источника → PIN-loop (3 попытки, хардкод) → challenge-response → сборка цепи (p12-chain + `certs/chain.pem`) → trust verify → host_binding (обязателен) → user_binding/legacy mapping → AuthContext → post_auth_success hooks → monitord SessionOpen (non-fatal) (flow.rs:430–762).

Источник конверта ДОЛЖЕН (MUST) определяться конфигурацией и принимать одно из двух значений:

- раздел USB-носителя (**дефолт**, текущее поведение): wait_for_usb → per-partition loop (mount → discover → envelope);
- объект данных на PKCS#11-токене: чтение приватного объекта `CKO_DATA` по метке (см. [token-data-carrier](../token-data-carrier/spec.md)) — без монтирования и без mass-storage.

Всё, что следует за получением конверта, НЕ ДОЛЖНО (MUST NOT) зависеть от источника.

Идентификатор носителя для removal-enforcement ДОЛЖЕН (MUST) браться из того устройства, которое фактически несёт конверт: при источнике «раздел USB-носителя» — serial USB-устройства (flow.rs:887), при источнике «токен» — `CK_TOKEN_INFO.serialNumber` (как в режиме B, flow.rs:1253). Пустой serial токена ДОЛЖЕН (MUST) давать `TokenSerialMissing` и прерывать аутентификацию: без идентификатора monitord не сможет сматчить извлечение носителя, и сессия переживёт вынутый токен.

#### Scenario: host_binding нарушен
- **WHEN** ни один дескриптор `pam_cert_host_binding` не совпал с host_id_hash
- **THEN** WARN + on-screen диагностика «Сертификат выпущен для другого устройства…» → `FlowError::CertScope` → `PAM_AUTH_ERR` (7), fail-closed (flow.rs:631–655)

#### Scenario: monitord недоступен при SessionOpen
- **WHEN** `monitor.open_session` вернул ошибку на auth-пути
- **THEN** только WARN, auth-вердикт не меняется (flow.rs:742–747)

#### Scenario: источник — токен
- **WHEN** источником конверта задан объект данных на токене
- **THEN** mass-storage не задействуется (нет wait_for_usb и монтирования), конверт читается с токена, дальнейшие проверки идут в неизменном порядке

#### Scenario: removal-enforcement при источнике «токен»
- **WHEN** конверт прочитан с токена и аутентификация успешна
- **THEN** `AuthContext.usb_serial` содержит serial токена, и monitord матчит по нему извлечение носителя

#### Scenario: у токена пустой serial
- **WHEN** `CK_TOKEN_INFO.serialNumber` после trim пуст
- **THEN** возвращается `TokenSerialMissing`, аутентификация прерывается — сессия без идентификатора носителя не создаётся

#### Scenario: источник не задан
- **WHEN** источник конверта в конфигурации отсутствует
- **THEN** применяется раздел USB-носителя — поведение существующих инсталляций не меняется

Недоступность monitord на этом call-site НЕ ДОЛЖНА (MUST NOT) менять auth-вердикт даже при `monitor_fail_mode="strict"`: фатальны (меняют вердикт) только `DEVICE_GONE` и `UNAUTHORIZED` (`ipc/failmode.rs`); уведомление monitord идёт после уже состоявшегося успеха аутентификации, транспортные ошибки IPC — non-fatal. `strict`/`permissive` управляют лишь тем, пробрасывает ли `FailModeWrapper` нефатальные ошибки IPC вызывающему коду.
