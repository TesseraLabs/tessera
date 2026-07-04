# qr-login-method Specification

## Purpose

Device-side метод входа по одноразовому коду (сценарий 2): устройство офлайн генерит challenge,
рендерит QR, принимает короткий код и проверяет его локально по MAC. Ядро — без графического
оверлея (отдельная capability `qr-login-overlay`) и без серверной стороны (Codes).

## ADDED Requirements

### Requirement: Генерация challenge, привязанного к попытке и уровню

Система ДОЛЖНА (MUST) в `pam_sm_authenticate` генерировать 128-битный `nonce` из OS RNG и
собирать `challenge = (device_id, nonce, role_id, level)`, где `role_id` — роль-учётка, `level` —
уровень МКЦ. nonce ДОЛЖЕН (MUST) держаться в `Zeroizing`. challenge привязан к попытке: смена
учётки/уровня = новая попытка = новый nonce.

#### Scenario: RNG-сбой
- **WHEN** OS RNG недоступен
- **THEN** отказ auth (fail-closed, без fallback внутри метода QR)

### Requirement: Чтение уровня МКЦ из метки процесса

Система ДОЛЖНА (MUST) читать уровень МКЦ из `/proc/self/attr/current` (формат
`конф:целостность:лин:кат:роли`), беря **2-е поле (целостность)** как уровень. Формат метки
ДОЛЖЕН (MUST) валидироваться по whitelist; неожиданная/пустая/частичная метка → fail-closed.

#### Scenario: Битая или отсутствующая метка
- **WHEN** `/proc/self/attr/current` недоступен, пуст, или формат не распознан
- **THEN** метод QR отказывает (fail-closed), уровень не угадывается

#### Scenario: TTY/SSH без parsec-контекста
- **WHEN** вход по TTY/SSH, МКЦ базовый
- **THEN** метка `0:0:...` → `level = 0` (валидно)

### Requirement: TOCTOU-перечитка уровня перед финальной валидацией

Система ДОЛЖНА (MUST) перечитать метку уровня непосредственно перед `PAM_SUCCESS` и сверить с
уровнем в challenge. Расхождение → fail-closed. Источник уровня pre-auth/greeter-производный и
сам по себе НЕ доверенный; авторизация уровня — backend PDP + MAC.

#### Scenario: Уровень изменился между challenge и success
- **WHEN** метка `/proc/self/attr/current` перед `PAM_SUCCESS` не совпадает с уровнем в challenge
- **THEN** отказ auth (fail-closed) — TOCTOU закрыт

### Requirement: Рендер QR текстом (режим 1)

Система ДОЛЖНА (MUST) рендерить payload как UTF-8 QR через `PAM_TEXT_INFO`. Payload =
allowlisted Codes-URL + закодированный challenge (`device_id`, `nonce`, `role_id`, `level`,
`version`). QR ДОЛЖЕН (MUST) быть сканируем в моноширинном терминале (half-block, нулевой
межстрочный интервал).

#### Scenario: base_url вне allowlist
- **WHEN** конфигурируемый Codes-URL не в allowlist
- **THEN** метод QR не активируется (anti-phishing, fail-closed)

### Requirement: Приём кода и собственный rate-limit

Система ДОЛЖНА (MUST) принимать код через `PAM_PROMPT_ECHO_ON` (режим 1) или IPC (режимы 2/3).
Длина ввода ДОЛЖНА (MUST) быть ограничена. Система ДОЛЖНА (MUST) вести **собственный** счётчик
попыток кода (per attempt/device/role) с задержками и lockout — `PAM_MAXTRIES` не ловит
socket-ввод режима 3.

#### Scenario: Превышен лимит попыток кода
- **WHEN** число неверных вводов кода превысило порог (attempt/device/role)
- **THEN** lockout (fail-closed), дальнейший ввод отвергается до сброса

### Requirement: Локальная проверка MAC и покрытие уровня

Система ДОЛЖНА (MUST) проверять `код == truncate_N(MAC(per_device_key, canon(device_id, nonce,
role_id, level)))` по канонической формуле контракта (byte-identical с бэкендом). Дополнительно
ДОЛЖНА (MUST) проверять, что локальное определение роль-учётки покрывает `level`. Провал любой
проверки → fail-closed.

#### Scenario: MAC валиден, но локальная роль не даёт уровень
- **WHEN** код проходит MAC, но локальная роль-учётка не покрывает запрошенный `level`
- **THEN** отказ (fail-closed) — device-side остаточный баунд (§8.3 trust-модель)

#### Scenario: TTL кода истёк
- **WHEN** код введён после локального TTL (monotonic-since-boot, device-clock недоверен)
- **THEN** код бракуется; реальный контроль перебора — rate-limit + одноразовость nonce

### Requirement: Одноразовость nonce с офлайн-персистом

Система ДОЛЖНА (MUST) трекать израсходованные nonce в grace-окне и персистить consumed-state
через reboot (офлайн-устройство). Повторное использование nonce ДОЛЖНО (MUST) отвергаться.

#### Scenario: Повторный ввод кода с израсходованным nonce
- **WHEN** код с уже потреблённым nonce вводится снова (в т.ч. после reboot)
- **THEN** отказ (fail-closed) — одноразовость держится офлайн-персистом

### Requirement: Аудит входа по коду

Система ДОЛЖНА (MUST) эмитить событие `qr_code_login` (корреляция nonce↔сессия, `role_id`,
`level`, исход) в hash-chain журнал, без раскрытия sensitive (полный код/ключ).

#### Scenario: Событие в журнале при входе по коду
- **WHEN** вход по коду завершился (успех или отказ)
- **THEN** `qr_code_login{nonce_ref, role_id, level, outcome}` записано в hash-chain журнал
