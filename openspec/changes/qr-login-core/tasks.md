# Tasks: qr-login-core

## 0. Prerequisite — крипто-контракт (блокер верификации)

- [ ] 0.1 Финализировать каноническую MAC-формулу (§8.1 дизайна) совместно с Codes:
      поля `device_id/nonce/role_id/level`, порядок, `canon()` кодировка, MAC-алгоритм, `N`.
      Решить TTL в/вне MAC (рекомендация — вне). Без этого п.4 не начинается.
- [ ] 0.2 Финализировать payload-схему (§8.2): `base_url` allowlist, `role_id` обязателен,
      `version`, кодировка (base32/base64url), URL-length budget для QR-плотности.

## 1. Challenge + уровень МКЦ (tessera_core)

- [ ] 1.1 Модуль `qr/challenge.rs`: генерация `nonce` (OS RNG, `Zeroizing`), сборка
      `challenge = (device_id, nonce, role_id, level)`.
- [ ] 1.2 `qr/mac_level.rs`: чтение уровня МКЦ из `/proc/self/attr/current` (2-е поле = целостность);
      whitelist форматов метки, mapping `N∈0..3`, fail-closed при неожиданной/пустой/частичной метке.
- [ ] 1.3 Негативные тесты уровня: битая метка, отсутствует `/proc/.../attr/current`, уровень вне
      диапазона, TTY/SSH без parsec-контекста (метка `0:0` — базовый).

## 2. Рендер режима 1 (pam_tessera)

- [ ] 2.1 UTF-8 QR из challenge через `PAM_TEXT_INFO` (libqrencode или чистый Rust-энкодер);
      payload = allowlisted Codes-URL + challenge (§8.2).
- [ ] 2.2 Сканируемость: half-block, моноширинный вывод; тест декодом (zbar) payload byte-identical.

## 3. Приём кода + rate-limit (pam_tessera + tessera_core)

- [ ] 3.1 Режим 1: `PAM_PROMPT_ECHO_ON` «Код:»; bounded длина ввода.
- [ ] 3.2 Собственный rate-limit кода (`qr/rate_limit.rs`): счётчик per attempt/device/role,
      задержки, lockout при превышении (PAM_MAXTRIES не ловит socket-ввод режима 3).

## 4. Локальная проверка MAC (за prerequisite §0)

- [ ] 4.1 `qr/verify.rs`: `код == truncate_N(MAC(...))` по канонической формуле (§0.1);
      per-device ключ из локального хранилища; `Zeroizing`.
- [ ] 4.2 TOCTOU уровня: перечитать `/proc/self/attr/current` перед PAM_SUCCESS, сверить с challenge,
      расхождение → fail-closed.
- [ ] 4.3 Проверка «локальная роль-учётка покрывает `level`»; MAC валиден, но роль не даёт уровень
      → fail-closed (§8.3 trust-модель).
- [ ] 4.4 nonce consumed-state: офлайн-персист (пережить reboot), проверка одноразовости в grace-окне.

## 5. PAM control-flow + fail-closed (pam_tessera)

- [ ] 5.1 Ветка метода «QR» в `pam_sm_authenticate`; регистрация метода (`pam-integration`).
- [ ] 5.2 Зафиксировать production control-flag и поведение: {нет канала, неверный код, ошибка
      модуля, timeout}; QR-метод fail-closed, стек-fallback на пароль/серт для доступности;
      исключить password-bypass вне валидного MAC.
- [ ] 5.3 Конфиг метода QR: вкл/выкл, allowlist Codes-URL, параметры rate-limit/grace/TTL.

## 6. Аудит

- [ ] 6.1 `logging-audit`: событие `qr_code_login` (nonce↔сессия, role_id, level, исход) в
      hash-chain журнал; без раскрытия sensitive (код/ключ/полный nonce в открытом виде).

## 7. Проверка

- [ ] 7.1 `openspec validate qr-login-core --strict` зелёный.
- [ ] 7.2 Интеграционный тест режима 1: challenge→рендер (декод zbar)→ввод кода→verify→сессия
      на запрошенном уровне; негативы (неверный код, битый уровень, повтор nonce, превышен rate).
- [ ] 7.3 **Pre-merge gate:** `threat-model` + `vuln-scan` (harness) для метода QR.
