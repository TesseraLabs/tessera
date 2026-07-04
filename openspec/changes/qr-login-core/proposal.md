# Proposal: qr-login-core

## Why

Сценарий 2 «Вход по QR-коду» (`tessera-ws/specs/2026-06-08-usage-scenarios-design.md`) требует
device-side метода входа по одноразовому коду: устройство офлайн показывает QR → инженер сканирует
телефоном → сайт Codes (SSO/2FA, four-eyes) → короткий код → ввод на устройстве → локальная
проверка. Дизайн отображения — `tessera-ws/specs/2026-07-03-qr-login-display-design.md` (прошёл
ревью master-code-reviewer + codex; дисплей-слой готов, крипто-контракт — блокер, см. Impact).

Этот change — **ядро метода**: генерация challenge, текстовый рендер QR (режим 1, работает
везде через PAM без графики), чтение уровня МКЦ, приём и локальная проверка кода, rate-limit,
fail-closed. Основа для оверлея (`qr-login-overlay`) и плагина. Вне scope: графический оверлей
(отдельный change), серверная сторона (Codes / `issuance-signals`).

## What Changes

- Новая capability **qr-login-method**: PAM-метод «QR» в `pam_tessera` (наряду с cert-путём).
  - **Challenge**: `pam_tessera` в `pam_sm_authenticate` генерит `nonce` (CSPRNG), собирает
    `challenge = (device_id, nonce, role_id, level)` — привязка к попытке и уровню.
  - **Уровень МКЦ**: читается из `/proc/self/attr/current` (2-е поле = целостность), спайк-доказано
    на живой Astra; **TOCTOU-перечитка** перед финальной валидацией.
  - **Рендер режима 1**: UTF-8 QR через `PAM_TEXT_INFO` (payload = allowlisted Codes-URL +
    challenge); сканируется в моноширинном терминале (TTY/SSH/recovery).
  - **Приём кода**: `PAM_PROMPT_ECHO_ON` (режим 1) или через IPC от оверлея (режимы 2/3, контракт
    в `qr-login-overlay`); **собственный rate-limit** (PAM_MAXTRIES не ловит socket-ввод).
  - **Локальная проверка**: `код == truncate_N(MAC(...))` по канонической формуле + локальная роль
    покрывает `level`; иначе fail-closed. nonce одноразовый, consumed-state персистится офлайн.
- **Модификация pam-integration**: регистрация метода «QR»; конфиг вкл/выкл, allowlist Codes-URL.
- **Модификация logging-audit**: событие входа по коду (корреляция nonce↔сессия).

## Capabilities

### New Capabilities

- `qr-login-method`: генерация challenge (nonce+уровень+role_id), рендер QR текстом (режим 1),
  чтение уровня МКЦ из `/proc/self/attr/current` с TOCTOU-перечиткой, приём кода, rate-limit,
  локальная проверка MAC (по контракту §8 дизайна), consumed-state nonce, fail-closed.

### Modified Capabilities

- `pam-integration`: метод «QR» в стеке `pam_tessera`, конфиг метода, allowlist Codes-URL.
- `logging-audit`: событие `qr_code_login` (nonce↔сессия, role_id, level, исход).

## Impact

- **Блокер (крипто-контракт §8 дизайна):** каноническая MAC-формула (поля/порядок/кодировка/
  truncation `N`) и payload-схема должны быть финализированы совместно с Codes ДО реализации
  «локальной проверки MAC». До этого — реализуется всё, кроме верификации кода (challenge,
  рендер, уровень, приём, rate-limit, fail-closed каркас). Верификация — за контрактом.
- `tessera_core`: модуль `qr/` (challenge-gen, уровень МКЦ, MAC-verify, nonce-store);
  переиспользует RNG/zeroize из `challenge/`.
- `pam_tessera`: ветка метода «QR» в `pam_sm_authenticate` (текст-рендер, prompt/IPC кода).
- `tessera_cli`: конфиг метода QR; персист consumed-nonce.
- Зависимость: `qr-login-overlay` (режимы 2/3) потребляет IPC-контракт этого change.
