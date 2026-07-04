# Proposal: qr-login-overlay

## Why

`qr-login-core` даёт вход по QR в текстовом виде (режим 1) — работает везде, но без графики. На
production-банкоматах Astra (fly-dm, тема `fly-modern`) нужен **графический QR на экране логина**,
не ломая родную тему. `fly-modern` (UiGreeter) плагины не грузит, а PAM info-сообщения выбрасывает
модальным `QMessageBox` — картинку так не показать. Решение (спайк-верифицировано на живой Astra
1.8.4, дизайн `tessera-ws/specs/2026-07-03-qr-login-display-design.md`): внешний X-оверлей поверх
greeter'а.

Два режима графики:
- **Режим 2**: оверлей рисует QR, ввод кода — в родном поле greeter (штатный PAM prompt).
- **Режим 3**: QR + поле + кнопка «Вход» целиком в оверлее; ввод уходит в `pam_tessera` по
  unix-socket → PAM_SUCCESS → вход продолжается автоматически. Требует `XSetInputFocus` (спайк:
  фокус увести с greeter на оверлей, grab не нужен).

Вне scope: ядро метода (`qr-login-core`), Wayland (forward-looking, greetd/tuigreet), плагин B1.

## What Changes

- Новая capability **qr-login-overlay**: X-демон `tessera-qr-overlay` + IPC-контракт с
  `pam_tessera`.
  - **Оверлей**: override-redirect always-on-top borderless X-окно на `:0`, QR через libqrencode;
    режим 3 добавляет поле ввода + кнопку.
  - **Фокус (режим 3)**: `XSetInputFocus` на окно оверлея после показа (фокус остаётся у greeter
    по умолчанию); focus state-machine — восстановление на `FocusOut`, cleanup при закрытии.
  - **IPC**: unix-socket `pam_tessera`↔оверлей. `CHALLENGE` (модуль→оверлей), `SUBMIT`
    (оверлей→модуль код), `REFRESH` (ротация nonce), `CANCEL/CLOSE/ERROR`. Framing, версия,
    lifecycle попытки (`attempt_id`), негативные сценарии.
  - **Socket hardening**: `SO_PEERCRED`, mode `0600`, защищённая runtime-dir, per-attempt
    случайное имя, single-connection, `O_NOFOLLOW`, cleanup при крэше.
  - **Overlay hardening**: минимум capabilities, no shell/env-inheritance, no network,
    no file-диалоги, bounded input, watchdog/cleanup, seccomp + AppArmor-профиль.
  - **Terminal-states**: таблица (cancel/back, смена юзера, greeter рестарт, оверлей упал, timeout,
    approve после TTL) → скрыть QR, очистить поле, закрыть socket, отозвать фокус, освободить nonce.

## Capabilities

### New Capabilities

- `qr-login-overlay`: X-оверлей QR поверх fly-modern (режимы 2/3), IPC-контракт с `pam_tessera`,
  focus state-machine (`XSetInputFocus`), socket+overlay hardening, terminal-states/cleanup.

## Impact

- Зависит от `qr-login-core` (IPC-контракт, генерация challenge/nonce, проверка кода). authority
  живых nonce — `pam_tessera`; оверлей только рисует и собирает ввод (непривилегирован).
- Новый бинарь/пакет `tessera-qr-overlay` (Qt + libqrencode или чистый X); отдельная сборка.
- X11-специфично (override-redirect + XSetInputFocus + X-доступ к `:0`). Wayland — forward-looking
  (§5.2 дизайна), не в scope.
- Развёртывание: оверлей-демон + конфиг fly-dm; xauth-доступ к дисплею greeter (fragile PID-
  discovery — зафиксировано в hardening).
- **Pre-merge gate:** `threat-model` + `vuln-scan` — оверлей это pre-auth код на публичном
  банкомате.
