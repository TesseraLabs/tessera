# Design: qr-login-overlay

Канон — `tessera-ws/specs/2026-07-03-qr-login-display-design.md` §4.1/§4.2/§8.5/§9 (спайк-
верифицировано на Astra 1.8.4). Здесь — device-side решения по оверлею.

## Почему оверлей, а не тема

`fly-modern` (UiGreeter) плагины не грузит; PAM info-сообщения → модальный `QMessageBox::warning`
(`ThemeWidget::showMessage`) — картинку показать нельзя. Плагин-путь (B1) работает только в
classic-поколении greeter'а (теряется fly-modern-вид). Оверлей — единственный способ показать
графический QR **не трогая тему и вендорский бинарь**. Спайк: override-redirect always-on-top окно
легло поверх живого fly-modern (часы/дата/лого Astra целы), QR декодировался zbar.

## Фокус (режим 3)

Оверлей рисуется поверх, но X-фокус клавиатуры остаётся у окна greeter (спайк: `XGrabKeyboard →
GrabSuccess` — greeter клавиатуру НЕ граничит; `XGetInputFocus` = окно greeter). Решение —
`XSetInputFocus` на окно оверлея после показа (grab свободен, конфликта нет). `XGrabKeyboard` НЕ
использовать (конфликтовал бы). После этого реальная клавиатура вводит код в оверлей (спайк: код
дошёл → PAM_SUCCESS). **Focus state-machine:** проверка `XGetInputFocus` после показа,
восстановление на `FocusOut`, явный cleanup при закрытии. Тест — физ.клавиатура/тач банкомата.

## IPC-контракт `pam_tessera` ↔ оверлей

Unix-socket. Lifecycle: `attempt_id` + `nonce_id`, один attempt = одна сессия socket.
```
оверлей connect → CHALLENGE{attempt_id, payload} (модуль→оверлей) → рисует QR
  → SUBMIT{attempt_id, code} (оверлей→модуль) → модуль валидирует
  → [ротация] REFRESH{payload} (модуль→оверлей) при смене nonce
  → CANCEL/CLOSE/ERROR{code} (обе стороны)
```
Framing: length-prefixed, версия протокола в заголовке, bounded длина (код ≤ фикс). **Authority
живых nonce — `pam_tessera`** (единственный генератор); оверлей nonce не знает, только рисует.
Проверка `SUBMIT.code` — против набора живых nonce попытки (текущий + previous в grace-окне).

Негативные (обязательно определить): duplicate `SUBMIT`, чужой `attempt_id`, connect без
`CHALLENGE`, timeout ожидания кода, оверлей упал, модуль вышел по timeout — каждый → определённое
terminal-состояние.

## Socket security contract

- `SO_PEERCRED` — проверка uid/pid подключившегося (только ожидаемый оверлей-юзер);
- mode `0600`, owner; защищённая runtime-dir (`/run/tessera/`, sticky, root-owned);
- **per-attempt случайное имя socket** (или токен в первом сообщении) — не занять заранее;
- `bind` с `O_NOFOLLOW`-семантикой; `unlink` + cleanup при закрытии/крэше;
- **single-connection**: первый коннект от валидного peer, остальные reject (против race
  «подключиться раньше оверлея»).

Подделанный код не пройдёт MAC (проверка в `pam_tessera`), но socket иначе открыт
injection/replay/race/DoS — контракт закрывает.

## Overlay hardening (обязательный, pre-auth код)

Минимум capabilities, no shell/env-inheritance, no network, no file-диалоги, locked runtime-dir,
bounded input, определённое crash-поведение (watchdog/cleanup), seccomp + AppArmor-профиль. xauth
оверлея (`/proc/<greeter>/environ`) даёт полный X-доступ к дисплею greeter (X11 не изолирует
клиентов) — PID-discovery хрупок, зафиксировать риск. Kiosk-hardening: блок VT-switch и горячих
клавиш, если применимо.

## Terminal-states / cleanup

| Событие | Действие |
|---|---|
| cancel/back | скрыть QR, очистить поле, `CANCEL`→модуль, закрыть socket, отозвать фокус |
| смена юзера | закрыть оверлей, освободить nonce попытки |
| greeter рестарт / оверлей упал | модуль по timeout → fail-closed, cleanup socket |
| модуль timeout | `CLOSE`→оверлей, оверлей закрывается |
| approve после TTL nonce | код бракуется, новая попытка = новый nonce |

## Вне scope

Wayland (§5.2 дизайна — layer-shell мёртв в mutter, путь greetd/tuigreet forward-looking).
