# Tasks: qr-login-overlay

## 1. IPC-контракт (совместно с qr-login-core)

- [ ] 1.1 Определить wire-протокол: типы (`CHALLENGE`/`SUBMIT`/`REFRESH`/`CANCEL`/`CLOSE`/`ERROR`),
      framing (length-prefixed + версия), `attempt_id`/`nonce_id` lifecycle, bounded длина кода.
- [ ] 1.2 Негативные сценарии: duplicate `SUBMIT`, чужой `attempt_id`, connect без `CHALLENGE`,
      timeout, оверлей упал, модуль timeout — каждый → определённое terminal-состояние.
- [ ] 1.3 Сторона `pam_tessera`: сервер socket, authority живых nonce, `REFRESH` при ротации,
      проверка `SUBMIT.code` против набора живых nonce попытки.

## 2. Socket security contract (pam_tessera)

- [ ] 2.1 `SO_PEERCRED` — проверка uid/pid peer (только ожидаемый оверлей-юзер).
- [ ] 2.2 mode `0600` + owner; защищённая runtime-dir `/run/tessera/` (sticky, root-owned);
      per-attempt случайное имя socket; `bind` с `O_NOFOLLOW`-семантикой.
- [ ] 2.3 single-connection (reject после первого валидного peer); `unlink`+cleanup при
      закрытии/крэше.

## 3. Оверлей — рендер (tessera-qr-overlay)

- [ ] 3.1 override-redirect always-on-top borderless X-окно на `:0`; xauth из
      `/proc/<greeter-pid>/environ` (зафиксировать хрупкость PID-discovery).
- [ ] 3.2 QR через libqrencode (или чистый Rust-энкодер) из payload `CHALLENGE`; декод-тест zbar.
- [ ] 3.3 Режим 2: только QR (ввод — родное поле greeter). Режим 3: QR + поле ввода + кнопка «Вход».

## 4. Фокус (режим 3)

- [ ] 4.1 `XSetInputFocus` на окно оверлея после показа (grab НЕ использовать).
- [ ] 4.2 Focus state-machine: проверка `XGetInputFocus` после показа, восстановление на `FocusOut`,
      явный cleanup при закрытии.
- [ ] 4.3 Тест ввода реальной клавиатурой/тачем банкомата (не только xdotool-эмуляция).

## 5. Terminal-states / cleanup

- [ ] 5.1 Реализовать таблицу terminal-состояний (design §terminal-states): cancel/back, смена
      юзера, greeter рестарт, оверлей упал, модуль timeout, approve после TTL.
- [ ] 5.2 Каждое → скрыть QR, очистить поле, закрыть socket, отозвать фокус, освободить nonce.

## 6. Overlay hardening

- [ ] 6.1 Минимум capabilities, no shell/env-inheritance, no network, no file-диалоги,
      bounded input, watchdog/cleanup при крэше.
- [ ] 6.2 seccomp + AppArmor-профиль для `tessera-qr-overlay`; kiosk-hardening (VT-switch/hotkeys)
      если применимо.

## 7. Развёртывание

- [ ] 7.1 Пакет/бинарь `tessera-qr-overlay`; интеграция с fly-dm (запуск, конфиг режима 2/3).
- [ ] 7.2 Матрица развёртывания: fly-modern (оверлей) vs classic (плагин B1) vs только текст (TTY).

## 8. Проверка

- [ ] 8.1 `openspec validate qr-login-overlay --strict` зелёный.
- [ ] 8.2 E2E режим 3 на живом fly-dm: challenge→оверлей(QR+поле)→ввод клавиатурой→socket→
      PAM_SUCCESS→сессия; скриншот + zbar-декод; terminal-states (cancel/timeout).
- [ ] 8.3 **Pre-merge gate:** `threat-model` + `vuln-scan` (harness) — pre-auth оверлей.
