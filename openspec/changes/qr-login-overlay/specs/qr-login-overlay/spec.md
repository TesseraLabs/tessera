# qr-login-overlay Specification

## Purpose

Графический QR на экране логина Astra (fly-dm) без правки темы: внешний X-оверлей поверх
greeter'а. Режим 2 — оверлей рисует QR, ввод в поле greeter. Режим 3 — QR + поле + кнопка целиком
в оверлее, ввод по unix-socket в `pam_tessera`. X11-специфично; Wayland вне scope.

## ADDED Requirements

### Requirement: X-оверлей поверх greeter без правки темы

Система ДОЛЖНА (MUST) рисовать QR в override-redirect always-on-top borderless X-окне на `:0`
поверх работающего fly-modern greeter, НЕ модифицируя тему и вендорский бинарь `fly-dm_greet`.
QR ДОЛЖЕН (MUST) быть сканируем (декодироваться в payload byte-identical).

#### Scenario: Оверлей поверх fly-modern
- **WHEN** fly-modern greeter активен и `pam_tessera` прислал `CHALLENGE`
- **THEN** оверлей рисует QR поверх, родная тема (часы/дата/лого) не тронута

### Requirement: Захват фокуса клавиатуры (режим 3)

Система ДОЛЖНА (MUST) в режиме 3 после показа окна выполнять `XSetInputFocus` на окно оверлея
(X-фокус по умолчанию остаётся у greeter). Система НЕ ДОЛЖНА (MUST NOT) использовать
`XGrabKeyboard` (конфликт с greeter). Система ДОЛЖНА (MUST) вести focus state-machine:
проверка `XGetInputFocus` после показа, восстановление на `FocusOut`, cleanup при закрытии.

#### Scenario: Ввод кода реальной клавиатурой
- **WHEN** оверлей показан и `XSetInputFocus` выполнен
- **THEN** нажатия физической клавиатуры попадают в поле оверлея, не в greeter

### Requirement: IPC-контракт с pam_tessera

Система ДОЛЖНА (MUST) вести обмен с `pam_tessera` по unix-socket: `CHALLENGE` (модуль→оверлей,
payload для QR), `SUBMIT` (оверлей→модуль, код), `REFRESH` (модуль→оверлей, новый payload при
ротации nonce), `CANCEL`/`CLOSE`/`ERROR`. Сообщения ДОЛЖНЫ (MUST) быть length-prefixed с версией
протокола; длина кода ограничена. Authority живых nonce — `pam_tessera`; оверлей nonce не
порождает.

#### Scenario: Ротация nonce
- **WHEN** `pam_tessera` сменил nonce (grace-окно) и прислал `REFRESH`
- **THEN** оверлей перерисовывает QR новым payload; старый nonce ещё валиден в grace-окне

#### Scenario: SUBMIT с чужим attempt_id
- **WHEN** приходит `SUBMIT` с `attempt_id`, не совпадающим с текущей попыткой
- **THEN** отвергается (terminal-состояние), auth не продолжается

### Requirement: Socket security contract

Система ДОЛЖНА (MUST) защищать unix-socket: проверка `SO_PEERCRED` (uid/pid ожидаемого
оверлей-юзера), mode `0600` + owner, защищённая runtime-dir, **per-attempt** случайное имя
socket, `bind` с `O_NOFOLLOW`-семантикой, **single-connection** (reject после первого валидного
peer), `unlink`+cleanup при закрытии/крэше.

#### Scenario: Попытка занять socket заранее (race)
- **WHEN** локальный процесс пытается подключиться к socket раньше легитимного оверлея
- **THEN** `SO_PEERCRED`/single-connection отвергают; per-attempt случайное имя не предугадать

### Requirement: Overlay hardening (pre-auth)

Оверлей — pre-auth код на публичном банкомате. Система ДОЛЖНА (MUST) работать с минимумом
capabilities, без наследования shell/env, без сети, без файл-диалогов, с ограниченной длиной
ввода, с определённым crash-поведением (watchdog/cleanup), под seccomp + AppArmor-профилем.

#### Scenario: Попытка kiosk-breakout из оверлея
- **WHEN** пользователь у банкомата пытается выйти из оверлея в систему (hotkeys/файл-диалог/сеть)
- **THEN** нет пути наружу — минимум capabilities, no shell/network/file-диалоги, AppArmor-профиль

### Requirement: Terminal-состояния и cleanup

Система ДОЛЖНА (MUST) для каждого терминального события (cancel/back, смена юзера, greeter
рестарт, крэш оверлея, timeout модуля, approve после TTL) выполнять: скрыть QR, очистить поле
ввода, закрыть socket, отозвать фокус, освободить nonce попытки.

#### Scenario: Инженер нажал «отмена»
- **WHEN** пользователь отменяет попытку
- **THEN** оверлей шлёт `CANCEL`, скрывает QR, очищает поле, закрывает socket, отзывает фокус
