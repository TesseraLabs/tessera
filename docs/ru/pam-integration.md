# Интеграция `tessera` в `/etc/pam.d/*`

Задача этого документа — встроить проверку сертификата Tessera в
PAM-стек нужных сервисов (`fly-dm`, `login`, `sudo`, `sshd`) и **не
залочить себя** в процессе. Вся правка `/etc/pam.d/*` делается одним
поставочным скриптом `/usr/share/tessera/integrate-pam.sh`, который
вставляет подключение модуля в правильную позицию и сохраняет
резервную копию каждого файла.

Порядок чтения: сначала выберите режим (§1) — от него зависит, можно
ли будет войти без USB-носителя и чем грозит его потеря; затем как
скрипт правит файлы (§2–§3) и специфика каждого сервиса (§4–§6); в
конце — крайние случаи (МКЦ, хосты без systemd) и восстановление.

> **ВАЖНО.** Перед правкой PAM-стека **открыть второй рут-shell**
> (например, `ssh root@<host>`). Если основной shell не сможет
> авторизоваться после изменений — второй терминал останется
> единственным способом отката.

## 1. Режимы аутентификации

`tessera` поддерживает три эксплуатационных режима, переключаемых
выбором PAM-сниппета:

| Режим             | snippet                            | Сценарий                              | Вход без USB                  |
|-------------------|------------------------------------|---------------------------------------|-------------------------------|
| `2fa` (default)   | `/etc/pam.d/tessera`              | Cert + пароль (классический 2FA)      | пароль работает, но без USB не зайти |
| `optional`        | `/etc/pam.d/tessera-optional`     | Cert ИЛИ пароль (миграция)            | да, по паролю                 |
| `cert-only`       | `/etc/pam.d/tessera-only`         | Cert как единственный фактор          | НЕТ, полная блокировка        |

### Активация

```bash
# 2FA на sudo (по умолчанию):
sudo /usr/share/tessera/integrate-pam.sh --mode=2fa /etc/pam.d/sudo

# Миграционный режим:
sudo /usr/share/tessera/integrate-pam.sh --mode=optional /etc/pam.d/sudo

# Cert-only (потеря флэшки = lockout!):
sudo /usr/share/tessera/integrate-pam.sh --mode=cert-only /etc/pam.d/sudo
```

Откат — одинаковый для всех режимов:

```bash
sudo /usr/share/tessera/integrate-pam.sh --unintegrate /etc/pam.d/sudo
```

### Lockout-warning для `cert-only`

Перед переключением сервиса в `cert-only` админ обязан иметь
резервный канал доступа:

1. **Открытый root-shell в другом терминале** (TTY/SSH) на всё время
   проверки — минимум до того, как убедились, что cert-only auth
   работает на тестовой учётной записи на этой машине.
2. **Альтернативный путь логина**, который НЕ проходит через
   `tessera` — например, отдельный sshd-stack с
   `PubkeyAuthentication=yes` + `UsePAM=no`, или sudoers-правило для
   административной учётной записи без `@include tessera`. Иначе потеря или
   блокировка единственного токена (USBGuard, ЗПС, физическая утрата)
   выведет хост из строя — никто не сможет залогиниться, включая
   локальный root.

Откат — `integrate-pam.sh --unintegrate` из живого root-shell или
через rescue-target (см.
[troubleshooting.md §4 «Замок-аут после неудачной правки PAM»](troubleshooting.md#4-pam-стек-и-lockout)).

## 2. Поставочный snippet и `integrate-pam.sh`

`tessera` поставляет включаемый сниппет `/etc/pam.d/tessera`
(см. [`dist/pam.d/tessera`](../../dist/pam.d/tessera)). Подключать его
строкой `@include tessera`.

Поставочный скрипт `/usr/share/tessera/integrate-pam.sh`
автоматически вставляет `@include tessera` в правильную позицию и
сохраняет резервную копию `<file>.bak.<UTC-timestamp>`.

### Точка вставки

- **Если в файле есть `auth ... pam_parsec_mac.so`** (типично для Astra
  SE `/etc/pam.d/login`, `/etc/pam.d/fly-dm`) — `@include` встаёт
  **после** этой строки. Иначе snippet `tessera-only` с `success=done`
  обрывал бы auth-стек до выполнения `pam_parsec_mac`, его
  account/session-инстансы валились бы с
  `"Can't obtain required data"` → login deny.
- **Иначе** `@include` встаёт перед первой `auth`-строкой
  (legacy behaviour для систем без МКЦ-стека, Ubuntu/Debian).

## 3. Two-include pattern (0.3.12+)

Начиная с 0.3.12 `integrate-pam.sh` подключает модуль **двумя**
строками:

1. `@include tessera*` (auth + account фазы) — попадает в верх файла
   после `auth ... pam_parsec_mac.so` (или перед первой
   `auth`-строкой, если МКЦ выключен);
2. `session    required   pam_tessera.so` — ставится **после**
   `@include common-session` (или после последней `session`-строки,
   если common-session нет).

### Зачем

`pam_sm_open_session` нашего модуля читает `XDG_SESSION_ID` из
PAM-environment и пушит его в monitord, чтобы USB-removal action
(`Lock` / `Logout`) умел адресовать logind-сессию пользователя.
`XDG_SESSION_ID` создаётся `pam_systemd.so` (обычно через
`@include common-session`) — поэтому наш `session` **обязан** идти
после.

### Миграция с 0.3.11 на 0.3.12

Поставочные snippets (`tessera`, `tessera-only`, `tessera-optional`)
с 0.3.12 содержат только `auth`+`account` — `session` живёт отдельной
строкой в host pam.d-файле. После апгрейда с 0.3.11 операторам нужно
**один раз** прогнать:

```bash
sudo /usr/share/tessera/integrate-pam.sh --unintegrate /etc/pam.d/login
sudo /usr/share/tessera/integrate-pam.sh --mode=<режим> /etc/pam.d/login
```

для каждого ранее интегрированного сервиса — старая session-строка
из snippet'а после обновления `.deb` исчезнет, а новую вставит
только повторный прогон.

### Валидация порядка

Daemon на старте валит `ERROR pam_stack_session_misorder`, если наша
session-строка стоит **перед** `@include common-session` /
`pam_systemd.so`. Проверить без рестарта:

```bash
sudo tessera check
```

При неверном порядке `XDG_SESSION_ID` не успевает попасть в
PAM-окружение к моменту нашего `pam_sm_open_session` (в журнале
PAM-модуля на уровне DEBUG: `XDG_SESSION_ID not yet in PAM env`,
таргет `tessera.session`), и сессия остаётся без logind id. Цена
ошибки высока: при извлечении флешки действие `lock`/`logout`
не может адресовать сессию, и демон уходит в fail-closed —
перезагрузка устройства с ALERT-строкой
`USB-removal … has no logind id; failing closed with reboot`
в журнале. Подробности — см.
[troubleshooting.md §4](troubleshooting.md#4-pam-стек-и-lockout).

## 4. fly-dm

### Зачем интегрировать именно fly-dm

`fly-dm` — графический display-manager Astra Linux SE; это **первый**
PAM-потребитель, через который пользователь попадает в графическую
сессию. Без интеграции `tessera` в `/etc/pam.d/fly-dm`
USB-токен на этапе GUI-логина не проверяется, пользователь зайдёт по
паролю как будто модуль не установлен. Остальные сервисы
(`sudo`, `login`, `sshd`) защищают только последующие действия.

Конкретные причины:

1. **Точка входа в сессию.** МКЦ-метка (`pam_cert_max_integrity ∩ МНКЦ
   пользователя`) применяется в `pam_sm_open_session` и наследуется
   всем дочерним процессам desktop-сессии. Если сессию открыл не
   `tessera`, метка не выставится.
2. **Привязка USB к сессии.** `tessera daemon` регистрирует
   удаление токена и отправляет lock-event в screen-locker. Регистрация
   возможна только если сессию открыл сам модуль — иначе у демона нет
   записи `(uid, session_id, token_serial)`.
3. **Hot-plug до логина.** `fly-dm` стартует раньше пользовательских
   сервисов; `tessera.service` обязан быть `Before=fly-dm.service`
   (поставочный unit это делает) — иначе на первом логине после
   ребута USB может быть ещё не проинициализирован.
4. **GUI-prompt для PIN.** `fly-dm` рендерит `PAM_PROMPT_ECHO_OFF` как
   password-field. Без интеграции PKCS#11-prompt уйдёт в `stderr`
   DM-процесса и пользователь его не увидит — выглядит как «токен не
   работает».
5. **Root-контекст на auth-этапе.** `fly-dm` бежит как root, поэтому
   доступ к `/dev/bus/usb/*` и PCSC-сокету разрешён без
   дополнительной udev-настройки.

### Применение

```bash
sudo /usr/share/tessera/integrate-pam.sh /etc/pam.d/fly-dm
sudo cat /etc/pam.d/fly-dm | head -5
```

Ожидаемый верх файла:

```
@include tessera
auth        requisite   pam_nologin.so
auth        required    pam_env.so
...
```

Контроль в сниппете [`dist/pam.d/tessera`](../../dist/pam.d/tessera) —
`required`: без успешной cert-аутентификации вход невозможен. Это
дефолтный режим `2fa` скрипта `integrate-pam.sh`; «парольного fallback'а
НЕТ» означает, что пароль **не заменяет** сертификат. Пароль при этом
по-прежнему запрашивается остальным PAM-стеком (`pam_unix.so` и т. д.)
как второй фактор — но отказ или отсутствие cert-аутентификации обойти
им нельзя. Мягкий вариант с fallback'ом на следующие модули (`pam_unix.so`) — это
отдельный сниппет [`dist/pam.d/tessera-optional`](../../dist/pam.d/tessera-optional)
с контролем `sufficient`; используйте его только на переходный период,
пока токены есть не у всех.

### Screen-locker (отдельный стек)

`fly-dm-screensaver` / `fly-wm-locker` имеют **собственный** PAM-стек.
Интеграция `/etc/pam.d/fly-dm` разлоком экрана не управляет. Чтобы
разблокировка работала по токену:

```bash
sudo /usr/share/tessera/integrate-pam.sh /etc/pam.d/fly-dm-screensaver
```

Без этого извлечение токена корректно блокирует экран (через
`tessera daemon` + D-Bus screen-lock hook), но разблокировать
сессию можно будет только паролем.

### Проверка стенда

```bash
systemctl status tessera        # daemon up до старта fly-dm?
pamtester fly-dm $USER authenticate  # сухой прогон auth-стека без GUI
journalctl -u fly-dm -f              # логи во время живого логина
```

### Banner с host_id на экране

См. [fly-dm-greeter.md](fly-dm-greeter.md) — wallpaper writer для
МКЦ-3 fly-modern, где PAM_TEXT_INFO не пробрасывается в UI.

## 5. sudo

```bash
sudo /usr/share/tessera/integrate-pam.sh --mode=cert-only /etc/pam.d/sudo
```

**Для ролевых учётных записей (пароль заблокирован через `passwd -l`,
см. [install.md §8.4](install.md#84-закрытие-остальных-путей-входа-в-ролевую-учётную-запись))
режим обязан быть `--mode=cert-only`.** И `2fa`, и `optional` в
какой-то ветке стека проваливаются на `pam_unix.so` — а `pam_unix`
на заблокированном пароле (`!`/`*` в `/etc/shadow`) всегда отказывает,
причём этот отказ выглядит как «сертификат не сработал», хотя реальная
причина в пароле. `cert-only` — единственный режим, в котором
`pam_unix` вообще не участвует в решении. На обычных (не ролевых)
учётных записях с обычным паролем годятся все три режима — выбор там
описан в §1.

Отдельная задача — не пускать посторонних инженеров в ролевую учётную
запись через `sudo -u serv` / `sudo -i -u serv`: это runas-scoping,
не имеющий отношения к тому, включён ли здесь `tessera`, — рецепт
(группа `tessera-roles`, отрицание в `sudoers`, проверка
`sudo -l -U`) в [install.md §8.4 «`su` и `sudo -u`»](install.md#84-закрытие-остальных-путей-входа-в-ролевую-учётную-запись).

## 6. login

```bash
sudo /usr/share/tessera/integrate-pam.sh --mode=cert-only /etc/pam.d/login
```

Та же причина, что и в §5: ролевая учётная запись входит в `login` с
заблокированным паролем, поэтому режим — только `cert-only`.

## 6½ sshd

```bash
sudo /usr/share/tessera/integrate-pam.sh --mode=cert-only /etc/pam.d/sshd
```

`sshd`, как и `login`/`sudo`, требует `--mode=cert-only` для ролевых
учётных записей — по той же причине заблокированного пароля.

Дополнительно `sshd` нужен собственный `Match User`-блок, закрывающий
все методы входа, кроме keyboard-interactive (через который приходит
PAM/Tessera) — рецепт, ловушка с областью действия `Match` и обе
проверки `sshd -T -C` — в [install.md §8.4
«`sshd`: оставить единственный метод аутентификации»](install.md#84-закрытие-остальных-путей-входа-в-ролевую-учётную-запись).

> **Известное ограничение: privilege separation.** OpenSSH с
> включённым `UsePrivilegeSeparation` (поведение по умолчанию на всех
> целевых дистрибутивах) выполняет auth-фазу и session-фазу PAM в
> **разных** процессах/PAM-хендлах. `AuthContext`, который
> `pam_sm_authenticate` кладёт через `pam_set_data`, живёт только в
> рамках одного `pam_start()`/`pam_end()` — то есть не переживает
> переход между процессами privsep. На практике это означает, что
> реальный `ssh`-вход по сертификату в `cert-only`-режиме может
> успешно пройти auth-фазу и тут же оборваться на открытии сессии.
> Смоук-тест через `pamtester` (§9 ниже) этого не покажет — `pamtester`
> сам не разделяет привилегии и держит один процесс на весь прогон.
> Единственная надёжная проверка — реальное SSH-подключение (см. §9
> «Проверка через реальный вход»). Если оно обрывается сразу после
> ввода PIN — это ограничение, а не ошибка настройки; временно
> откатите интеграцию (`--unintegrate`) и используйте `login`/`fly-dm`
> для входа по сертификату, пока это не будет исправлено.

## 6¾ su

`su` **не требует** интеграции `tessera` — и не должен её получать.
Переход в ролевую учётную запись достаточно закрыть на уровне
`pam_succeed_if.so` (`requisite … notingroup tessera-roles`,
рецепт и обе проверки — в [install.md §8.4
«`su` и `sudo -u`»](install.md#84-закрытие-остальных-путей-входа-в-ролевую-учётную-запись)):
такое правило блокирует переход в `serv` для всех, включая `root`,
без участия PAM-стека `tessera` вообще. Добавлять сюда
`@include tessera*` не нужно — `su` не должен обзаводиться отдельным
путём входа по сертификату; предъявитель уже прошёл через `tessera` в
том сервисе, откуда он получил свою текущую сессию (`login`/`sshd`/
`fly-dm`).

## 7. PAM-стек с учётом МКЦ

Стек зависит от того, включено ли МКЦ-ядро PARSEC. `pam_parsec_mac.so`
в стеке нужен **только когда МКЦ-ядро реально работает**. Подробности
— [operations.md §7 «МКЦ (MAC integrity)»](operations.md#7-мкц-mac-integrity)
и [mac-integrity.md](mac-integrity.md).

### Проверить состояние МКЦ

```bash
mount | grep -i parsec                           # пусто → МКЦ выключен
cat /etc/parsec/mswitch.conf 2>/dev/null         # zero_if_notfound: yes → МКЦ выключен
ls /sys/kernel/security/parsec 2>/dev/null       # ENOENT → МКЦ выключен
```

### Краткие шаблоны

**МКЦ выключен** — без `pam_parsec_mac.so` в стеке, `[mac].runtime = "disabled"`.

**МКЦ включён** — `auth required pam_parsec_mac.so` + `@include tessera`
+ `pam_parsec_cap.so`/`pam_parsec_mac.so` в session. `[mac].runtime = "required"`.

**Смешанный парк** — `runtime = "auto"`, стек с `pam_parsec_mac.so`
безопасен.

Поставляемый стек и процедура активации МКЦ —
[operations.md §7 «МКЦ (MAC integrity)»](operations.md#7-мкц-mac-integrity)
и [install.md §«МКЦ — опциональная активация»](install.md#мкц-mac-integrity--опциональная-активация).
Полная матрица `runtime × cert_integrity` и интеграционная
документация — в коммерческой поставке (см.
[mac-integrity.md, «Что в коммерческой поставке»](mac-integrity.md#что-в-коммерческой-поставке)).

## 8. Безопасность правки

- Перед правкой убедиться, что есть второй открытый рут-shell.
- Проверять каждое изменение командой `pamtester` сразу после правки.
- В случае поломки восстановить из бекапа:
  ```bash
  sudo cp /etc/pam.d/sudo.bak.<TS> /etc/pam.d/sudo
  ```
- Полный recovery из rescue.target — см.
  [troubleshooting.md §4](troubleshooting.md#4-pam-стек-и-lockout).

## 9. `pamtester` не заменяет реальный вход

`AuthContext`, который `pam_sm_authenticate` кладёт через
`pam_set_data`, живёт только в рамках одного `pam_start()`/
`pam_end()` — одного процесса, читающего/пишущего один и тот же
PAM-хендл. Три отдельных вызова `pamtester` (`authenticate`,
`open_session`, `close_session` по отдельности) — это три независимых
PAM-транзакции: `account`/`session`-фазы такого прогона не увидят
контекст, оставленный auth-фазой из предыдущего вызова, и упадут с
ошибкой, не имеющей отношения к реальной работе модуля. Правильный
вызов передаёт все операции одним списком — тогда используется один
`pam_start()` на весь прогон:

```bash
pamtester sudo alice authenticate acct_mgmt open_session close_session
```

Ожидание: `pamtester` печатает `successfully` на каждую операцию по
очереди (при вставленном USB-носителе или токене).

```bash
sudo tessera check    # ловит pam_stack_session_misorder и др.
```

### `pamtester` ≠ реальный вход

`pamtester` — не полноценный логин-стек: он не разделяет привилегии
между процессами, как `sshd` (см. §6½, «Известное ограничение») или
`login`/`fly-dm` в некоторых конфигурациях display-менеджера, и не
проходит через PAM-conversation так, как её ведёт реальный сервис
(запрос PIN, TTY, X11-сессия). Успешный `pamtester`-прогон подтверждает
корректность самого PAM-стека (порядок строк, `pam_tessera` вызывается,
`AuthContext` передаётся внутри одного процесса) — но не гарантирует,
что реальный вход через проверяемый сервис отработает так же.

### Проверка через реальный вход

После `pamtester` обязательно проверяйте живым логином на каждый
интегрированный сервис:

```bash
ssh serv@<host>                 # sshd
login: serv                     # login (локальная консоль/TTY)
sudo -u serv -i                 # sudo, если у вызывающего есть право runas
```

Ожидание — запрос PIN, успешный вход, и (для сервисов с session-фазой)
рабочая USB-removal-реакция (`lock`/`logout`) при извлечении токена —
её `pamtester` тоже не проверяет, так как не открывает реальную
logind-сессию.

## 10. Хосты без systemd: SysV init

Пакет `tessera` ставит **оба** init-варианта:

- **systemd-юнит** `tessera.service` — основной, на хостах с
  systemd активируется автоматически через `dh_installsystemd`;
- **SysV init-скрипт** `/etc/init.d/tessera` — для non-systemd
  окружений (чистый sysvinit, OpenRC). Включается через `update-rc.d`
  или вручную:

  ```bash
  sudo update-rc.d tessera defaults
  sudo service tessera start
  sudo service tessera status
  ```

Скрипт оборачивает запуск `/usr/bin/tessera` через
`start-stop-daemon`, кладёт PID-файл в
`/run/tessera/tessera.pid` и читает
`/etc/tessera/config.toml`.

### Caveats

- На SysV-хостах нет hardening-сэндбокса (cgroups, ProtectSystem) —
  оператор принимает компромисс осознанно.
- USB-removal `Lock`/`Logout` без `pam_systemd.so` **не работает** —
  `XDG_SESSION_ID` физически не создаётся. Fallback: верхнеуровневый
  ключ `on_usb_removed = "shutdown"` (или `"hook"`). См.
  [troubleshooting.md §4 «Logout requested but session has no logind id», Причина 3](troubleshooting.md#4-pam-стек-и-lockout).
- На systemd-хостах править SysV-скрипт не требуется — авторитативный
  источник конфигурации службы — `tessera.service`.

## 11. См. также

- [install.md](install.md) — установка `tessera` целиком.
- [mac-integrity.md](mac-integrity.md) — граница open/commercial по
  МКЦ и черта МКЦ/МРД.
- [operations.md §7](operations.md#7-мкц-mac-integrity) — активация
  МКЦ (поставляемый стек, drop-in, привилегии).
- [fly-dm-greeter.md](fly-dm-greeter.md) — host_id на экране входа.
- [troubleshooting.md §4](troubleshooting.md#4-pam-стек-и-lockout) —
  lockout, recovery, `Logout requested but session has no logind id`.
- [configuration.md](configuration.md) — справочник по `config.toml`.
