# Интеграция `tessera` в `/etc/pam.d/*`

Руководство по правке PAM-стеков на Astra/Debian/Ubuntu. Документ
выделен из install.md §8 + §11 — здесь всё про `integrate-pam.sh`,
two-include pattern, режимы, специфику fly-dm/sudo/login/sshd и
SysV-init.

> **ВАЖНО.** Перед правкой PAM-стека **открыть второй рут-shell**
> (например, `ssh root@<host>`). Если основной shell не сможет
> авторизоваться после изменений — второй терминал останется
> единственным способом отката.

## 1. Поставочный snippet и `integrate-pam.sh`

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

## 2. Two-include pattern (0.3.12+)

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

Иначе в journald появится:

```
WARN tessera.session: XDG_SESSION_ID not in PAM env during sm_open_session
WARN tessera.monitord: USB-removal action dropped: session has no logind id
```

При извлечении флешки logout НЕ произойдёт — см.
[troubleshooting.md §4](troubleshooting.md#4-pam-стек-и-lockout).

## 3. fly-dm

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
`required`: без успешной cert-аутентификации вход невозможен, парольного
fallback'а НЕТ (это дефолтный режим `2fa` скрипта `integrate-pam.sh`).
Мягкий вариант с fallback'ом на следующие модули (`pam_unix.so`) — это
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

## 4. Режимы аутентификации

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
   работает на тестовом аккаунте на этой машине.
2. **Альтернативный путь логина**, который НЕ проходит через
   `tessera` — например, отдельный sshd-stack с
   `PubkeyAuthentication=yes` + `UsePAM=no`, или sudoers-правило для
   админ-аккаунта без `@include tessera`. Иначе потеря или
   блокировка единственного токена (USBGuard, ЗПС, физическая утрата)
   выведет хост из строя — никто не сможет залогиниться, включая
   локальный root.

Откат — `integrate-pam.sh --unintegrate` из живого root-shell или
через rescue-target (см.
[troubleshooting.md §4 «Замок-аут после неудачной правки PAM»](troubleshooting.md#4-pam-стек-и-lockout)).

## 5. sudo

```bash
sudo /usr/share/tessera/integrate-pam.sh /etc/pam.d/sudo
```

## 6. login

```bash
sudo /usr/share/tessera/integrate-pam.sh /etc/pam.d/login
```

## 7. PAM-стек с учётом МКЦ

Стек зависит от того, включено ли МКЦ-ядро PARSEC. `pam_parsec_mac.so`
в стеке нужен **только когда МКЦ-ядро реально работает**. Подробности
— [mac-integrity.md §6 «PAM-стек для МКЦ-сценариев»](mac-integrity.md#6-pam-стек-для-мкц-сценариев).

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

Полные примеры стеков, валидация и matrix `runtime × cert_integrity`
— [mac-integrity.md](mac-integrity.md).

## 8. Безопасность правки

- Перед правкой убедиться, что есть второй открытый рут-shell.
- Проверять каждое изменение командой `pamtester` сразу после правки.
- В случае поломки восстановить из бекапа:
  ```bash
  sudo cp /etc/pam.d/sudo.bak.<TS> /etc/pam.d/sudo
  ```
- Полный recovery из rescue.target — см.
  [troubleshooting.md §4](troubleshooting.md#4-pam-стек-и-lockout).

## 9. Verification

```bash
pamtester sudo alice authenticate
```

Ожидание: `Authentication successful` (при вставленном USB-носителе
или токене).

```bash
sudo tessera check    # ловит pam_stack_session_misorder и др.
```

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
  `XDG_SESSION_ID` физически не создаётся. Fallback:
  `[on_usb_removed].action = "shutdown"` или `"hook"`. См.
  [troubleshooting.md §4 «Logout requested but session has no logind id», Причина 3](troubleshooting.md#4-pam-стек-и-lockout).
- На systemd-хостах править SysV-скрипт не требуется — авторитативный
  источник конфигурации службы — `tessera.service`.

## 11. См. также

- [install.md](install.md) — установка `tessera` целиком.
- [mac-integrity.md](mac-integrity.md) — МКЦ end-to-end активация и
  полная матрица PAM-стеков.
- [fly-dm-greeter.md](fly-dm-greeter.md) — wallpaper banner на fly-dm.
- [troubleshooting.md §4](troubleshooting.md#4-pam-стек-и-lockout) —
  lockout, recovery, `Logout requested but session has no logind id`.
- [configuration.md](configuration.md) — справочник по `config.toml`.
