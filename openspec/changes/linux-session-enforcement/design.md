# Design: linux-session-enforcement

## Контекст

МКЦ уже применяется через паттерн `mac/`: trait `MacBackend`
(probe/apply_session) + `StubBackend` (открытая) / `ParsecBackend` (коммерческая),
оркестратор в `mac/orchestrator.rs`, вплетение в `session.rs`. Linux-enforcement
повторяет паттерн, но реализация backend целиком **открытая** (по `role-format`
split: linux-payload — «Открытая»).

## Решение: backend применения по образцу МКЦ

Ввести `LinuxEnforcementBackend` (открытое ядро) с операциями:
применить supplementary-группы, RLIMIT, systemd-лимиты. Оркестратор берёт
снапшот payload роли из сессии и вызывает применение в нужной PAM-фазе.

`SessionRolePayload` расширяется до полного Linux-payload:

```
role, role_version, ttl,
mac_mask: Option<u64>,        // как сейчас
groups:   Vec<String>,        // НОВОЕ — переносить из RoleSlice
sudo_role: Option<String>,    // НОВОЕ
limits:   LinuxLimits,        // НОВОЕ (nofile/nproc)
session_limits: SessionLimits // НОВОЕ (memory_max/tasks_max/cpu/io)
```

(Поля уже определены и валидируются в `role/schema.rs`; задача — донести их
до сессии, не менять формат роли.)

## Принятые решения (ревью 2026-06-15)

### 1. Группы — через NSS (`libnss_tessera`), не `setgroups`-в-`setcred`

**Почему не `setcred`.** Прототип на Astra SE 1.8.4 (2026-06-17) показал, что
зонд `setgroups`-через-PAM ненадёжен как индикатор: вход по ssh-pubkey и
passwordless sudo минуют PAM auth, тестовые юзеры под Astra-kiosk (`pam_kiosk2`)
не дают exec, а неподписанный модуль отвергается ЗПС. Глубже — login/fly-dm при
`setuid` сами зовут `initgroups()` и могут перетереть набор, выставленный нашим
`setcred`. Зависимость от порядка PAM-фаз и поведения приложения неприемлема.

**Решение — стать источником групп для самого приложения.** `libnss_tessera` —
NSS-плагин (источник строки `group:` в `nsswitch.conf`:
`group: files tessera systemd`). Когда login/fly-dm/sshd при входе зовут штатный
`initgroups(user)` → `getgrouplist()`, glibc спрашивает наш модуль, и он отдаёт
**ровно группы активной роли** (replace поверх бесправной техучётки — least
privilege). Перетирать нечего: приложение само применяет то, что мы вернули.
Работает единообразно для login/fly-dm/sshd/su, не зависит от PAM-фаз.

**Доставка «активной роли» в NSS — registry-по-процессу.** NSS-запрос
stateless («группы user X»), роль динамическая. Поэтому:
1. `pam_tessera` в фазе `auth` (роль выбрана и валидирована) регистрирует в
   monitord: `{ ключ-процесса входа → role, группы роли }`. Расширяем
   существующий session-registry (`/run/tessera/sessions.json` + monitord).
2. login дальше зовёт `initgroups(user)` → `libnss_tessera.initgroups_dyn`.
3. Модуль идентифицирует текущий процесс входа (см. под-вопрос ниже), находит
   запись registry, возвращает группы роли.

Порядок сходится: `auth` (регистрация) выполняется до того, как приложение
делает `initgroups`.

**Fail-safe (критично).** NSS-модуль грузится во ВСЕ процессы, зовущие
`getgrouplist`. Нет записи для процесса/пользователя → `NSS_STATUS_NOTFOUND`,
тихо к следующему источнику (`files`/`systemd`). Никогда не падать, не
блокировать — иначе ломается разрешение групп всей системы. Быстрый путь для
«нет записи». Группы отдаются только для зарегистрированной активной сессии.

**Жизненный цикл записи.** Создаётся в `auth`, удаляется при завершении сессии
(monitord уже отслеживает removal/logout — туда же очистка). NSS-кэш glibc
(`nscd`/builtin) для `group` должен быть отключён/короткий, иначе старая роль
залипнет.

**ОТКРЫТЫЙ ПОД-ВОПРОС (прототип) — идентификация процесса в registry.** Как
`libnss_tessera` в `initgroups_dyn` сопоставляет свой вызов с записью входа:
по `getpid`/`getppid`/`getsid`? Надёжность зависит от того, в каком процессе и
когда приложение зовёт `initgroups` относительно процесса, где отработал
`pam_tessera auth`. Проверить на реальных login/fly-dm/sshd Astra SE
инструментированным NSS-прототипом — **блокирующий шаг** до основной реализации.

### 2. `RLIMIT` — в `pam_sm_setcred`

`RLIMIT_NOFILE`/`NPROC` применяются через `setrlimit` в `pam_sm_setcred`
(`entry.rs:510`, сейчас роль не применяет). В отличие от групп, `RLIMIT` не
страдает от `initgroups` приложения — лимиты процесса наследуются и не
переустанавливаются login'ом. NSS тут не нужен.

### 3. systemd cgroup-лимиты — logind DBus `SetUnitProperties`

После создания session-scope (его создаёт `pam_systemd`) Tessera в `open_session`
получает scope и выставляет `MemoryMax`/`TasksMax`/`CPUWeight`/`IOWeight` через
DBus к systemd (runtime property). cgroup-уровень, не обходится из сессии. На
терминалах Astra logind присутствует. logind/DBus недоступен → fail-closed
(роль с `[session]`-лимитами не входит без возможности их применить). `RLIMIT`
(nofile/nproc) покрывается `setrlimit` в `setcred` отдельно — не зависит от logind.

### 4. sudo-права — через группы; `sudo_role` депрекейт

sudo-доступ выражается членством в группе, на которую заранее настроено правило
в `sudoers.d` (напр. `%service ALL=...`). Роль даёт членство через `groups`.
Поле `sudo_role` дублирует `groups` (в `serv.toml`: `groups=["service","wheel"]`
+ `sudo_role="service"`) и **депрекейтится** — sudo выражается только группами.
Tessera **не пишет** в `/etc/sudoers.d` на лету — правила раскатываются заранее,
роль лишь активирует членство.

## ЗПС-подпись модулей

`libnss_tessera.so` и `libpam_tessera.so` грузятся в системные процессы — в
режиме ЗПС/DIGSIG `enforce` неподписанный `.so` ядро отвергнет на `mmap`.
Оба модуля подписываются `bsign` сборочным CI (как уже требует threat-model
3.6.1). Прототип на VM при необходимости использует ЗПС `logging-only`.

## Граница open/commercial

- Linux-enforcement (NSS-группы / RLIMIT / systemd-лимиты) — **открытое ядро**,
  реализация целиком в open-сборке, включая crate `nss_tessera`.
- МКЦ (`ParsecBackend`) и SELinux-адаптер — коммерческие, не затрагиваются.
- Fail-safe NSS (NOTFOUND) и fail-closed enforcement (отказ при неудаче
  RLIMIT/systemd-лимита) — единый принцип, как `mac_mask`/`selinux` без backend.

## Тестирование

- Unit: перенос payload в `SessionRolePayload`; registry (запись/чтение/очистка);
  NSS fail-safe (нет записи → NOTFOUND); отказ при неудаче RLIMIT/systemd-лимита.
- **NSS-прототип (блокирующий)**: реальное членство в группах роли в сессии
  login/fly-dm/sshd на Astra SE — проверка идентификации процесса в registry.
- Интеграция: RLIMIT в сессии; systemd-лимиты на scope через logind.
- Регресс: МКЦ-путь и hook-путь (`child_setup`) не затронуты; разрешение групп
  обычных юзеров (не Tessera-вход) не сломано NSS-модулем.
