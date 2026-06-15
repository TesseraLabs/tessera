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

### 1. Фаза применения — `setcred` + `open_session`

Группы и `RLIMIT` применяются в `pam_sm_setcred(ESTABLISH_CRED)` (`entry.rs:510`)
— штатное место для credentials, набор попадает в пользовательский процесс до
`setuid`. systemd cgroup-лимиты — в `open_session` (нужен `XDG_SESSION_ID`, как
у monitord). Порядок относительно МКЦ-orchestrator фиксируется в реализации.
Совпадает с семантикой PAM и порядком login-стека.

### 2. Supplementary-группы — replace набором роли

`setgroups` устанавливает **ровно** группы из роли, заменяя набор. Общая
техническая учётка сама по себе бесправна — весь доступ только от роли (чистый
least-privilege, суть продукта). Базовые группы (tty и пр.), если нужны,
добавляются в роль явно. Своя реализация (не `pam_group`) — защита от
nosuid/DBus-пропусков. Наследование пользовательской сессией подтвердить на
Astra SE и Debian при реализации.

### 3. systemd cgroup-лимиты — logind DBus `SetUnitProperties`

После создания session-scope (его создаёт `pam_systemd`) Tessera в `open_session`
получает scope и выставляет `MemoryMax`/`TasksMax`/`CPUWeight`/`IOWeight` через
DBus к systemd (runtime property). cgroup-уровень, не обходится из сессии. На
банкоматах Astra logind присутствует. logind/DBus недоступен → fail-closed
(роль с `[session]`-лимитами не входит без возможности их применить). `RLIMIT`
(nofile/nproc) покрывается `setrlimit` в `setcred` отдельно — не зависит от logind.

### 4. sudo-права — через группы; `sudo_role` депрекейт

sudo-доступ выражается членством в группе, на которую заранее настроено правило
в `sudoers.d` (напр. `%service ALL=...`). Роль даёт членство через `groups`.
Поле `sudo_role` дублирует `groups` (в `serv.toml`: `groups=["service","wheel"]`
+ `sudo_role="service"`) и **депрекейтится** — sudo выражается только группами.
Tessera **не пишет** в `/etc/sudoers.d` на лету — правила раскатываются заранее,
роль лишь активирует членство.

## Граница open/commercial

- Linux-enforcement (группы/sudo/RLIMIT/systemd-лимиты) — **открытое ядро**,
  реализация целиком в open-сборке.
- МКЦ (`ParsecBackend`) и SELinux-адаптер — коммерческие, не затрагиваются.
- Fail-closed остаётся единым: примитив не применился → отказ входа с
  диагностикой, как `mac_mask`/`selinux` без backend.

## Тестирование

- Unit: перенос полного payload в `SessionRolePayload`; выбор примитивов;
  отказ при неудаче применения.
- Интеграция: реальное членство в группах и RLIMIT в открытой сессии
  (root-окружение / контейнер); systemd-лимиты на scope (если выбран logind).
- Регресс: МКЦ-путь и hook-путь (`child_setup`) не затронуты.
