# pam-integration Specification

## Purpose

Интеграция в PAM-стек Astra: снипеты режимов, порядок строк (две известные грабли — pam_parsec_mac и pam_systemd), packaging-поведение.

Файлы: `dist/pam.d/{tessera,tessera-optional,tessera-only}`, `dist/scripts/integrate-pam.sh`, `debian/postinst`.

## Requirements

### Requirement: Три режима (control-flags, не аргументы модуля)

Интеграция ДОЛЖНА (MUST) поддерживать три режима, различающиеся control-flag'ами (не аргументами модуля):

| Режим | Snippet | auth-строка | Вход без носителя |
|---|---|---|---|
| 2fa (default) | tessera | `auth required pam_tessera.so` | пароль спросят, но 2FA не пройти |
| optional | tessera-optional | `auth sufficient pam_tessera.so` | да, по паролю (миграция) |
| cert-only | tessera-only | `auth [success=done default=die] pam_tessera.so` | НЕТ — полный lockout |

Все три содержат `account required pam_tessera.so`. cert-only ДОЛЖЕН (MUST) применяться только при наличии резервного канала (второй root-shell / recovery) — потеря носителя = lockout.

#### Scenario: cert-only без резервного канала
- **WHEN** включён режим cert-only и носитель потерян без резервного root-shell / recovery
- **THEN** полный lockout — режим cert-only допустим только при наличии резервного канала

### Requirement: Грабля №1 — позиция @include vs pam_parsec_mac

`integrate-pam.sh` ДОЛЖЕН (MUST) вставлять `@include tessera*` ПОСЛЕ строки `auth ... pam_parsec_mac.so` (если есть; иначе перед первой auth-строкой) (integrate-pam.sh:196–214). Причина: `success=done` в cert-only обрывает auth-стек до pam_parsec_mac → его account/session инстансы падают «Can't obtain required data» → login deny (баг до 0.3.8, исправлен).

#### Scenario: Присутствует pam_parsec_mac
- **WHEN** в стеке есть строка `auth ... pam_parsec_mac.so`
- **THEN** `@include tessera*` вставляется ПОСЛЕ неё, чтобы `success=done` не оборвал auth-стек до pam_parsec_mac

### Requirement: Грабля №2 — two-include pattern (session после pam_systemd)

Session-фаза НЕ ДОЛЖНА (MUST NOT) входить в `@include`-снипеты (0.3.12+); отдельная строка `session required pam_tessera.so` ДОЛЖНА (MUST) вставляться ПОСЛЕ `@include common-session` (там pam_systemd создаёт XDG_SESSION_ID). Без этого USB-removal Lock/Logout не работает (нет logind id). Misorder ДОЛЖЕН (MUST) ловиться startup-check'ом `pam_stack_session_misorder` (ERROR → демон не стартует). Двойной вызов open_session идемпотентен.

Эталонный порядок `/etc/pam.d/login`:
```
auth required pam_parsec_mac.so      ← первой
@include tessera-only               ← наш auth+account
...
@include common-session              ← pam_systemd
session required pam_tessera.so     ← наш поздний session
session required pam_parsec_cap.so / pam_parsec_aud.so / pam_parsec_mac.so
```

#### Scenario: Session-строка раньше common-session
- **WHEN** `session required pam_tessera.so` стоит до `@include common-session`
- **THEN** startup-check `pam_stack_session_misorder` даёт ERROR → демон не стартует

### Requirement: integrate-pam.sh контракт

`integrate-pam.sh` ДОЛЖЕН (MUST) быть идемпотентным (повторные строки не дублируются), делать один backup на вызов; `--unintegrate` удаляет ОБА артефакта (@include + session-строку); `--strict`/`--optional` — deprecated алиасы `--mode=`.

#### Scenario: Повторный запуск
- **WHEN** `integrate-pam.sh` вызывается повторно на уже интегрированном стеке
- **THEN** строки не дублируются (идемпотентность), делается один backup на вызов

### Requirement: postinst — НЕ трогает PAM-стек

postinst ДОЛЖЕН (MUST): создать system-user `tessera`, выставить права config-dir (0750 root:tessera), создать state/cache dir, daemon-reload; на Astra strict — МКЦ-метки (см. [mac-integrity](../mac-integrity/spec.md)). postinst НЕ ДОЛЖЕН (MUST NOT) интегрировать PAM, включать unit и править config.toml — только печатать next-steps (сознательное lockout-safety решение; debconf-вариант пробовался в 0.3.16 и удалён в 0.3.18).

#### Scenario: Установка пакета
- **WHEN** выполняется postinst при установке .deb
- **THEN** создаётся user/dirs/права и daemon-reload, но PAM не интегрируется и unit не включается — печатаются только next-steps

### Requirement: fly-dm и screen-locker

fly-dm ДОЛЖЕН (MUST) интегрироваться отдельно (вход в сессию, GUI PIN-prompt, root на auth-этапе). Screen-locker (fly-dm-screensaver) — ОТДЕЛЬНЫЙ PAM-стек, разблокировка по токену требует отдельной интеграции.

#### Scenario: Интеграция screen-locker
- **WHEN** требуется разблокировка fly-dm-screensaver по токену
- **THEN** нужна отдельная интеграция — это отдельный PAM-стек от fly-dm

### Requirement: SysV

Пакет ДОЛЖЕН (MUST) ставить оба init-варианта; на SysV USB-removal Lock/Logout НЕ работает (нет XDG_SESSION_ID) — fallback `shutdown`/`hook`.

#### Scenario: Хост на SysV
- **WHEN** хост использует SysV init (нет XDG_SESSION_ID)
- **THEN** USB-removal Lock/Logout недоступен → применяется fallback `shutdown`/`hook`

### Requirement: Эксплуатационные правила правки pam.d (runbook)

Перед правкой `/etc/pam.d/*` оператор ДОЛЖЕН (MUST): держать второй SSH-сеанс (sshd-стек отдельный, выживает), backup каждого файла, переносить файлы scp+install (не copy-paste — ломает переносы). Recovery — rescue.target. Обновление .so применяется на следующем логине (активные сессии держат старую версию).

#### Scenario: Правка pam.d
- **WHEN** оператор редактирует `/etc/pam.d/*`
- **THEN** держится второй SSH-сеанс, делается backup каждого файла, файлы переносятся scp+install; recovery через rescue.target
