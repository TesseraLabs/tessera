# cli-diagnostics — delta (rescue-channel-hardening)

## ADDED Requirements

### Requirement: Проверки закрытости rescue-канала

Пайплайн startup-check (`tessera check` и старт демона) ДОЛЖЕН (MUST)
выполнять группу advisory-проверок `rescue_*` состояния rescue-канала хоста.
Ни одна проверка группы НЕ ДОЛЖНА (MUST NOT) выдавать severity ERROR:
состояние rescue-канала — политика хоста, а не инвариант работоспособности
демона; отказ старта из-за неё сам создавал бы lockout (T8).

Состав группы:

- `rescue_root_locked` — поле пароля root в `/etc/shadow`:
  заблокировано (`!`, `!!`, `*`) → INFO; валидный хеш → WARN
  (rescue-диалог открыт паролем root); пустое поле → WARN
  (консольный root-шелл без аутентификации);
- `rescue_sulogin_force` — `SYSTEMD_SULOGIN_FORCE` в override'ах
  `rescue.service`/`emergency.service` (`/etc/systemd/system/*.d/`)
  и системных env-файлах (`/etc/default/`, `/etc/sysconfig/`):
  не найдена → INFO; `=1` → WARN (блокировка root в rescue обесценена);
- `rescue_boot_password` — `superusers`/`password_pbkdf2` в конфигурации
  GRUB (`/boot/grub/grub.cfg`, `/etc/grub.d/`, `/boot/grub/user.cfg`):
  найдены → INFO; не найдены → WARN (правка строки ядра,
  включая `init=/bin/bash`, не защищена);
- `rescue_grub_user_cfg_perms` — права `/boot/grub/user.cfg`:
  отсутствует или недоступен не-root → INFO; читается
  непривилегированными пользователями → WARN (PBKDF2-хеш пароля
  загрузчика доступен для офлайн-перебора).

Проверки ДОЛЖНЫ (MUST) только читать файлы (без запуска внешних команд)
и ДОЛЖНЫ (MUST) параметризоваться корнем ФС для юнит-тестов.

#### Scenario: Рекомендуемая конфигурация
- **WHEN** поле root в `/etc/shadow` — `*`, `SYSTEMD_SULOGIN_FORCE`
  не задана, пароль GRUB установлен, `user.cfg` имеет режим 0600
- **THEN** все четыре проверки выдают INFO и не влияют на exit-код
  `tessera check`

#### Scenario: Канал молча открыт форс-переменной
- **WHEN** root заблокирован, но в override `rescue.service` задано
  `Environment=SYSTEMD_SULOGIN_FORCE=1`
- **THEN** `rescue_sulogin_force` выдаёт WARN с указанием файла-источника,
  а exit-код `tessera check` остаётся 0

#### Scenario: Пустое поле пароля root
- **WHEN** поле пароля root в `/etc/shadow` пустое
- **THEN** `rescue_root_locked` выдаёт WARN о консольном root-шелле
  без аутентификации (не ERROR)

### Requirement: Невозможность проверки не считается её прохождением

Проверка группы `rescue_*`, не сумевшая прочитать источник, ДОЛЖНА (MUST)
выдать WARN с причиной («проверка невозможна: …») и НЕ ДОЛЖНА (MUST NOT)
молча выдавать INFO. Типовые случаи: EACCES на `/etc/shadow` под
непривилегированным пользователем, отсутствие ожидаемой конфигурации GRUB.

#### Scenario: tessera check без прав root
- **WHEN** `tessera check` запущен под пользователем без права чтения
  `/etc/shadow`
- **THEN** `rescue_root_locked` выдаёт WARN «проверка невозможна»
  с указанием причины и рекомендацией запустить под root

#### Scenario: Нестандартная схема загрузчика
- **WHEN** ни один из ожидаемых путей конфигурации GRUB не существует
- **THEN** `rescue_boot_password` выдаёт WARN «конфигурация GRUB
  не найдена» (не утверждая ни наличие, ни отсутствие пароля)
