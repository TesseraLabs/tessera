# Tasks: rescue-channel-hardening

## 1. Проверки rescue_* в startup-check

- [ ] 1.1 Модуль `tessera_cli/src/startup_check/rescue.rs`: каркас
      (параметризация корня ФС как в `pam_stack.rs`), подключение
      в пайплайн `run_startup_checks`
- [ ] 1.2 `rescue_root_locked`: парсинг поля root в `/etc/shadow`
      (locked/hash/empty/unreadable) + юнит-тесты на все четыре исхода
- [ ] 1.3 `rescue_sulogin_force`: скан override'ов
      `rescue.service`/`emergency.service` и env-файлов + тесты
      (переменная в drop-in, в /etc/default, отсутствует)
- [ ] 1.4 `rescue_boot_password`: поиск `superusers`/`password_pbkdf2`
      по фиксированным путям GRUB + тесты (есть пароль, нет пароля,
      конфигурация GRUB не найдена)
- [ ] 1.5 `rescue_grub_user_cfg_perms`: проверка mode/владельца
      `user.cfg` + тесты (0600, 0644, отсутствует)
- [ ] 1.6 Сквозной тест семантики «unable ≠ pass»: EACCES на shadow →
      WARN с причиной, не INFO; проверка связной формулировки INFO
      `rescue_root_locked` (ссылка на состояние пароля загрузчика)

## 2. rescue-boot-audit в monitord

- [ ] 2.1 Модуль детекта: перечисление загрузок (`journalctl --list-boots
      -o json` child-процесс, таймаут), поиск достижения
      `rescue.target`/`emergency.target` по новым загрузкам
- [ ] 2.2 Курсор `/var/lib/tessera/rescue_audit_cursor`: чтение,
      атомарная запись (tmp+rename), обработка отсутствия/повреждения
- [ ] 2.3 Событие `rescue_boot_detected` в target `rescue.audit`
      (поля boot_id/unit/first_seen_ts); WARN `rescue_audit_blind`
      при volatile journal; WARN при сбое journalctl без блокировки старта
- [ ] 2.4 Вызов детекта на старте демона после startup-checks
      (вне auth-пути); юнит-тесты на парсинг вывода journalctl
      и логику курсора (фикстуры JSON)

## 3. Документация (RU канон)

- [ ] 3.1 `docs/ru/operations.md`: раздел «Rescue-канал и восстановление» —
      рекомендуемая конфигурация (root заблокирован, без SULOGIN_FORCE,
      пароль GRUB, user.cfg 0600, persistent journal), три лестницы
      восстановления, требование зафиксировать внеполосные секреты
      до перевода в cert-only, поведение в emergency + `nofail`
- [ ] 3.2 `docs/ru/troubleshooting.md`: заменить рецепт
      `systemd.unit=rescue.target init=/bin/bash` на рабочий при
      заблокированном root путь `init=/bin/bash` (+ remount rw);
      добавить симптом «устройство висит в emergency»
- [ ] 3.3 `docs/ru/install.md`: ссылка на новый раздел operations
      из §11 (recovery) и чек-лист перевода в cert-only
- [ ] 3.4 Прогон лестницы 2 на Astra VM (консоль): подтвердить отказ
      `sulogin` при `root:*`, снять точные экранные формулировки
      для troubleshooting
- [ ] 3.5 `docs/ru/threat-model.md`: обновить T8 (mitigations: проверки,
      аудит, требование процедуры), зафиксировать инвариант
      «канал восстановления НЕ ДОЛЖЕН (MUST NOT) зависеть от Tessera»,
      формулировку «требование аутентификации в однопользовательском
      режиме выполняется отказом», ограничение tamper-evidence
      (очистка журнала сама оставляет след)

## 4. EN-синк и spec-гигиена

- [ ] 4.1 EN-перевод правок: `docs/en/operations.md`,
      `docs/en/troubleshooting.md`, `docs/en/install.md`
      (threat-model — RU-only по конвенции)
- [ ] 4.2 `openspec/specs/logging-audit/spec.md`: дополнить перечень
      стабильных targets (`rescue.audit`) при sync спек
- [ ] 4.3 `tessera check --help` / комментарии check.rs: упомянуть
      группу rescue_* (advisory)

## 5. Верификация

- [ ] 5.1 Полный тест-прогон workspace + clippy как в CI
      (`--all-features`)
- [ ] 5.2 Прогон `tessera check` на Astra VM: рекомендуемая конфигурация →
      4×INFO; подложенный `SULOGIN_FORCE=1` → WARN; от непривилегированного
      пользователя → WARN «проверка невозможна»
- [ ] 5.3 Прогон rescue-аудита на VM: загрузка в rescue → следующий старт
      monitord эмитит `rescue_boot_detected`; volatile journal →
      `rescue_audit_blind`
- [ ] 5.4 master-code-reviewer + codex-ревью перед PR
