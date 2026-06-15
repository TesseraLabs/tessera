# Tasks: linux-session-enforcement

## 1. Перенос payload в сессию

- [ ] 1.1 Расширить `SessionRolePayload` (`role/selection.rs`) полями `groups`, `limits`, `session_limits`; перенос из `RoleSlice` при фиксации payload; снапшот на момент открытия (как для `mac_mask`). `sudo_role` НЕ переносится — депрекейтится (sudo через `groups`)
- [ ] 1.2 Unit-тесты: полный перенос payload; роль без linux-полей; неизменность формата `RoleSlice`

## 2. Backend применения (открытое ядро)

- [ ] 2.1 Ввести `LinuxEnforcementBackend` по образцу `mac/` (trait + open-реализация): операции apply-groups / apply-rlimit / apply-session-limits; probe доступности (logind для systemd-лимитов)
- [ ] 2.2 Supplementary-группы — replace набором роли (`setgroups` = ровно группы роли), своя реализация (не `pam_group`); подтвердить наследование сессией на Astra SE и Debian
- [ ] 2.3 `RLIMIT_NOFILE`/`NPROC` к пользовательской сессии в `setcred` (не путать с hook-путём `hooks/rlimit.rs`)
- [ ] 2.4 systemd cgroup-лимиты в `open_session` через logind DBus `SetUnitProperties` на session-scope; `MemoryMax`/`TasksMax`/`CPUWeight`/`IOWeight`; logind недоступен → fail-closed
- [ ] 2.5 `sudo_role` — депрекейт: sudo через `groups`; снять поле из переноса в сессию, обновить `role/schema.rs` (депрекейт-маркер) и пример `dist/roles/serv.toml`

## 3. Вплетение в PAM-фазы

- [ ] 3.1 Применение по фазам: группы/RLIMIT — `pam_sm_setcred`; systemd cgroup-лимиты — `open_session`
- [ ] 3.2 Применение в `entry.rs`/`session.rs` рядом с MAC-orchestrator; порядок относительно МКЦ
- [ ] 3.3 Fail-closed: неуспех применения любого примитива → отказ входа с типизированной диагностикой + audit deny; без молчаливого сужения прав

## 4. Спека и документация

- [ ] 4.1 Обновить дельту `role-selection` (применение полного payload — реальность); зафиксировать новую capability `linux-session-enforcement`
- [ ] 4.2 Согласовать `tessera-platform.md` §per-OS адаптеры с реализацией; снять расхождение спека↔код
- [ ] 4.3 `docs/architecture.md` — раздел enforcement приводится в соответствие; раздел `atm-deployment.md` (роли oper/serv) публикуется как рабочий после реализации
- [ ] 4.4 Регресс-прогон: МКЦ-путь, hook-путь (`child_setup`), PKCS#11/#12-аутентификация не затронуты
