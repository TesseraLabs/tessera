# Tasks: linux-session-enforcement

## 1. Перенос payload в сессию

- [ ] 1.1 Расширить `SessionRolePayload` (`role/selection.rs`) полями `groups`, `limits`, `session_limits`; перенос из `RoleSlice` при фиксации payload; снапшот на момент открытия (как для `mac_mask`). `sudo_role` НЕ переносится — депрекейтится (sudo через `groups`)
- [ ] 1.2 Unit-тесты: полный перенос payload; роль без linux-полей; неизменность формата `RoleSlice`

## 2. Группы через NSS

- [ ] 2.1 **БЛОКИРУЮЩИЙ NSS-прототип** (до 2.2): инструментированный `libnss_tessera` (initgroups_dyn + лог) + регистрация роли в `auth`; проверить на Astra SE (fly-dm, `login`, `sshd` парольный) и Debian, что группы роли реально попадают в сессию и что идентификация процесса в registry надёжна (getpid/getsid). Не-kiosk юзер с паролем; ЗПС logging-only на время теста
- [ ] 2.2 Crate `nss_tessera` → `libnss_tessera.so` (C-ABI): `initgroups_dyn`, `getgrnam_r`/`getgrgid_r` для групп роли; replace набором роли; fail-safe — нет записи → `NSS_STATUS_NOTFOUND`, быстрый путь, никогда не падать
- [ ] 2.3 Registry активной роли: расширить monitord session-registry (`/run/tessera/sessions.json`) полем роль/группы; запись по ключу-процесса входа; права сокета/файла для чтения из NSS-контекста
- [ ] 2.4 Регистрация роли из `pam_tessera` в фазе `auth` (после выбора+валидации роли); очистка записи при завершении сессии (monitord removal/logout)
- [ ] 2.5 Интеграция `nsswitch.conf` (`group: files tessera systemd`) в `integrate-pam.sh`/инсталлятор; отключение/укорачивание NSS-кэша `group`; ЗПС-подпись `libnss_tessera.so` и `libpam_tessera.so` (`bsign`)

## 3. RLIMIT и systemd-лимиты

- [ ] 3.1 `RLIMIT_NOFILE`/`NPROC` в `pam_sm_setcred` (не путать с hook-путём `hooks/rlimit.rs`)
- [ ] 3.2 systemd cgroup-лимиты в `open_session` через logind DBus `SetUnitProperties` на session-scope; `MemoryMax`/`TasksMax`/`CPUWeight`/`IOWeight`; logind недоступен → fail-closed
- [ ] 3.3 `sudo_role` — депрекейт: sudo через `groups`; снять поле из переноса в сессию, обновить `role/schema.rs` (депрекейт-маркер) и пример `dist/roles/serv.toml`
- [ ] 3.4 Применение рядом с MAC-orchestrator (`entry.rs`/`session.rs`), порядок относительно МКЦ; fail-closed при неуспехе RLIMIT/systemd-лимита (типизированная диагностика + audit deny)

## 4. Спека и документация

- [ ] 4.1 Обновить дельту `role-selection` (применение полного payload — реальность); зафиксировать новую capability `linux-session-enforcement`
- [ ] 4.2 Согласовать `tessera-platform.md` §per-OS адаптеры с реализацией; снять расхождение спека↔код
- [ ] 4.3 `docs/architecture.md` — раздел enforcement приводится в соответствие; раздел `atm-deployment.md` (роли oper/serv) публикуется как рабочий после реализации
- [ ] 4.4 Регресс-прогон: МКЦ-путь, hook-путь (`child_setup`), PKCS#11/#12-аутентификация не затронуты
