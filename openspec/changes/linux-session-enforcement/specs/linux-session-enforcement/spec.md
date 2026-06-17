# linux-session-enforcement Delta Specification

## ADDED Requirements

### Requirement: Группы роли через NSS-источник

Группы активной роли ДОЛЖНЫ (MUST) применяться к сессии через NSS-модуль
`libnss_tessera` (источник строки `group:` в `nsswitch.conf`), а НЕ через
`setgroups` в PAM-фазах. Модуль ДОЛЖЕН (MUST) на штатный `initgroups(user)` /
`getgrouplist()` приложения входа (login/fly-dm/sshd) возвращать **ровно**
группы активной роли (replace поверх групп технической учётки — least
privilege). Применение групп самим приложением через его `initgroups`
исключает перетирание набора, выставленного PAM.

#### Scenario: Вход инженера под ролью
- **WHEN** инженер вошёл под ролью, чей payload содержит `groups`
- **THEN** `initgroups` приложения через `libnss_tessera` возвращает группы роли, и они присутствуют в процессе сессии

#### Scenario: Replace, а не append
- **WHEN** техническая учётка статически состоит в группах, не входящих в роль
- **THEN** в сессии присутствуют только группы роли (плюс первичная gid), статические группы учётки не добавляются

### Requirement: Доставка активной роли в NSS через registry-по-процессу

Активная роль входа ДОЛЖНА (MUST) доставляться в `libnss_tessera` через
registry, который ведёт `monitord`: `pam_tessera` в фазе `auth` (после выбора и
валидации роли) регистрирует запись `{ ключ-процесса входа → роль, группы }`,
а NSS-модуль в `initgroups_dyn` находит запись по идентификатору текущего
процесса входа. Регистрация в `auth` ДОЛЖНА (MUST) предшествовать вызову
`initgroups` приложением. Registry — расширение существующего session-registry
(`/run/tessera/sessions.json`).

#### Scenario: Регистрация до initgroups
- **WHEN** `pam_tessera` завершил `auth` с выбранной ролью
- **THEN** запись «процесс входа → роль/группы» доступна в registry до того, как приложение вызовет `initgroups`

#### Scenario: NSS читает активную роль
- **WHEN** `libnss_tessera.initgroups_dyn` вызван в процессе входа с активной записью
- **THEN** модуль возвращает группы роли из записи registry

### Requirement: Fail-safe NSS-модуля

`libnss_tessera` ДОЛЖЕН (MUST) при отсутствии записи для текущего процесса или
пользователя возвращать `NSS_STATUS_NOTFOUND` и передавать разрешение
следующему источнику (`files`/`systemd`). Модуль НЕ ДОЛЖЕН (MUST NOT) падать,
блокировать или возвращать ошибку, ломающую разрешение групп для процессов вне
Tessera-входа. Группы ДОЛЖНЫ (MUST) отдаваться только для зарегистрированной
активной сессии.

#### Scenario: Посторонний процесс
- **WHEN** `getgrouplist` вызван процессом без записи в registry (обычный системный процесс)
- **THEN** `libnss_tessera` возвращает `NSS_STATUS_NOTFOUND`, разрешение групп идёт через `files`/`systemd` без сбоя

#### Scenario: Недоступен registry
- **WHEN** registry/сокет недоступен в момент NSS-запроса
- **THEN** модуль возвращает `NSS_STATUS_NOTFOUND` (fail-safe), не блокирует и не падает

### Requirement: Жизненный цикл записи активной роли

Запись активной роли в registry ДОЛЖНА (MUST) удаляться при завершении сессии
(logout, извлечение носителя, обрыв) — через тот же механизм `monitord`, что
отслеживает завершение. NSS-кэш `group` glibc (`nscd`/встроенный) ДОЛЖЕН (MUST)
быть отключён или иметь короткий TTL, чтобы группы прежней роли не залипали
между входами.

#### Scenario: Завершение сессии
- **WHEN** сессия инженера завершена (logout / удалён носитель)
- **THEN** запись активной роли удалена из registry; последующий NSS-запрос для этого процесса → `NOTFOUND`

### Requirement: RLIMIT через setcred

`RLIMIT_NOFILE` и `RLIMIT_NPROC` из payload роли ДОЛЖНЫ (MUST) применяться
через `setrlimit` в `pam_sm_setcred`. Этот путь отделён от групп (NSS) и от
hook-пути (`hooks/rlimit.rs`, дочерние процессы). Неуспех применения `RLIMIT`
ДОЛЖЕН (MUST) приводить к отказу входа с типизированной диагностикой и audit
deny — не молчаливое сужение прав.

#### Scenario: Применение лимитов роли
- **WHEN** роль задаёт `limits.nofile`/`nproc` и вход проходит
- **THEN** `setrlimit` в `setcred` выставляет лимиты для сессии

#### Scenario: Неуспех setrlimit
- **WHEN** `setrlimit` завершается ошибкой
- **THEN** отказ входа с диагностикой и audit deny

### Requirement: systemd cgroup-лимиты через logind

systemd cgroup-лимиты сессии ДОЛЖНЫ (MUST) применяться в `open_session` через logind DBus `SetUnitProperties` на session-scope: `MemoryMax`/`TasksMax`/`CPUWeight`/`IOWeight`. Если logind/DBus недоступен, а роль задаёт `[session]`-лимиты,
вход ДОЛЖЕН (MUST) быть отклонён (fail-closed) — без молчаливого пропуска
лимитов.

#### Scenario: Применение cgroup-лимитов
- **WHEN** роль задаёт `[session]`-лимиты и logind доступен
- **THEN** лимиты выставлены на session-scope через `SetUnitProperties`

#### Scenario: logind недоступен
- **WHEN** роль задаёт `[session]`-лимиты, а logind/DBus недоступен
- **THEN** отказ входа (fail-closed) с диагностикой

### Requirement: ЗПС-подпись модулей

`libnss_tessera.so` и `libpam_tessera.so` ДОЛЖНЫ (MUST) быть подписаны для
работы в режиме ЗПС/DIGSIG `enforce` (`bsign` сборочным CI) — неподписанный
`.so` ядро отвергает на загрузке. Открытая сборка Linux-enforcement (NSS,
RLIMIT, logind), включая crate `nss_tessera`, ДОЛЖНА (MUST) оставаться в
открытом ядре; МКЦ (`ParsecBackend`) и SELinux-адаптер — коммерческие.

#### Scenario: Загрузка под ЗПС enforce
- **WHEN** `libnss_tessera.so`/`libpam_tessera.so` загружаются на Astra SE с ЗПС в `enforce`
- **THEN** подписанные модули загружаются; неподписанный отвергается ядром
