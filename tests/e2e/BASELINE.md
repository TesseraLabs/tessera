# Baseline e2e

Зафиксированное состояние кейсов. Обновляется только явной командой `--update-baseline`.
Статусы `ERROR` и провалы teardown здесь не фиксируются.

| id | статус | дата | версия | профиль | комментарий |
|---|---|---|---|---|---|
| AUTH-001 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container |  |
| AUTH-002 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container | Был красным на дефекте PAM_MAXTRIES (модуль отдавал 8 PAM_CRED_INSUFFICIENT вместо 11); закрыт изменением pam-maxtries-fix, проверено на артефакте сборки 83613888 |
| AUTH-003 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container |  |
| INST-001 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container |  |
| INST-002 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container |  |
| INST-003 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container |  |
| INST-004 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container |  |
| INST-005 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container |  |
| ISS-001 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container |  |
| ISS-002 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container |  |
| ISS-003 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container |  |
| ISS-004 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container |  |
| ISS-005 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container | Сквозной кейс, вскрывший четыре дефекта совместимости выпуска и проверки: keyUsage/EKU листа, расходившиеся дефолты profile_version, непригодные рамки делегирования и требование роли. Все закрыты; зелёный с role-account-login |
| REV-001 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container |  |
| REV-002 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container |  |
| REV-003 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container |  |
| REV-004 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container |  |
| REV-005 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container |  |
| REV-006 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container |  |
| ROLE-001 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container | Был красным до перепроводки role-selection: модуль спрашивал роль prompt'ом вместо вывода из имени учётной записи входа. Закрыт изменением role-account-login |
| ROLE-002 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container | Был красным до перепроводки role-selection: модуль спрашивал роль prompt'ом вместо вывода из имени учётной записи входа. Закрыт изменением role-account-login |
| ROLE-003 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container | Был красным до перепроводки role-selection: модуль спрашивал роль prompt'ом вместо вывода из имени учётной записи входа. Закрыт изменением role-account-login |
| ROLE-004 | PASS | 2026-07-27 | 0.4.0-1 | ubuntu-container | Был красным до перепроводки role-selection: модуль спрашивал роль prompt'ом вместо вывода из имени учётной записи входа. Закрыт изменением role-account-login |
