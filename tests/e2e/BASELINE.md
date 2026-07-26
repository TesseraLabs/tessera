# Baseline e2e

Зафиксированное состояние кейсов. Обновляется только явной командой `--update-baseline`.
Статусы `ERROR` и провалы teardown здесь не фиксируются.

| id | статус | дата | версия | профиль | комментарий |
|---|---|---|---|---|---|
| AUTH-001 | PASS | 2026-07-26 | 0.4.0-1 | ubuntu-container |  |
| AUTH-002 | FAIL | 2026-07-26 | 0.4.0-1 | ubuntu-container | Известный дефект: исчерпание попыток PIN отдаётся как 8 PAM_CRED_INSUFFICIENT вместо 11 PAM_MAXTRIES. Ошибка сквозная — flow.rs:267, тест flow.rs:2312 и спека cert-authentication-flow одинаково считают, что PAM_MAXTRIES=8. Кейс ожидает обещанное поведение и будет красным, пока дефект не устранён |
| AUTH-003 | PASS | 2026-07-26 | 0.4.0-1 | ubuntu-container |  |
| INST-001 | PASS | 2026-07-26 | 0.4.0-1 | ubuntu-container |  |
| INST-002 | PASS | 2026-07-26 | 0.4.0-1 | ubuntu-container |  |
| INST-003 | PASS | 2026-07-26 | 0.4.0-1 | ubuntu-container |  |
| INST-004 | PASS | 2026-07-26 | 0.4.0-1 | ubuntu-container |  |
| INST-005 | PASS | 2026-07-26 | 0.4.0-1 | ubuntu-container |  |
