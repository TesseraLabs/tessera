# ipc-protocol Delta Specification

## ADDED Requirements

### Requirement: Роль в сообщениях сессии

Сообщения открытия сессии ДОЛЖНЫ (MUST) нести поля `role` (role_id) и `role_version` (u32),
опциональные на проводе (отсутствие = вход без enforcement ролей, `roles.enforce=false`).
Добавление полей ДОЛЖНО (MUST) быть обратно совместимым в рамках PROTOCOL_VERSION = 2
(новые опциональные поля NDJSON; строгое равенство версии сохраняется). Если совместимость
нарушится иными изменениями этого change — bump до 3 по существующему правилу строгого равенства.

#### Scenario: Session open с ролью
- **WHEN** pam_tessera открывает сессию с ролью `serv` v7
- **THEN** в IPC-сообщении присутствуют `role="serv"`, `role_version=7`; демон пишет их в свои события

#### Scenario: Session open без роли (enforce=false)
- **WHEN** вход выполнен при `roles.enforce = "false"`
- **THEN** поля `role`/`role_version` отсутствуют, сообщение валидно для PROTOCOL_VERSION = 2
