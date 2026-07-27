# Tasks: roles-always-enforced

- [x] 1. Конфиг: удалить поле `enforce` из `[roles]` (`raw.rs`, `validated.rs`) и enum `RawRolesEnforce`/`RolesEnforce`
- [x] 2. Адресная диагностика на удалённый ключ: конфиг с `[roles].enforce` отвергается сообщением о том, что ключ удалён и проверка ролей безусловна, а не общим «unknown field»
- [x] 3. `role/selection.rs`, `role/mod.rs`: убрать `RoleEnforce` и `Resolution::Skipped`; резолв роли перестаёт иметь ветку «проверка отключена»
- [x] 4. `trust/delegation.rs`, `trust/mod.rs`: убрать `enforce_delegation_opt` — роль есть всегда, ветка `None` недостижима; вызывающие переводятся на `enforce_delegation`
- [x] 5. `pam_tessera/src/entry.rs`, `src/flow.rs`: убрать ветки отключённого enforcement
- [x] 6. Тесты: конфиг с `enforce` отвергается с ожидаемой диагностикой; удалённые ветки не оставили мёртвых утверждений
- [x] 7. `dist/config/config.toml.example`: убрать ключ
- [x] 8. `docs/ru/configuration.md`, `docs/en/configuration.md`: убрать `enforce` из таблицы `[roles]` и семантику миграционных стадий
- [x] 9. `tests/e2e/cases/30-roles.yaml`: снять кейс, закреплявший поведение `enforce = "false"`; в `BASELINE.md` отразить снятие
- [x] 10. `docs/ru/changelog.md` — раздел Breaking, с указанием миграции
- [x] 11. Прогон e2e (`--profile ubuntu-container --filter roles`) — ROLE-001…004 остались красными по прежней причине (`prompt: Роль (role):` вместо вывода роли из имени учётной записи), расхождений с baseline нет. ISS-005 потребовал правки кейса: вход теперь всегда требует роль, поэтому кейс поднимает ролевое хранилище и входит по имени ролевой учётной записи
