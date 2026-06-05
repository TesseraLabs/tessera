# configuration Delta Specification

## ADDED Requirements

### Requirement: Секция [roles]

Конфиг ДОЛЖЕН (MUST) поддерживать секцию `[roles]` (как и весь конфиг — `deny_unknown_fields`):

| Поле | Тип | Дефолт | Семантика |
|---|---|---|---|
| `enforce` | `"false" \| "warn" \| "require"` | `"false"` | этап миграции: `false` — роли не проверяются (поведение v0.3.19); `warn` — проверка с логом, без отказов; `require` — полный enforcement |
| `dir` | путь | `/var/lib/tessera/roles` | каталог базы ролей |
| `default_session_ttl` | duration | `12h` | TTL сессии, когда ни удостоверение, ни роль его не задают |

`enforce = "require"` при пустой/невалидной базе ролей ДОЛЖЕН (MUST) приводить к отказу
входов, требующих роль (fail-closed), с диагностикой «роли не настроены».

#### Scenario: enforce=false — поведение прежней версии
- **WHEN** `roles.enforce = "false"` (или секция отсутствует)
- **THEN** суффикс/prompt не запрашиваются, покрытие не проверяется, вход работает как в v0.3.19

#### Scenario: enforce=require при пустой базе
- **WHEN** `roles.enforce = "require"` и каталог ролей пуст
- **THEN** вход отклоняется с диагностикой «роли не настроены», audit `role_deny reason=not_found`
