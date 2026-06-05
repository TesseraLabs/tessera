# logging-audit Delta Specification

## ADDED Requirements

### Requirement: Audit-события ролей (target role.audit)

События ролей ДОЛЖНЫ (MUST) идти в стабильный tracing-target `role.audit` со структурными
полями. Обязательный словарь событий:

| Событие | Поля | Когда |
|---|---|---|
| `role_session_open` | `user` (канон), `role`, `role_version`, `method` (cert/code), `ttl` | успешное открытие сессии |
| `role_deny` | `user`, `requested_role`, `reason` (`not_found` / `not_covered` / `backend_unavailable` / `mask_exceeds_ceiling` / `syntax`) | любой отказ по роли |
| `role_slice_invalid` | `path`, `error` | срез отвергнут валидацией (standalone: per-роль) |
| `bundle_rejected` | `reason` (`signature` / `rollback` / `hash_mismatch`), `bundle_version` | managed: отказ всей базы (severity critical) |
| `bundle_baseline_established` | `bundle_version` | первый манифест после потери персиста (TOFU) |
| `cert_allowed_roles_parse_failed` | `subject` | malformed расширение (fail-closed) |

Канон имени и запрошенная роль — всегда отдельные поля (не склейка `user+role`); сырая
введённая строка логируется только в `role_deny reason=syntax`.

#### Scenario: Отказ по непокрытой роли
- **WHEN** запрошенная роль не входит в allowed_roles серта
- **THEN** эмитится `role_deny` с `user`, `requested_role`, `reason=not_covered` в target `role.audit`

#### Scenario: Отказ базы в managed
- **WHEN** манифест отвергнут (rollback)
- **THEN** эмитится `bundle_rejected` severity critical с `reason=rollback` и обеими версиями в полях
