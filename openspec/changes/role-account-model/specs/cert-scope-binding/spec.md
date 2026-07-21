# Delta: cert-scope-binding

## MODIFIED Requirements

### Requirement: verify_user_binding

Проверка user_binding ДОЛЖНА (MUST) работать так: Wildcard → любой пользователь;
Exact → БАЙТОВОЕ case-SENSITIVE сравнение с pam_user (Linux usernames
регистрозависимы). Нет совпадений → `UserNotAllowed` + WARN
(host_binding.rs:140–160).

**Семантика дескрипторов (модель «роль = ролевая учётная запись», 2026-06-19):**
Exact-дескрипторы `user_binding` — это имена **ролевых учётных записей**,
в которые разрешён вход по данному листу; в целевой модели вход выполняется в
ролевую УЗ с именем роли (`oper@host`), и `user_binding` — единственный гейт
допуска роли на входе. Выпускная сторона (кабинет/CLI) заполняет
`user_binding` тем же списком, что и `allowed_roles`. Легаси-схемы с
персональными учётными записями (вход `ivanov` + суффикс роли) остаются
валидными данными расширения — механика сравнения от семантики не зависит;
Wildcard в целевой модели означает «любая ролевая УЗ, разрешённая рамками».

- Вызов в проде: `authorize_user` (flow.rs, Step 10) — cert-путь приоритетен; в legacy `[[user_mapping]]` уходят только сертификаты БЕЗ расширения user_binding, присутствующее-но-malformed расширение даёт отказ (fail-closed). Нормативное описание — см. [cert-authentication-flow](../cert-authentication-flow/spec.md).

#### Scenario: Несовпадение pam_user с Exact-дескриптором
- **WHEN** user_binding содержит Exact-дескриптор, не равный байтово текущему pam_user
- **THEN** возвращается `UserNotAllowed` + WARN

#### Scenario: Вход в ролевую учётную запись по user_binding
- **WHEN** лист несёт `user_binding = [oper, serv]` и инженер входит `ssh oper@device`
- **THEN** pam_user `oper` совпадает с Exact-дескриптором — допуск пройден; вход `admin@device` тем же листом даёт `UserNotAllowed`
