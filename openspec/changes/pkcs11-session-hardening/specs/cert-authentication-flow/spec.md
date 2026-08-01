## ADDED Requirements

### Requirement: Средовые отказы отличимы от неверного PIN

Отказ, при котором PIN не был предъявлен провайдеру, ДОЛЖЕН (MUST) отображаться в `PAM_AUTHINFO_UNAVAIL` (9), а не в `PAM_AUTH_ERR` (7). К этому классу относится `LogoutFailed` из `Pkcs11Session::open` наравне с `ModuleLoadFailed`, `InitFailed` и `TokenWaitTimeout`.

Основание: `PAM_AUTH_ERR` — тот же код, что и неверный PIN, поэтому инженер видит «Ошибка аутентификации» и перенабирает верный PIN впустую.

#### Scenario: Снять остаточный логин не удалось
- **WHEN** `open` вернул `LogoutFailed`
- **THEN** PAM получает `PAM_AUTHINFO_UNAVAIL` (9), и диагностика на экране говорит о недоступности носителя, а не об ошибке ввода
