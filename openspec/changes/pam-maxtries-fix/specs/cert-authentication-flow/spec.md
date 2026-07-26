# cert-authentication-flow Delta Specification

## MODIFIED Requirements

### Requirement: Маппинг FlowError → PAM-код

Модуль ДОЛЖЕН (MUST) различать классы ошибок (flow.rs:189–229):

| Класс | PAM rc |
|---|---|
| Usb / Mount / Discovery / P12Envelope / Pkcs11-инфраструктура | 9 PAM_AUTHINFO_UNAVAIL |
| MaxTries / PinLocked / MaxAttemptsExceeded | 11 PAM_MAXTRIES |
| Pkcs12 / Crypto / Trust / Mapping | 6 PAM_PERM_DENIED |
| Conv / CertScope / PreAuthHook / PostAuthHook / прочие Pkcs11 | 7 PAM_AUTH_ERR |
| Internal | 4 PAM_SYSTEM_ERR |

Числовые значения ДОЛЖНЫ (MUST) соответствовать `<security/pam_appl.h>`, а не
представлению о них: `PAM_MAXTRIES` = 11, `PAM_CRED_INSUFFICIENT` = 8. Утверждения
в тестах ДОЛЖНЫ (MUST) содержать имя константы рядом с числом, чтобы расхождение
имени и значения было заметно при чтении.

#### Scenario: Маппинг класса ошибки в PAM-код
- **WHEN** `flow::authenticate` завершился `FlowError` (например, MaxTries)
- **THEN** возвращается соответствующий классу PAM rc (для MaxTries — 11 PAM_MAXTRIES), а не единый PAM_AUTH_ERR

#### Scenario: Исчерпание попыток PIN отличимо от недоступности данных
- **WHEN** бюджет попыток PIN исчерпан
- **THEN** приложение получает 11 PAM_MAXTRIES и может прекратить дальнейшие запросы, а не 8 PAM_CRED_INSUFFICIENT, означающий проблему с доступом к данным аутентификации
