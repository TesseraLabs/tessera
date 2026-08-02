# token-pkcs11 Delta Specification

## MODIFIED Requirements

### Requirement: Non-extractable инвариант (режим B)

Ключ с `CKA_EXTRACTABLE == TRUE` ДОЛЖЕН (MUST) отклоняться с `ExtractableKeyRejected` (fail-closed; в сообщении — тип ключа и hex-префикс `CKA_ID`, без ключевого материала) — дефолтное поведение при `pkcs11_allow_extractable_keys = false`. При явном операторском opt-in `pkcs11_allow_extractable_keys = true` модуль ДОЛЖЕН (MUST) логировать WARN `pkcs11_extractable_key` и продолжать.

Отсутствие ответа НЕ ДОЛЖНО (MUST NOT) толковаться как `FALSE`. `cryptoki` молча выбрасывает из результата чтения атрибуты, которые токен отказался отдать, поэтому модуль ДОЛЖЕН (MUST) различать три состояния: подтверждённое `FALSE`, подтверждённое `TRUE` и «атрибут не сообщён». Третье состояние ДОЛЖНО (MUST) отклоняться отдельной ошибкой `ExtractableAttributeUnavailable` — дефолтное поведение при `pkcs11_allow_unreported_extractable = false`. При `pkcs11_allow_unreported_extractable = true` модуль ДОЛЖЕН (MUST) логировать WARN `pkcs11_extractable_attribute_unavailable` и продолжать.

Ключи обхода НЕЗАВИСИМЫ (MUST): `pkcs11_allow_extractable_keys` разрешает только подтверждённое `TRUE`, `pkcs11_allow_unreported_extractable` — только неотвеченный атрибут. Ни один из них НЕ ДОЛЖЕН (MUST NOT) разрешать случай, которым управляет другой.

Причина отказа провайдера ДОЛЖНА (MUST) устанавливаться уточняющим запросом на холодном пути и попадать в ошибку и в журнал (`sensitive`, `type_invalid`, `unavailable`, противоречие между вызовами, сбой запроса). Если уточняющий запрос сообщает, что атрибут читаем, модуль ДОЛЖЕН (MUST) выполнить одиночное перечитывание `CKA_EXTRACTABLE` и решать по его результату: `FALSE` — допуск, `TRUE` — `ExtractableKeyRejected`, по-прежнему нет значения — `ExtractableAttributeUnavailable`. Основание: чтение просит атрибут в общем шаблоне с `CKA_KEY_TYPE`, а уточняющий запрос — в одиночку, и провайдеры, ломающиеся на смешанных шаблонах, известны; прямое чтение `FALSE` и есть требуемое доказательство.

Значение, дошедшее до вызывающего, ДОЛЖНО (MUST) сохранять различие между «подтверждено `FALSE`» и «не сообщено»; второе НЕ ДОЛЖНО (MUST NOT) переписываться в первое.

Все обращения к провайдеру на этом пути, включая уточняющий запрос и перечитывание, ДОЛЖНЫ (MUST) идти под тем же process-global локом, что и остальные cryptoki-вызовы (см. требование «Locking mode»).

Обе ошибки маппятся на PAM как прочие pkcs11-ошибки auth-пути (`PAM_AUTH_ERR`) (key_lookup.rs, error.rs).

#### Scenario: Extractable-ключ при дефолтной политике
- **WHEN** `CKA_EXTRACTABLE == TRUE` и `pkcs11_allow_extractable_keys = false` (дефолт)
- **THEN** возвращается `ExtractableKeyRejected` → `PAM_AUTH_ERR`; аутентификация не продолжается

#### Scenario: Extractable-ключ при операторском opt-in
- **WHEN** `CKA_EXTRACTABLE == TRUE` и `pkcs11_allow_extractable_keys = true`
- **THEN** WARN `pkcs11_extractable_key`, работа продолжается

#### Scenario: Токен не сообщил атрибут
- **WHEN** `CKA_EXTRACTABLE` отсутствует в результате чтения, уточняющий запрос даёт `sensitive`, `type_invalid` или `unavailable`, и `pkcs11_allow_unreported_extractable = false` (дефолт)
- **THEN** возвращается `ExtractableAttributeUnavailable` с причиной → `PAM_AUTH_ERR`; аутентификация не продолжается

#### Scenario: Токен не сообщил атрибут при операторском opt-in
- **WHEN** `CKA_EXTRACTABLE` не сообщён и `pkcs11_allow_unreported_extractable = true`
- **THEN** WARN `pkcs11_extractable_attribute_unavailable` с причиной, работа продолжается

#### Scenario: Батч-чтение потеряло атрибут, который токен умеет читать
- **WHEN** `CKA_EXTRACTABLE` отсутствует в результате чтения, а уточняющий запрос сообщает, что значение читаемо
- **THEN** выполняется одиночное перечитывание; при `FALSE` ключ допускается, при `TRUE` возвращается `ExtractableKeyRejected`, при по-прежнему отсутствующем значении — `ExtractableAttributeUnavailable`

#### Scenario: Один ключ обхода не открывает чужой случай
- **WHEN** `pkcs11_allow_extractable_keys = true`, `pkcs11_allow_unreported_extractable = false`, а токен не сообщил `CKA_EXTRACTABLE`
- **THEN** возвращается `ExtractableAttributeUnavailable`; opt-in на извлекаемые ключи неотвеченный атрибут не разрешает
