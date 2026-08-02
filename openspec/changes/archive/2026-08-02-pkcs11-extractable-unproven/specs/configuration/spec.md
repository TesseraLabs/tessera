# configuration Delta Specification

## MODIFIED Requirements

### Requirement: Ключевые top-level поля

Каждое значение поля ДОЛЖНО (MUST) соответствовать своему default и диапазону из таблицы ниже; нарушение диапазона = ошибка валидации конфига.

| Поле | Default | Диапазон |
|---|---|---|
| `crypto_backend` | обязательно | openssl \| pkcs11_native |
| `mode` | обязательно | pkcs12 \| pkcs11 |
| `pkcs12_path_pattern` | `certs/user.p12` | relative, без `..`, `${user}` |
| `usb_wait_seconds` | 10 | 0..=300 |
| `usb_allowed_devices` | `[]` | список `"vid:pid"`, по 4 hex-цифры (lsusb-формат); пустой = фильтра нет (см. [usb-media-pkcs12](../usb-media-pkcs12/spec.md)) |
| `max_usb_partitions` | 8 | 1..=64 |
| `on_usb_removed` | lock | lock\|logout\|hook\|shutdown |
| `usb_removed_grace_seconds` / `suspend_grace_seconds` | 0 | ≤600 только через [monitor] |
| `monitor_fail_mode` | strict | strict\|permissive |
| `pkcs11_module` | — | обязателен при mode=pkcs11 |
| `pkcs11_max_pin_attempts` | 3 | 1..=5 |
| `pkcs11_slot_wait_seconds` | 10 | 0..=60 |
| `pkcs11_pin_prompt` | «Введите PIN токена: » | ≤128 байт |
| `pkcs11_allow_extractable_keys` | false | bool; true = WARN вместо отказа для подтверждённого `CKA_EXTRACTABLE=TRUE`; неотвеченный атрибут им НЕ разрешается (см. [token-pkcs11](../token-pkcs11/spec.md)) |
| `pkcs11_allow_unreported_extractable` | false | bool; true = WARN вместо отказа, когда токен не сообщил `CKA_EXTRACTABLE`; подтверждённое `TRUE` им НЕ разрешается (см. [token-pkcs11](../token-pkcs11/spec.md)) |
| `pkcs12_pin_prompt` | «Smart-card PIN: » | непустой, ≤128 байт; применяется в PIN-prompt PKCS#12-пути |
| `gost_engine_path` | — | только при openssl; readable файл |

#### Scenario: Поле вне диапазона
- **WHEN** значение top-level поля выходит за указанный диапазон (например `max_usb_partitions=100`)
- **THEN** валидация конфига завершается ошибкой

#### Scenario: Ключи обхода не подменяют друг друга
- **WHEN** задан только один из `pkcs11_allow_extractable_keys` / `pkcs11_allow_unreported_extractable`
- **THEN** он разрешает только свой случай; второй случай продолжает отклоняться по дефолту
