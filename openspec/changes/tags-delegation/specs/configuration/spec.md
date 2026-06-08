# configuration Delta Specification

## ADDED Requirements

### Requirement: Конфигурация version-gate и источника тегов

Конфигурация ДОЛЖНА (MUST) задавать `[trust].max_supported_profile_version` (целое; верхняя
граница version-gate, `trust-chain-validation`) и секцию `[tags]` (путь/режим источника тегов
устройства: managed-манифест `role-store` либо standalone-файл). Дефолты ДОЛЖНЫ (MUST) быть
совместимы с fail-closed: отсутствие источника тегов = «тегов нет» (групповые рамки
неудовлетворимы), а не «все теги разрешены».

#### Scenario: Источник тегов не сконфигурирован
- **WHEN** секция `[tags]` отсутствует или путь не указывает на доверенный источник
- **THEN** Engine считает, что тегов нет (групповой делегированный вход → reject), per-host вход без рамок не затронут

#### Scenario: max_supported_profile_version не задан
- **WHEN** `[trust].max_supported_profile_version` отсутствует в конфиге
- **THEN** применяется компилированный дефолт Engine (известная поддерживаемая версия), серты выше → reject
