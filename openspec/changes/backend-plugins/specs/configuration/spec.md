# configuration Delta Specification

## ADDED Requirements

### Requirement: Выбор бэкенда в секции [mac]

Секция `[mac]` ДОЛЖНА (MUST) поддерживать поле `backend` (строка, имя плагина по заголовку;
отсутствие = StubBackend). Паттерн «kind → поле выбора в своей секции» — канонический для
будущих видов бэкендов. Ключей, влияющих на верификацию подписи плагинов, в схеме НЕ ДОЛЖНО
(MUST NOT) существовать (политика — в бинарнике).

#### Scenario: backend назван, плагин валиден
- **WHEN** `[mac] backend = "parsec"` и плагин проходит верификацию/ABI/init
- **THEN** активен ParsecBackend из плагина

#### Scenario: backend назван, плагина нет
- **WHEN** `[mac] backend = "parsec"`, файла нет в /usr/lib/tessera/plugins/
- **THEN** загрузка конфига не падает; активен StubBackend; audit `plugin_rejected reason=missing`
