# trust-chain-validation Delta Specification

## ADDED Requirements

### Requirement: Version-gate профиля

Engine ДОЛЖЕН (MUST) знать `max_supported_profile_version` и для **каждого** серта цепи проверять
`pam_cert_profile_version ≤ max_supported`; серт с версией выше ДОЛЖЕН (MUST) приводить к reject
всей цепи (fail-closed). Дополнительно: непонятое critical-расширение на любом серте цепи
ДОЛЖНО (MUST) приводить к reject. Два слоя независимы: непонятый OID → reject; понятый OID, но
версия профиля новее → reject.

#### Scenario: Версия профиля выше поддерживаемой
- **WHEN** серт цепи несёт `pam_cert_profile_version` больше `max_supported`
- **THEN** цепь отвергается (fail-closed)

#### Scenario: Непонятое critical-расширение
- **WHEN** серт цепи несёт critical-расширение, неизвестное Engine
- **THEN** цепь отвергается (fail-closed)

### Requirement: Конверт делегирования по тегам

Для **каждого** CA-серта цепи, несущего `pam_cert_delegation_constraints`, Engine ДОЛЖЕН (MUST)
проверять `device.tags ⊇ requireTags` — generic-сравнение множеств пар (без хардкода имён ключей):
для каждой пары `(k,v)∈requireTags` тег устройства `device.tags[k]` ДОЛЖЕН (MUST) существовать и
байтово равняться `v`. Несоответствие или отсутствие тегов → reject (fail-closed). Проверка
ДОЛЖНА (MUST) применяться по логическому И ко всем CA-сертам цепи: даже если дочерний CA объявил
более широкий `requireTags`, родительский конверт всё равно применяется — misissued звено не
вырывается из родительских рамок.

#### Scenario: Теги устройства не удовлетворяют конверту
- **WHEN** CA-серт цепи требует `requireTags{region:north}`, а у устройства `region=south`
- **THEN** цепь отвергается (fail-closed)

#### Scenario: Дочерний CA шире родителя
- **WHEN** родительский CA требует `requireTags{region:north}`, а дочерний CA объявил пустой `requireTags`
- **THEN** родительский конверт всё равно применяется (AND по всем звеньям), устройство вне `region:north` отвергается

### Requirement: Потолки роли, уровня и TTL по цепи

Engine ДОЛЖЕН (MUST) проверять по логическому И/MIN ко всем CA-сертам цепи: запрошенная роль
входит в `allowRoles` каждого CA-серта (и в список allowed-roles листа); запрошенный уровень
`≤ maxLevel` каждого CA-серта (и `≤` потолка `max_integrity` листа); срок каждого звена цепи
`(notAfter − notBefore) ≤ maxTtl` родителя. Любое нарушение → reject (fail-closed).

#### Scenario: Запрошенная роль вне allowRoles CA
- **WHEN** запрошена роль, отсутствующая в `allowRoles` одного из CA-сертов цепи
- **THEN** цепь отвергается (fail-closed)

#### Scenario: Срок звена превышает maxTtl родителя
- **WHEN** срок действия серта превышает `maxTtl`, объявленный родительским CA
- **THEN** цепь отвергается (fail-closed)

### Requirement: Wildcard host_binding под конвертом

Лист с `host_binding=*` ДОЛЖЕН (MUST) считаться допустимым только на устройствах, удовлетворяющих
конверту делегирования цепи (`requireTags` всех CA-сертов). Эффективный набор устройств листа =
пересечение совпадения `host_binding` и множества устройств, чьи теги удовлетворяют конверту.
Wildcard без конверта в цепи сохраняет прежнюю семантику (любое устройство, bootstrap + короткий TTL).

#### Scenario: Wildcard-лист под северным CA на южном устройстве
- **WHEN** лист `host_binding=*` выпущен под CA с `requireTags{region:north}`, а устройство `region=south`
- **THEN** вход отвергается (конверт не удовлетворён), несмотря на wildcard
