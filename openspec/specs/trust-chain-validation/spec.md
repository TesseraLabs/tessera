# trust-chain-validation Specification

## Purpose

Построение и верификация цепочки доверия X.509: pre-validate листа → build chain → подписи → basic constraints → отзыв → SPKI-pinning. Точка входа `OpensslVerifier::verify_at` (trust/openssl_verifier.rs:159–228).

Код: `crates/tessera_core/src/x509/`, `trust/`.
## Requirements
### Requirement: Источники доверия

Anchors ДОЛЖНЫ (MUST) задаваться `[trust].anchors` (PEM self-signed корни), промежуточные — `[trust].intermediates` (локальный пул) + presented-цепь из носителя (.p12 + `certs/chain.pem`). Конструктор verifier ДОЛЖЕН (MUST) отвергать пустой список anchors и `max_depth == 0` (openssl_verifier.rs:125–130).

Принятая модель развёртывания (May 2026): на машине только root anchor; intermediate приезжает в `.p12` chain → ротация intermediate не требует касания парка.

#### Scenario: Пустой список anchors
- **WHEN** конструктор verifier получает пустой список anchors или `max_depth == 0`
- **THEN** конструктор отвергает конфигурацию (fail-closed, openssl_verifier.rs:125–130)

### Requirement: Pre-validate leaf

Лист ДОЛЖЕН (MUST) проходить по порядку: X.509 v3 → validity с допуском `clock_skew_seconds` → whitelist алгоритмов подписи → KeyUsage `digitalSignature` → EKU `clientAuth` → basicConstraints отсутствует или CA=FALSE (pre_validate.rs:51–102). Отсутствие KeyUsage/EKU → reject (fail-closed).

#### Scenario: Пустой whitelist алгоритмов → безопасный дефолт
- **WHEN** `allowed_signature_algorithms` опущен или равен `[]`
- **THEN** валидатор конфигурации ДОЛЖЕН (MUST) подставить дефолтный whitelist `DEFAULT_SIGNATURE_ALGORITHMS` (config/validated.rs:792–868): `sha256/384/512WithRSAEncryption` + `ecdsa-with-SHA256/384/512`. SHA-1 и прочие deprecated-алгоритмы в дефолт НЕ входят; GOST в дефолт НЕ входит (gost-engine не подтягивается, `needs_gost=false`) — GOST включается только явным перечислением в конфиге

#### Scenario: EKU emailProtection
- **WHEN** leaf без emailProtection EKU
- **THEN** tessera НЕ отвергает (проверяется только clientAuth)
- Историческая справка: требование emailProtection исходит от штатного валидатора Astra / openssl CMS_verify (контекст 0.2.x), НЕ от tessera — docs (cert-issuance.md, clone-image.md) атрибутируют его именно штатному валидатору Astra.

### Requirement: Построение цепочки

`build_chain` ДОЛЖЕН (MUST) итеративно искать issuer: anchors → presented → pool; критерий — DN match + (при наличии AKI) AKI==SKI кандидата. Anchor ДОЛЖЕН (MUST) приниматься только self-signed. Нет issuer → `PathBuild` (fail-closed); глубина > `max_chain_depth` → `DepthExceeded` (chain.rs:30–105).

#### Scenario: Issuer не найден
- **WHEN** для очередного сертификата цепочки не находится issuer ни в anchors, ни в presented, ни в pool
- **THEN** возвращается `PathBuild` (fail-closed)

- Краевой случай: проверка глубины не применяется на anchor-ветке — итоговая длина может быть max_depth+1, если anchor замыкает цепь на пределе (chain.rs:62).

### Requirement: Подписи и constraints промежуточных

Каждая пара (child, parent) ДОЛЖНА (MUST) верифицироваться `child.verify(parent.pubkey)`; anchor ДОЛЖЕН (MUST) self-verify (signatures.rs:19–45). Для не-leaf ДОЛЖНЫ (MUST) выполняться: basicConstraints присутствует + CA=TRUE, pathLenConstraint не превышен, validity-окно с clock_skew, KeyUsage `keyCertSign` (basic_constraints.rs:35–114). Всё fail-closed.

#### Scenario: Промежуточный без CA=TRUE
- **WHEN** не-leaf сертификат в цепочке не имеет basicConstraints CA=TRUE или у него отсутствует KeyUsage `keyCertSign`
- **THEN** верификация отклоняется (fail-closed)

### Requirement: Whitelist алгоритмов — строгое равенство

Сравнение ДОЛЖНО (MUST) быть строгим равенством (exact match, case-sensitive) против Display-формы OpenSSL — substring-сравнение убрано намеренно (пропускало `sha1WithRSAEncryption` под `sha`) (pre_validate.rs:71–82). Известные алгоритмы: RSA-SHA256/384/512, ECDSA-SHA256/384/512, GOST 2012-256/512 (TC26 OID + алиасы) (sig_alg.rs:48–76).

#### Scenario: Алгоритм совпадает только по подстроке
- **WHEN** алгоритм подписи совпадает с элементом whitelist лишь как подстрока (например, `sha1WithRSAEncryption` против `sha`)
- **THEN** совпадение НЕ засчитывается — требуется строгое равенство, иначе reject

### Requirement: SPKI-pinning

При `[trust.pinning].enabled=true` SPKI-хеш anchor'а ДОЛЖЕН (MUST) входить в `allowed_root_spki_sha256` (64 hex), иначе reject. При `enabled=false` проверка ДОЛЖНА (MUST) быть no-op.

#### Scenario: SPKI anchor не в allow-list
- **WHEN** `[trust.pinning].enabled=true` и SPKI-хеш anchor'а отсутствует в `allowed_root_spki_sha256`
- **THEN** цепочка отклоняется (reject)

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

