---
id: gost-crypto
kind: операция
context: auth
name: "ГОСТ-криптография"
aliases:
  - "gost-crypto"
relations:
  references:
    - auth.trust-chain
anchors:
  code:
    - "crates/tessera_core/src/challenge/gost.rs"
  test:
    - "crates/tessera_core/tests/gost_challenge_real.rs"
requirements:
  GOST-001:
    kind: операционное
    subjects:
      - auth.gost-crypto
    origins:
      - "gost-crypto::Ленивая загрузка engine"
    evidence:
      code:
        - "crates/tessera_core/src/challenge/gost.rs"
  GOST-002:
    kind: операционное
    subjects:
      - auth.gost-crypto
    origins:
      - "gost-crypto::Путь к engine"
    evidence:
      code:
        - "crates/tessera_core/src/challenge/gost.rs"
  GOST-003:
    kind: контракт
    subjects:
      - auth.gost-crypto
    origins:
      - "gost-crypto::Алгоритмы"
    evidence:
      test:
        - "crates/tessera_core/tests/gost_challenge_real.rs"
  GOST-004:
    kind: операционное
    subjects:
      - auth.gost-crypto
    origins:
      - "gost-crypto::Packaging"
    evidence:
      code:
        - "crates/tessera_core/src/challenge/gost.rs"
  GOST-005:
    kind: операционное
    subjects:
      - auth.gost-crypto
    origins:
      - "gost-crypto::ГОСТ-делегация в открытой части"
    evidence:
      code:
        - "crates/tessera_core/src/challenge/gost.rs"
  GOST-006:
    kind: операционное
    subjects:
      - auth.gost-crypto
    origins:
      - "gost-crypto::Feature-флаги"
    evidence:
      code:
        - "crates/tessera_core/src/challenge/gost.rs"
---
# ГОСТ-криптография

Эта страница заменяет процедурную capability-спеку OpenSpec «gost-crypto»: она
помещает каждое прежнее требование в адресуемую норму с владельцем, видом и
проверяемым происхождением. Под каждым нормативным предложением сохранены подробные условия, отрицательные
сценарии и rationale; они входят в ту же страницу и уточняют границы нормы.

### GOST-001 — Ленивая загрузка engine

[[auth.gost-crypto|ГОСТ-криптография]] MUST соблюдать правило «Ленивая загрузка engine» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/gost-crypto/spec.md, requirement «Ленивая загрузка engine».

Engine должен загружаться once-per-process (OnceLock) и ТОЛЬКО если в цепочке есть GOST-подписанный сертификат (`ensure_loaded_if_any_gost`, engine.rs:104–113). На чистых RSA/ECDSA цепочках engine не должен затрагиваться (терминальный RSA-only кейс работает без gost-engine).

#### Scenario: GOST-цепочка, engine не грузится
- **WHEN** предъявлена GOST-цепочка, engine отсутствует/сломан
- **THEN** `TrustError::EngineLoadFailed` → отказ верификации (fail-closed)

### GOST-002 — Путь к engine

[[auth.gost-crypto|ГОСТ-криптография]] MUST соблюдать правило «Путь к engine» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/gost-crypto/spec.md, requirement «Путь к engine».

`gost_engine_path` (только при `crypto_backend="openssl"`): если allow-list разрешает ГОСТ-подписи, абсолютный путь обязателен, файл и все его предки должны быть root-owned без group/world write. Неявный поиск engine `"gost"` через унаследованный `OPENSSL_ENGINES` должен отклоняться при валидации конфигурации. После загрузки через SO_PATH+ID+LOAD — `ENGINE_set_default(ALL)` + sanity: должен быть зарегистрирован `md_gost12_256` ИЛИ `streebog256` (разные форки именуют по-разному), иначе `DigestUnavailable`.

#### Scenario: ГОСТ разрешён без явного пути
- **WHEN** OpenSSL allow-list содержит ГОСТ-подпись, но `gost_engine_path` отсутствует
- **THEN** конфигурация отклоняется до загрузки native-кода

#### Scenario: Streebog-digest недоступен после загрузки
- **WHEN** engine загружен, но ни `md_gost12_256`, ни `streebog256` не зарегистрированы
- **THEN** возвращается `DigestUnavailable` (engine.rs:173–182)

### GOST-003 — Алгоритмы

[[auth.gost-crypto|ГОСТ-криптография]] MUST соблюдать правило «Алгоритмы» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/gost-crypto/spec.md, requirement «Алгоритмы».

Модуль должен поддерживать: GOST R 34.10-2012 256/512 (TC26 OID `1.2.643.7.1.1.3.2`/`3.3`), Streebog-256/512 (NID 1177/1178). Подпись GOST-цепочек верифицируется штатным `X509::verify` после установки engine default.

#### Scenario: Верификация GOST-цепочки
- **WHEN** предъявлена цепочка с GOST R 34.10-2012 (256 или 512) и engine установлен как default
- **THEN** подпись верифицируется штатным `X509::verify` с использованием Streebog-256/512

### GOST-004 — Packaging

[[auth.gost-crypto|ГОСТ-криптография]] MUST соблюдать правило «Packaging» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/gost-crypto/spec.md, requirement «Packaging».

`debian/control` должен перечислять альтернативы `libgost-engine | gost-engine | libgost-astra` (на Astra пакет называется `libgost-astra`); libpdp/libparsec — в Recommends, не Depends (иначе пакет неустанавливаем на не-Astra).

#### Scenario: Установка на не-Astra
- **WHEN** пакет устанавливается на систему без `libpdp`/`libparsec`
- **THEN** установка проходит — эти зависимости в Recommends, а не Depends, а GOST-engine берётся из альтернатив `libgost-engine | gost-engine | libgost-astra`

### GOST-005 — ГОСТ-делегация в открытой части

[[auth.gost-crypto|ГОСТ-криптография]] MUST соблюдать правило «ГОСТ-делегация в открытой части» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/gost-crypto/spec.md, requirement «ГОСТ-делегация в открытой части».

ГОСТ-функциональность edge-агента (делегация в gost-engine: ленивая загрузка, challenge-response GOST 2012-256/512, верификация GOST-цепочек) входит в открытую часть проекта и должна оставаться полностью функциональной в открытой сборке (`crates/tessera_core/src/gost/` — этот репозиторий, см. [licensing-distribution](../licensing-distribution/spec.md)).

#### Scenario: Открытая сборка с ГОСТ
- **WHEN** репозиторий собирается без доступа к коммерческим компонентам
- **THEN** ГОСТ-путь (gost-engine делегация) полностью функционален

### GOST-006 — Feature-флаги

[[auth.gost-crypto|ГОСТ-криптография]] MUST соблюдать правило «Feature-флаги» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/gost-crypto/spec.md, requirement «Feature-флаги».

`gost-tests` должен гейтить только интеграционные тесты `gost_*_real.rs`; runtime-код engine компилируется всегда.

#### Scenario: Сборка без gost-tests
- **WHEN** проект собирается без feature-флага `gost-tests`
- **THEN** интеграционные тесты `gost_*_real.rs` исключаются, но runtime-код engine компилируется как обычно

- ГОСТ-путь end-to-end проверяется вручную (локально/Vagrant): фикстуры `tests/fixtures/gost/` не закоммичены, `gost-tests` не включается в CI. Автоматизация — proposal [ci-hardening](../../changes/ci-hardening/).
- GOST через PKCS#11 не подписывает (`MechanismNotSupported`) — design-граница, см. [challenge-response](../challenge-response/spec.md); реализация — proposal [gost-pkcs11](../../changes/gost-pkcs11/).
