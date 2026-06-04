# gost-crypto Specification

## Purpose

Делегация ГОСТ-криптографии сертифицированному `gost-engine` (OpenSSL engine). Tessera SHALL NOT реализовывать собственную криптографию — это принципиальное продуктовое решение (сертификационная стратегия: крипта = чужая сертифицированная, наш периметр = тонкий СЗИ).

Код: `crates/tessera_core/src/gost/` (engine.rs, algorithms.rs, sys.rs, errors.rs).

## Requirements

### Requirement: Ленивая загрузка engine

Engine ДОЛЖЕН (MUST) загружаться once-per-process (OnceLock) и ТОЛЬКО если в цепочке есть GOST-подписанный сертификат (`ensure_loaded_if_any_gost`, engine.rs:104–113). На чистых RSA/ECDSA цепочках engine НЕ ДОЛЖЕН (MUST NOT) затрагиваться (терминальный RSA-only кейс работает без gost-engine).

#### Scenario: GOST-цепочка, engine не грузится
- **WHEN** предъявлена GOST-цепочка, engine отсутствует/сломан
- **THEN** `TrustError::EngineLoadFailed` → отказ верификации (fail-closed)

### Requirement: Путь к engine

`gost_engine_path` (только при `crypto_backend="openssl"`): `Some(p)` → файл ДОЛЖЕН (MUST) существовать, динамическая загрузка SO_PATH+ID+LOAD; `None` → поиск engine `"gost"` по стандартному OPENSSL_ENGINES (engine.rs:165–170). После загрузки — `ENGINE_set_default(ALL)` + sanity: ДОЛЖЕН (MUST) быть зарегистрирован `md_gost12_256` ИЛИ `streebog256` (разные форки именуют по-разному), иначе `DigestUnavailable` (engine.rs:173–182).

#### Scenario: Streebog-digest недоступен после загрузки
- **WHEN** engine загружен, но ни `md_gost12_256`, ни `streebog256` не зарегистрированы
- **THEN** возвращается `DigestUnavailable` (engine.rs:173–182)

### Requirement: Алгоритмы

Модуль ДОЛЖЕН (MUST) поддерживать: GOST R 34.10-2012 256/512 (TC26 OID `1.2.643.7.1.1.3.2`/`3.3`), Streebog-256/512 (NID 1177/1178). Подпись GOST-цепочек верифицируется штатным `X509::verify` после установки engine default.

#### Scenario: Верификация GOST-цепочки
- **WHEN** предъявлена цепочка с GOST R 34.10-2012 (256 или 512) и engine установлен как default
- **THEN** подпись верифицируется штатным `X509::verify` с использованием Streebog-256/512

### Requirement: Packaging

`debian/control` ДОЛЖЕН (MUST) перечислять альтернативы `libgost-engine | gost-engine | libgost-astra` (на Astra пакет называется `libgost-astra`); libpdp/libparsec — в Recommends, не Depends (иначе пакет неустанавливаем на не-Astra).

#### Scenario: Установка на не-Astra
- **WHEN** пакет устанавливается на систему без `libpdp`/`libparsec`
- **THEN** установка проходит — эти зависимости в Recommends, а не Depends, а GOST-engine берётся из альтернатив `libgost-engine | gost-engine | libgost-astra`

### Requirement: Feature-флаги

`gost-tests` ДОЛЖЕН (MUST) гейтить только интеграционные тесты `gost_*_real.rs`; runtime-код engine компилируется всегда.

#### Scenario: Сборка без gost-tests
- **WHEN** проект собирается без feature-флага `gost-tests`
- **THEN** интеграционные тесты `gost_*_real.rs` исключаются, но runtime-код engine компилируется как обычно

- ⚠ KNOWN GAP (testing): GOST-фикстуры не закоммичены (`tests/fixtures/gost/` пуст), `gost-tests` не включается в CI → ГОСТ-путь end-to-end автоматически НЕ проверяется (только локально/Vagrant вручную).
- ⚠ KNOWN GAP: GOST через PKCS#11 не подписывает (`MechanismNotSupported`) — см. [challenge-response](../challenge-response/spec.md).
