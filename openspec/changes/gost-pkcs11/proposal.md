# Proposal: gost-pkcs11

## Why

architecture.md перечисляет JaCarta-2 GOST и Рутокен ЭЦП (ГОСТ-СКЗИ) как поддерживаемые носители,
но GOST-подпись на PKCS#11-пути **не работает**: `select_mechanism` для ключа типа GOSTR3410
возвращает `MechanismNotSupported` (mechanism.rs:160–166). Блокер — crate cryptoki 0.7 не
экспонирует `CKM_GOSTR3410*`-механизмы. Итог: ГОСТ работает только на PKCS#12-пути (файл на USB
через gost-engine), а главный сценарий «неизвлекаемый ГОСТ-ключ на сертифицированном токене»
(режим B — то, ради чего токены и покупают) — отказ. KNOWN GAP зафиксирован в challenge-response,
token-pkcs11 и gost-crypto спеках.

## What Changes

- **GOST-подпись на токене** (`C_Sign`) для ключей GOSTR3410 (2012-256/512): выбор GOST-механизма
  вместо `MechanismNotSupported`; параметры ключа определяются по атрибутам объекта
  (`CKA_GOSTR3410_PARAMS` / размер ключа).
- **Разблокировка cryptoki** — по лестнице вариантов (детали в design.md):
  1) upgrade cryptoki до версии с GOST-механизмами (или upstream-PR);
  2) прокидывание численных CKM-констант (TC26) через vendor-defined-механизм;
  3) точечный raw FFI через `cryptoki-sys` только для GOST-вызова.
- **Хост-верификация** подписи токена — публичным ключом ИЗ серта через gost-engine
  (Streebog-256/512), как и весь GOST: своей криптографии по-прежнему нет; формат подписи
  (raw r||s, порядок байт по ГОСТ) согласуется с ожиданием gost-engine и фиксируется тестами.
- **Честный fallback**: если токен не заявляет GOST-механизм в `C_GetMechanismList` —
  по-прежнему типизированный отказ `MechanismNotSupported` (fail-closed, без молчаливой
  деградации на хост-подпись: приватный ключ неизвлекаем by design).

## Capabilities

### Modified Capabilities

- `challenge-response`: PKCS#11-вариант покрывает GOST — подпись nonce на устройстве,
  верификация на хосте через gost-engine; снимается KNOWN GAP.
- `token-pkcs11`: требование «Механизмы подписи» — строка GOSTR3410 меняется с
  `MechanismNotSupported` на выбор GOST-механизма; проверка наличия механизма у токена.
- `gost-crypto`: новое требование — хост-верификация GOST-подписи токена через gost-engine
  (ленивая загрузка, fail-closed); снимается KNOWN GAP-маркер про PKCS#11.

## Impact

- `tessera_core`: `token/pkcs11/mechanism.rs` (GOST-ветка вместо отказа), `sign.rs`
  (GOST-вариант верификации через gost-engine), `key_lookup.rs` (чтение GOST-атрибутов),
  возможно `Cargo.toml` (версия cryptoki / `cryptoki-sys`).
- Supply-chain: изменение версии cryptoki проходит `cargo deny check` + `cargo audit` (lint.yml).
- Тесты: unit на выбор механизма по атрибутам; интеграционные с реальным железом
  (JaCarta-2 GOST, Рутокен ЭЦП 2.0/3.0) — вручную по runbook'у; CI-автоматизация железа —
  KNOWN GAP, трекается в change `ci-hardening` (п. «реальный USB/токен»).
- docs/architecture.md: заявка «JaCarta/Рутокен поддерживаются» становится правдой для GOST-ключей.
- RSA/ECDSA-пути PKCS#11 и PKCS#12-путь GOST не затрагиваются.
