# challenge-response Delta Specification

## MODIFIED Requirements

### Requirement: PKCS#11-вариант — подпись на токене

Для токенов подпись ДОЛЖНА (MUST) выполняться на устройстве (`C_Sign`), верификация — на хосте
публичным ключом из найденного на токене сертификата (sign.rs:83–127). ECDSA raw `r||s` ДОЛЖЕН
(MUST) перекодироваться в DER до верификации OpenSSL. Для ключей GOSTR3410 (2012-256/512)
подпись ДОЛЖНА (MUST) выполняться GOST-механизмом токена (предпочтительно «хэш на токене»;
при его отсутствии — Streebog на хосте через gost-engine + raw-подпись по дайджесту), а
верификация — публичным ключом из серта через gost-engine (ленивая загрузка, fail-closed
при недоступности). Подпись токена (raw `r||s`) ДОЛЖНА (MUST) перекодироваться в форму,
ожидаемую gost-engine, до верификации. Если токен не заявляет ни одного GOST-механизма
в `C_GetMechanismList` — типизированный отказ `MechanismNotSupported` (без молчаливого
fallback'а на хост-подпись: приватный ключ неизвлекаем by design).

#### Scenario: GOST через PKCS#11
- **WHEN** на токене ключ GOSTR3410 (2012-256 или 2012-512) и токен заявляет GOST-механизм
- **THEN** nonce подписывается на устройстве, подпись верифицируется на хосте gost-engine'ом публичным ключом из серта; провал верификации → `BadSignature` → `PAM_PERM_DENIED`

#### Scenario: GOST-токен без GOST-механизмов
- **WHEN** ключ GOSTR3410, но `C_GetMechanismList` токена не содержит ни одного GOST-механизма
- **THEN** `MechanismNotSupported` → отказ (fail-closed)

#### Scenario: GOST-токен при недоступном gost-engine
- **WHEN** ключ GOSTR3410, gost-engine не загружается на хосте
- **THEN** `EngineLoadFailed` → отказ (fail-closed) — верификация подписи токена без engine невозможна
