# challenge-response Specification

## Purpose

Локальный proof-of-possession: доказать, что носитель владеет приватным ключом, парным публичному ключу валидированного leaf-сертификата. Это НЕ сетевой challenge-response протокол — nonce генерируется и проверяется в одном процессе.

Код: `crates/tessera_core/src/challenge/` (mod.rs, rsa_pss.rs, ecdsa.rs, gost.rs), PKCS#11-вариант в `flow.rs::pkcs11_challenge_response` + `token/pkcs11/sign.rs`.

## Requirements

### Requirement: Round-trip подписи свежего nonce

Система ДОЛЖНА (MUST): сгенерировать 32-байтовый nonce из OS RNG → подписать приватным ключом → проверить подпись публичным ключом ИЗ leaf-сертификата (не из заявленного носителем). Nonce и подпись ДОЛЖНЫ (MUST) держаться в `Zeroizing` (стирание при drop). Провал верификации → `CryptoError::BadSignature` → `PAM_PERM_DENIED`, fail-closed (challenge/mod.rs:38–86).

#### Scenario: RNG-сбой
- **WHEN** OS RNG недоступен
- **THEN** `CryptoError::Rng` → отказ auth (fail-closed, без fallback)

### Requirement: Диспетчеризация по типу ключа

Система ДОЛЖНА (MUST) выбирать алгоритм по `pub_key.id()` (challenge/mod.rs:51–86):

| Ключ | Алгоритм |
|---|---|
| RSA | RSASSA-PSS, SHA-256, MGF1-SHA256, salt=32 |
| EC P-256 | ECDSA + SHA-256 |
| EC P-384 | ECDSA + SHA-384 |
| GOST 2012-256 (NID 979) | gost-engine + Streebog-256 |
| GOST 2012-512 (NID 980) | gost-engine + Streebog-512 |
| Ed25519 | ДОЛЖЕН (MUST) отвергаться (`UnsupportedKey`, явно вне scope) |
| EC без named curve / иное | ДОЛЖЕН (MUST) отвергаться |

#### Scenario: GOST-ключ без engine
- **WHEN** GOST-ключ, gost-engine не загружается
- **THEN** `EngineLoadFailed` → отказ (fail-closed); self_check ловит это раньше при `needs_gost()` (self_check.rs:51–58)

### Requirement: PKCS#11-вариант — подпись на токене

Для токенов подпись ДОЛЖНА (MUST) выполняться на устройстве (`C_Sign`), верификация — на хосте публичным ключом из найденного на токене сертификата (sign.rs:83–127). ECDSA raw `r||s` ДОЛЖЕН (MUST) перекодироваться в DER до верификации OpenSSL.

#### Scenario: GOST через PKCS#11
- **WHEN** на токене ключ GOSTR3410
- **THEN** `MechanismNotSupported` → отказ (mechanism.rs:160–167)
- Design-граница: GOST поддерживается только на PKCS#12-пути через gost-engine; на PKCS#11-пути GOST-подпись не выполняется (cryptoki 0.7 без CKM_GOSTR3410), Рутокен/JaCarta применимы для RSA/ECDSA-сертификатов (так и зафиксировано в architecture.md). Поддержка GOST через PKCS#11 — proposal [gost-pkcs11](../../changes/gost-pkcs11/).

### Requirement: Отсутствие replay-protection — by design

Challenge-response НЕ ДОЛЖЕН (MUST NOT) претендовать на защиту от replay: nonce генерируется и проверяется внутри одного вызова доверенного PAM-процесса; внешнего канала, который можно записать и воспроизвести, не существует. Инвариант — только «носитель владеет приватным ключом в момент аутентификации». Зафиксировано как осознанное решение (сессии May 2026; memory `reference_astra_e2e`).

#### Scenario: Nonce в пределах одного процесса
- **WHEN** выполняется challenge-response
- **THEN** nonce генерируется и проверяется внутри одного вызова PAM-процесса; защита от replay не предоставляется и не заявляется
