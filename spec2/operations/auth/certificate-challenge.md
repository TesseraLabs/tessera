---
id: certificate-challenge
kind: операция
context: auth
name: "Проверка владения ключом"
aliases:
  - "challenge-response"
relations:
  references:
    - auth.credential
anchors:
  code:
    - "crates/tessera_core/src/challenge/mod.rs"
  test:
    - "crates/tessera_core/tests/challenge_dispatch.rs"
requirements:
  CCH-001:
    kind: инвариант
    subjects:
      - auth.certificate-challenge
    origins:
      - "challenge-response::Round-trip подписи свежего nonce"
    evidence:
      test:
        - "crates/tessera_core/tests/challenge_dispatch.rs"
  CCH-002:
    kind: операционное
    subjects:
      - auth.certificate-challenge
    origins:
      - "challenge-response::Диспетчеризация по типу ключа"
    evidence:
      code:
        - "crates/tessera_core/src/challenge/mod.rs"
  CCH-003:
    kind: инвариант
    subjects:
      - auth.certificate-challenge
    origins:
      - "challenge-response::PKCS#11-вариант — подпись на токене"
    evidence:
      test:
        - "crates/tessera_core/tests/challenge_dispatch.rs"
  CCH-004:
    kind: операционное
    subjects:
      - auth.certificate-challenge
    origins:
      - "challenge-response::Отсутствие replay-protection — by design"
    evidence:
      code:
        - "crates/tessera_core/src/challenge/mod.rs"
---
# Проверка владения ключом

Эта страница заменяет процедурную capability-спеку OpenSpec «challenge-response»: она
помещает каждое прежнее требование в адресуемую норму с владельцем, видом и
проверяемым происхождением. Под каждым нормативным предложением сохранены подробные условия, отрицательные
сценарии и rationale; они входят в ту же страницу и уточняют границы нормы.

### CCH-001 — Round-trip подписи свежего nonce

[[auth.certificate-challenge|Проверка владения ключом]] MUST соблюдать правило «Round-trip подписи свежего nonce» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/challenge-response/spec.md, requirement «Round-trip подписи свежего nonce».

Система должна: сгенерировать 32-байтовый nonce из OS RNG → подписать приватным ключом → проверить подпись публичным ключом ИЗ leaf-сертификата (не из заявленного носителем). Nonce и подпись должны держаться в `Zeroizing` (стирание при drop). Провал верификации → `CryptoError::BadSignature` → `PAM_PERM_DENIED`, fail-closed (challenge/mod.rs:38–86).

#### Scenario: RNG-сбой
- **WHEN** OS RNG недоступен
- **THEN** `CryptoError::Rng` → отказ auth (fail-closed, без fallback)

### CCH-002 — Диспетчеризация по типу ключа

[[auth.certificate-challenge|Проверка владения ключом]] MUST соблюдать правило «Диспетчеризация по типу ключа» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/challenge-response/spec.md, requirement «Диспетчеризация по типу ключа».

Система должна выбирать алгоритм по `pub_key.id()` (challenge/mod.rs:51–86):

| Ключ | Алгоритм |
|---|---|
| RSA | RSASSA-PSS, SHA-256, MGF1-SHA256, salt=32 |
| EC P-256 | ECDSA + SHA-256 |
| EC P-384 | ECDSA + SHA-384 |
| GOST 2012-256 (NID 979) | gost-engine + Streebog-256 |
| GOST 2012-512 (NID 980) | gost-engine + Streebog-512 |
| Ed25519 | должен отвергаться (`UnsupportedKey`, явно вне scope) |
| EC без named curve / иное | должен отвергаться |

#### Scenario: GOST-ключ без engine
- **WHEN** GOST-ключ, gost-engine не загружается
- **THEN** `EngineLoadFailed` → отказ (fail-closed); self_check ловит это раньше при `needs_gost()` (self_check.rs:51–58)

### CCH-003 — PKCS#11-вариант — подпись на токене

[[auth.certificate-challenge|Проверка владения ключом]] MUST соблюдать правило «PKCS#11-вариант — подпись на токене» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/challenge-response/spec.md, requirement «PKCS#11-вариант — подпись на токене».

Для токенов подпись должна выполняться на устройстве (`C_Sign`), верификация — на хосте публичным ключом из найденного на токене сертификата (sign.rs:83–127). ECDSA raw `r||s` должен перекодироваться в DER до верификации OpenSSL.

#### Scenario: GOST через PKCS#11
- **WHEN** на токене ключ GOSTR3410
- **THEN** `MechanismNotSupported` → отказ (mechanism.rs:160–167)
- Design-граница: GOST поддерживается только на PKCS#12-пути через gost-engine; на PKCS#11-пути GOST-подпись не выполняется (cryptoki 0.7 без CKM_GOSTR3410), Рутокен/JaCarta применимы для RSA/ECDSA-сертификатов (так и зафиксировано в architecture.md). Поддержка GOST через PKCS#11 — proposal [gost-pkcs11](../../changes/gost-pkcs11/).

### CCH-004 — Отсутствие replay-protection — by design

[[auth.certificate-challenge|Проверка владения ключом]] MUST соблюдать правило «Отсутствие replay-protection — by design» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/challenge-response/spec.md, requirement «Отсутствие replay-protection — by design».

Challenge-response не должен претендовать на защиту от replay: nonce генерируется и проверяется внутри одного вызова доверенного PAM-процесса; внешнего канала, который можно записать и воспроизвести, не существует. Инвариант — только «носитель владеет приватным ключом в момент аутентификации». Зафиксировано как осознанное решение (сессии May 2026; memory `reference_astra_e2e`).

#### Scenario: Nonce в пределах одного процесса
- **WHEN** выполняется challenge-response
- **THEN** nonce генерируется и проверяется внутри одного вызова PAM-процесса; защита от replay не предоставляется и не заявляется

