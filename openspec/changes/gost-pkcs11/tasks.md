# Tasks: gost-pkcs11

## 1. Разблокировка cryptoki

- [ ] 1.1 Исследовать актуальные версии cryptoki (changelog parallaxsecond/rust-cryptoki): есть ли CKM_GOSTR3410*/vendor-defined механизмы; зафиксировать выбранный вариант лестницы (upgrade / vendor-defined / raw FFI) в design.md
- [ ] 1.2 Собрать модуль GOST-констант (CKM_*, CKA_GOSTR3410_PARAMS) по заголовкам Рутокен SDK / JaCarta SDK / TC26-спецификации с ссылками на источники; unit-тест согласованности констант с выбранной библиотекой
- [ ] 1.3 Обновить зависимость (или добавить cryptoki-sys-островок); прогнать `cargo deny check` + `cargo audit`; убедиться, что RSA/ECDSA-пути не регрессируют (полный тест-сьют)

## 2. Выбор механизма (mechanism.rs)

- [ ] 2.1 GOST-ветка `select_mechanism`: определение 256/512 по атрибутам ключа, сверка с NID публичного ключа серта (979/980), расхождение → отказ; unit-тесты (256, 512, mismatch, отсутствие атрибутов)
- [ ] 2.2 Проверка `C_GetMechanismList`: предпочтение «хэш на токене», fallback «Streebog на хосте + raw-подпись», ни одного GOST-механизма → `MechanismNotSupported`; unit-тесты ветвления
- [ ] 2.3 Вариант «хэш на хосте»: Streebog-256/512 через gost-engine до C_Sign (ленивая загрузка, fail-closed при отсутствии engine)

## 3. Подпись и верификация (sign.rs, gost-crypto)

- [ ] 3.1 GOST-вариант верификации подписи токена: публичный ключ ИЗ серта + gost-engine; перекодировка raw r||s токена в форму, ожидаемую engine (порядок байт — зафиксировать тестами на эталонных векторах)
- [ ] 3.2 Негативные тесты: битая подпись → BadSignature → PAM_PERM_DENIED; GOST-ключ при недоступном engine → отказ; Zeroizing для nonce/подписи сохраняется

## 4. Железо и документация

- [ ] 4.1 Runbook ручной проверки (tests/scripts/install-and-test.sh или отдельный): JaCarta-2 GOST и Рутокен ЭЦП 2.0/3.0 — happy-path, wrong-PIN→MAXTRIES, removal-enforcement с GOST-токеном; критерий приёмки — round-trip «подписал токен → верифицировал engine» на обоих вендорах
- [ ] 4.2 Прогон на Astra VM с проброшенным токеном (VBox USB passthrough), включая `pkcs11_locking_mode = mutex` на legacy JaCarta
- [ ] 4.3 Обновить docs/architecture.md (носители: GOST на PKCS#11 работает), configuration.md; снять KNOWN GAP-маркеры в main-спеках challenge-response/token-pkcs11/gost-crypto через `/opsx:sync` или archive
