# Tasks: issuer-file-backend-and-serve-backends

## 1. Файловый бэкенд (модуль)

- [x] 1.1 Cargo: фича `file` в `tessera_issuer` (native-only), зависимости `p384` и `pkcs8` (фичи `encryption`, `pem`) в workspace и крейте
- [x] 1.2 `file.rs`: загрузка PKCS#8 (PEM/DER), расшифровка EncryptedPrivateKeyInfo, определение типа ключа (P-256/P-384/RSA), типизированные ошибки (`NotFound`, `Permissions`, `Malformed`, `WrongPassphrase`, `UnsupportedKeyType`, `AlgorithmMismatch`; добавлен `PassphraseUnavailable` — контракт источника пароля)
- [x] 1.3 `file.rs`: проверка прав файла на Unix (`mode & 0o077 != 0` → отказ до чтения), локализованное предупреждение о незашифрованном ключе
- [x] 1.4 `file.rs`: источник пароля — pinentry, fallback `TESSERA_ISSUER_KEY_PASSPHRASE`; `SecretString`/`zeroize` для пароля и расшифрованного DER
- [x] 1.5 `FileSigner: SignatureBackend` — `algorithm()` из ключа, `sign()` тремя алгоритмами; сверка `KeyId` (дефолт — basename файла) с семантикой `UnknownKey`
- [x] 1.6 Юнит-тесты: подпись P-256/P-384/RSA с криптографической проверкой подписи; зашифрованный ключ (генерация в тесте через `pkcs8`); неверный пароль; широкие права (0644); mismatch `--algorithm`; неподдерживаемый тип ключа; плейн-предупреждение

## 2. CLI: --backend file

- [x] 2.1 `cli.rs`: `BackendKind::File`, флаг `--key-file` в `BackendArgs`, `run_file` в `dispatch_with_backend`; валидация «`--key-file` обязателен для file»; `--key`/`--algorithm` стали Option (для file опциональны, для pkcs11/vault валидируются в runtime)
- [x] 2.2 `l10n.rs`: локализовано предупреждение о плейн-ключе; ошибки бэкенда — английский Display под локализованным префиксом `CliError::Backend` (паттерн pkcs11/vault)
- [x] 2.3 e2e CLI-тест без внешних зависимостей: `issue-root` → `issue-ca` → `issue-leaf` → `verify` c `--backend file` (все три алгоритма), включая зашифрованный ключ (инъекция PassphraseSource; env-fallback покрыт в keypass)

## 3. serve: выбор бэкенда

- [x] 3.1 `ServeArgs`: `--backend` (дефолт `pkcs11`), `--key-file`, vault-флаги (`--vault-addr`, `--mount`, `--vault-key`, `--ca-bundle`, `--prehashed`) — имена едины с `BackendArgs`
- [x] 3.2 `run_serve`: построение бэкенда по `--backend` (Pkcs11Signer | VaultSigner | FileSigner) и передача в генерик `serve()` через общий `finish_serve`; валидация обязательных флагов по бэкенду; `serve.rs::Agent`/`serve()` не изменены
- [x] 3.3 Тесты: валидация флагов по бэкендам; контракт-тест старой формы `issuer serve --module … --key …` (без `--backend` → PKCS#11); agent-тест с FileSigner — handler-level цикл `/info` + `/sign` с криптографической проверкой подписи
- [x] 3.4 Gated `vault-tests`: сценарий агента поверх Vault dev-сервера (по образцу `vault_sign.rs`), graceful skip без vault-бинаря

## 4. Документация

- [x] 4.1 `docs/{ru,en}/issuer.md`: подраздел «Ключ в файле» в «Бэкендах подписи» (формат, права, пароль, конвертация openssl, ГОСТ-ограничение); примеры запуска `issuer serve` для всех трёх бэкендов. Оговорка «файл не поддерживается» существует только в незакоммиченной ветке cabinet-operation-choice — снять при мерже веток
- [x] 4.2 `docs/{ru,en}/threat-model.md` §11: интро «не кастодиан» уточнено, строка 11.1.7 (поверхность файлового ключа), пункт в 11.3 (извлекаемость при компрометации хоста; прод-рекомендация — PKCS#11/Vault)
- [ ] 4.3 `docs/ru/changelog.md`: запись о новых возможностях (при подготовке релиза)

## 5. Финализация

- [x] 5.1 Полный прогон: `cargo test` workspace (native) зелёный; `cargo clippy`/`cargo fmt --check` чистые (полный набор фич); wasm-сборка (`tessera_issuer_wasm`) проверена — фича `file` в wasm-граф не попадает
- [x] 5.2 Ревью master-code-reviewer: APPROVE, CRITICAL/HIGH нет; LOW-фиксы применены (RSA base-blinding через `sign_with_rng`; оговорка про владение файлом в доках); информационные каветы (drop-гигиена upstream SigningKey, TOCTOU-окно) зафиксированы в ревью
- [x] 5.3 Обновить релизный профиль сборки бинаря `issuer`: `ISSUER_FEATURES` в `.github/workflows/release-issuer.yml` дополнен фичей `file`
