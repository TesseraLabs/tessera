# Гид контрибьютора `tessera`

Этот документ — гид для разработчика, который впервые открывает
репозиторий и хочет внести изменение. Цель: рабочее окружение,
прохождение тестов и первый PR за один день.

## 1. Локальная сборка

### 1.1 Системные зависимости

Astra Linux SE / Ubuntu 22.04 / Debian 12:

```bash
sudo apt install -y \
    build-essential pkg-config \
    libssl-dev libudev-dev libdbus-1-dev libpam0g-dev libsystemd-dev \
    softhsm2 opensc opensc-pkcs11 \
    pamtester clang
```

Toolchain Rust — фиксирован в [`rust-toolchain.toml`](../rust-toolchain.toml).
При наличии `rustup` toolchain скачивается автоматически:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup show              # выберет версию из rust-toolchain.toml
```

### 1.2 Сборка

```bash
cargo build --workspace
cargo build --workspace --release
```

### 1.3 Cargo features

- Default: без специальных фич.
- `tessera_core/pkcs11-tests` — включает интеграционные тесты,
  требующие реального `gost-engine` или softhsm2:

  ```bash
  cargo test --workspace --features tessera_core/pkcs11-tests
  ```

## 2. Тесты

### 2.1 Юнит и обычные интеграционные тесты

```bash
cargo test --workspace
```

Все unit- и integration-тесты должны проходить.

### 2.2 Интеграционные тесты с softhsm2

```bash
sudo apt install softhsm2 opensc-pkcs11
softhsm2-util --init-token --slot 0 \
    --label test --pin 1234 --so-pin 5678
SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf \
    cargo test --workspace --features tessera_core/pkcs11-tests
```

PKCS#11-тесты добавляют дополнительный набор интеграционных проверок
(загрузка модуля, поиск сертификата, проверка `CKA_EXTRACTABLE`).

### 2.3 Smoke с `pamtester`

Требует Linux + root + установленный `tessera`:

```bash
# В отдельной VM Astra SE 1.7.5:
sudo apt install ./target/release/tessera_0.1.1-1_amd64.deb
sudo /usr/share/tessera/integrate-pam.sh --mode=2fa /etc/pam.d/sudo
pamtester sudo alice authenticate
```

## 3. Pre-commit hooks

В корне репозитория поставляется
[`.pre-commit-config.yaml`](../.pre-commit-config.yaml). Установка:

```bash
pip install pre-commit
pre-commit install
```

Что проверяется при коммите:

- `cargo fmt --all -- --check`;
- `cargo clippy --workspace --all-targets -- -D warnings`;
- `cargo deny check`;
- `cargo test --workspace`;
- `markdownlint-cli2 "**/*.md"` (для `*.md` файлов в коммите).

Если у вас нет `pre-commit`-фреймворка, можно запускать команды
вручную:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## 4. Стиль коммитов

Формат — Conventional Commits:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Примеры:

- `feat(monitord): добавлена обработка suspend/resume через D-Bus`
- `fix(core): исправлено поведение OCSP timeout при mode = "crl_then_ocsp"`
- `docs(install): добавлен сценарий для Mode A с FAT32-носителем`
- `chore: обновлена зависимость serde до 1.0.x`
- `refactor(proto): переименован Pong в HelloAck для консистентности`
- `test(monitord): добавлен e2e-тест suspend_grace`

`<scope>` соответствует крейту или модулю: `monitord`, `core`, `proto`,
`pam`, `install`, `arch`, `security`, `release`, `dev`.

## 5. Workflow PR

1. **Branch off `main`:**

   ```bash
   git checkout -b feat/awesome-feature main
   ```

2. **Атомарные коммиты:** один логически целостный коммит за раз. PR
   обычно содержит 1–5 коммитов.
3. **Авто-запуск CI:** GitHub Actions
   ([`.github/workflows/build-deb.yml`](../.github/workflows/build-deb.yml))
   проверяет:
   - `cargo fmt`;
   - `cargo clippy`;
   - `cargo test`;
   - сборку `.deb`;
   - `lintian`.
4. **Code review checklist:**
   - есть ли тест на новую функциональность?
   - обновлены ли соответствующие docs (configuration, architecture,
     threat-model)?
   - не появилось ли новое поле в TOML без документации?
   - не нарушает ли изменение fail-closed инварианты (см.
     [architecture.md §13](architecture.md#13-fail-closed-правила))?
   - reproducible build не сломался?
5. **Слить через squash + rebase merge.** Большие PR — review по 3–5
   коммитов; squash в `main` для чистой истории.

## 6. Как добавить новый PKCS#11-провайдер

Текущая поддержка реализована в
[`crates/tessera_core/src/token/`](../crates/tessera_core/src/token/).

Шаги:

1. Изучить интерфейсы (`PkcsModule`, `Session`, `Slot`).
2. Реализовать новый адаптер в подмодуле (например, `token/newvendor/`).
3. Зарегистрировать его через `crypto_backend = "pkcs11_native"`
   с указанием `pkcs11_module = "/usr/lib/libnewvendor.so"`.
4. Добавить тесты:
   - positive: загрузка модуля + поиск сертификата;
   - negative: модуль не загрузился (несуществующий путь);
   - non-extractable: проверка `CKA_EXTRACTABLE = false`.
5. Обновить документацию:
   - [README.md](../README.md) — раздел «Поддерживаемые токены»;
   - [docs/install.md](install.md) — раздел установки драйвера;
   - [docs/configuration.md](configuration.md) — таблица модулей;
   - [docs/threat-model.md](threat-model.md) — §3.3 (если меняется
     модель угроз).

## 7. Как добавить новый источник host_id

См. [`crates/tessera_core/src/host_identity/`](../crates/tessera_core/src/host_identity/).

Шаги:

1. Создать модуль `<source>.rs` с реализацией трейта `HostIdSource`.
2. Зарегистрировать в `chain.rs` (`HostIdentityResolver::from_validated`).
3. Добавить в `RawHostIdentity::sources` (валидация имени).
4. Добавить в `HostIdSourceKind` (ssoc-енум).
5. Тесты:
   - positive: источник возвращает значение;
   - negative: источник недоступен → следующий в chain срабатывает.
6. Обновить [docs/configuration.md](configuration.md) (таблица
   `[host_identity]`) и [architecture.md §12](architecture.md#12-host-identity-chain).

## 7.1 Где живёт логика авторизации сертификата

Авторизация «какой пользователь на каком хосте» полностью описана в
самом сертификате через X.509-расширения и проверяется в коде:

- `crates/tessera_core/src/x509/host_binding_ext.rs` — парсинг
  расширения `pam_cert_host_binding` (OID и ASN.1-структура — в
  `x509/oids.rs`).
- `crates/tessera_core/src/x509/user_binding_ext.rs` — парсинг
  расширения `pam_cert_user_binding`.
- `verify_cert_scope` — финальная сверка распарсенных записей с
  `host_id_hash` и `pam_user`. См. также
  [docs/cert-issuance.md](cert-issuance.md) для семантики записей.

## 8. Версионирование

Семантика SemVer 2.0.0:

- **MAJOR** — breaking changes (несовместимые изменения схемы
  `config.toml`, IPC-протокола, удалённые опции конфигурации).
- **MINOR** — backward-compatible новая функциональность (новый
  PKCS#11-провайдер, новый источник host_id, новый стейдж в hooks).
- **PATCH** — bug fixes, doc updates, обновления зависимостей без
  изменения API.

Каждый MAJOR-релиз требует:

- миграционной заметки в [docs/changelog.md](changelog.md);
- обновления `PROTOCOL_VERSION` в
  [`crates/tessera_proto/src/version.rs`](../crates/tessera_proto/src/version.rs)
  (если изменяется wire-протокол);
- обновления модели угроз ([docs/threat-model.md](threat-model.md)).

## 9. Дальнейшее чтение

- [docs/architecture.md](architecture.md).
- [docs/configuration.md](configuration.md).
- [docs/threat-model.md](threat-model.md).
- [docs/changelog.md](changelog.md).

## Git hooks

The repo ships hooks in `scripts/git-hooks/` that block commits and pushes to
`main` on weekdays between 09:00 and 19:00 local time. Enable them once per
clone:

```sh
git config core.hooksPath scripts/git-hooks
```

`git commit --no-verify` / `git push --no-verify` override in emergencies.
