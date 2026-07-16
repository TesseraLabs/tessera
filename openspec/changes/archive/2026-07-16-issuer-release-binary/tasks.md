# Tasks: issuer-release-binary

CI-конфиг (не application-код) — правит координатор. Rust не меняется.

## 1. Workflow release-issuer.yml

- [x] 1.1 `cabinet-dist` job (ubuntu, Node+Rust+wasm32): `bash cabinet/build.sh` → upload-artifact `cabinet-dist` (`cabinet/dist/**`).
- [x] 1.2 `build-issuer` matrix (needs cabinet-dist): linux-x86_64 (container `ghcr.io/tesseralabs/tessera-astra-builder:latest`), macos-arm64 (macos-latest), windows-x86_64 (windows-latest). Каждый: download `cabinet-dist` → `cabinet/dist`; rust toolchain (rustup show); `cargo build --release -p tessera_issuer --features cli,pkcs11,vault,serve,embed-cabinet`; стейдж бинаря (`target/release/issuer[.exe]` → `issuer-<target>[.exe]`); upload-artifact.
- [x] 1.3 `release-issuer` job (needs build-issuer, `if: startsWith(github.ref,'refs/tags/v')` + `github.repository == 'TesseraLabs/tessera'`): download все issuer-*; `sha256sum` → `SHA256SUMS`; `softprops/action-gh-release@v3` (draft, `files:` бинари+SHA256SUMS, тот же тег).
- [x] 1.4 Триггеры: `push: tags ['v*']` + `workflow_dispatch` (input tag для ре-релиза). Пин сторонних actions по SHA (паритет с build.yml). GHCR-доступ к astra-builder (у issuer.yml/build.yml уже настроен — тот же insteadOf/токен).

## 2. Согласованность

- [x] 2.1 Проверить, что astra-builder содержит нужный Rust toolchain (rust-toolchain.toml) — как для `.deb`. macOS/Windows раннеры — setup rust.
- [x] 2.2 Vault (native-tls) на Linux-контейнере: убедиться, что в astra-builder есть openssl/pkg-config (для нативного бэкенда сборки); если нет — доустановить в шаге.

## 3. Верификация

- [x] 3.1 YAML-валидность `release-issuer.yml` (+ actionlint если есть).
- [x] 3.2 Локально: `cabinet/build.sh` → `cargo build --release -p tessera_issuer --features cli,pkcs11,vault,serve,embed-cabinet` компилируется; бинарь `issuer serve --module … --key …` раздаёт кабинет (смоук).
- [ ] 3.3 Полный прогон — на первом теге/`workflow_dispatch` после мержа (отметить как post-merge проверку).

## 4. Спека

- [ ] 4.1 `openspec archive issuer-release-binary` → промоут MODIFIED `Release job` в `openspec/specs/build-release/spec.md`.
