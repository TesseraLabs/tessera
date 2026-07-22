# Tasks: cabinet-externalization

## 1. Externalization

- [x] 1.1 Remove `cabinet/`, `crates/tessera_issuer_wasm`, the `embed-cabinet` feature and `include_dir`/`wasm-bindgen` workspace deps
- [x] 1.2 `issuer serve`: external bundle via `--cabinet-dir` (SPA fallback, reserved API routes, traversal containment), localized placeholder without the flag
- [x] 1.3 CI: drop cabinet jobs from `issuer.yml` and `cabinet-dist` from `release-issuer.yml`; release features `cli,pkcs11,vault,serve`
- [x] 1.4 Docs (`docs/{ru,en}`): cabinet narrative switched to the external bundle
- [x] 1.5 Move the `issuer-cabinet` spec out of `openspec/specs`
- [x] 1.6 Sync the `build-release` delta and archive this change
