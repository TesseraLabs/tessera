# Tasks: drop-serve

## 1. Remove the serve command and its code

- [x] 1.1 Delete `crates/tessera_issuer/src/serve.rs`; drop `pub mod serve` from `lib.rs`
- [x] 1.2 Retain `confirm.rs` as public library API; un-gate it from `serve` to `native` (generic operator-confirmation channel for signing frontends), drop its `Msg` dependency (inline localized strings)
- [x] 1.3 Remove the `serve` crate feature and the `tiny_http`/`subtle` deps (crate + workspace `tiny_http`); `subtle` stays for `tessera_core`
- [x] 1.4 `cli.rs`: remove the `Serve` command, `ServeArgs`, the `run_serve`/`finish_serve`/`resolve_cabinet_source`/`resolve_registry_key`/`reject_registry_key` block, and the serve tests
- [x] 1.5 Registry signing: remove the CLI wiring (`--registry-key`, `resolve_registry_key`/`reject_registry_key`) with `serve`; **keep** the PKCS#11 backend capability (`Pkcs11Config.registry_key`, `verify_registry_key_p256`, `RegistryKeyNotP256`, `resolve_algorithm` branch, unit + SoftHSM tests) as public library API with neutral docs
- [x] 1.6 `l10n.rs`: drop the serve-only `Msg` variants (incl. the confirm strings, now inlined in `confirm.rs`); keep the CLI messages and the summary module

## 2. CI and release

- [x] 2.1 `issuer.yml`: drop `serve` from the feature lists; CLI-only narrative
- [x] 2.2 `release-issuer.yml`: `ISSUER_FEATURES=cli,pkcs11,vault,file`

## 3. Docs

- [x] 3.1 `issuer.md` (ru/en): agent + cabinet become a commercial-delivery pointer; open issuer = CLI
- [x] 3.2 `index.md` (ru/en): issuer summary drops the agent/cabinet
- [x] 3.3 `threat-model.md` §11 (ru/en): keep the browser-issuance analysis, mark the surface as moved to the commercial product

## 4. Openspec

- [x] 4.1 `issuer-signing` delta: ADDED (`Выделенный ключ реестра в PKCS#11-бэкенде`); MODIFIED (file backend key-id surface, cross-platform, localization → CLI); REMOVED (`Локальный агент issuer serve`, `Подтверждение операции оператором на стороне агента`)
- [x] 4.2 `build-release` delta: MODIFIED `Release job` → CLI-only `issuer` binary (`cli,pkcs11,vault,file`); archive strictly after `cabinet-externalization` (see proposal)
- [x] 4.3 Remove the `issuer-registry-signing` change (agent surface commercial; backend requirement folded into the `issuer-signing` delta)
- [x] 4.4 Update the specs `README.md` index entry for `issuer-signing` (drop the agent clause)
- [ ] 4.5 Sync the `issuer-signing` + `build-release` deltas (Purpose + requirements in the main specs) and archive this change

## 5. Verification

- [x] 5.1 `cargo build` (default and all remaining features)
- [x] 5.2 `cargo clippy --all-targets --all-features -- -D warnings`
- [x] 5.3 `cargo test -p tessera_issuer -p tessera_cli`
- [x] 5.4 `openspec validate drop-serve --strict`
- [x] 5.5 grep-cleanliness: `serve`/`cabinet-dir`/`sign-registry` gone from code and CI (outside change history and the retained threat-model analysis)
