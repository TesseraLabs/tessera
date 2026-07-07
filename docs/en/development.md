# `tessera` contributor guide

This document is a guide for a developer who is opening the repository for the
first time and wants to make a change. The goal: a working environment, passing
tests, and a first PR in a single day.

## 1. Local build

### 1.1 System dependencies

Astra Linux SE / Ubuntu 22.04 / Debian 12:

```bash
sudo apt install -y \
    build-essential pkg-config \
    libssl-dev libudev-dev libdbus-1-dev libpam0g-dev libsystemd-dev \
    softhsm2 opensc opensc-pkcs11 \
    pamtester clang
```

The Rust toolchain is pinned in [`rust-toolchain.toml`](../../rust-toolchain.toml).
If `rustup` is present, the toolchain is downloaded automatically:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup show              # picks the version from rust-toolchain.toml
```

### 1.2 Build

```bash
cargo build --workspace
cargo build --workspace --release
```

### 1.3 Cargo features

- Default: no special features.
- `tessera_core/pkcs11-tests` — enables the integration tests that require a
  real `gost-engine` or softhsm2:

  ```bash
  cargo test --workspace --features tessera_core/pkcs11-tests
  ```

## 2. Tests

### 2.1 Unit and ordinary integration tests

```bash
cargo test --workspace
```

All unit and integration tests must pass.

### 2.2 Integration tests with softhsm2

```bash
sudo apt install softhsm2 opensc-pkcs11
softhsm2-util --init-token --slot 0 \
    --label test --pin 1234 --so-pin 5678
SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf \
    cargo test --workspace --features tessera_core/pkcs11-tests
```

The PKCS#11 tests add an extra set of integration checks (module loading,
certificate lookup, the `CKA_EXTRACTABLE` check).

### 2.3 Smoke test with `pamtester`

Requires Linux + root + an installed `tessera`:

```bash
# In a separate Astra SE 1.7.5 VM:
sudo apt install ./target/release/tessera_0.4.0-1_amd64.deb
sudo /usr/share/tessera/integrate-pam.sh --mode=2fa /etc/pam.d/sudo
pamtester sudo alice authenticate
```

## 3. Pre-commit hooks

A [`.pre-commit-config.yaml`](../../.pre-commit-config.yaml) is shipped at the
root of the repository. To install:

```bash
pip install pre-commit
pre-commit install
```

What is checked on commit:

- `cargo fmt --all -- --check`;
- `cargo clippy --workspace --all-targets -- -D warnings`;
- `cargo deny check`;
- `cargo test --workspace`;
- the syntax of bash scripts (`bash -n`);
- the `Cargo.toml` version matching `debian/changelog`;
- the absence of MAX_INTEGRITY OID placeholders in tracked files.

If you do not have the `pre-commit` framework, you can run the commands
manually:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## 4. Commit style

The format is Conventional Commits:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Commit messages are in English. Examples:

- `feat(monitord): handle suspend/resume via D-Bus`
- `fix(core): correct CRL freshness check for mode = "crl"`
- `docs(install): add Mode A scenario with FAT32 media`
- `chore: bump serde to 1.0.x`
- `refactor(proto): rename Pong to HelloAck for consistency`
- `test(monitord): add suspend_grace e2e test`

`<scope>` corresponds to the crate or module: `monitord`, `core`, `proto`,
`pam`, `install`, `arch`, `security`, `release`, `dev`.

## 5. PR workflow

1. **Branch off `main`:**

   ```bash
   git checkout -b feat/awesome-feature main
   ```

2. **Atomic commits:** one logically coherent commit at a time. A PR usually
   contains 1–5 commits.
3. **Automatic CI runs:** GitHub Actions:
   - [`.github/workflows/build.yml`](../../.github/workflows/build.yml) —
     tests (ubuntu: `cargo test`, astra container: `cargo nextest run`),
     building the `.deb` in both variants, `lintian` (the ubuntu leg);
   - [`.github/workflows/lint.yml`](../../.github/workflows/lint.yml) —
     `cargo clippy -D warnings` and supply-chain (`cargo deny`, `cargo audit`);
   - [`.github/workflows/nightly.yml`](../../.github/workflows/nightly.yml) —
     a daily run of the tests in the release profile.
   `cargo fmt --check` runs in the pre-commit hook, not in CI.
4. **Code review checklist:**
   - is there a test for the new functionality?
   - are the relevant docs updated (configuration, architecture,
     threat-model)?
   - has a new TOML field appeared without documentation?
   - does the change violate the fail-closed invariants (see
     [architecture.md §13](architecture.md#13-fail-closed-rules))?
   - is the reproducible build still intact?
5. **Merge via squash + rebase merge.** Large PRs — reviewed in batches of 3–5
   commits; squashed into `main` for a clean history.

## 6. How to add a new PKCS#11 provider

The current support is implemented in
[`crates/tessera_core/src/token/`](../../crates/tessera_core/src/token/).

Steps:

1. Study the interfaces (`PkcsModule`, `Session`, `Slot`).
2. Implement a new adapter in a submodule (for example, `token/newvendor/`).
3. Register it via `crypto_backend = "pkcs11_native"` with
   `pkcs11_module = "/usr/lib/libnewvendor.so"`.
4. Add tests:
   - positive: module loading + certificate lookup;
   - negative: the module did not load (a nonexistent path);
   - non-extractable: the `CKA_EXTRACTABLE = false` check.
5. Update the documentation:
   - [README.md](../../README.md) — the "Supported tokens" section;
   - [docs/install.md](install.md) — the driver installation section;
   - [docs/configuration.md](configuration.md) — the modules table;
   - [docs/threat-model.md](threat-model.md) — §3.3 (if the threat model
     changes).

## 7. How to add a new host_id source

See [`crates/tessera_core/src/host_identity/`](../../crates/tessera_core/src/host_identity/).

Steps:

1. Create a `<source>.rs` module implementing the `HostIdSource` trait.
2. Register it in `chain.rs` (`HostIdentityResolver::from_validated`).
3. Add it to `RawHostIdentity::sources` (name validation).
4. Add it to `HostIdSourceKind` (the associated enum).
5. Tests:
   - positive: the source returns a value;
   - negative: the source is unavailable → the next in the chain fires.
6. Update [docs/configuration.md](configuration.md) (the `[host_identity]`
   table) and [architecture.md §12](architecture.md#12-host-identity-chain).

## 7.1 Where the certificate authorization logic lives

The authorization of "which user on which host" is fully described in the
certificate itself through X.509 extensions and is verified in code:

- `crates/tessera_core/src/x509/host_binding_ext.rs` — parsing of the
  `pam_cert_host_binding` extension (the OID and ASN.1 structure are in
  `x509/oids.rs`).
- `crates/tessera_core/src/x509/user_binding_ext.rs` — parsing of the
  `pam_cert_user_binding` extension.
- `verify_cert_scope` — the final matching of the parsed entries against
  `host_id_hash` and `pam_user`. See also
  [docs/cert-issuance.md](cert-issuance.md) for the semantics of the entries.

## 8. Versioning

SemVer 2.0.0 semantics:

- **MAJOR** — breaking changes (incompatible changes to the `config.toml`
  schema, the IPC protocol, removed configuration options).
- **MINOR** — backward-compatible new functionality (a new PKCS#11 provider, a
  new host_id source, a new stage in hooks).
- **PATCH** — bug fixes, doc updates, dependency updates without an API change.

Each MAJOR release requires:

- a migration note in [docs/changelog.md](../ru/changelog.md) (Russian);
- an update of `PROTOCOL_VERSION` in
  [`crates/tessera_proto/src/version.rs`](../../crates/tessera_proto/src/version.rs)
  (if the wire protocol changes);
- an update of the threat model ([docs/threat-model.md](threat-model.md)).

## 9. Further reading

- [docs/architecture.md](architecture.md).
- [docs/configuration.md](configuration.md).
- [docs/threat-model.md](threat-model.md).
- [docs/changelog.md](../ru/changelog.md) (Russian).

## Git hooks

The repo ships hooks in `scripts/git-hooks/` that block commits and pushes to
`main` on weekdays between 08:00 and 19:00 local time. Enable them once per
clone:

```sh
git config core.hooksPath scripts/git-hooks
```

`git commit --no-verify` / `git push --no-verify` override in emergencies.
