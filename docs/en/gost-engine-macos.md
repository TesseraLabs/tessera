# Building the GOST engine for OpenSSL on macOS (Homebrew, arm64)

Homebrew has no prebuilt package for `openssl@3` — build it from the
source of the [gost-engine](https://github.com/gost-engine/engine)
project. Needed only for issuing test GOST certificates locally (§3–§4
of [install.md](install.md)) on the administrator's workstation;
`tessera` itself is Linux-only and does not install on macOS.

## 1. Build tools

```bash
brew install cmake
```

## 2. Clone the engine

```bash
git clone --recurse-submodules https://github.com/gost-engine/engine.git gost-engine
cd gost-engine
```

## 3. Build against your OpenSSL version

```bash
mkdir build && cd build
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3) \
  -DOPENSSL_ENGINES_DIR=$(brew --prefix openssl@3)/lib/engines-3
cmake --build . -j"$(sysctl -n hw.ncpu)"
```

The engine is a binary ABI module — it must be built against the exact
OpenSSL version it will run with. If you later update `openssl@3` via
`brew`, rebuild the engine.

## 4. Install into the engines directory

```bash
sudo cmake --install .
```

With `OPENSSL_ENGINES_DIR` set as above, this lands directly at
`$(brew --prefix openssl@3)/lib/engines-3/gost.dylib`; `/opt/homebrew`
is usually user-owned, so `sudo` may not be needed.

If the install target isn't found, copy it manually:

```bash
cp bin/gost.dylib $(brew --prefix openssl@3)/lib/engines-3/gost.dylib
```

## 5. Register the engine in `openssl.cnf` (optional)

Find the active config: `openssl version -d`. Add to `openssl.cnf`:

```ini
openssl_conf = openssl_def

[openssl_def]
engines = engine_section

[engine_section]
gost = gost_section

[gost_section]
engine_id = gost
dynamic_path = /opt/homebrew/Cellar/openssl@3/<version>/lib/engines-3/gost.dylib
default_algorithms = ALL
CRYPT_PARAMS = id-Gost28147-89-CryptoPro-A-ParamSet
```

Without editing the config, the engine still loads explicitly with the
`-engine gost` flag on `openssl` commands — which is how every example
in [install.md](install.md) invokes it.

## 6. Verify

```bash
openssl engine -t -c gost
```

Expected output: a list of GOST algorithms (`GOST94`, `GOST2001`,
`GOST28147`, …) and `[ available ]`.

## Don't forget the explicit `-engine gost`

On macOS, without editing `openssl.cnf` (step 5), the engine is not
loaded automatically — every command reading or verifying a GOST key or
certificate needs an explicit `-engine gost`. In particular, `openssl
verify` without this flag fails with `X509_PUBKEY_get0:decode error` /
`unable to get local issuer certificate`, even though the key and
certificate are perfectly valid — the engine simply has nothing to
decode the GOST public-key structure with. The correct form:

```bash
openssl verify -engine gost -CAfile ca.pem ca.pem
```
