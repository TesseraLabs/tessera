# softhsm2 integration test setup

This directory contains the helper scripts needed to provision a
softhsm2 token suitable for the PKCS#11 integration tests under
`crates/tessera_core/tests/pkcs11_integration.rs` and
`crates/pam_tessera/tests/auth_e2e_pkcs11.rs`.

## Prerequisites

Both `softhsm2-util` and `pkcs11-tool` (from `opensc`) must be on
`PATH`, plus `openssl` for the cert-generation recipe at the bottom.

* Linux (Debian/Ubuntu/Astra): `sudo apt install softhsm2 opensc openssl`
* macOS (Apple silicon): `brew install softhsm opensc openssl`
* macOS (Intel):           `brew install softhsm opensc openssl`

## Quick start

```bash
# Provision (idempotent — safe to run again).
eval "$(crates/tessera_core/tests/scripts/setup_softhsm2.sh)"

# Verify the token + keys are visible.
pkcs11-tool --module "$PKCS11_MODULE_PATH" \
            --token-label "$SOFTHSM_TEST_LABEL" \
            --pin "$SOFTHSM_USER_PIN" --list-objects

# Run the gated integration tests.
cargo test -p tessera_core --features pkcs11-tests
```

## What the script does

1. Probes the host for the softhsm2 `.so` (Linux: `/usr/lib*/softhsm`;
   macOS: `/opt/homebrew/lib/softhsm` or `/usr/local/lib/softhsm`) and
   sets `PKCS11_MODULE_PATH` accordingly.
2. Creates a private token store under
   `$HOME/.tessera_test/softhsm2/` — never touching the system
   `softhsm2.conf`.
3. Initialises a token (`tessera_test`) with PINs from the
   environment (`USER_PIN=1234`, `SO_PIN=12345678` by default).
4. Generates two keypairs:
   - `tessera_rsa` — RSA-2048 (`--id 01`).
   - `tessera_ec_p256` — ECDSA P-256 (`--id 02`).
5. Emits eval-friendly `export …` lines on stdout.

The output env vars used by the test suite are:

| Variable                 | Default                                       |
|--------------------------|-----------------------------------------------|
| `PKCS11_MODULE_PATH`     | auto-detected softhsm2 `.so`                  |
| `SOFTHSM2_CONF`          | `$TESTDIR/softhsm2.conf`                      |
| `SOFTHSM_TEST_LABEL`     | `tessera_test`                           |
| `SOFTHSM_USER_PIN`       | `1234`                                        |
| `SOFTHSM_RSA_LABEL`      | `tessera_rsa`                            |
| `SOFTHSM_ECDSA_LABEL`    | `tessera_ec_p256`                        |

## Tearing down

```bash
crates/tessera_core/tests/scripts/teardown_softhsm2.sh
```

This wipes the entire `$TESTDIR`.  Use only after the integration
tests have completed — softhsm2 holds no per-process state.

## Adding self-signed certs (manual recipe)

The integration tests only need the keypairs.  When you also
want to exercise `find_certificate`, generate matching certs as
follows.  This is documented here rather than baked into the script
because it requires the test CA from `tests/fixtures/ca.pem`, which is
not always desired (e.g. CI runs that bring their own anchors).

```bash
# 1. extract the on-token public key
pkcs11-tool --module "$PKCS11_MODULE_PATH" \
            --token-label "$SOFTHSM_TEST_LABEL" \
            --pin "$SOFTHSM_USER_PIN" \
            --read-object --type pubkey --label "$SOFTHSM_RSA_LABEL" \
            -o /tmp/rsa.pub.der

# 2. wrap as PEM and craft a CSR using the test CA's private key
#    (this CA is the same one used by the existing PKCS#12 fixtures).
openssl rsa -inform DER -pubin -in /tmp/rsa.pub.der -pubout -out /tmp/rsa.pub.pem
openssl req -new -key crates/tessera_core/tests/fixtures/ca.key \
    -subj "/CN=softhsm-rsa-test/O=tessera_tests" \
    -out /tmp/rsa.csr -force_pubid /tmp/rsa.pub.pem  # OpenSSL ≥ 3 only

# 3. sign with the CA
openssl x509 -req -in /tmp/rsa.csr \
    -CA crates/tessera_core/tests/fixtures/ca.pem \
    -CAkey crates/tessera_core/tests/fixtures/ca.key \
    -CAcreateserial -out /tmp/rsa.cert.pem -days 365

# 4. import as CKO_CERTIFICATE on the token
openssl x509 -in /tmp/rsa.cert.pem -outform DER -out /tmp/rsa.cert.der
pkcs11-tool --module "$PKCS11_MODULE_PATH" \
            --token-label "$SOFTHSM_TEST_LABEL" \
            --login --pin "$SOFTHSM_USER_PIN" \
            --write-object /tmp/rsa.cert.der --type cert \
            --label "$SOFTHSM_RSA_LABEL" --id 01
```

Repeat for the ECDSA key with `--key-type EC` adjustments.

## CI integration

A `make test-softhsm2` (or shell wrapper) target should:

1. Run `setup_softhsm2.sh` and capture the env.
2. `cargo test -p tessera_core --features pkcs11-tests`
3. `cargo test -p pam_tessera --features pkcs11-tests`

On macOS dev hosts without softhsm2, every PKCS#11 integration test
runtime-detects the missing `PKCS11_MODULE_PATH` env var, prints
`skipped: PKCS#11 module not available`, and returns `Ok` — see
`crates/tessera_core/src/token/pkcs11/test_helpers.rs`.

## Live hardware acceptance

Green on softhsm2 does not mean green on a token.  softhsm2 survives
races that vendor providers do not: `rtpkcs11ecp` 2.14.1 kills the
process when `C_Initialize` is entered from two threads at once, and
that class of defect stayed invisible for three years because every
PKCS#11 test ran against softhsm2 only.

So a run against real hardware is part of acceptance, and it is
**multithreaded on purpose**:

```bash
export PKCS11_MODULE_PATH=/usr/lib/librtpkcs11ecp.so
# No --test-threads=1: concurrency is the scenario under test.
cargo test -p tessera_core --features pkcs11-tests
```

What to check:

1. The process does not abort.  A `SIGABRT` with `std::terminate` in the
   backtrace is a provider defect reproduced through our code, not a
   flaky test — record the provider name and version.
2. `pkcs11_singleton.rs` passes: one `C_Initialize` per module path
   however many backends are loaded, no re-initialization after the last
   one is dropped (the context is never finalized), independent contexts
   for distinct paths, and no residual login between two sequential
   authentications.
3. Both locking modes are exercised at least once —
   `pkcs11_locking_mode = "mutex"` (the default) and an explicit
   `"os"` — since only the former is covered by the default config.
   The mode is fixed by the first load of a module path in a process, so
   the two modes must be exercised by separate test binaries (they are:
   `pkcs11_locking.rs` loads in `os`, everything else in `mutex`).
4. A second `C_Login` in one process succeeds.  SoftHSM2 2.7 fails it
   with `CKR_GENERAL_ERROR` regardless of `C_Logout` — reproduced
   against bare `cryptoki`, so it is the provider, not our code — and
   `login_state_does_not_outlive_the_session` prints a `note:` and stops
   short when it happens.  On hardware that note must not appear: a
   provider that cannot log in twice cannot serve a second
   authentication from a `fly-dm` process that lives for the whole
   uptime.

A single physical token cannot serve two logins at once; tests that
drive a PIN or a signature against one device still need to be run one
at a time.  That constraint is about the device, not about the library
initialization, and must not be used to hide the concurrent run above.
