#!/usr/bin/env bash
#
# Idempotent softhsm2 provisioning script for the stage-4 PKCS#11
# integration tests (T18).  Generates an RSA-2048 keypair and an
# ECDSA-P256 keypair on a fresh softhsm2 token and emits the env vars
# the test suite reads.
#
# Usage:
#   eval "$(crates/tessera_core/tests/scripts/setup_softhsm2.sh)"
#   cargo test -p tessera_core --features pkcs11-tests
#
# Environment variables (all optional, with sensible defaults):
#   TESTDIR           — root for the softhsm2 token store (defaults to
#                       $HOME/.tessera_test/softhsm2)
#   TOKEN_LABEL       — token CKA_LABEL (default: tessera_test)
#   USER_PIN          — CKU_USER PIN (default: 1234)
#   SO_PIN            — CKU_SO PIN  (default: 12345678)
#   PKCS11_MODULE     — softhsm2 .so path; auto-detected if unset
#
# Output (stdout, eval-friendly):
#   export PKCS11_MODULE_PATH=...
#   export SOFTHSM2_CONF=...
#   export SOFTHSM_TEST_LABEL=...
#   export SOFTHSM_USER_PIN=...
#   export SOFTHSM_RSA_LABEL=tessera_rsa
#   export SOFTHSM_ECDSA_LABEL=tessera_ec_p256
#
# Diagnostics go to stderr so `eval $(setup_softhsm2.sh)` is safe.
#
# Notes:
# - This script does NOT install softhsm2 or opensc.  Operators run it
#   on a host that already has both (e.g. apt: softhsm2 + opensc, or
#   brew: softhsm + opensc).  The tooling check at the top of the
#   script fails fast with a clear message.
# - On macOS the softhsm2 .so is typically under /opt/homebrew (Apple
#   silicon) or /usr/local (Intel).  On Linux it's
#   /usr/lib/softhsm/libsofthsm2.so or
#   /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so.  The detection
#   loop below covers all four.
# - Cert generation (write_object'ing self-signed RSA + ECDSA certs
#   tied to the on-token keys) is deferred to the README — operators
#   running real e2e tests need to drive openssl manually with the
#   on-token public keys.  See README-softhsm2.md for the full recipe.

set -euo pipefail

# ---------------------------------------------------------------------------
# 0. Tooling probe
# ---------------------------------------------------------------------------
need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: '$1' not found in PATH; install softhsm2 + opensc first" >&2
        echo "       Linux:  sudo apt install softhsm2 opensc" >&2
        echo "       macOS:  brew install softhsm opensc" >&2
        exit 1
    fi
}
need softhsm2-util
need pkcs11-tool

# ---------------------------------------------------------------------------
# 1. Locate the softhsm2 .so for this platform
# ---------------------------------------------------------------------------
PKCS11_MODULE="${PKCS11_MODULE:-}"
if [[ -z "$PKCS11_MODULE" ]]; then
    for candidate in \
        /opt/homebrew/lib/softhsm/libsofthsm2.so \
        /usr/local/lib/softhsm/libsofthsm2.so \
        /usr/lib/softhsm/libsofthsm2.so \
        /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so
    do
        if [[ -f "$candidate" ]]; then
            PKCS11_MODULE="$candidate"
            break
        fi
    done
fi
if [[ -z "$PKCS11_MODULE" || ! -f "$PKCS11_MODULE" ]]; then
    echo "ERROR: softhsm2 .so not found.  Set PKCS11_MODULE explicitly." >&2
    exit 1
fi
echo "softhsm2 module:        $PKCS11_MODULE" >&2

# ---------------------------------------------------------------------------
# 2. Token store
# ---------------------------------------------------------------------------
TESTDIR="${TESTDIR:-$HOME/.tessera_test/softhsm2}"
TOKEN_LABEL="${TOKEN_LABEL:-tessera_test}"
USER_PIN="${USER_PIN:-1234}"
SO_PIN="${SO_PIN:-12345678}"
RSA_LABEL="tessera_rsa"
ECDSA_LABEL="tessera_ec_p256"

mkdir -p "$TESTDIR/tokens"
SOFTHSM2_CONF="$TESTDIR/softhsm2.conf"
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $TESTDIR/tokens
objectstore.backend = file
log.level = ERROR
EOF
export SOFTHSM2_CONF
echo "softhsm2 conf:          $SOFTHSM2_CONF" >&2

# ---------------------------------------------------------------------------
# 3. Init token (idempotent)
# ---------------------------------------------------------------------------
if ! softhsm2-util --show-slots 2>/dev/null | grep -q "Label:[[:space:]]*${TOKEN_LABEL}"; then
    echo "initialising softhsm2 token: $TOKEN_LABEL" >&2
    softhsm2-util --init-token --free \
        --label "$TOKEN_LABEL" --so-pin "$SO_PIN" --pin "$USER_PIN" >&2
else
    echo "token already initialised:  $TOKEN_LABEL" >&2
fi

# ---------------------------------------------------------------------------
# 4. Generate keypairs (idempotent — skip when label already exists)
# ---------------------------------------------------------------------------
list_objects() {
    pkcs11-tool --module "$PKCS11_MODULE" \
                --token-label "$TOKEN_LABEL" \
                --pin "$USER_PIN" \
                --list-objects 2>/dev/null
}

if ! list_objects | grep -q "label:[[:space:]]*${RSA_LABEL}"; then
    echo "generating RSA-2048 keypair: $RSA_LABEL" >&2
    pkcs11-tool --module "$PKCS11_MODULE" \
                --token-label "$TOKEN_LABEL" \
                --login --pin "$USER_PIN" \
                --keypairgen --key-type rsa:2048 \
                --label "$RSA_LABEL" --id 01 >&2
else
    echo "RSA keypair already present: $RSA_LABEL" >&2
fi

if ! list_objects | grep -q "label:[[:space:]]*${ECDSA_LABEL}"; then
    echo "generating ECDSA-P256 keypair: $ECDSA_LABEL" >&2
    pkcs11-tool --module "$PKCS11_MODULE" \
                --token-label "$TOKEN_LABEL" \
                --login --pin "$USER_PIN" \
                --keypairgen --key-type EC:secp256r1 \
                --label "$ECDSA_LABEL" --id 02 >&2
else
    echo "ECDSA keypair already present: $ECDSA_LABEL" >&2
fi

# ---------------------------------------------------------------------------
# 5. Cert generation note
# ---------------------------------------------------------------------------
# Importing a self-signed cert tied to each on-token key requires:
#   1. extracting the pubkey from the token via `pkcs11-tool --read-object`,
#   2. building a CSR + cert with openssl, and
#   3. writing the DER back to the token via `pkcs11-tool --write-object`.
# That recipe is in README-softhsm2.md; the integration tests in T18
# accept tokens that have only the bare keys (cert_lookup will fall
# back to the matching pubkey).

# ---------------------------------------------------------------------------
# 6. Emit env on stdout
# ---------------------------------------------------------------------------
cat <<EOF
export PKCS11_MODULE_PATH=$PKCS11_MODULE
export SOFTHSM2_CONF=$SOFTHSM2_CONF
export SOFTHSM_TEST_LABEL=$TOKEN_LABEL
export SOFTHSM_USER_PIN=$USER_PIN
export SOFTHSM_RSA_LABEL=$RSA_LABEL
export SOFTHSM_ECDSA_LABEL=$ECDSA_LABEL
EOF

echo "softhsm2 setup OK." >&2
