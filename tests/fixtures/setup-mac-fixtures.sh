#!/usr/bin/env bash
# Generate 6 MAC integrity test leaves signed by the shared test CA.
#
# Pre-conditions:
#   - openssl ≥ 3.0 (custom OID with raw DER:.. syntax)
#   - tests/fixtures/ca.key.pem and tests/fixtures/ca.crt.pem present;
#     if absent, copy them from crates/tessera_core/tests/fixtures/
#     (ca.key → ca.key.pem, ca.pem → ca.crt.pem).
#
# Outputs to ./{name}.{key,crt}.pem under tests/fixtures/.
#
# This script is intentionally NOT run by CI: regenerating fixtures on
# every build would invalidate test cert pinning. Run manually when
# rotating the test CA or after changing the MAX_INTEGRITY extension
# encoding.
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

CA_KEY="${CA_KEY:-ca.key.pem}"
CA_CRT="${CA_CRT:-ca.crt.pem}"

if [[ ! -f "$CA_KEY" || ! -f "$CA_CRT" ]]; then
    echo "error: $CA_KEY / $CA_CRT not found in $HERE" >&2
    echo "       copy from crates/tessera_core/tests/fixtures/" >&2
    exit 1
fi

CASES=(
    leaf-l2-c01
    leaf-l1-empty
    leaf-no-ext
    leaf-l3
    leaf-malformed
    leaf-l0-fullcats
)

for name in "${CASES[@]}"; do
    cnf="${name}.cnf"
    key="${name}.key.pem"
    csr="${name}.csr.pem"
    crt="${name}.crt.pem"

    if [[ ! -f "$cnf" ]]; then
        echo "warn: $cnf missing, skipping" >&2
        continue
    fi

    echo "[*] generating ${name}..."
    openssl genrsa -out "$key" 2048 2>/dev/null
    openssl req -new -key "$key" -out "$csr" -config "$cnf" -reqexts leaf_ext
    openssl x509 -req \
        -in "$csr" \
        -CA "$CA_CRT" \
        -CAkey "$CA_KEY" \
        -CAcreateserial \
        -out "$crt" \
        -days 365 \
        -sha256 \
        -extfile "$cnf" \
        -extensions leaf_ext
    rm -f "$csr"
done

echo "[+] done. inspect with: openssl x509 -in <leaf>.crt.pem -noout -text"
