#!/usr/bin/env bash
# Generate role-coverage test leaves carrying the pam_cert_allowed_roles
# extension, signed by the shared test CA.
#
# Pre-conditions:
#   - openssl >= 3.0 (custom OID with raw DER:.. syntax)
#   - tests/fixtures/roles/ca.key.pem and tests/fixtures/roles/ca.crt.pem
#     present; if absent, copy them from crates/tessera_core/tests/fixtures/
#     (ca.key -> ca.key.pem, ca.pem -> ca.crt.pem). The same CA used by
#     setup-mac-fixtures.sh — these leaves chain to the same trust anchor.
#
# Outputs to ./{name}.{key,crt}.pem under tests/fixtures/roles/.
#
# Leaves (mirrors the 6.3 role E2E set):
#   role-serv       pam_cert_allowed_roles = [serv]  -> covers `+serv`
#   role-oper       pam_cert_allowed_roles = [oper]  -> does NOT cover `+serv`
#   role-malformed  pam_cert_allowed_roles = bad DER -> parse-failed, no roles
#
# The OID and DER encoding match crates/tessera_core/src/x509/oids.rs and the
# DER shapes asserted in
# crates/tessera_core/tests/allowed_roles_ext_parse.rs. Do NOT change them.
#
# This script is intentionally NOT run by CI: regenerating fixtures on every
# build would invalidate cert pinning. Run manually when rotating the test CA
# or after changing the allowed_roles extension encoding.
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

CA_KEY="${CA_KEY:-ca.key.pem}"
CA_CRT="${CA_CRT:-ca.crt.pem}"

if [[ ! -f "$CA_KEY" || ! -f "$CA_CRT" ]]; then
    echo "error: $CA_KEY / $CA_CRT not found in $HERE" >&2
    echo "       copy from crates/tessera_core/tests/fixtures/" >&2
    echo "         cp ../../../crates/tessera_core/tests/fixtures/ca.key $CA_KEY" >&2
    echo "         cp ../../../crates/tessera_core/tests/fixtures/ca.pem $CA_CRT" >&2
    exit 1
fi

CASES=(
    role-serv
    role-oper
    role-malformed
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

echo "[+] done. inspect with:"
echo "      openssl x509 -in role-serv.crt.pem -noout -text | grep -A2 2.25.1853"
