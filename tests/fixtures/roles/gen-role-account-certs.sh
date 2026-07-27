#!/usr/bin/env bash
# Generate role-account test leaves for the target role model
# ("role = role account"): the engineer logs into the role account by name
# (`ssh serv@device`), the requested role equals the login account name, and
# admission is decided by pam_cert_user_binding plus pam_cert_allowed_roles.
#
# These leaves are the only ones the module can be exercised with: the suffix
# form `<user>+<role>` that gen-role-certs.sh produces leaves for no longer
# exists, and those leaves bind to a human account (`ivanov`) that no login can
# reach.
#
# Pre-conditions:
#   - openssl >= 3.0 (custom OID with raw DER:.. syntax)
#   - tests/fixtures/roles/ca.key.pem and tests/fixtures/roles/ca.crt.pem
#     present; if absent, copy them from crates/tessera_core/tests/fixtures/
#     (ca.key -> ca.key.pem, ca.pem -> ca.crt.pem). The same CA used by
#     gen-role-certs.sh — these leaves chain to the same trust anchor.
#
# Outputs to ./accounts/{name}.{key,crt}.pem plus ./accounts/{name}.p12
# (PIN 123456, same as the suffix-model bundles).
#
# Leaves:
#   acct-serv             user_binding=[serv] allowed_roles=[serv]
#                         -> login into `serv`, role covered: admit
#   acct-serv-oper-only   user_binding=[serv] allowed_roles=[oper]
#                         -> login into `serv` permitted, role NOT covered
#   acct-foreign          user_binding=[oper] allowed_roles=[oper]
#                         -> login into `serv` refused by user_binding
#
# All leaves carry host_binding = ["*"] so they admit on any test stand.
#
# The OIDs and DER encodings match crates/tessera_core/src/x509/oids.rs and the
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
OUT_DIR="${OUT_DIR:-accounts}"
P12_PASS="${P12_PASS:-123456}"
DAYS="${DAYS:-3650}"

if [[ ! -f "$CA_KEY" || ! -f "$CA_CRT" ]]; then
    echo "error: $CA_KEY / $CA_CRT not found in $HERE" >&2
    echo "       copy from crates/tessera_core/tests/fixtures/" >&2
    echo "         cp ../../../crates/tessera_core/tests/fixtures/ca.key $CA_KEY" >&2
    echo "         cp ../../../crates/tessera_core/tests/fixtures/ca.pem $CA_CRT" >&2
    exit 1
fi

CASES=(
    acct-serv
    acct-serv-oper-only
    acct-foreign
)

for name in "${CASES[@]}"; do
    cnf="${OUT_DIR}/${name}.cnf"
    key="${OUT_DIR}/${name}.key.pem"
    csr="${OUT_DIR}/${name}.csr.pem"
    crt="${OUT_DIR}/${name}.crt.pem"
    p12="${OUT_DIR}/${name}.p12"

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
        -days "$DAYS" \
        -sha256 \
        -extfile "$cnf" \
        -extensions leaf_ext
    rm -f "$csr"

    openssl pkcs12 -export \
        -out "$p12" \
        -inkey "$key" \
        -in "$crt" \
        -certfile "$CA_CRT" \
        -name "$name" \
        -passout "pass:${P12_PASS}"
done

echo "[+] done. inspect with:"
echo "      openssl x509 -in ${OUT_DIR}/acct-serv.crt.pem -noout -text | grep -A2 2.25.2154"
echo "      openssl pkcs12 -in ${OUT_DIR}/acct-serv.p12 -noout -passin pass:${P12_PASS}"
