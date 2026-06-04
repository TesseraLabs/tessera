#!/usr/bin/env bash
#
# Regenerates the GOST X.509 test fixtures used by the
# `tests/gost_*_real.rs` integration tests in `tessera_core`.
#
# Prerequisites:
#   - system OpenSSL 1.1.x with gost-engine installed
#     (Astra SE 1.7+: ships gost-engine pre-built;
#      Ubuntu/Debian: build https://github.com/gost-engine/engine from source)
#
# Usage:
#   ./gen_gost.sh
#
# The script writes its output into `./gost/` (i.e. next to itself).  It is
# idempotent — re-running it overwrites all previously-generated artefacts.
#
# These fixtures are NOT committed to the repository; the `.gitignore` at the
# repo root excludes them.  On macOS dev hosts the engine cannot be built, so
# the GOST integration tests skip gracefully when the fixtures are absent.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p gost
cd gost

# 1) Sanity check — the engine must be loadable before we do anything else.
if ! openssl engine -t gost 2>&1 | grep -q '\[ available \]'; then
    echo "ERROR: OpenSSL reports gost-engine is NOT available." >&2
    echo "  Astra SE: install libgost-astra (or the SE-specific package)." >&2
    echo "  Ubuntu/Debian: build https://github.com/gost-engine/engine from source." >&2
    echo "  macOS: not supported — use a Linux VM (Lima/UTM/multipass)." >&2
    exit 1
fi

PASS="correct-pin"

# 2) GOST-2012-256 self-signed CA.
openssl req -x509 -engine gost -newkey gost2012_256 \
    -pkeyopt paramset:A \
    -keyout gost_ca_256.key -nodes \
    -out gost_ca_256.pem -days 3650 \
    -subj "/CN=tessera Test GOST CA 256" \
    -md_gost12_256 \
    -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n')

# 3) GOST-2012-512 self-signed CA.
openssl req -x509 -engine gost -newkey gost2012_512 \
    -pkeyopt paramset:A \
    -keyout gost_ca_512.key -nodes \
    -out gost_ca_512.pem -days 3650 \
    -subj "/CN=tessera Test GOST CA 512" \
    -md_gost12_512 \
    -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n')

# 4) GOST-2012-256 end-entity (signed by gost_ca_256).
openssl req -engine gost -newkey gost2012_256 \
    -pkeyopt paramset:A \
    -keyout gost_ee_256.key -nodes \
    -out gost_ee_256.csr \
    -subj "/CN=tessera-test-ee-256" \
    -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n')
openssl x509 -req -engine gost \
    -in gost_ee_256.csr \
    -CA gost_ca_256.pem -CAkey gost_ca_256.key -CAcreateserial \
    -out gost_ee_256.pem -days 365 \
    -md_gost12_256

# 5) GOST-2012-512 end-entity (signed by gost_ca_512).
openssl req -engine gost -newkey gost2012_512 \
    -pkeyopt paramset:A \
    -keyout gost_ee_512.key -nodes \
    -out gost_ee_512.csr \
    -subj "/CN=tessera-test-ee-512" \
    -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n')
openssl x509 -req -engine gost \
    -in gost_ee_512.csr \
    -CA gost_ca_512.pem -CAkey gost_ca_512.key -CAcreateserial \
    -out gost_ee_512.pem -days 365 \
    -md_gost12_512

# 6) PKCS#12 bundles for the round-trip test.
openssl pkcs12 -export -engine gost \
    -inkey gost_ee_256.key \
    -in gost_ee_256.pem \
    -certfile gost_ca_256.pem \
    -name "tessera-test-ee-256" \
    -password "pass:$PASS" \
    -out gost_ee_256.p12
openssl pkcs12 -export -engine gost \
    -inkey gost_ee_512.key \
    -in gost_ee_512.pem \
    -certfile gost_ca_512.pem \
    -name "tessera-test-ee-512" \
    -password "pass:$PASS" \
    -out gost_ee_512.p12

# 7) GOST-signed ACL fixture.
cat > gost_signed_acl.toml <<'EOF'
version = 1
issued_at = "2026-01-01T00:00:00Z"
entries = []
EOF
openssl dgst -engine gost -md_gost12_256 \
    -sign gost_ca_256.key \
    -out gost_signed_acl.toml.sig \
    gost_signed_acl.toml

# 8) Empty GOST-signed CRL.  Some openssl builds reject the inline -config
# trick; if that happens we leave behind an empty file and the integration
# test treats that as "skip CRL test".
mkdir -p gost_crl_db
: > gost_crl_db/index.txt
echo 1000 > gost_crl_db/crlnumber
cat > gost_crl_openssl.cnf <<'EOF'
[ ca ]
default_ca = test_ca

[ test_ca ]
database = gost_crl_db/index.txt
crlnumber = gost_crl_db/crlnumber
default_md = md_gost12_256
default_crl_days = 30
policy = policy_any

[ policy_any ]
commonName = supplied
EOF
openssl ca -gencrl -engine gost \
    -keyfile gost_ca_256.key -cert gost_ca_256.pem \
    -config gost_crl_openssl.cnf \
    -md md_gost12_256 \
    -crldays 30 \
    -out gost_signed.crl 2>/dev/null \
    || {
        echo "WARN: GOST CRL generation failed — leaving an empty placeholder." >&2
        : > gost_signed.crl
    }

rm -rf gost_crl_db gost_crl_openssl.cnf
rm -f *.csr *.srl

echo "GOST fixtures written to: $(pwd)"
