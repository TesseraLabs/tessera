#!/usr/bin/env bash
# Regenerates the X.509 test fixtures used by stage-2 tests.
# These artifacts are public test material and are committed alongside the script.
set -euo pipefail
cd "$(dirname "$0")"

# Root CA (self-signed)
openssl genrsa -out ca.key 2048
openssl req -x509 -new -key ca.key -sha256 -days 3650 \
    -subj "/CN=CertAuth Test Root CA" \
    -extensions v3_ca -config <(cat <<'EOF'
[req]
distinguished_name = dn
[dn]
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
) -out ca.pem

# Intermediate (signed by Root)
openssl genrsa -out int.key 2048
openssl req -new -key int.key -subj "/CN=CertAuth Test Intermediate" -out int.csr
openssl x509 -req -in int.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 1825 -sha256 \
    -extfile <(cat <<'EOF'
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
) -out int.pem

# Leaf RSA (signed by Intermediate)
openssl genrsa -out leaf_rsa.key 2048
openssl req -new -key leaf_rsa.key -subj "/CN=alice" \
    -addext "subjectAltName=email:alice@example.org" -out leaf_rsa.csr
openssl x509 -req -in leaf_rsa.csr -CA int.pem -CAkey int.key -CAcreateserial \
    -days 365 -sha256 \
    -extfile <(cat <<'EOF'
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = email:alice@example.org
2.25.183976554325829274683049824615098 = ASN1:SEQUENCE:hb_any
2.25.215438916728501023845629178354627 = ASN1:SEQUENCE:ub_any

[hb_any]
e0 = UTF8String:*

[ub_any]
e0 = UTF8String:*
EOF
) -out leaf_rsa.pem

# Leaf ECDSA P-256 (signed by Intermediate)
openssl ecparam -name prime256v1 -genkey -noout -out leaf_ecdsa.key
openssl req -new -key leaf_ecdsa.key -subj "/CN=bob" \
    -addext "subjectAltName=email:bob@example.org" -out leaf_ecdsa.csr
openssl x509 -req -in leaf_ecdsa.csr -CA int.pem -CAkey int.key -CAcreateserial \
    -days 365 -sha256 \
    -extfile <(cat <<'EOF'
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = email:bob@example.org
2.25.183976554325829274683049824615098 = ASN1:SEQUENCE:hb_any
2.25.215438916728501023845629178354627 = ASN1:SEQUENCE:ub_any

[hb_any]
e0 = UTF8String:*

[ub_any]
e0 = UTF8String:*
EOF
) -out leaf_ecdsa.pem

# Leaf RSA without pam_cert_user_binding (legacy mapping fallback fixture).
# Used by tests that need to exercise the legacy [[user_mapping]] path:
# the cert carries host_binding (so cert-scope passes) but no user_binding,
# so flow.rs Step 10 (subject mapping) runs instead of being skipped.
openssl genrsa -out leaf_no_user_binding.key 2048
openssl req -new -key leaf_no_user_binding.key -subj "/CN=alice" \
    -addext "subjectAltName=email:alice@example.org" -out leaf_no_user_binding.csr
openssl x509 -req -in leaf_no_user_binding.csr -CA int.pem -CAkey int.key -CAcreateserial \
    -days 365 -sha256 \
    -extfile <(cat <<'EOF'
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = email:alice@example.org
2.25.183976554325829274683049824615098 = ASN1:SEQUENCE:hb_any

[hb_any]
e0 = UTF8String:*
EOF
) -out leaf_no_user_binding.pem

# Revoked leaf RSA (signed by Intermediate, with a known serial 0x99)
openssl genrsa -out revoked_leaf.key 2048
openssl req -new -key revoked_leaf.key -subj "/CN=mallory" \
    -addext "subjectAltName=email:mallory@example.org" -out revoked_leaf.csr
openssl x509 -req -in revoked_leaf.csr -CA int.pem -CAkey int.key \
    -set_serial 0x99 -days 365 -sha256 \
    -extfile <(cat <<'EOF'
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = email:mallory@example.org
2.25.183976554325829274683049824615098 = ASN1:SEQUENCE:hb_any
2.25.215438916728501023845629178354627 = ASN1:SEQUENCE:ub_any

[hb_any]
e0 = UTF8String:*

[ub_any]
e0 = UTF8String:*
EOF
) -out revoked_leaf.pem

# Expired leaf RSA (signed by Intermediate; notBefore + notAfter both in the past)
# We use `openssl ca` so we can pass explicit -startdate/-enddate.
openssl genrsa -out expired_leaf.key 2048
openssl req -new -key expired_leaf.key -subj "/CN=alice" \
    -reqexts user_exts \
    -config <(cat <<'EOF'
[req]
distinguished_name = dn
[dn]
[user_exts]
subjectAltName = email:alice@example.org
2.25.183976554325829274683049824615098 = ASN1:SEQUENCE:hb_any_e
2.25.215438916728501023845629178354627 = ASN1:SEQUENCE:ub_any_e
[hb_any_e]
e0 = UTF8String:*
[ub_any_e]
e0 = UTF8String:*
EOF
) -out expired_leaf.csr
mkdir -p expired_db
: > expired_db/index.txt
echo 2000 > expired_db/serial
mkdir -p expired_db/newcerts
cat > expired_openssl.cnf <<'EOF'
[ ca ]
default_ca = test_ca

[ test_ca ]
database = expired_db/index.txt
serial = expired_db/serial
new_certs_dir = expired_db/newcerts
default_md = sha256
policy = policy_any
copy_extensions = copy
x509_extensions = v3_clientauth

[ policy_any ]
commonName = supplied

[ v3_clientauth ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
openssl ca -config expired_openssl.cnf -in expired_leaf.csr \
    -keyfile int.key -cert int.pem \
    -startdate 200101000000Z -enddate 200601000000Z \
    -out expired_leaf.pem -batch -notext 2>/dev/null

# CRL: valid (issued by Intermediate), with mallory's serial 0x99 revoked.
mkdir -p crl_db
: > crl_db/index.txt
echo 1000 > crl_db/crlnumber
cat > crl_openssl.cnf <<'EOF'
[ ca ]
default_ca = test_ca

[ test_ca ]
database = crl_db/index.txt
crlnumber = crl_db/crlnumber
default_md = sha256
default_crl_days = 3650
policy = policy_any

[ policy_any ]
commonName = supplied
EOF

# Mark mallory revoked in the openssl CA index.
# Format: V|R<TAB>YYMMDDHHMMSSZ<TAB>[revocation_date]<TAB>serial<TAB>unknown<TAB>subject
NOW=$(date -u +%y%m%d%H%M%SZ)
EXP=$(date -u -v+365d +%y%m%d%H%M%SZ 2>/dev/null || date -u -d "+365 days" +%y%m%d%H%M%SZ)
printf 'R\t%s\t%s\t99\tunknown\t/CN=mallory\n' "$EXP" "$NOW" > crl_db/index.txt

openssl ca -gencrl -keyfile int.key -cert int.pem \
    -config crl_openssl.cnf \
    -crldays 3650 \
    -out crl_valid.pem 2>/dev/null

# Foreign-issuer CRL: signed by the *root* CA over an empty revocation list.
# Used to verify that we reject CRLs whose issuer DN does not match the
# certificate issuer (or whose signature does not validate under the
# expected key).  Configured separately so the openssl ca command can
# point at the root key/cert.
openssl ca -gencrl -keyfile ca.key -cert ca.pem \
    -config crl_openssl.cnf \
    -crldays 3650 \
    -out crl_foreign.pem 2>/dev/null

# PKCS#12 bundles for stage-2 tests (T11+).
# The PIN "correct-pin" is intentionally fixed and committed alongside the
# bundles — these are public test fixtures, not real credentials.
# -descert + sha256 keep the bundle inside the modern algorithm set so OpenSSL
# 3.x (which Astra ships) accepts it without --legacy.
openssl pkcs12 -export \
    -inkey leaf_rsa.key \
    -in leaf_rsa.pem \
    -certfile int.pem \
    -name "alice" \
    -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256 \
    -passout pass:correct-pin \
    -out leaf_rsa.p12

openssl pkcs12 -export \
    -inkey leaf_ecdsa.key \
    -in leaf_ecdsa.pem \
    -certfile int.pem \
    -name "bob" \
    -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256 \
    -passout pass:correct-pin \
    -out leaf_ecdsa.p12

openssl pkcs12 -export \
    -inkey leaf_no_user_binding.key \
    -in leaf_no_user_binding.pem \
    -certfile int.pem \
    -name "alice" \
    -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256 \
    -passout pass:correct-pin \
    -out leaf_no_user_binding.p12

# PKCS#12 bundle for the revoked leaf (CN=mallory, serial 0x99).
# The matching CRL `crl_valid.pem` lists this serial as revoked.
openssl pkcs12 -export \
    -inkey revoked_leaf.key \
    -in revoked_leaf.pem \
    -certfile int.pem \
    -name "mallory" \
    -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256 \
    -passout pass:correct-pin \
    -out revoked_leaf.p12

# PKCS#12 bundle for the expired leaf (CN=alice, notAfter long in the past).
openssl pkcs12 -export \
    -inkey expired_leaf.key \
    -in expired_leaf.pem \
    -certfile int.pem \
    -name "alice-expired" \
    -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256 \
    -passout pass:correct-pin \
    -out expired_leaf.p12

rm -f *.csr *.srl
rm -rf crl_db crl_openssl.cnf
rm -rf expired_db expired_openssl.cnf
rm -f revoked_leaf.key expired_leaf.key
