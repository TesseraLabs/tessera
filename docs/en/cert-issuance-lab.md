# Issuing a test CA and a credential (ECDSA P-256)

> The test CA and everything described here is only suitable for a lab
> deployment. For production an external CA is used — see
> [docs/operations.md](operations.md).

Everything below is a plain `openssl` invocation, with no engine at
all: ECDSA P-256 is supported by OpenSSL 3.x's built-in `default`
provider on any system, including macOS (both the system
OpenSSL/LibreSSL and Homebrew) — neither `-engine` nor a custom build
is needed. That means these steps don't have to run on the target
Astra machine — it's more convenient to run them on the administrator's
workstation.

## Creating a test CA

### 1. Directory

```bash
mkdir -p /tmp/ca && cd /tmp/ca
```

### 2. CA key

```bash
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
chmod 0600 ca.key
```

### 3. CA certificate

```bash
openssl req -new -x509 -key ca.key \
    -out ca.pem -days 3650 \
    -subj "/CN=tessera Test CA/O=Test/OU=Internal" \
    -addext "extendedKeyUsage=clientAuth" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
```

### Check

```bash
openssl x509 -in ca.pem -text -noout | head -30
```

Expected line: `Signature Algorithm: ecdsa-with-SHA256`.

### Verification (CA section)

```bash
openssl verify -CAfile ca.pem ca.pem
```

Expected: `ca.pem: OK`.

## Creating the role account's credential

The role at login is the name of the login account: the engineer logs
into a **role account** named after the role (`ssh serv@device`), and
the requested role equals the name of that account. There is no
separate role prompt.

The rest of the scenario uses the role `serv` ("service engineer") —
the repository ships a ready-made role slice for it,
`dist/roles/serv.toml`, which is needed in [install.md](install.md)
§8. The login account is called `serv` as well; it is created there,
together with the role store.

### 4. Key and CSR

```bash
openssl ecparam -name prime256v1 -genkey -noout -out serv.key
chmod 0600 serv.key
openssl req -new -key serv.key -out serv.csr \
    -subj "/CN=service-engineer/UID=serv"
```

The engineer's identity lives in the credential and in the issuance
journal, not in the name of the login account. The `CN` does not
affect authorization: the decision is made from the extensions in the
next section.

### 5. Extensions and signing the CSR

The leaf must carry **two** extensions:

| Extension | OID | Question it answers |
|-----------|-----|---------------------|
| `pam_cert_host_binding` | `2.25.183976554325829274683049824615098` | on which devices the bearer may log in |
| `pam_cert_allowed_roles` | `2.25.185305973969816596290730578528098241367` | which roles the bearer may activate |

Each is a `SEQUENCE OF UTF8String`; `pam_cert_allowed_roles` is issued
non-critical. The OIDs and the ASN.1 syntax are from
[cert-issuance.md](cert-issuance.md).

There is no separate list of permitted accounts, and none is needed.
The name of the login account IS the role, so `pam_cert_allowed_roles`
answers both questions at once — "which roles the bearer may activate"
and "into which accounts the bearer is admitted": it is the same
string. Two lists over one string would describe an unrealizable
state: "admitted into `serv`, but not entitled to be `serv`".

Without either of the two the module rejects authentication
**fail-closed**: a missing host extension yields
`HostExtensionMissing`, and a missing `pam_cert_allowed_roles` means
the credential grants no role at all — while a role is required at
every login. In both cases [install.md
§7](install.md#7-authorization-credential-extensions) will not find
the OID in the credential, and `pamtester` in [install.md
§10](install.md#10-smoke-test-via-pamtester) will not pass.

First find out this machine's `host_id_hash` — the source the daemon
uses right now (the row with `active_under_current_config=yes`,
column `hash_hex`). This is taken **from the target Astra machine** —
tessera must already be installed there (`install.md` §1–§2):

```bash
HOST_HASH=$(sudo tessera dump-host-id | awk -F'\t' '$7 == "yes" { print $3 }')
echo "host_id_hash = ${HOST_HASH}"   # 64 hex characters
```

Assemble the `extfile` with both extensions (host — only this
machine, role, which is also the login account, — only `serv`):

```bash
cat > serv.ext <<EOF
extendedKeyUsage = clientAuth
keyUsage = critical,digitalSignature

# Host: only this machine (host_id_hash obtained above)
2.25.183976554325829274683049824615098 = ASN1:SEQUENCE:hb
# Roles, which are also the login accounts: only serv
2.25.185305973969816596290730578528098241367 = ASN1:SEQUENCE:ar

[ hb ]
e0 = UTF8String:sha256:${HOST_HASH}

[ ar ]
e0 = UTF8String:serv
EOF
```

Sign the CSR with this `extfile`:

```bash
openssl x509 -req -in serv.csr \
    -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out serv.pem -days 365 \
    -extfile serv.ext
```

### Check the OIDs

```bash
openssl x509 -in serv.pem -noout -text \
    | grep -E '2\.25\.(183976554325829274683049824615098|185305973969816596290730578528098241367)'
```

Expected: both dotted-OID lines are present in the output.

### 6. Packing into P12

```bash
openssl pkcs12 -export -inkey serv.key -in serv.pem \
    -out serv.p12 -name serv -passout pass:test
chmod 0600 serv.p12
```

### Verification (credential section)

```bash
openssl pkcs12 -in serv.p12 -nokeys -passin pass:test \
    | openssl x509 -noout -subject
```

Expected: `subject=CN=service-engineer, UID=serv` (the exact RDN order
depends on the OpenSSL version).

The result of this whole section is `ca.pem` and `serv.p12` in
`/tmp/ca/`, ready to be copied onto the USB media ([install.md
§5](install.md#5-preparing-the-usb-media-pkcs12-mode--mode-a)).
