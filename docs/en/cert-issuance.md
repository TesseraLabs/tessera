# Certificate issuance: host_binding and user_binding

## Introduction

The "which user on which host" authorization is encoded in two X.509
extensions of the leaf certificate, which the PAM module checks during the
authentication phase:

- `pam_cert_host_binding`
- `pam_cert_user_binding`

When both extensions are present, they and they alone define the certificate's
scope. The `[[user_mapping]]` list in `config.toml` remains as a **legacy
fallback** for certificates issued without the `pam_cert_user_binding`
extension; for new issuance the extensions must always be set by the CA (see
`docs/threat-model.md`, the mandatory-extension policy).

This document describes the extension syntax and provides ready-made recipes for
`openssl.cnf` from which a certificate can be issued with a stock
`openssl x509 -req`.

## OID table

| Extension name | Dotted OID | ASN.1 syntax |
|---|---|---|
| `pam_cert_host_binding` | `2.25.183976554325829274683049824615098` | `extnValue ::= SEQUENCE OF UTF8String` |
| `pam_cert_user_binding` | `2.25.215438916728501023845629178354627` | `extnValue ::= SEQUENCE OF UTF8String` |
| `pam_cert_allowed_roles` | `2.25.185305973969816596290730578528098241367` | `extnValue ::= SEQUENCE OF UTF8String` |
| `pam_cert_profile_version` | `2.25.107983357797077476746994938370032043240` | `extnValue ::= INTEGER` (**critical**) |
| `pam_cert_delegation_constraints` | `2.25.242193075883906031821745064285793775511` | `SEQUENCE { requireTags, allowRoles, maxLevel, maxTtl }` (**critical**, `CA=TRUE` only) |

The OIDs live in the unregistered `2.25.<UUID>` branch (RFC 4530), which
guarantees uniqueness without consulting any external registry. These values are
fixed in the code (`tessera_core::x509::oids`) and are part of the on-the-wire
X.509 contract — they must not be changed.

## Semantics

Each `UTF8String` entry in `pam_cert_host_binding` is interpreted as follows:

| Entry | Meaning |
|---|---|
| `*` | allowed on any host |
| `sha256:<HEX>` | allowed only on the host whose `host_id_hash` matches the given sixty-four-character lowercase-hex value (case-insensitive) |
| Any other UTF-8 string | the string is interpreted as a "raw" `machine_id` and the comparison goes through SHA-256 of the string |

In `pam_cert_user_binding` an entry is either `*` (any PAM user) or an exact
username (case-sensitive — Linux usernames are case-sensitive).

To authorize a certificate on a specific host/user, **at least one matching
entry** is required in each of the two extensions.

## Scenario 1 — workstation: one host, one user

A specific operator's workplace. The certificate can be used only on the machine
with the known `machine_id` and only for the specific PAM user.

```ini
# openssl.cnf — fragment
[ user_exts ]
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature
extendedKeyUsage       = clientAuth
subjectAltName         = email:ivanov@example.org

# Host: SHA-256 of the operator workstation's machine-id
2.25.183976554325829274683049824615098 = ASN1:SEQUENCE:hb_one
# User: the single name
2.25.215438916728501023845629178354627 = ASN1:SEQUENCE:ub_one

[ hb_one ]
e0 = UTF8String:sha256:a1b2c3d4e5f6...64charsTotal...

[ ub_one ]
e0 = UTF8String:ivanov
```

Issuance command:

```sh
openssl req -new -key user.key -subj "/CN=Иванов" \
    -reqexts user_exts -config openssl.cnf -out user.csr
openssl x509 -req -in user.csr -CA int.pem -CAkey int.key \
    -CAcreateserial -days 365 -sha256 \
    -extfile openssl.cnf -extensions user_exts -out user.pem
```

## Scenario 2 — terminal operator: several hosts, one user

```ini
[ hb_three_hosts ]
e0 = UTF8String:sha256:1111111111111111111111111111111111111111111111111111111111111111
e1 = UTF8String:sha256:2222222222222222222222222222222222222222222222222222222222222222
e2 = UTF8String:sha256:3333333333333333333333333333333333333333333333333333333333333333

[ ub_operator ]
e0 = UTF8String:operator
```

## Scenario 3 — mobile administrator: any host, exact user

```ini
[ hb_any ]
e0 = UTF8String:*

[ ub_admin ]
e0 = UTF8String:admin
```

`*` in host_binding lets the certificate work on any machine; in user_binding a
hard restriction on the username still remains.

## Verifying an issued certificate

```sh
openssl x509 -in user.pem -noout -text
```

The output must contain both lines with the dotted OIDs:

```
2.25.183976554325829274683049824615098:
    0...sha256:a1b2c3d4...
2.25.215438916728501023845629178354627:
    0...ivanov
```

## Verification table

| Entry | Matches… |
|---|---|
| `*` | any host / any user |
| `sha256:<HEX>` | the host whose `host_id_hash` equals `HEX` (case-insensitive) |
| `<raw>` (host_binding) | the host whose `host_id_hash` equals `sha256(raw)` |
| `<name>` (user_binding) | the PAM user with the exact name `<name>` |
| Extension absent | **deny** (`HostExtensionMissing` / `UserExtensionMissing`) |
| Extension empty or DER-broken | **deny** (`*ExtensionMalformed`) |
| Entries present but none matched | **deny** (`HostNotAllowed` / `UserNotAllowed`) |

See also [`docs/configuration.md`](configuration.md).

## The `MAX_INTEGRITY` extension (Astra МКЦ, 0.3.0+)

`MAX_INTEGRITY` is a non-critical X.509 v3 extension encoding the maximum
integrity label `(level, categories)` up to which the certificate may be
admitted on an Astra SE host with strict-mode enabled.

OID: `2.25.273824307386008814506455310913083078403`

Structure (DER):

```asn1
IntegrityLabel ::= SEQUENCE {
    level       INTEGER (-128..127),
    categories  BIT STRING DEFAULT ''B
}
```

Server-side semantics:

- On `open_session` the PAM module picks the effective label as
  `intersect(cert, runtime_caps, fallback?)`.
- `cert_integrity = "required"` → a certificate without the extension is
  rejected.
- `cert_integrity = "optional"` → the absence of the extension is allowed; if
  `[mac.fallback_max_integrity]` is set, it is applied.
- `cert_integrity = "ignore"` → the extension is ignored.

See `docs/configuration.md` §"MAC integrity" and `docs/threat-model.md`
§"Privilege-escalation via MAC label".

Ready-made openssl.cnf templates for test certificates:
`tests/fixtures/leaf-{l2-c01,l1-empty,no-ext,l3,malformed,l0-fullcats}.cnf`.
Generation — `tests/fixtures/setup-mac-fixtures.sh`.

Example line in `openssl.cnf` for `level=2, categories={0}`:

```ini
2.25.273824307386008814506455310913083078403 = DER:30:07:02:01:02:03:02:00:01
```

The DER here is three TLVs: `SEQUENCE` (length 7), `INTEGER 2`,
`BIT STRING '01'B`. The extension is declared non-critical (see above); the
parser tolerates the critical flag, but issuance should be non-critical.

## The `allowed_roles` extension (role selection at login, role-format)

`pam_cert_allowed_roles` is a non-critical X.509 v3 extension listing the
`role_id`s that the leaf certificate is entitled to activate at login
(`user+role`). The semantics are authorization-oriented: a requested role is
covered if its `role_id` is present in the list.

OID: `2.25.185305973969816596290730578528098241367`

Structure (DER) — the same as host/user binding:

```asn1
extnValue ::= SEQUENCE OF UTF8String
```

Each `UTF8String` is a `role_id` and must match `^[a-z][a-z0-9-]{0,15}$`. The
list is parsed strictly fail-closed: on malformed DER **or** any string not
passing the `role_id` regex, the whole extension is considered malformed (not a
skip of a single string), the role list is empty → the requested role is not
covered → deny (audit `cert_allowed_roles_parse_failed`). The absence of the
extension = the certificate grants no roles (with `roles.enforce = require` —
login denied; with `warn` — logged and skipped, migration mode).

Server-side semantics: see `docs/configuration.md` §"roles" and the delta spec
`role-selection`. Extraction only from a verified certificate (`VerifiedX509`),
as with `max_integrity`.

`openssl.cnf` fragment via `ASN1:SEQUENCE` (two roles — `oper`, `serv`):

```ini
# Roles the cert may activate at login
2.25.185305973969816596290730578528098241367 = ASN1:SEQUENCE:allowed_roles

[ allowed_roles ]
e0 = UTF8String:oper
e1 = UTF8String:serv
```

Equivalent as a single DER string (`SEQUENCE { UTF8String "oper", UTF8String "serv" }`):

```ini
2.25.185305973969816596290730578528098241367 = DER:30:0c:0c:04:6f:70:65:72:0c:04:73:65:72:76
```

The DER here: `SEQUENCE` (30 0c) → `UTF8String "oper"` (0c 04 6f 70 65 72) →
`UTF8String "serv"` (0c 04 73 65 72 76). The extension is non-critical (no
`critical,` prefix).

## The `profile_version` extension (version-gate, tags-delegation)

`pam_cert_profile_version` is a **critical** X.509 v3 extension carrying the
integer version of the cert format. Engine knows
`max_supported_profile_version` (config `[trust].max_supported_profile_version`,
default `0`); a cert at **any** link of the chain with a higher version →
reject the whole chain (fail-closed version-gate). This is the second layer of
protection against format evolution: an ununderstood critical OID is rejected by
RFC, and an understood but newer profile — by the version-gate.

OID: `2.25.107983357797077476746994938370032043240`

Structure (DER):

```asn1
extnValue ::= INTEGER
```

Extraction only from a verified cert (`VerifiedX509`). Malformed (not an
INTEGER) or a negative value → reject (audit `profile_version_rejected`). The
absence of the extension = baseline (version `0`), allowed.

`openssl.cnf` fragment for version `1`:

```ini
2.25.107983357797077476746994938370032043240 = critical,ASN1:INTEGER:1
```

Equivalent as a DER string (`INTEGER 1`): `critical,DER:02:01:01`.

## The `delegation_constraints` extension (delegation envelope, tags-delegation)

`pam_cert_delegation_constraints` is a **critical** X.509 v3 extension, valid
**only on a cert with `basicConstraints CA=TRUE`** (on a leaf → malformed →
reject). It declares the issuing CA's delegation envelope: which device group
(by tags), which roles, the level ceiling, and the TTL it is entitled to issue.
The guarantee is checked on the device offline against its own signed tags, by a
logical AND/MIN over **all** CA links of the chain (a misissued child CA does
not break out of the parent envelope).

OID: `2.25.242193075883906031821745064285793775511`

Structure (DER):

```asn1
DelegationConstraints ::= SEQUENCE {
    requireTags  SEQUENCE OF SEQUENCE { key UTF8String, value UTF8String },
    allowRoles   SEQUENCE OF UTF8String,   -- each a valid role_id
    maxLevel     INTEGER,                  -- МКЦ-level ceiling (-128..127)
    maxTtl       INTEGER                   -- link lifetime ceiling, seconds
}
```

Device-side semantics: `device.tags ⊇ requireTags` (generic pair comparison, no
hardcoded key names); the requested role ∈ `allowRoles`; the requested level
`≤ maxLevel`; the child link lifetime `≤ maxTtl`. Any violation → reject (audit
`delegation_denied`; the engineer sees a generic reason). Extraction only from
`VerifiedX509`; malformed or an invalid `role_id` → reject.

`openssl.cnf` fragment via `ASN1:SEQUENCE` (a CA for `region=north`, roles
`oper`/`serv`, level ≤ 5, TTL ≤ 14400 s):

```ini
# Only on a CA cert (basicConstraints CA:TRUE)
2.25.242193075883906031821745064285793775511 = critical,ASN1:SEQUENCE:deleg

[ deleg ]
field1 = SEQUENCE:require_tags
field2 = SEQUENCE:allow_roles
field3 = INTEGER:5            # maxLevel
field4 = INTEGER:14400        # maxTtl

[ require_tags ]
t0 = SEQUENCE:tag_region

[ tag_region ]
key = UTF8String:region
val = UTF8String:north

[ allow_roles ]
r0 = UTF8String:oper
r1 = UTF8String:serv
```

Equivalent as a DER string:

```ini
2.25.242193075883906031821745064285793775511 = critical,DER:30:28:30:11:30:0f:0c:06:72:65:67:69:6f:6e:0c:05:6e:6f:72:74:68:30:0c:0c:04:6f:70:65:72:0c:04:73:65:72:76:02:01:05:02:02:38:40
```

DER: `SEQUENCE`(30 28){ `SEQUENCE`(30 11) requireTags { `SEQUENCE`(30 0f){
`UTF8String "region"`, `UTF8String "north"` } }, `SEQUENCE`(30 0c) allowRoles {
`UTF8String "oper"`, `UTF8String "serv"` }, `INTEGER 5`(02 01 05),
`INTEGER 14400`(02 02 38 40) }.

**Monotone narrowing.** A child CA MUST issue an envelope ⊆ the parent's (more
`requireTags`, a subset of `allowRoles`, no larger `maxLevel`/`maxTtl`) — for
early denial and clarity; but security does not depend on the links being
honest: Engine applies each CA's envelope by AND, so a wider child envelope does
not broaden the permissions. Narrowing example: parent
`requireTags{region:north}`, `allowRoles{oper,serv,admin}`, `maxLevel:7`; child
region CA `requireTags{region:north,site:hq}`, `allowRoles{oper,serv}`,
`maxLevel:5`.

## Workflow for cloned images

The full end-to-end runbook (reference → clone → flip → per-host issuance) is in
**[docs/clone-image.md](clone-image.md)**. Here — only the CA side: how to read
the TSV dump and what goes into the issued certificate.

### The TSV dump from the operator

After `finish-bootstrap.sh` the operator sends the CA admin the file
`host-ids-<hostname>-<UTC>.tsv` (over USB or through a secure channel). Columns:

```
source  status  hash_hex  hash_prefix  raw  normalized  active_under_current_config  reason
```

One row per **known** source (not only those configured in
`[host_identity].sources`): `machine_id`, `dmi_board_serial`,
`dmi_system_uuid`, `dmi_system_serial`, `hostname`, plus `custom_command` (if
configured).

The row with `active_under_current_config=yes` is the source the daemon is
using **right now**. Only its `hash_hex` goes into the certificate.

### Issuing the per-host certificate

The `hash_hex` is fed into the CA issuance tool (see
[clone-image.md §6.1](clone-image.md) — the CA tools are shipped separately, not
in this repository).

The cert receives `pam_cert_host_binding = <hash_hex>`,
`pam_cert_user_binding = <service_user>` and the standard
`extendedKeyUsage = clientAuth, emailProtection` (`emailProtection` is required
by the stock Astra validator — openssl `CMS_verify`; `tessera` itself does not
check this EKU). On a МКЦ workstation, additionally
`pam_cert_max_integrity` (see the `MAX_INTEGRITY` extension section).

The resulting `.p12` is packed onto the same USB stick by the CA tool and
returned to the workstation.

### Pre-flight checks

`tessera dump-host-id` (invoked inside `finish-bootstrap.sh` or by hand) exits
with a **non-zero code** if no source returned a non-empty value. This is an
unambiguous "do not issue the certificate until the login is fixed" signal —
typical causes: empty DMI fields in a VM, a cleared `machine_id`, a
non-working `custom_command`. See [clone-image.md §8](clone-image.md) —
troubleshooting.

### Manual dump (without the script)

After a flip has already happened:

- `tessera dump-host-id --usb` — to a USB stick;
- `tessera dump-host-id --output /tmp/host.tsv` — to a file;
- `tessera dump-host-id` (no flags) — to stdout.
