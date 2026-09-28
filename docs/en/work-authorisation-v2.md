# Work authorisation v2 foundation

The `tessera_core::work_authorisation` module provides bounded parsing, canonical
encoding, signature/context verification and pure reference/coverage checks.
It activates no issuer, RPC, publication, status or revocation consumer. Codes
v1 readers, signed bytes, fixtures and the Codes challenge/MAC are unchanged.

A `SignatureChecked` value proves a signature and expected identity matched.
It is not a current issuance authorization. Consumers still need current
published authority, chain ceilings, approvals, authenticated device context,
directory checks and exact-grant revocation/status for the same authorisation
ID and body digest. A v1 engineer-wide status is not an exact-grant status.

## Envelope and canonical body

The exact ASCII envelope is:

```text
tessera-work/v2/authorisation;body=<lowercase hex>;signature=<lowercase hex>
```

There are exactly two fields in that order. No whitespace, BOM, line terminator,
unknown field, odd/uppercase hex or trailing bytes are accepted. Parsing does
not verify a signature. The draft uses the byte `00` as a signature placeholder;
it is not a cryptographic signature or a verification bypass.

The complete decoded body is the signature message. Every primitive below is
encoded as `u32_be(byte_length) || bytes`, including numbers, presence flags,
list counts and digests. Numeric payloads have exactly their declared width.
There is no padding. List counts are u32; each list item is framed individually.
A role row is its consecutive framed fields, without an additional row wrapper.
Any bytes after the last row are rejected.

| Order | Field | Payload |
|---|---|---|
| 1 | label | ASCII `tessera-work-contract/v2/authorisation` |
| 2 | schema_version | u32 big-endian, exactly 2 |
| 3 | authorisation_id | 16 UUID bytes, not zero |
| 4 | fleet_id | 16 UUID bytes, not zero |
| 5 | tenant_node_id | 16 UUID bytes, not zero |
| 6 | engineer | NFC UTF-8, 1–128 bytes |
| 7 | organisation | NFC UTF-8, 1–128 bytes |
| 8 | key_fingerprint | 32 bytes, engineer key fingerprint |
| 9 | devices_kind | one byte: 0 Any, 1 Only |
| 10 | device_count | u32; Any requires zero, Only requires 1–64 |
| 11 | device items | canonical significant ASCII checked numbers, 2–64 bytes each |
| 12 | tag_count | u32, 1–64 |
| 13 | tag items | NFC UTF-8, 1–256 bytes each |
| 14 | not_before | u64 big-endian Unix seconds, inclusive |
| 15 | not_after | u64 big-endian Unix seconds, exclusive and greater than start |
| 16 | role_count | u32, 1–256 |
| 17 | role rows | the fields below, for each row |

UUID bytes use network/text order, not a platform's mixed-endian GUID encoding.
No new UUID version/variant requirement is imposed. The body signs fleet and
node identity explicitly. The verifier must resolve the existing
`SignerRef::AuthorisationKey` in the caller's independently established fleet
trust domain; the document cannot choose its own signer.

The existing engineer key fingerprint axis is preserved. Zero32 is an explicit
unverified marker, never a wildcard matching another key. Nonzero bytes are not
proof of possession: consumers must independently establish the engineer's
record and key proof before supplying `ExpectedIdentity`.

Engineer and organisation strings reject controls, `;` and `=`. Tags additionally
reject `,`, are strictly ordered by UTF-8 bytes and contain no duplicates. NFC
is required without silent normalization. Tags retain literal equality; `*`
acquires no new wildcard meaning. Devices retain explicit Any/Only semantics;
Only lists must be strictly sorted significant numbers without duplicates.
The parser rejects alternate spelling rather than silently repairing it.

## Role rows

| Order | Field | Payload |
|---|---|---|
| R1 | role_id | existing ASCII `^[a-z][a-z0-9-]{0,15}$` |
| R2 | target_os | ASCII `astra`, `linux` or `windows` |
| R3 | stream_id | ASCII `[A-Za-z0-9_.-]{1,128}` |
| R4 | trust_sha256 | 32 bytes, trusted catalogue key's canonical SPKI SHA-256 |
| R5 | bundle_version | u64 big-endian |
| R6 | manifest_sha256 | 32 bytes, complete raw manifest including signature |
| R7 | slice_version | u32 big-endian |
| R8 | slice_sha256 | 32 bytes, raw role file SHA-256 |
| R9 | codes_present | one byte, 0 or 1 |
| R10 | codes_max_level | only when present: one byte, 0–127 |
| R11 | certificate_present | one byte, 0 or 1 |
| R12 | certificate_max_level | only when present: signed one-byte two's complement |
| R13 | certificate_max_categories | only when present: u64 big-endian |

Rows are strictly sorted by `(role_id ASCII, target_os ASCII)` and the pair is
unique. All rows for one OS must name the same stream, trust, bundle version and
manifest digest. Wildcard roles are not admitted by v2; this does not alter v1.
At least one method must be present in each row. Missing means unavailable;
present zero remains an explicit bound. Categories are a bit set, not a numeric
level. Certificate coverage uses signed level comparison and category subset.
Codes never borrows a certificate bound, and neither uses the display level.

The envelope is at most 65,536 bytes, decoded body at most 24,576 bytes, and
signature 1–4,096 bytes. Per-field/count bounds also apply. The row count bound
does not promise that every combination of maximum-sized rows fits the byte
budget. Builder and parser use the same invariants. This module changes no
existing transport limits; v2 is not automatically accepted by old endpoints.

## Digests and checks

`body_digest` is SHA-256 of the full canonical body, excluding the signature.
`approval_digest` is SHA-256 of the exact UTF-8 draft envelope with
`signature=00`. These digests differ. If a transport also needs a digest of the
complete signed envelope, that is a third, distinct value. Reusing an
`authorisation_id` with a different body is not an update; consumers must reject
that conflict and persist exact-grant state atomically.

The reference checker accepts byte-verified catalogues paired with independently
protected fleet/node/stream/trust context. Context must not be copied from the
untrusted intent. It compares manifest and slice versions/digests and explicit
method caps. `VerifiedRoleCatalogue` retains the canonical SPKI fingerprint of
the exact Ed25519 key that verified it: relabelling a catalogue with a claimed
fingerprint cannot change that provenance. PEM and DER encodings of one key
produce the same fingerprint. This new catalogue projection rejects other key
profiles; the legacy manifest signature API is unchanged.

A reference match establishes neither active publication nor a chain ceiling,
TTL, directory admission, device identity or current grant status. Time helpers
check only the supplied half-open interval. Consumer clocks and representable
X.509 time bounds are their own checks. Coverage refuses wider requests instead
of clamping them. There is no `is_authorized` or currentness shortcut.

## Verification and rollout

Independent golden body hex files live under
`crates/tessera_core/tests/fixtures/work_authorisation_v2/`. They pin the
reviewed domain and field layout; fixture signatures use a public deterministic
test key. Tests cover signature tampering, caller identity, catalogue key
provenance, missing methods, signed certificate limits, malformed/truncated
input, allocation bounds, randomized inputs and v1 rejection of the new domain.

A future consumer rollout requires all relevant readers to support the new
format and the same exact-grant identity in status/revocation. Older strict
readers reject it. Publication, activation, device host binding and issuer
wiring remain unavailable through this foundation alone. No new keys, signing
purposes, session enforcement or runtime fallback are introduced.
