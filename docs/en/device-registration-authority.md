# Device-registration authority and delegated records

These pure `tessera_codes_contract` types define bounded public documents and
signature checks. They perform no I/O, clock reads, publication, signing or
protected-state updates. They do not implement a registration service, approval
workflow, certificate trust/CRL resolver or rollback-safe source. Runtime support
and compatible readers must be deployed before a writer emits these formats.
Existing `DeviceRecord` v1 bytes, direct-owner signatures and verification remain
unchanged. No v1 `owner_signature` is reinterpreted as a delegation proof.

## Encoding

`F(x)` is a four-byte unsigned big-endian byte length followed by exactly `x`.
All numbers are also framed: `U(x)=F(u32_be(x))`, `N(x)=F(u64_be(x))`.
The existing canonical Encoder is reused. Text must already be NFC, without
control characters, wire separators `;`/`=`, or surrounding whitespace. Owner and
organisation IDs are1…128 UTF-8 bytes. UUIDs are nonzero lowercase canonical
36-byte text, including hyphens. Binary text-wire values use lowercase hex only.
No trailing bytes, unknown fields, alternate integer widths or repaired spelling
are accepted. Text documents have no surrounding whitespace.

Authority envelope:

```
tessera-codes/v1/device-registration-authority;body=<lowerhex>;owner_signature=<lowerhex>
```

The body is exactly:

```
F("tessera-codes-contract/v1/device-registration-authority")
F(fleet_uuid) F(owner_id) N(sequence) N(not_before) N(not_after) U(grant_count)
[ F(grant_core) F(mode) ] * grant_count
```

Sequence is positive; `not_before < not_after` is an explicit half-open interval.
Grants are strictly ordered by delegation UUID, without duplicates. Empty grants
explicitly authorize no delegation. Mode is exactly `register` or `verify-only`.
Limits are64KiB complete envelope,24KiB decoded body,16 grants,2KiB per grant core.
Constructors and parsers enforce the same limits.

The immutable grant core is exactly:

```
F("tessera-codes-contract/v1/device-registration-grant")
F(delegation_uuid) F(tenant_node_uuid) F(organisation_id)
F(delegate_compressed_p256_point) N(delegate_key_version)
F("self-join-registration-v1") F(operator_policy_digest32)
N(not_before) N(register_until) N(verify_until) N(max_record_lifetime_seconds)
U(minimum_epoch) U(maximum_epoch) F(key_protection_floor) F(allow_replacement_byte)
```

P-256 points have33 bytes, prefix02/03. Key version and maximum lifetime are
positive. `not_before < register_until <= verify_until`; minimum epoch does not
exceed maximum. Protection uses the existing four `KeyProtection` tokens and
strength order. This retains their declared/observed meaning and makes no hardware
attestation claim. The final boolean is one byte00 or01. The profile is closed;
it conveys no work permission, role, CA or arbitrary-message signing authority.

Authority checkpoint identity is `(sequence, SHA256(canonical BODY))`, excluding
the ECDSA signature envelope. Two valid signatures over one body are the same
checkpoint. Grant identity is SHA256 of the canonical grant core, excluding mode
and authority sequence. An unchanged core can move to verify-only while preserving
existing bounded records. Removing its entry revokes records under that grant;
changing any core field changes its digest. Rotation uses distinct grant IDs.

## Explicit device record v2

Marker: `tessera-codes/v2/device-record`. Fixed ordered `key=value` fields:

```
device, key, epoch, serials, key_protection, anchor, batch, baseline,
organisation, owner, possession_signature, organisation_signature,
owner_proof, fleet_id, tenant_node_id, delegation_id, grant_digest,
request_digest, plan_digest, registration_generation, previous_record_digest,
registered_at, not_after, authority_sequence_at_registration, delegate_signature
```

`owner_proof` is exactly `delegation-v1`. A missing previous digest is exactly
`-`; a present one is32 bytes in lowercase hex. Generation and registration
sequence are positive u64. Integers in text wire use canonical decimal, with no
leading zeroes. The device number renders in its significant checked form (≤32
bytes; constructor input spelling≤64 bytes). The device point is compressed P-256.
At most16 distinct serials are retained in their existing v1 order; serial kind,
value and batch are NFC and at most128 bytes each. The v1 payload encoding,
possession-message domain and organisation-message domain remain identical.

The three carried signatures use bounded canonical DER (≤72 bytes). The actual
backend also checks scalar ranges and real P-256 signature math. Whole record
limit is16KiB. A parser does not make a certificate chain or claimed signer trusted.

The delegate signs exactly:

```
F("tessera-codes-contract/v1/registry-owner-delegated")
F(v1_payload_canonical) F(possession_signature) F(organisation_id)
F(organisation_signature) F(owner_id)
F(fleet_uuid) F(tenant_node_uuid) F(delegation_uuid) F(grant_digest32)
F(request_digest32) F(plan_digest32)
N(registration_generation) F(previous_record_digest_or_empty)
N(registered_at) N(not_after) N(authority_sequence_at_registration)
```

`record_digest` is SHA256 of `F(delegate_proof_message) F(delegate_signature)`.
It identifies the exact retained signed artifact, including the signature bytes.
Do not normalize S, replace a valid DER signature, or re-sign during replay. This
identity intentionally differs from authority BODY-only checkpoint identity.
A previous-record digest is an opaque protected-history reference; validating
replacement provenance and assigning generations remains the consumer's job.

## Verification boundaries

`SignedAuthority::verify_candidate` requires independently supplied fleet, owner
identity, actual pinned owner point and trusted time. `P256SignatureVerifier` has
mandatory point-validation and exact-message signature-verification methods with
no permissive defaults. All grant points, including unselected ones, must pass
real curve validation before a candidate is returned. A33-byte shape is not a
curve-membership proof. Candidate fields are immutable and actual owner-key
provenance is retained.

A candidate is not current merely because its signature holds. Admission requires
`CurrentAuthorityContext` with the **exact** protected current sequence/body digest,
the same owner pin, scope and current time. Neither a larger sequence nor a cached
last-successful body is implicitly accepted. Publishing a candidate and advancing
persistent floors require a separate atomic, protected runtime operation.

`registration_grant` additionally checks register mode, registration window, node,
organisation, actual delegate point/version, operator-policy digest, epoch,
protection and explicit replacement permission. It does not prove that required
approvals were obtained or that custody can safely sign this domain.

`DelegatedDeviceRecord::verify` requires that current authority context plus an
independent protected current-record generation/digest. Missing currentness has no
optional fallback. It verifies v1 device possession and organisation signatures,
the delegated signature, matching immutable grant, scope, epoch/floor,
registration window, finite checked record lifetime and current expiration.
Verify-only permits bounded existing records but cannot admit a new registration.
Named organisational verification keeps the existing trusted verifier semantics;
chain eligibility and revocation checks remain mandatory in that implementation.

`RegistryRecord::parse` explicitly dispatches v1 versus v2 and authenticates neither.
A runtime activating protected generation checks must apply its policy to all
relevant readers, including potentially superseded v1 records; it must not fall
back to direct v1 verification when the protected source is unavailable. Protected
legacy baselines, replacement state, source failure, grant withdrawal and offline
revocation availability remain runtime prerequisites. No running session or
already delivered short-lived code is retroactively invalidated by this codec.

## Fixtures

`tests/golden/registration/` contains an independent Python LP writer with OpenSSL
signatures and publicly known test scalars1…4. Rust tests use a dev-only pure-Rust
`p256` backend to check every signature. Bodies/digests are deterministic; explicitly
regenerating ECDSA envelopes changes their bytes. These are test keys and sample
time/epoch bounds, never installation defaults. The existing272 v1 tests/goldens
remain unchanged. No public runtime crypto dependency was added.
