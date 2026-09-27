# Signed role catalogue metadata

The optional `issuance` section belongs to the existing `manifest.toml`. Its
raw bytes are covered by the existing owner signature and `bundle_version`.
It references roles already pinned by that manifest; it introduces no new key,
role database, signature format or device rollback counter.

```toml
[issuance]
schema_version = 1

[issuance.roles.oper.codes]
max_level = 7

[issuance.roles.oper.certificate]
max_level = 127
max_categories = "0xffffffffffffffff"
```

The section, each role entry and each method are closed schemas: unknown
fields, methods, versions, duplicate fields, invalid values and references to
roles absent from `manifest.roles` are rejected. Each method is optional. A
missing method is unavailable for issuance. An absent role entry grants no
methods. A legacy manifest without `issuance` remains valid, with its issuance
catalogue unpublished. Empty metadata does not grant any method.

Codes `max_level` is an integer from 0 through 127, the Control issuance bound
for catalogue version 1. The existing Codes wire `Level(u32)` is unchanged.
Certificate bounds use the existing `IntegrityLabel`: `max_level` is a signed
integer from -128 through 127; `max_categories` is a string containing a
hexadecimal (`0x`/`0X`) or decimal `u64` category mask. Both certificate fields
are required when that method is present. A category mask is not a linear
level. Category coverage is subset inclusion; linear coverage compares the
signed levels.

`RoleSlice.level` remains a display hint and is never substituted for either
issuance bound. `payload.mac_mask` remains the role's category mask. The role's
existing `session.max_ttl_seconds` is exposed unchanged and is not inferred
from either level. These fields describe configured bounds; neither their
presence nor catalogue verification proves session enforcement. No Linux
groups, sudo, resource limits, NSS or confidentiality enforcement is added.

## Library projection

`role::catalogue::verify_catalogue` takes raw manifest bytes, role files keyed
by `RoleId`, the existing trusted owner public key, an optional minimum bundle
version and an optional accepted `CatalogueCheckpoint`. It checks the raw
signature, rollback, same-version replacement, file hashes, slice schemas,
role identifiers, slice version pins and the manifest's single target OS.
It rejects unlisted files and bounds input to 256 roles, 256 KiB per manifest
and 64 KiB per role. It never consults the reader host's OS or account database.

The immutable result contains the bundle version, complete raw-manifest
SHA-256, target OS, existing role data and explicit issuance bounds. A missing
issuance schema version means a legacy bundle, not a usable product issuance
catalogue. The API performs no filesystem writes or issuance.

Consumers scope accepted checkpoints to the same owner trust and publication
stream, including the target OS. They persist both version and digest together
with publication in an atomic compare-and-swap against the checkpoint used for
verification. The digest covers the complete manifest, including the signature;
any byte change requires a new bundle version. An equal-version different
digest is refused even if both signatures are valid. A minimum version alone
cannot provide this replacement check.

Consumers must establish current publication/freshness and recheck the bound
checkpoint at issuance time. The library does not invent an expiry timestamp,
publish the catalogue, authorize work or combine role bounds with a verified
credential chain. Device rollback persistence remains the existing mechanism.
Malformed issuance metadata is rejected by the shared manifest parser before a
device verifier can accept a new rollback floor.

## Compatibility and rollout

Existing role files, manifests without `issuance`, signed payload bytes and
Codes serialization are unchanged. Older strict manifest readers reject the
new section. Upgrade every reader that will consume a bundle before publishing
metadata in it; do not deliver it to an older reader or claim downgrade
compatibility after publication. Editing or stripping metadata changes the
signed bytes and requires the normal signing and versioned publication process.
There is no separate catalogue inspection CLI.

Publication of the new section is an explicit future format cutover, not a
claim that older binaries can read new persistent state. Before that cutover,
a publisher must keep issuance-metadata publication disabled and refuse it
until version and capability evidence establishes that every target reader in
the fleet supports this schema. Missing, stale or unknown compatibility
evidence blocks publication; an operator must not infer support from a
successful signature check or from this library being installed on the server.

The fleet's root owner must explicitly authorize the concrete publication for
that fleet after reader compatibility is established. This requirement is
separate from permission to implement or test the library. The publisher must
also have a forward-only recovery procedure for the cutover: restore service
with compatible readers and, when replacing published content, a correctly
signed higher bundle version. Downgrading to an older strict reader, stripping
metadata in place or lowering the accepted rollback floor is not a recovery
procedure.

These publisher capability checks, publication authorization gates and recovery
orchestration are release prerequisites. This library implements none of those
gates and its successful verification result must not be treated as evidence
that they have passed. Until the publisher implements them and records the
required evidence, issuance-metadata publication remains unavailable.
