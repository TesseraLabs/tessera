# Initial registry baselines and ordered legacy imports

`tessera_codes_contract::registry_baseline` is a pure public codec. It performs
bounded parsing and signature/context checks, with no I/O, database, clock read,
writer fence, persistent nonce consumption or protected state installation.
Existing direct-owner v1 and delegated v2 record bytes/APIs remain unchanged.
The import companion is optional before protected registry activation; after
activation, out-of-band v1 admission requires ordering evidence or an already
protected ordered registration intent. A valid old record alone cannot reset
currentness. No hardware attestation or work permission is introduced.

## Canonical forms and limits

`F(x)` is `u32_be(length)||x`, `N(x)=F(u64_be(x))`, `U(x)=F(u32_be(x))`.
Fields have exactly the listed order. Text must be canonical NFC with no surrounding
whitespace/control characters/wire delimiters; owner/organisation identifiers
use1–128 UTF-8 bytes. UUIDs are nonzero lowercase canonical strings. Device
numbers use their significant checked uppercase spelling, at most32 bytes.
Constructors use the existing `CheckedDeviceNumber` identity rules; parsers reject
alternate wire spellings. Signatures are bounded canonical P-256 ECDSA-SHA256 DER;
actual curve/signature math is mandatory in the supplied verifier.

Signed bodies are at most2KiB; complete text envelopes8KiB. Binary inventories
allow at most4096 entries,512bytes per entry,2MiB overall. New ordered imports
accept a carried direct-v1 record of at most16KiB. Both aggregate and individual
bounds apply; none is a production lifetime or authorization default.

## Baseline manifest and inventory

Envelope:

```
tessera-codes/v1/registry-baseline;body=<lowerhex>;owner_signature=<lowerhex>
```

Signed body:

```
F("tessera-codes-contract/v1/registry-baseline")
F(fleet_uuid) F(owner_id) F(baseline_uuid)
F(registry_instance_uuid) F(activation_cut_uuid) N(cut_sequence) F(cut_digest32)
N(not_before) N(accept_until)
F(completeness) U(entry_count) N(inventory_byte_length) F(inventory_sha256)
```

`empty-history` requires count0 and explicitly attests no prior registrations in
the fleet, including retired numbers. `complete-history` requires a nonempty
complete set of current heads and previously registered-number tombstones. This
is not a list of future permitted numbers or every old record version. An absent
file, an empty query result or individually signed records cannot attest
completeness. The manifest identifies a separate canonical inventory artifact:

```
F("tessera-codes-contract/v1/registry-inventory") U(count)
[ F(entry) ] * count
entry = F(number) F(registration_node_uuid) F(organisation_id)
        F(state) N(generation) F(record_kind) F(record_digest_or_empty)
```

Entries have strictly ascending unique significant numbers across the fleet.
`current` requires a positive generation and exact known record identity.
`retired` retains a known last identity or uses `unknown` plus an empty digest;
the latter still reserves a historical number and cannot authorize ordinary
automatic replacement. Imported v1/tombstone generation1 denotes the first
protected-index ordinal, not a claimed historical registration count. A retained
v2 head must keep its actual signed proof generation.

Digest kinds are exact and distinct:

- `direct-v1-wire-sha256`: SHA256 of the exact retained full v1 wire bytes.
- `delegated-v2-current-digest`: existing `DelegatedDeviceRecord::record_digest`,
  SHA256 of `F(proof_message)||F(actual_delegate_DER_signature)`. It is not merely
  the proof-message hash and never normalizes/replaces the signature.
- `unknown`: only a retired entry without its previous artifact.

Baseline identity is SHA256 of the canonical signed manifest **body**, excluding
its ECDSA envelope. Alternative valid signatures over the same body do not create
another baseline. `SignedBaseline::verify_candidate` verifies actual independently
pinned owner point/signature, scope and inventory hash/count/length. Its immutable
`SignatureCheckedBaseline` retains that owner provenance and exact historical
inventory. **Cryptographic historical verification works after accept_until**;
this is necessary to replay an already committed baseline.

Only `check_initialisation(BootstrapContext)` checks the half-open bootstrap
window `[not_before,accept_until)`, exact still-held `ProtectedActivationCut`,
unchanged owner/fleet and `BootstrapState::Uninitialised`. An installed registry
cannot be reset even by another valid signed baseline. The cut contains an
independently protected registry instance, unique barrier UUID and exact journal
sequence/head; sequence0 permits a separately defined genesis. The caller must
fence every relevant writer/importer, reconcile pre-cut work and CAS that same
uninitialized cut while retaining the fence. This codec cannot prove that the
barrier is held or the owner's completeness statement is true.

`BaselineInventory::lookup_at_cut` deliberately reports historical entries only.
Its `None` is **not ongoing protected absence**. After bootstrap, current heads,
tombstones, reservations and absence derive from the protected runtime's replayed
baseline plus all subsequent transitions. Source loss does not justify v1 fallback.
The bootstrap time window does not expire already committed registry history.

## Owner import companion

Envelope marker: `tessera-codes/v1/registry-import`, with the same two envelope fields.
Signed body:

```
F("tessera-codes-contract/v1/registry-import")
F(fleet_uuid) F(owner_id) F(baseline_uuid) F(baseline_body_digest32)
F(registry_instance_uuid) F(operation_uuid)
F(number) F(registration_node_uuid) F(organisation_id)
N(not_before) N(not_after)
F(expected_state) N(expected_generation) F(expected_kind) F(expected_digest_or_empty)
F(new_direct_v1_wire_digest32)
```

Expected `absent` is generation0, kind`none`, empty digest. It must match confirmed
protected absence under the complete baseline. Expected `current`/`retired`
requires an exact positive generation and known kind/digest. Reserved,
unavailable or unknown-history tombstone state refuses this helper; controlled
repair is a separate operation. The new record is always unchanged direct v1;
its exact retained bytes are hashed and all existing PoP/organisation/owner
proofs still verify. Device keys retain their existing v1 backend semantics,
including uncompressed P-256/P-384 SEC1 points; the new owner proof profile does
not impose its compressed P-256 key shape on a legacy device. The owner countersignature is additionally checked against
the independently pinned actual owner point, not just a matching name.

`SignedRegistryImport::verify_transition` requires an `ImportContext` from
independently current protected state: exact baseline/instance/owner, number and
scope, queried operation UUID/status, current head/reservation status and last
allocated generation. Existing trusted organisation-chain/revocation checks,
operator approval and replacement-stop requirements remain caller duties. A
companion does not bypass them or place the owner key online. Automatic delegated
registration does not use this companion or require a per-device owner action.

The verifier checks the half-open import admission window, exact predecessor and
unseen operation, then proposes checked `last_allocated_generation+1`. The floor
cannot precede the current head; overflow refuses. Gaps after failed attempts are
valid. A number with no completed registration may retain an allocation floor
from a failed attempt without pretending it has a completed predecessor.

`VerifiedRegistryImport` retains immutable verified baseline/owner/scope/number,
operation/body identity, predecessor, previous allocation floor and proposed new
head. It is **not committed state**: the caller must atomically consume that
operation UUID and CAS the same head/allocation/reservation state. Concurrent
proposals can both verify; only the protected CAS may win. `OperationState::Seen`
refuses any fresh admission; idempotent historical replies must not reapply old
heads. The same applies after companion expiry: history can be read, but a new
transition cannot be admitted. An untrusted database row is not a substitute for
any of these context inputs.

## Fixtures

`tests/golden/registry-baseline/` has an independent Python encoder and external
OpenSSL signatures using publicly known TEST keys. It reads the unchanged earlier
v1/v2 golden records to bind their real, different digest recipes. Frozen vectors
cover complete/empty baselines and new/replacement import preconditions; Rust's
real p256/p384 test backends verify them (legacy device signatures use the
existing SHA256 prehash for both curves). Tests also cover tombstones, owner provenance,
cut and initialization state, historical replay after bootstrap expiry, exact
record proofs, reported consumed operations, reservations, unavailable state,
generation overflow/gaps and malformed/bounded inputs. They do not claim a
protected runtime, durable replay defense, deployment or live owner values.
