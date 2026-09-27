# Unsigned client-authentication TBS preparation

`tessera_issuer::client_auth` prepares one fixed standard X.509 client profile
without generating keys, signing, reading a clock, contacting a backend or
activating a credential. It is separate from the engineer shift-leaf issuer.
Existing engineer CSR and certificate APIs retain their behavior.

`prepare_client_auth_tbs` takes an exact DER CSR, a caller-derived identity URI,
a mandatory distinct signing public key, public issuer certificate, fixed
validity, allocated serial and the selected issuer signature algorithm. The
caller must establish its own approved identity, issuer trust and purpose.
A URI copied from an untrusted request is not established by this function.

The CSR is bounded to 16 KiB and must carry a P-256 key with a valid
ECDSA/SHA-256 proof of possession. Signature algorithm parameters and unused
signature/key bits are rejected when inconsistent with the profile. Exact DER
round-trip is checked; PEM, trailing bytes and repaired encodings are refused.
The public key is emitted as canonical uncompressed P-256 SPKI. CSR Subject and
requested extensions do not shape the certificate.

The supplied distinct key accepts compressed or uncompressed P-256 SEC1 public
points. Equality is checked as curve points: comparing a hash of SPKI with a
hash of compressed SEC1 would not detect reuse of the same key. This check does
not establish who owns either public key; the caller must bind them to its
verified context. Registering other signing keys later must preserve the same
separation rule.

## Fixed profile

The subject is an empty DER Name. There is exactly one caller-derived URI SAN,
with no additional names, subject attributes or optional custom extensions.
The URI is bounded to 256 ASCII bytes and must have URI syntax; a consumer
must additionally enforce its own exact identity namespace and binding.

| Order | Extension | Critical | Value |
|---|---|---|---|
| 1 | basicConstraints, 2.5.29.19 | yes | CA=false, no pathLen |
| 2 | keyUsage, 2.5.29.15 | yes | digitalSignature only |
| 3 | extendedKeyUsage, 2.5.29.37 | no | clientAuth, 1.3.6.1.5.5.7.3.2 only |
| 4 | subjectAltName, 2.5.29.17 | yes | one uniformResourceIdentifier |

There are no Engine host-binding, allowed-role, integrity, delegation or
profile-version extensions. The helper accepts no arbitrary Subject or
extension list and cannot request CA=true or serverAuth. TBS version is X.509v3;
serial is the existing allocated positive `Serial`, at most 20 encoded content
octets. A sign-padding octet counts toward that limit. No serial is allocated
or changed during retry.

The exact issuer Subject supplies the TBS issuer name. Public issuer inputs
are bounded to 64 KiB and checked structurally: CA=true, keyCertSign, unique
well-formed extensions, nonempty name, compatible issuer-key/signature algorithm
and containing validity window. These are shape checks, not verification of
the issuer's signature, chain, current revocation or authorization to issue.
The caller must enforce those and any narrower parent/policy lifetime limits.

`PreparedClientAuthTbs` is immutable and exposes exact TBS, CSR and issuer
fingerprints, emitted SPKI and URI. Repeated identical inputs give identical
TBS bytes. The output is not an approved operation or a signed certificate.
Consumers must bind the exact CSR/SPKI/TBS/issuer/serial/window to their decision
and reject substitutions before a separately authorized signing operation.

`validate_client_auth_tbs` reparses the complete TBS and requires exact DER
round-trip, standard algorithm shape, positive bounded serial, valid window,
canonical P-256 SPKI and the exact extension profile above. It does not prove
who selected the URI or that any issuer/signing decision exists. Compare the
exact bytes with the independently prepared object as a separate check.

## Separation and verification limits

ClientAuth alone does not distinguish this credential from an engineer leaf:
both use that EKU. Existing Engine behavior additionally rejects this critical
SAN, absent host binding and missing allowed roles. The Engine's critical
extension allowlist is unchanged. A future Engine that learns to process SAN
still must not infer role coverage from a URI or Subject.

The empty Subject supplies no common name for a service identity reader. This
is a profile separation property, not a replacement for a receiver's own trust,
identity, purpose, activation and revocation checks.

Tests create a real signed public fixture certificate and verify its standard
PKIX chain for SSL_CLIENT, while SSL_SERVER and the existing Engine checks
refuse it. They exercise distinct point representations, malicious CSR
attributes, DER canonicality, malformed lengths, BIT STRING padding, serial
boundaries and randomized inputs.

An existing Access CA can contain critical custom delegation/profile extensions.
The unsigned helper can read its standard issuer fields without pretending to
validate a TLS path. The stock TLS path verifier test explicitly rejects such
an intermediate: no unknown-critical bypass is enabled. A deployed transport
still needs a correctly scoped verifier and a proven compatible configured
chain; neither a fixture chain nor this TBS primitive establishes that readiness.

The implementation remains pure Rust and can be compiled without native
features for the existing WASM issuer build. There is no new CLI, RPC, signing
purpose, trust anchor, private-key export or runtime issuance path.
