# Locally owned keys and public enrollment material

The Unix `enrollment::local_keys` and `enrollment::public_material` APIs support
public delivery to a device that retains its own keys. They perform no network
requests, publish no device registry record, produce no applied receipt, and do
not alter configuration, trust anchors for TLS, or login enforcement. The existing
courier `EnrollmentPackage` and PIN-protected delivery-container path remain separate.

`LocalEnrollmentKeys::create_new` reserves a fresh owner-only directory, generates
two distinct P-256 keys using the native cryptographic provider, and writes both
as key-only PKCS#12 files beneath a staging directory. A single directory rename
publishes the complete pair and its immutable CSR after file/directory fsync.
Existing and partial stores are refused; retries use `load`, never regenerate keys.
A crash before publication can leave a protected reservation needing explicit
operator recovery. No private bytes or containers are returned by the public API.
The public methods return the Codes SEC1 point, TLS SPKI/CSR and a bounded ECDSA
Codes signature. The protocol adapter supplies its own canonical signature domain.

The store uses mode0700 directories and mode0600 key containers, owned by the
running account (root for device provisioning). It is software custody, not hardware
protection or proof of non-exportability. All path ancestors must pass the existing
privileged-path trust policy; symlinks are refused. Tests use owned directories with
trusted ancestors, not a caller-controlled switch that disables checks.

The local Codes loader accepts this certificate-free P-256 container format.
Certificate-bearing containers still pass through the existing complete PKCS#12
loader; the courier importer still requires its delivery certificate. No artificial
self-signed certificate or new CA is created to make key storage work.

`PreparedPublicEnrollment::prepare` reads a bounded directory containing the exact
existing owner-signed manifest and its declared role/CRL/Codes files. Private-delivery
fields (`p12_sha256`, `codes.key_container`), undeclared entries and `.p12`/`.pfx`
files are refused. The manifest bytes are never rewritten. The existing Ed25519
catalogue verifier checks the signature, OS, schema, role hashes and version floor.
Codes pins, ticket signatures and public anchor are checked with the existing
parsers. The application also preserves epoch and revocation monotonicity.
Ticket time, scope and role eligibility still belong to the normal login path.

A returned DER leaf must contain the actual local TLS public key. This check does
**not** authenticate the server, certificate chain, issuer, purpose, identity or
validity. The private protocol adapter must verify those facts and the outer signed
envelope before applying this generic material. The Codes point matcher likewise
checks equality to the local key, not the authority of the enclosing document.

`apply` receives explicit local destination paths and revalidates keys, floors and
existing state. It stages role files and validates device accounts before recording
a durable pending attempt. Its digest binds all public bytes, both public keys and
all destinations. It publishes the certificate, optional CRL and Codes material,
then uses the existing role-store swap and shared `bundle.version` floor. It fsyncs
and rechecks the installed bytes/floors/keys before recording completion. This is
recoverable multi-file application, not simultaneous activation of every consumer.
No failure or uncertain crash is reported as completed. Repeating the exact attempt
repairs partial state; a different input or destination is refused. `state` checks
actual installed material, not merely a completion flag.

The adapter must not send an applied acknowledgement from a file's existence or a
stored boolean. It needs the verified outer-package identity and a current successful
application result. Subsequent operational updates continue through their existing
paths; this journal does not define a second bundle rollback counter, new approval
mechanism, CA trust migration or a generic configuration updater.
