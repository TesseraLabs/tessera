//! Golden vectors: the frozen bytes of the contract.
//!
//! The vectors live in `tests/golden/` as plain text — a human-readable input
//! beside the bytes it must produce — and this test replays every one of them.
//! It runs inside the crate rather than as an integration test so that the
//! derived key can be compared without an accessor that would hand `K` to every
//! consumer of the library.
//!
//! A vector that no longer matches is not a test to be updated: the bytes are
//! the compatibility surface of the channel, and changing them is a
//! breaking change under the workspace compatibility policy.
//!
//! The ticket of a vector is written in its wire form and parsed like any other
//! ticket, so the vectors freeze the canonical bytes of the ticket document as
//! well — the key derivation hangs off them, and a ticket that encoded
//! differently would move every key in the file without any other test noticing.

use std::fs;
use std::path::{Path, PathBuf};

use crate::canon::{canon, CodeInput, Level};
use crate::code::{compute_code, verify_code, Alphabet};
use crate::device_number::CheckedDeviceNumber;
use crate::key::{derive_key, Epoch, KeyContext, SharedSecret};
use crate::nonce::Nonce;
use crate::params::{FleetParams, FleetParamsInput};
use crate::ticket::SignedTicket;

/// One parsed vector file.
struct Vector {
    name: String,
    device_number: String,
    nonce: String,
    role_id: String,
    level: u32,
    epoch: u32,
    engineer_id: String,
    ticket: String,
    shared_secret: Vec<u8>,
    alphabet: Alphabet,
    code_len: u8,
    nonce_width: u8,
    canon_hex: String,
    ticket_hex: String,
    context_hex: String,
    key_hex: String,
    code: String,
}

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

fn field<'a>(lines: &'a [(String, String)], key: &str) -> Option<&'a str> {
    lines
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a malformed vector file must fail the test on the spot"
)]
fn parse(name: &str, text: &str) -> Vector {
    let lines: Vec<(String, String)> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (key, value) = line.split_once('=').unwrap();
            (key.trim().to_owned(), value.trim().to_owned())
        })
        .collect();

    // `role_id_hex` carries the exact bytes when the role identifier is not in
    // NFC — the vector that proves normalisation happens could not be written
    // as plain text without an editor silently composing it.
    let role_id = match field(&lines, "role_id_hex") {
        Some(encoded) => String::from_utf8(hex::decode(encoded).unwrap()).unwrap(),
        None => field(&lines, "role_id").unwrap().to_owned(),
    };

    let alphabet = match field(&lines, "alphabet").unwrap() {
        "decimal" => Alphabet::Decimal,
        "crockford32" => Alphabet::CrockfordBase32,
        other => panic!("unknown alphabet `{other}` in vector `{name}`"),
    };

    Vector {
        name: name.to_owned(),
        device_number: field(&lines, "device_number").unwrap().to_owned(),
        nonce: field(&lines, "nonce").unwrap().to_owned(),
        role_id,
        level: field(&lines, "level").unwrap().parse().unwrap(),
        epoch: field(&lines, "epoch").unwrap().parse().unwrap(),
        engineer_id: field(&lines, "engineer_id").unwrap().to_owned(),
        ticket: field(&lines, "ticket").unwrap().to_owned(),
        shared_secret: hex::decode(field(&lines, "z_hex").unwrap()).unwrap(),
        alphabet,
        code_len: field(&lines, "code_len").unwrap().parse().unwrap(),
        nonce_width: field(&lines, "nonce_width").unwrap().parse().unwrap(),
        canon_hex: field(&lines, "canon_hex").unwrap().to_owned(),
        ticket_hex: field(&lines, "ticket_hex").unwrap().to_owned(),
        context_hex: field(&lines, "context_hex").unwrap().to_owned(),
        key_hex: field(&lines, "k_hex").unwrap().to_owned(),
        code: field(&lines, "code").unwrap().to_owned(),
    }
}

#[expect(
    clippy::unwrap_used,
    reason = "a vector that cannot be replayed must fail the test on the spot"
)]
fn replay(vector: &Vector) {
    let params = FleetParams::parse(FleetParamsInput {
        alphabet: vector.alphabet,
        code_len: vector.code_len,
        nonce_width: vector.nonce_width,
        ..FleetParamsInput::defaults()
    })
    .unwrap();

    let device_number = CheckedDeviceNumber::parse(&vector.device_number).unwrap();
    let input = CodeInput {
        device_number: &device_number,
        nonce: &vector.nonce,
        role_id: &vector.role_id,
        level: Level::new(vector.level),
        epoch: Epoch::new(vector.epoch),
        engineer_id: &vector.engineer_id,
    };

    let canonical = canon(&input).unwrap();
    assert_eq!(
        hex::encode(&canonical),
        vector.canon_hex,
        "canonical bytes changed in vector `{}`",
        vector.name
    );

    let ticket = SignedTicket::parse(&vector.ticket).unwrap();
    assert_eq!(
        hex::encode(ticket.encode().unwrap()),
        vector.ticket_hex,
        "canonical ticket bytes changed in vector `{}`",
        vector.name
    );

    let hash = ticket.context_hash().unwrap();
    let context = KeyContext::new(&device_number, hash);
    assert_eq!(
        hex::encode(context.encode().unwrap()),
        vector.context_hex,
        "key context bytes changed in vector `{}`",
        vector.name
    );

    let secret = SharedSecret::new(vector.shared_secret.clone()).unwrap();
    let key = derive_key(&secret, &context).unwrap();
    assert_eq!(
        hex::encode(key.expose()),
        vector.key_hex,
        "derived key changed in vector `{}`",
        vector.name
    );

    let code = compute_code(&key, &input, &params).unwrap();
    assert_eq!(
        code.as_str(),
        vector.code,
        "code changed in vector `{}`",
        vector.name
    );
    assert_eq!(
        verify_code(&key, &input, &params, &vector.code),
        Ok(()),
        "vector `{}` no longer verifies",
        vector.name
    );

    // The nonce of a vector is a document of the channel too: a width or an
    // alphabet the parser stopped accepting would leave these bytes reachable
    // only through a nonce nobody could present.
    assert!(
        Nonce::parse(&vector.nonce, &params).is_ok(),
        "the nonce of vector `{}` no longer parses",
        vector.name
    );
}

#[test]
#[expect(
    clippy::unwrap_used,
    reason = "an unreadable vector directory must fail the test on the spot"
)]
fn golden_vectors_still_hold() {
    let mut replayed = 0usize;
    let mut entries: Vec<PathBuf> = fs::read_dir(golden_dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "txt"))
        .collect();
    entries.sort();

    for path in entries {
        let name = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_default()
            .to_owned();
        let text = fs::read_to_string(&path).unwrap();
        replay(&parse(&name, &text));
        replayed += 1;
    }

    assert!(replayed >= 7, "expected the golden vectors to be present");
}

/// Golden vectors of the documents the server channel exchanges.
///
/// The vectors above freeze the arithmetic — the canonical bytes of the MAC
/// input, the derived key, the code. These freeze the *documents*: the signed
/// request an engineer brings and the grant the issuing side answers with. Both
/// travel between two implementations that must read each other, and both carry
/// signatures over bytes that a change to the encoding would silently move: a
/// grant whose request encoded differently is a grant whose signature no longer
/// covers what anybody signed.
///
/// The vector files hold the inputs in the wire form of the channel and the
/// bytes they must produce. A vector that no longer matches is not a test to be
/// updated — it is a breaking change under the workspace compatibility policy.
mod documents {
    use std::fs;
    use std::path::PathBuf;

    use crate::grant::{Grant, GrantFields, UnsignedGrant};
    use crate::params::FleetParams;
    use crate::request::{
        EngineerRequest, EngineerSignature, FourEyesDigest, GroundsReference, RequestFields,
        SignedRequest,
    };
    use crate::signature::Signature;
    use crate::time::ClaimedTime;

    use super::{field, golden_dir};

    /// Reads one vector file into its `key = value` pairs.
    #[expect(
        clippy::unwrap_used,
        reason = "a malformed vector file must fail the test on the spot"
    )]
    fn pairs(name: &str) -> Vec<(String, String)> {
        let path: PathBuf = golden_dir().join("documents").join(name);
        let text = fs::read_to_string(&path).unwrap();
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                let (key, value) = line.split_once('=').unwrap();
                (key.trim().to_owned(), value.trim().to_owned())
            })
            .collect()
    }

    /// Rebuilds the signed request of a vector.
    #[expect(
        clippy::unwrap_used,
        reason = "a malformed vector file must fail the test on the spot"
    )]
    fn signed_request(lines: &[(String, String)], params: &FleetParams) -> SignedRequest {
        let challenge =
            crate::challenge::Challenge::parse(field(lines, "challenge").unwrap(), params).unwrap();
        let request = EngineerRequest::new(RequestFields {
            challenge,
            grounds: field(lines, "grounds").unwrap(),
            grounds_reference: Some(
                GroundsReference::new(
                    field(lines, "grounds_ref_kind").unwrap(),
                    field(lines, "grounds_ref_id").unwrap(),
                )
                .unwrap(),
            ),
            requested_at: ClaimedTime::new(field(lines, "requested_at").unwrap().parse().unwrap()),
            four_eyes: FourEyesDigest::of_policy(
                field(lines, "four_eyes_policy").unwrap().as_bytes(),
            ),
        })
        .unwrap();
        // Two vectors, one builder: the signature field of the file decides
        // which case this is, exactly as the wire form decides it for a reader.
        let signature = match field(lines, "engineer_signature_hex") {
            Some(hex) => {
                EngineerSignature::Signed(Signature::new(hex::decode(hex).unwrap()).unwrap())
            }
            None => EngineerSignature::unverified(
                field(lines, "engineer_signature_unverified_reason").unwrap(),
            )
            .unwrap(),
        };
        SignedRequest::new(request, signature)
    }

    #[test]
    #[expect(
        clippy::unwrap_used,
        reason = "a vector that cannot be replayed must fail the test on the spot"
    )]
    fn the_personal_number_still_reads_the_same_way() {
        // The vector both sides of the channel read. The number is not signed
        // and carries no bytes anybody hashes, so nothing here breaks a
        // signature — what it breaks is worse to find: a fleet prints numbers
        // one implementation accepts and the other refuses, and the failure
        // shows up at a keyboard on a site.
        use crate::engineer_number::{EngineerNumber, EngineerNumberError};

        let lines = pairs("engineer-number-v1.txt");
        let built = EngineerNumber::from_body(field(&lines, "body").unwrap()).unwrap();
        assert_eq!(built.as_str(), field(&lines, "number").unwrap());

        let parsed = EngineerNumber::parse(field(&lines, "number").unwrap()).unwrap();
        assert_eq!(parsed.significant(), field(&lines, "significant").unwrap());
        assert_eq!(
            parsed.organisation_segment(),
            field(&lines, "organisation_segment").unwrap()
        );
        assert_eq!(parsed.serial(), field(&lines, "serial").unwrap());
        assert_eq!(
            parsed.check_character().to_string(),
            field(&lines, "check_character").unwrap()
        );

        // Three spellings of one number. If they folded apart, two people
        // writing one number would compute two different codes.
        for key in ["spelling_lowercase", "spelling_spaces", "spelling_dots"] {
            let spelled = EngineerNumber::parse(field(&lines, key).unwrap()).unwrap();
            assert_eq!(
                spelled.significant(),
                parsed.significant(),
                "spelling `{key}` folded to a different number"
            );
        }

        assert!(matches!(
            EngineerNumber::parse(field(&lines, "wrong_check").unwrap()),
            Err(EngineerNumberError::CheckCharacterMismatch { .. })
        ));
    }

    #[test]
    #[expect(
        clippy::unwrap_used,
        reason = "a vector that cannot be replayed must fail the test on the spot"
    )]
    fn the_signed_request_still_encodes_the_same_bytes() {
        let params = FleetParams::defaults();
        let lines = pairs("request-v1.txt");
        let signed = signed_request(&lines, &params);

        // The bytes the engineer signs. A change here moves every signature
        // ever made over a request, in both directions: old documents stop
        // verifying and new ones verify against nothing anybody checked.
        assert_eq!(
            hex::encode(signed.request().encode().unwrap()),
            field(&lines, "canon_hex").unwrap(),
            "the canonical bytes of the request changed"
        );
        assert_eq!(
            signed.to_wire(),
            field(&lines, "wire").unwrap(),
            "the wire form of the signed request changed"
        );
        // And it reads back: a vector that only froze the writer would let the
        // reader drift away from it unnoticed.
        assert_eq!(SignedRequest::parse(&signed.to_wire(), &params), Ok(signed));
    }

    #[test]
    #[expect(
        clippy::unwrap_used,
        reason = "a vector that cannot be replayed must fail the test on the spot"
    )]
    fn the_unverified_request_still_encodes_the_same_bytes() {
        // The other half of the pair, and the one a reader must never mistake
        // for the first: a request nobody's authenticator signed. Frozen
        // separately so that a change which made the two encode alike — an
        // empty signature, a placeholder, a dropped marker — is a red test and
        // not a silent equivalence.
        let params = FleetParams::defaults();
        let lines = pairs("request-unverified-v1.txt");
        let signed = signed_request(&lines, &params);

        assert!(
            !signed.engineer_signature().is_signed(),
            "the vector of an unsigned request produced a signed one"
        );
        assert_eq!(
            signed.to_wire(),
            field(&lines, "wire").unwrap(),
            "the wire form of an unsigned request changed"
        );
        assert_eq!(
            SignedRequest::parse(&signed.to_wire(), &params),
            Ok(signed.clone())
        );
        // And it is not the signed vector with a field swapped: the two
        // documents differ in the bytes a reader sees.
        let other = pairs("request-v1.txt");
        assert_ne!(signed.to_wire(), field(&other, "wire").unwrap());
    }

    #[test]
    #[expect(
        clippy::unwrap_used,
        reason = "a vector that cannot be replayed must fail the test on the spot"
    )]
    fn the_engineer_authorisation_still_encodes_the_same_bytes() {
        use crate::canon::Level;
        use crate::engineer::{AuthorisationFields, EngineerAuthorisation};
        use crate::mac::DIGEST_LEN;

        let lines = pairs("engineer-authorisation-v1.txt");
        let fingerprint: [u8; DIGEST_LEN] =
            hex::decode(field(&lines, "key_fingerprint_hex").unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        let authorisation = EngineerAuthorisation::new(AuthorisationFields {
            engineer_id: field(&lines, "engineer").unwrap(),
            organisation_id: field(&lines, "organisation").unwrap(),
            key_fingerprint: fingerprint,
            tags: field(&lines, "tags")
                .unwrap()
                .split(',')
                .map(str::to_owned)
                .collect(),
            roles: field(&lines, "roles")
                .unwrap()
                .split(',')
                .map(str::to_owned)
                .collect(),
            max_level: Level::new(field(&lines, "max_level").unwrap().parse().unwrap()),
            not_after: ClaimedTime::new(field(&lines, "not_after").unwrap().parse().unwrap()),
            authorisation_signature: Signature::new(
                hex::decode(field(&lines, "signature_hex").unwrap()).unwrap(),
            )
            .unwrap(),
        })
        .unwrap();

        // The bytes the fleet's authorisation key signs. The document changed
        // signer with this vector: it used to be verified against the
        // organisation that granted it, which let an organisation write its own
        // ceiling.
        assert_eq!(
            hex::encode(authorisation.encode().unwrap()),
            field(&lines, "canon_hex").unwrap(),
            "the signed bytes of the engineer authorisation changed"
        );
        assert_eq!(
            authorisation.to_wire(),
            field(&lines, "wire").unwrap(),
            "the wire form of the engineer authorisation changed"
        );
        assert_eq!(
            EngineerAuthorisation::parse(&authorisation.to_wire()),
            Ok(authorisation)
        );
    }

    #[test]
    #[expect(
        clippy::unwrap_used,
        reason = "a vector that cannot be replayed must fail the test on the spot"
    )]
    fn the_revocation_list_still_encodes_the_same_bytes() {
        use crate::revocation::{
            RevocationEntry, RevocationList, RevocationListFields, SignedRevocationList,
            SubjectKind,
        };

        let lines = pairs("revocation-list-v1.txt");
        let entries = field(&lines, "entries")
            .unwrap()
            .split('|')
            .map(|item| {
                let parts: Vec<&str> = item.split(':').collect();
                RevocationEntry::new(
                    SubjectKind::parse(parts.first().copied().unwrap()).unwrap(),
                    parts.get(1).copied().unwrap(),
                    ClaimedTime::new(parts.get(2).copied().unwrap().parse().unwrap()),
                    parts.get(3).copied().unwrap(),
                )
                .unwrap()
            })
            .collect();
        let list = RevocationList::new(RevocationListFields {
            serial: field(&lines, "serial").unwrap().parse().unwrap(),
            issued_at: ClaimedTime::new(field(&lines, "issued_at").unwrap().parse().unwrap()),
            entries,
        })
        .unwrap();

        // The bytes the authorisation key signs. A change here silently voids
        // every list a fleet has already published: the old ones stop
        // verifying, and the new ones verify against a signature nobody made
        // over what they now say.
        assert_eq!(
            hex::encode(list.encode().unwrap()),
            field(&lines, "canon_hex").unwrap(),
            "the signed bytes of the revocation list changed"
        );
        assert_eq!(
            list.to_wire(),
            field(&lines, "wire").unwrap(),
            "the wire form of the revocation list changed"
        );

        let signed = SignedRevocationList::new(
            list,
            Signature::new(hex::decode(field(&lines, "signature_hex").unwrap()).unwrap()).unwrap(),
        );
        assert_eq!(
            signed.to_wire(),
            field(&lines, "signed_wire").unwrap(),
            "the wire form of the signed revocation list changed"
        );
        assert_eq!(
            SignedRevocationList::parse(&signed.to_wire()),
            Ok(signed),
            "the reader drifted from the writer"
        );
    }

    #[test]
    #[expect(
        clippy::unwrap_used,
        reason = "a vector that cannot be replayed must fail the test on the spot"
    )]
    fn the_grant_still_encodes_the_same_bytes() {
        let params = FleetParams::defaults();
        let lines = pairs("grant-v1.txt");
        let signed = signed_request(&lines, &params);
        let server_id = field(&lines, "server_id").unwrap();
        let server_signature =
            Signature::new(hex::decode(field(&lines, "server_signature_hex").unwrap()).unwrap())
                .unwrap();

        // What the issuing side signs is known before the signature exists, and
        // it is the same message the finished grant states as its own.
        let unsigned = UnsignedGrant::new(signed.clone(), server_id).unwrap();
        assert_eq!(
            hex::encode(unsigned.signing_message().unwrap()),
            field(&lines, "server_message_hex").unwrap(),
            "the message the issuing side signs changed"
        );

        let grant = Grant::new(GrantFields {
            request: signed,
            server_id,
            server_signature: server_signature.clone(),
            confirmation: None,
        })
        .unwrap();
        assert_eq!(
            hex::encode(grant.server_message().unwrap()),
            field(&lines, "server_message_hex").unwrap(),
            "the signed grant disagrees with the unsigned one about what is signed"
        );
        assert_eq!(
            grant.to_wire(),
            field(&lines, "wire").unwrap(),
            "the wire form of the grant changed"
        );
        assert_eq!(Grant::parse(&grant.to_wire(), &params), Ok(grant));
    }
}
