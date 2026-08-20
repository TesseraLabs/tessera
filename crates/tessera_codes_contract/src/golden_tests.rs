//! Golden vectors: the frozen bytes of the contract.
//!
//! The vectors live in `tests/golden/` as plain text — a human-readable input
//! beside the bytes it must produce — and this test replays every one of them.
//! It runs inside the crate rather than as an integration test so that the
//! derived key can be compared without an accessor that would hand `K` to every
//! consumer of the library.
//!
//! A vector that no longer matches is not a test to be updated: the bytes are
//! the compatibility surface of the phone channel, and changing them is a
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
use crate::nonce::{Nonce, NonceError};
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
    ticket: String,
    shared_secret: Vec<u8>,
    alphabet: Alphabet,
    code_len: u8,
    counter_width: u8,
    tail_width: u8,
    canon_hex: String,
    ticket_hex: String,
    context_hex: String,
    key_hex: String,
    code: String,
    /// Counter the nonce of the vector must parse back to, when the vector
    /// exercises the nonce as well as the code.
    nonce_counter: Option<u64>,
    /// Whether that counter is the last one its width holds, so that the next
    /// nonce must overflow instead of wrapping.
    nonce_counter_is_last: bool,
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
        ticket: field(&lines, "ticket").unwrap().to_owned(),
        shared_secret: hex::decode(field(&lines, "z_hex").unwrap()).unwrap(),
        alphabet,
        code_len: field(&lines, "code_len").unwrap().parse().unwrap(),
        counter_width: field(&lines, "counter_width").unwrap().parse().unwrap(),
        tail_width: field(&lines, "tail_width").unwrap().parse().unwrap(),
        canon_hex: field(&lines, "canon_hex").unwrap().to_owned(),
        ticket_hex: field(&lines, "ticket_hex").unwrap().to_owned(),
        context_hex: field(&lines, "context_hex").unwrap().to_owned(),
        key_hex: field(&lines, "k_hex").unwrap().to_owned(),
        code: field(&lines, "code").unwrap().to_owned(),
        nonce_counter: field(&lines, "nonce_counter").map(|value| value.parse().unwrap()),
        nonce_counter_is_last: field(&lines, "nonce_counter_is_last") == Some("true"),
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
        counter_width: vector.counter_width,
        tail_width: vector.tail_width,
        ..FleetParamsInput::defaults()
    })
    .unwrap();

    let device_number = CheckedDeviceNumber::parse(&vector.device_number).unwrap();
    let input = CodeInput {
        device_number: &device_number,
        nonce: &vector.nonce,
        role_id: &vector.role_id,
        level: Level::new(vector.level),
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
    let context = KeyContext::new(&device_number, Epoch::new(vector.epoch), hash);
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

    if let Some(counter) = vector.nonce_counter {
        let nonce = Nonce::parse(&vector.nonce, &params).unwrap();
        assert_eq!(
            nonce.counter(),
            counter,
            "nonce counter changed in vector `{}`",
            vector.name
        );
        if vector.nonce_counter_is_last {
            assert!(
                matches!(
                    nonce.next_with_tail(nonce.tail(), &params),
                    Err(NonceError::CounterOverflow { .. })
                ),
                "the counter of vector `{}` no longer stops at the end of its width",
                vector.name
            );
        }
    }
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
