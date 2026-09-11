//! What the wire between the module and the overlay is held to.
//!
//! Two kinds of test live here and they are not interchangeable. The golden
//! vector fixes the *bytes*: it is what makes a rearranged header or a widened
//! length field a failing test rather than a silent incompatibility with the
//! overlay already installed on a machine. The session tests fix the *states*:
//! every way an attempt can end, including the ways that are not messages.
//!
//! A test that only round-trips through `encode` and `decode` would pass on any
//! self-consistent format, which is exactly the kind of agreement two halves of
//! one product reach by accident.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a test that cannot set itself up should fail on the spot, and a \
              vector written against fixed offsets is the point of a golden test"
)]

use super::{
    declared_frame_len, decode, encode, module, AttemptId, Ending, FrameError, Message,
    OverlayAction, OverlayError, OverlaySession, SessionError, ATTEMPT_ID_LEN, HEADER_LEN,
    MAX_BODY_LEN, PROTOCOL_VERSION,
};

/// The attempt every vector below is written against.
const ATTEMPT: [u8; ATTEMPT_ID_LEN] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

/// A payload of the shape the channel actually carries.
const PAYLOAD: &str = "https://codes.example/#tessera-codes/v1/signed-challenge;device=77-000123X";

fn attempt() -> AttemptId {
    AttemptId::from_bytes(ATTEMPT)
}

fn other_attempt() -> AttemptId {
    AttemptId::from_bytes([0x77; ATTEMPT_ID_LEN])
}

#[test]
fn the_bytes_of_a_challenge_frame_are_these_bytes() {
    let frame = encode(attempt(), &Message::Challenge(PAYLOAD.to_owned())).unwrap();

    let mut expected = Vec::new();
    expected.extend_from_slice(b"TQRO");
    expected.push(1); // protocol version
    expected.push(1); // kind: challenge
    expected.extend_from_slice(&ATTEMPT);
    expected.extend_from_slice(&[0x00, 0x4a]); // body length, big endian: 74
    expected.extend_from_slice(PAYLOAD.as_bytes());

    assert_eq!(
        PAYLOAD.len(),
        0x4a,
        "the vector below was written for this length"
    );
    assert_eq!(frame, expected);
    assert_eq!(frame.len(), HEADER_LEN + PAYLOAD.len());
}

#[test]
fn the_bytes_of_the_other_two_kinds_are_these_bytes() {
    // The golden half for what is left of the protocol. A rearranged header or
    // a widened length field has to be a failing test rather than a silent
    // incompatibility with the overlay already installed on a machine.
    let kinds = [
        (
            Message::Refresh(PAYLOAD.to_owned()),
            2_u8,
            PAYLOAD.as_bytes(),
        ),
        (Message::Cancel, 3, &[][..]),
    ];
    for (message, kind, body) in kinds {
        let frame = encode(attempt(), &message).unwrap();
        assert_eq!(frame[4], PROTOCOL_VERSION, "{message:?}");
        assert_eq!(frame[5], kind, "{message:?}");
        assert_eq!(&frame[HEADER_LEN..], body, "{message:?}");
        assert_eq!(
            decode(&frame).unwrap(),
            (attempt(), message.clone()),
            "{message:?}"
        );
    }
}

#[test]
fn the_kinds_the_reverse_direction_used_are_not_reused() {
    // `CLOSE` and `ERROR` were 4 and 5 before the reverse direction was
    // removed. A later build must not hand those numbers to something else: a
    // device still running the older overlay would have its frames read as a
    // different message rather than refused.
    for kind in [4_u8, 5] {
        let mut frame = encode(attempt(), &Message::Cancel).unwrap();
        frame[5] = kind;
        assert_eq!(
            decode(&frame),
            Err(FrameError::Kind { got: kind }),
            "kind {kind} was given a meaning again"
        );
    }
}

#[test]
fn the_module_builds_the_three_frames_it_is_allowed_to_send() {
    // The module has no session and no reader — see the module documentation —
    // so what it owns is three builders. Checked through `decode`, so that a
    // builder that produced something unreadable fails here rather than on a
    // greeter.
    assert_eq!(
        decode(&module::challenge(attempt(), PAYLOAD).unwrap()).unwrap(),
        (attempt(), Message::Challenge(PAYLOAD.to_owned()))
    );
    assert_eq!(
        decode(&module::refresh(attempt(), "second").unwrap()).unwrap(),
        (attempt(), Message::Refresh("second".to_owned()))
    );
    assert_eq!(
        decode(&module::cancel(attempt()).unwrap()).unwrap(),
        (attempt(), Message::Cancel)
    );
    // And a payload over the budget is refused at the builder rather than put
    // on the wire.
    assert!(module::challenge(attempt(), &"x".repeat(MAX_BODY_LEN + 1)).is_err());
}

#[test]
fn the_overlay_records_giving_up_without_telling_anybody() {
    // The reason is the overlay's own: it goes to its standard error and its
    // own state, and nothing carries it back. What is asserted is that the
    // attempt ends and stays ended.
    let mut overlay = OverlaySession::new();
    overlay
        .receive(&encode(attempt(), &Message::Challenge(PAYLOAD.to_owned())).unwrap())
        .unwrap();

    assert_eq!(
        overlay.gave_up(OverlayError::Display),
        &Ending::Failed(OverlayError::Display)
    );
    assert_eq!(overlay.payload(), None);
    // The first ending is the ending: cleanup paths run in whatever order the
    // failure took, and two of them firing must not rewrite the account of it.
    assert_eq!(
        overlay.timed_out(),
        &Ending::Failed(OverlayError::Display),
        "a second ending overwrote the first"
    );
}

#[test]
fn an_unparsable_frame_ends_the_overlay_session_and_says_how_it_failed() {
    let mut overlay = OverlaySession::new();
    let refusal = overlay.receive(b"not a frame at all").unwrap_err();
    assert!(
        matches!(refusal, SessionError::Frame(FrameError::Short { .. })),
        "{refusal:?}"
    );
    assert_eq!(overlay.ending(), Some(&Ending::Violation(refusal)));
    assert_eq!(overlay.payload(), None);
}

#[test]
fn the_attempt_identifier_names_the_socket_it_is_served_on() {
    assert_eq!(
        attempt().socket_name(),
        "attempt-00112233445566778899aabbccddeeff"
    );
    assert_ne!(attempt().socket_name(), other_attempt().socket_name());
}

#[test]
fn the_package_creates_the_directory_this_module_names() {
    // Two own paths that agree about a mistake is the failure this guards: the
    // constant and the tmpfiles rule are written separately, and a socket
    // opened in a directory the package never created fails at the first
    // graphical login on a fleet and nowhere earlier.
    let tmpfiles = include_str!("../../../../../dist/tmpfiles/tessera.conf");
    let rule = tmpfiles
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some(super::SOCKET_DIRECTORY))
        .unwrap_or_else(|| {
            panic!(
                "the package creates no directory {}",
                super::SOCKET_DIRECTORY
            )
        });
    let mode = rule.split_whitespace().nth(2).unwrap_or_default();
    assert_eq!(
        mode,
        format!("{:04o}", super::SOCKET_DIRECTORY_MODE),
        "the package creates the directory with a mode this module does not expect: {rule:?}"
    );
    assert!(
        rule.contains(" root root "),
        "the directory of the attempt sockets is not root-owned: {rule:?}"
    );
}

#[test]
fn a_frame_shorter_than_a_header_is_refused_without_reading_past_it() {
    for length in 0..HEADER_LEN {
        let frame = vec![0_u8; length];
        assert_eq!(
            decode(&frame),
            Err(FrameError::Short {
                needed: HEADER_LEN,
                got: length
            })
        );
    }
}

#[test]
fn a_frame_of_another_protocol_is_refused_by_its_first_bytes() {
    let mut frame = encode(attempt(), &Message::Cancel).unwrap();
    frame[0] = b'X';
    assert_eq!(decode(&frame), Err(FrameError::Magic));
}

#[test]
fn a_version_this_build_does_not_speak_is_refused_rather_than_negotiated() {
    let mut frame = encode(attempt(), &Message::Cancel).unwrap();
    frame[4] = PROTOCOL_VERSION + 1;
    assert_eq!(
        decode(&frame),
        Err(FrameError::Version {
            got: PROTOCOL_VERSION + 1
        })
    );
}

#[test]
fn a_message_kind_this_build_does_not_know_is_refused() {
    let mut frame = encode(attempt(), &Message::Cancel).unwrap();
    frame[5] = 200;
    assert_eq!(decode(&frame), Err(FrameError::Kind { got: 200 }));
}

#[test]
fn a_body_longer_than_the_declaration_is_not_quietly_truncated() {
    // The frame carries a whole message and nothing after it. A decoder that
    // read `declared` bytes and ignored the rest would accept a frame with a
    // second message glued on and hand the caller only the first.
    let mut frame = encode(attempt(), &Message::Challenge(PAYLOAD.to_owned())).unwrap();
    frame.push(b'!');
    assert_eq!(
        decode(&frame),
        Err(FrameError::Length {
            declared: PAYLOAD.len(),
            got: PAYLOAD.len() + 1
        })
    );
}

#[test]
fn a_body_shorter_than_the_declaration_is_refused() {
    let mut frame = encode(attempt(), &Message::Challenge(PAYLOAD.to_owned())).unwrap();
    frame.pop();
    assert_eq!(
        decode(&frame),
        Err(FrameError::Length {
            declared: PAYLOAD.len(),
            got: PAYLOAD.len() - 1
        })
    );
}

#[test]
fn a_declared_length_beyond_the_bound_is_refused_before_any_allocation() {
    // The declaration is refused on the header alone: a reader must be able to
    // stop without first collecting the bytes a hostile peer promised.
    let mut header = encode(attempt(), &Message::Cancel).unwrap();
    let too_long = u16::try_from(MAX_BODY_LEN + 1).unwrap();
    header[6 + ATTEMPT_ID_LEN..].copy_from_slice(&too_long.to_be_bytes());
    assert_eq!(
        declared_frame_len(&header),
        Err(FrameError::TooLong {
            got: MAX_BODY_LEN + 1
        })
    );
    assert_eq!(
        decode(&header),
        Err(FrameError::TooLong {
            got: MAX_BODY_LEN + 1
        })
    );
}

#[test]
fn a_reader_learns_how_much_to_take_off_the_stream() {
    let frame = encode(attempt(), &Message::Challenge(PAYLOAD.to_owned())).unwrap();
    assert_eq!(declared_frame_len(&frame[..HEADER_LEN - 1]), Ok(None));
    assert_eq!(declared_frame_len(&frame), Ok(Some(frame.len())));

    let mut stream = frame.clone();
    stream.extend_from_slice(&encode(attempt(), &Message::Cancel).unwrap());
    let first = declared_frame_len(&stream).unwrap().unwrap();
    assert_eq!(
        decode(&stream[..first]).unwrap().1,
        Message::Challenge(PAYLOAD.to_owned())
    );
    assert_eq!(decode(&stream[first..]).unwrap().1, Message::Cancel);
}

#[test]
fn a_payload_over_the_budget_is_refused_at_the_encoder() {
    let payload = "a".repeat(MAX_BODY_LEN + 1);
    assert_eq!(
        encode(attempt(), &Message::Challenge(payload.clone())),
        Err(FrameError::Payload {
            got: MAX_BODY_LEN + 1
        })
    );
    assert!(encode(attempt(), &Message::Challenge("a".repeat(MAX_BODY_LEN))).is_ok());
}

#[test]
fn a_payload_that_is_not_utf8_is_refused() {
    let mut frame = encode(attempt(), &Message::Challenge("ok".to_owned())).unwrap();
    frame[HEADER_LEN] = 0xff;
    assert_eq!(decode(&frame), Err(FrameError::Encoding));
}

#[test]
fn a_challenge_without_a_payload_is_refused() {
    // An empty payload draws an empty symbol, and an empty symbol on a screen
    // is indistinguishable from an overlay that has not started yet.
    let mut frame = encode(attempt(), &Message::Challenge("x".to_owned())).unwrap();
    frame.truncate(HEADER_LEN);
    frame[6 + ATTEMPT_ID_LEN..].copy_from_slice(&0_u16.to_be_bytes());
    assert_eq!(decode(&frame), Err(FrameError::Body));
}

#[test]
fn a_cancel_carrying_a_body_is_refused() {
    let mut frame = encode(attempt(), &Message::Cancel).unwrap();
    frame[6 + ATTEMPT_ID_LEN..HEADER_LEN].copy_from_slice(&1_u16.to_be_bytes());
    frame.push(b'x');
    assert_eq!(decode(&frame), Err(FrameError::Body));
}

// ---------------------------------------------------------------------------
// The module's side of an attempt
// ---------------------------------------------------------------------------

#[test]
fn an_overlay_that_was_connected_to_without_a_challenge_draws_nothing() {
    // The negative case the design names first: something connected and started
    // talking. An overlay that acted on a refresh it never got a challenge for
    // would draw whatever any local process sent it.
    for message in [Message::Refresh(PAYLOAD.to_owned()), Message::Cancel] {
        let mut overlay = OverlaySession::new();
        let frame = encode(attempt(), &message).unwrap();
        assert_eq!(
            overlay.receive(&frame),
            Err(SessionError::OutOfTurn),
            "{message:?}"
        );
        assert_eq!(overlay.payload(), None, "{message:?}");
        assert!(
            matches!(overlay.ending(), Some(Ending::Violation(_))),
            "{message:?}"
        );
    }
}

#[test]
fn the_overlay_draws_the_challenge_and_redraws_the_refresh() {
    let mut overlay = OverlaySession::new();
    let challenge = encode(attempt(), &Message::Challenge(PAYLOAD.to_owned())).unwrap();
    assert_eq!(
        overlay.receive(&challenge).unwrap(),
        OverlayAction::Draw(PAYLOAD.to_owned())
    );
    assert_eq!(overlay.payload(), Some(PAYLOAD));

    let refresh = encode(attempt(), &Message::Refresh("second".to_owned())).unwrap();
    assert_eq!(
        overlay.receive(&refresh).unwrap(),
        OverlayAction::Redraw("second".to_owned())
    );
    assert_eq!(overlay.payload(), Some("second"));
}

#[test]
fn the_overlay_takes_the_window_down_on_cancel() {
    let mut overlay = OverlaySession::new();
    overlay
        .receive(&encode(attempt(), &Message::Challenge(PAYLOAD.to_owned())).unwrap())
        .unwrap();
    let cancel = encode(attempt(), &Message::Cancel).unwrap();
    assert_eq!(
        overlay.receive(&cancel).unwrap(),
        OverlayAction::Finish(Ending::Cancelled)
    );
    assert_eq!(overlay.payload(), None);
    assert_eq!(overlay.receive(&cancel), Err(SessionError::Ended));
}

#[test]
fn a_second_challenge_is_a_replay_and_not_a_refresh() {
    let mut overlay = OverlaySession::new();
    let challenge = encode(attempt(), &Message::Challenge(PAYLOAD.to_owned())).unwrap();
    overlay.receive(&challenge).unwrap();
    assert_eq!(overlay.receive(&challenge), Err(SessionError::OutOfTurn));
}

#[test]
fn the_overlay_refuses_a_frame_from_another_attempt_after_it_knows_its_own() {
    let mut overlay = OverlaySession::new();
    overlay
        .receive(&encode(attempt(), &Message::Challenge(PAYLOAD.to_owned())).unwrap())
        .unwrap();
    let foreign = encode(other_attempt(), &Message::Refresh("elsewhere".to_owned())).unwrap();
    assert_eq!(
        overlay.receive(&foreign),
        Err(SessionError::ForeignAttempt {
            expected: attempt(),
            got: other_attempt()
        })
    );
    assert_eq!(overlay.payload(), None);
}

#[test]
fn the_module_going_away_under_the_overlay_is_an_ending_of_its_own() {
    let mut overlay = OverlaySession::new();
    overlay
        .receive(&encode(attempt(), &Message::Challenge(PAYLOAD.to_owned())).unwrap())
        .unwrap();
    assert_eq!(overlay.peer_lost(), &Ending::Lost);
    assert_eq!(overlay.payload(), None);
    assert_eq!(overlay.timed_out(), &Ending::Lost);
}
