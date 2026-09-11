//! What a personal number is held to.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed setup step in a test should fail the test on the spot"
)]

use super::{EngineerNumber, EngineerNumberError};

/// The number the fixtures of the stand carry.
const GOLDEN: &str = "ORG1-0000014";

#[test]
fn the_golden_number_is_this_number() {
    // A vector, not a round trip: a round trip agrees with itself whatever the
    // arithmetic does, and this number is printed in the stand bundle, read by
    // the server side and compared against a second implementation in C#.
    let number = EngineerNumber::from_body("ORG1-000001").unwrap();
    assert_eq!(number.as_str(), GOLDEN);
    assert_eq!(number.significant(), "ORG10000014");
    assert_eq!(number.check_character(), '4');
    assert_eq!(number.organisation_segment(), "ORG");
    // Note where the boundary falls: the digit of `ORG1` belongs to the serial
    // part, because the segment is the leading run of LETTERS. The fixture is
    // spelled `ORG1-000001` for a person; the arithmetic and this type read it
    // as segment `ORG` and serial `1000001`.
    assert_eq!(number.serial(), "1000001");
}

#[test]
fn a_number_parses_back_into_its_parts() {
    let number = EngineerNumber::parse(GOLDEN).unwrap();
    assert_eq!(number.organisation_segment(), "ORG");
    assert_eq!(number.serial(), "1000001");
    assert_eq!(number.check_character(), '4');
}

#[test]
fn separators_and_case_do_not_change_the_number() {
    // The same number written three ways. If they folded differently, two
    // spellings of one engineer would compute two different codes and the
    // failure would look like a wrong code rather than a wrong number.
    let spellings = ["ORG1-0000014", "org1 000001 4", "ORG1.000001.4"];
    for spelling in spellings {
        let number = EngineerNumber::parse(spelling).unwrap();
        assert_eq!(number.significant(), "ORG10000014", "{spelling}");
        // And the number keeps the form it was written in, because that is what
        // goes back to the person who typed it.
        assert_eq!(number.as_str(), spelling);
    }
}

#[test]
fn a_wrong_check_character_is_refused_with_both_characters_named() {
    let refusal = EngineerNumber::parse("ORG1-0000015").unwrap_err();
    assert_eq!(
        refusal,
        EngineerNumberError::CheckCharacterMismatch {
            expected: '4',
            got: '5'
        }
    );
}

#[test]
fn every_single_wrong_character_is_caught() {
    let number = EngineerNumber::parse(GOLDEN).unwrap();
    let significant: Vec<char> = number.significant().chars().collect();
    for position in 0..significant.len() {
        for replacement in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars() {
            let mut damaged = significant.clone();
            if damaged.get(position).copied() == Some(replacement) {
                continue;
            }
            if let Some(slot) = damaged.get_mut(position) {
                *slot = replacement;
            }
            let text: String = damaged.into_iter().collect();
            assert!(
                EngineerNumber::parse(&text).is_err(),
                "a wrong character at {position} slipped through: {text}"
            );
        }
    }
}

#[test]
fn a_number_without_an_organisation_segment_is_refused() {
    // The whole point of the segment: two contractors assigning the same serial
    // would leave a device journal that attributes a login to nobody.
    assert_eq!(
        EngineerNumber::from_body("0000001").unwrap_err(),
        EngineerNumberError::SegmentNotLetterLed
    );
    assert_eq!(
        EngineerNumber::from_body("A000001").unwrap_err(),
        EngineerNumberError::Segment { got: 1 }
    );
    assert_eq!(
        EngineerNumber::from_body("ABCDEFGHI000001").unwrap_err(),
        EngineerNumberError::Segment { got: 9 }
    );
}

#[test]
fn a_serial_part_outside_the_format_is_refused() {
    assert_eq!(
        EngineerNumber::from_body("ORG-001").unwrap_err(),
        EngineerNumberError::Serial { got: 3 }
    );
    assert_eq!(
        EngineerNumber::from_body("ORG-0000000000001").unwrap_err(),
        EngineerNumberError::Serial { got: 13 }
    );
    // Letters after the serial began: the boundary is not where the letters
    // stop, so this string has no shape the format names.
    assert_eq!(
        EngineerNumber::from_body("ORG-0001X").unwrap_err(),
        EngineerNumberError::Serial { got: 5 }
    );
    // And the shortest serial the format does allow is accepted, so the bound
    // above is a bound and not a refusal of everything.
    assert!(EngineerNumber::from_body("ORG-0001").is_ok());
}

#[test]
fn the_widest_and_the_narrowest_shapes_the_format_names_are_accepted() {
    // The refusals above name every bound, and a bound stated only by what it
    // refuses is a bound that could be one character off in either direction
    // without a test noticing: an off-by-one that rejects the longest serial a
    // fleet legitimately issues shows up as an engineer who cannot log in.
    for body in [
        // Segment at its shortest and at its longest.
        "AB-0001",
        "ABCDEFGH-0001",
        // Serial at its shortest and at its longest. The digit that starts
        // `ORG1` belongs to the serial, so twelve digits are spelled here as
        // eleven after the letters.
        "ORG-0001",
        "ORG-000000000001",
    ] {
        let number = EngineerNumber::from_body(body).unwrap_or_else(|error| {
            panic!("the format names {body} as valid, and it was refused: {error}")
        });
        // Round-tripping the built number proves the bound holds on the way in
        // as well: `parse` checks the shape a second time, over a string that
        // now carries the check character.
        EngineerNumber::parse(number.as_str()).unwrap();
    }
}

#[test]
fn the_shape_is_checked_when_reading_a_number_and_not_only_when_building_one() {
    // The tests above build numbers, and building is the easy direction: the
    // constructor never sees a hostile string. Reading is where the strings
    // come from a prompt and a wire, and a `parse` that checked only the
    // arithmetic would accept anything with a correct last character —
    // including a device number, a serial with no segment, or a segment eleven
    // letters long.
    let wrong_shapes = [
        "00000010",
        "A0000010",
        "ABCDEFGHI0000010",
        "ORG-0010",
        "ORG-0001X0",
    ];
    for text in wrong_shapes {
        let significant = crate::number::significant_characters(text);
        let (body, _) = crate::number::split_check(&significant).unwrap();
        // Give each one the check character it actually deserves, so that the
        // only thing left to refuse is the shape.
        let correct = format!("{body}{}", crate::number::check_character(body).unwrap());
        let refusal = EngineerNumber::parse(&correct).unwrap_err();
        assert!(
            !matches!(refusal, EngineerNumberError::CheckCharacterMismatch { .. }),
            "`{correct}` was refused for its check character, not its shape"
        );
    }
}

#[test]
fn a_number_of_nothing_is_refused_before_the_shape_is_examined() {
    assert_eq!(
        EngineerNumber::parse("-").unwrap_err(),
        EngineerNumberError::TooShort
    );
    assert_eq!(
        EngineerNumber::parse("A").unwrap_err(),
        EngineerNumberError::TooShort
    );
}

#[test]
fn a_device_number_is_not_a_personal_number() {
    // The reason these are two types and not one. A device number passes the
    // arithmetic and fails the shape, which is the answer a caller needs: this
    // is a number, but not a number of this kind.
    let device = "77-000123S";
    assert!(tessera_device_number_parses(device));
    assert_eq!(
        EngineerNumber::parse(device).unwrap_err(),
        EngineerNumberError::SegmentNotLetterLed
    );
}

fn tessera_device_number_parses(text: &str) -> bool {
    crate::device_number::CheckedDeviceNumber::parse(text).is_ok()
}

#[test]
fn the_two_numbers_share_one_arithmetic() {
    // Not a claim about tidiness: if the two check characters ever parted, a
    // fleet would print numbers one side accepts and the other refuses.
    let body = "ORG1-000001";
    let shared = crate::number::check_character(body).unwrap();
    assert_eq!(
        EngineerNumber::from_body(body).unwrap().check_character(),
        shared
    );
    assert_eq!(crate::device_number::check_character(body).unwrap(), shared);
}
