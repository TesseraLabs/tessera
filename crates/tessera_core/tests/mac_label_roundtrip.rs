//! Roundtrip tests for `IntegrityLabel` DER (de)serialization.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use tessera_core::mac::IntegrityLabel;
use proptest::prelude::*;

#[test]
fn roundtrip_basic() {
    let l = IntegrityLabel {
        level: 2,
        categories: 0b0011_u64,
    };
    let der = l.to_der().expect("encode");
    let back = IntegrityLabel::from_der(&der).expect("decode");
    assert_eq!(l, back);
}

#[test]
fn empty_categories_round_trip() {
    let l = IntegrityLabel {
        level: 1,
        categories: 0_u64,
    };
    let der = l.to_der().expect("encode");
    let back = IntegrityLabel::from_der(&der).expect("decode");
    assert_eq!(back.categories, 0);
}

#[test]
fn full_u64_categories_round_trip() {
    // u64::MAX → 9-byte BIT STRING payload (1 unused-bits prefix + 8 bytes).
    let l = IntegrityLabel {
        level: 0,
        categories: u64::MAX,
    };
    let der = l.to_der().expect("encode");
    let back = IntegrityLabel::from_der(&der).expect("decode");
    assert_eq!(back, l);
}

#[test]
fn decode_boundary_levels_ok() {
    for level in [i8::MIN, -1, 0, 1, i8::MAX] {
        let l = IntegrityLabel {
            level,
            categories: u64::MAX,
        };
        let der = l.to_der().expect("encode");
        let back = IntegrityLabel::from_der(&der).expect("decode");
        assert_eq!(back, l);
    }
}

#[test]
fn decode_malformed_fails_safe() {
    assert!(IntegrityLabel::from_der(&[]).is_err());
    assert!(IntegrityLabel::from_der(&[0x30, 0x80]).is_err());
    // sequence with INTEGER length > 1 byte where value cannot fit in i8
    // (e.g. 0x01 0x80 — 2-byte BER encoding for value 128 — out of i8 range).
    assert!(IntegrityLabel::from_der(&[0x30, 0x04, 0x02, 0x02, 0x00, 0x80]).is_err());
}

#[test]
fn categories_above_32bit_round_trip_preserves_high_bits() {
    let l = IntegrityLabel {
        level: 0,
        categories: 0xFFFF_FFFF_FFFF_FFFF_u64,
    };
    let der = l.to_der().unwrap();
    let back = IntegrityLabel::from_der(&der).unwrap();
    assert_eq!(back.categories >> 32, 0xFFFF_FFFF_u64);
    assert_eq!(back, l);
}

#[test]
fn rejects_bit_string_unused_bits_above_seven() {
    // SEQ { INT 0, BIT STRING (unused_bits=0xFF, payload=0x01) }
    let der = [0x30, 0x06, 0x02, 0x01, 0x00, 0x03, 0x02, 0xFF, 0x01];
    assert!(IntegrityLabel::from_der(&der).is_err());
}

#[test]
fn rejects_trailing_bytes_after_bit_string() {
    // SEQ { INT 0, BIT STRING (1 byte payload), trailing 0xAA }
    let der = [0x30, 0x07, 0x02, 0x01, 0x00, 0x03, 0x02, 0x00, 0x01, 0xAA];
    assert!(IntegrityLabel::from_der(&der).is_err());
}

proptest! {
    #[test]
    fn proptest_roundtrip(level in any::<i8>(), cats in any::<u64>()) {
        let l = IntegrityLabel { level, categories: cats };
        let der = l.to_der().unwrap();
        let back = IntegrityLabel::from_der(&der).unwrap();
        prop_assert_eq!(l, back);
    }
}
