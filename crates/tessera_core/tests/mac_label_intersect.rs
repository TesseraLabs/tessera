//! Unit tests for `IntegrityLabel` intersection semantics.

use tessera_core::mac::IntegrityLabel;

#[test]
fn intersect_takes_min_level_and_and_categories() {
    let a = IntegrityLabel {
        level: 2,
        categories: 0b0011_u64,
    };
    let b = IntegrityLabel {
        level: 3,
        categories: 0b0101_u64,
    };
    let r = a.intersect(&b);
    assert_eq!(r.level, 2);
    assert_eq!(r.categories, 0b0001_u64);
}

#[test]
fn empty_categories_means_unbounded() {
    let cert = IntegrityLabel {
        level: 5,
        categories: 0_u64,
    };
    let user = IntegrityLabel {
        level: 3,
        categories: 0b1111_u64,
    };
    // empty categories on cert = "no restriction" => user.categories preserved.
    let r = cert.intersect_cert_with_user(&user);
    assert_eq!(r.level, 3);
    assert_eq!(r.categories, 0b1111_u64);
}

#[test]
fn ordering_strict_less_when_level_or_cats_drop() {
    let lo = IntegrityLabel {
        level: 1,
        categories: 0b01_u64,
    };
    let hi = IntegrityLabel {
        level: 2,
        categories: 0b11_u64,
    };
    assert!(lo.strictly_below(&hi));
    assert!(!hi.strictly_below(&lo));
}

#[test]
fn from_mac_mask_places_bits_in_categories_at_level_zero() {
    let label = IntegrityLabel::from_mac_mask(0b110);
    assert_eq!(label.level, 0);
    assert_eq!(label.categories, 0b110);
}

#[test]
fn covers_accepts_subset_mask_and_rejects_extra_bits() {
    let ceiling = IntegrityLabel {
        level: 3,
        categories: 0b100,
    };
    // mask 0b100 is a subset of the ceiling categories at level <= ceiling.
    assert!(ceiling.covers(&IntegrityLabel::from_mac_mask(0b100)));
    // mask 0b110 asks for a category bit (0b010) the ceiling lacks.
    assert!(!ceiling.covers(&IntegrityLabel::from_mac_mask(0b110)));
}

#[test]
fn covers_rejects_requested_level_above_ceiling() {
    let ceiling = IntegrityLabel {
        level: 1,
        categories: u64::MAX,
    };
    let requested = IntegrityLabel {
        level: 2,
        categories: 0,
    };
    assert!(!ceiling.covers(&requested));
}

#[test]
fn full_u64_mask_roundtrips_through_intersect() {
    let cert = IntegrityLabel {
        level: 127,
        categories: u64::MAX,
    };
    let user = IntegrityLabel {
        level: 5,
        categories: u64::MAX,
    };
    let r = cert.intersect(&user);
    assert_eq!(r.level, 5);
    assert_eq!(r.categories, u64::MAX);
}
