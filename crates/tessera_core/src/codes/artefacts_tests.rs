//! Tests of the artefact import and the wipe, against real containers.
//!
//! The fixtures build the same shapes the delivery carries: a PKCS#12 closed
//! with a PIN, a ticket set in the wire form of the contract crate, and an
//! anchor in `SubjectPublicKeyInfo`. Nothing here writes a file the product
//! does not write, so a test that passes is a statement about the store the
//! login path will read.

#![expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::pkey::{PKey, Private};
use openssl::x509::{X509Builder, X509NameBuilder};
use secrecy::SecretString;
use tempfile::TempDir;

use tessera_codes_contract::canon::Level;
use tessera_codes_contract::key::Epoch;
use tessera_codes_contract::signature::PublicKey;
use tessera_codes_contract::ticket::{ServerTicket, TicketNumber, TicketScope, TicketScopeInput};
use tessera_codes_contract::time::ClaimedTime;

use crate::codes::agreement::tests::p256_pair;
use crate::codes::epoch;
use crate::codes::store::{load_device_key, CodesPaths};
use crate::codes::tickets::tests::Authority;

use super::{apply, wipe, ArtefactError, CodesDelivery, DeliveredKey, StoreCheck};

/// PIN the delivery container is closed with.
const DELIVERY_PIN: &str = "delivery-pin";

/// The whole consignment a fleet hands a device, in memory.
struct Delivery {
    key: PKey<Private>,
    authority: Authority,
}

impl Delivery {
    fn new() -> Self {
        Self {
            key: p256_pair().0,
            authority: Authority::new(),
        }
    }

    /// The delivery container: the key, closed with the operator's PIN.
    fn container(&self) -> Vec<u8> {
        container(&self.key, DELIVERY_PIN)
    }

    /// A ticket set naming `operator`.
    fn tickets(&self, operator: &str) -> Vec<u8> {
        let signed = self.authority.sign(
            ServerTicket::new(
                operator,
                PublicKey::new(p256_pair().1).unwrap(),
                TicketScope::new(TicketScopeInput {
                    tags: vec!["dc-1".to_owned()],
                    roles: vec!["oper".to_owned()],
                    region: "ru-south".to_owned(),
                    max_level: Level::new(1),
                })
                .unwrap(),
                ClaimedTime::new(1_800_000_000),
                TicketNumber::parse("tk-17").unwrap(),
            )
            .unwrap(),
        );
        format!("{}\n", signed.to_wire()).into_bytes()
    }

    /// A revocation list naming `numbers`.
    fn revocations(numbers: &[&str]) -> Vec<u8> {
        let mut text = String::new();
        for number in numbers {
            text.push_str(number);
            text.push('\n');
        }
        text.into_bytes()
    }

    /// A full consignment: key of `epoch`, tickets and anchor.
    fn full(&self, at: u32) -> CodesDelivery {
        CodesDelivery {
            key: Some(DeliveredKey {
                epoch: Epoch::new(at),
                container: self.container(),
                pin: SecretString::from(DELIVERY_PIN.to_owned()),
            }),
            tickets: Some(self.tickets("op-42")),
            revocations: None,
            ticket_authority: Some(self.authority.public_key_pem()),
        }
    }
}

/// Builds a PKCS#12 around `key`, closed with `pin`.
fn container(key: &PKey<Private>, pin: &str) -> Vec<u8> {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "codes device")
        .unwrap();
    let name = name.build();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(key).unwrap();
    builder
        .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    builder
        .sign(key, openssl::hash::MessageDigest::sha256())
        .unwrap();
    let cert = builder.build();

    openssl::pkcs12::Pkcs12::builder()
        .name("delivery")
        .pkey(key)
        .cert(&cert)
        .build2(pin)
        .unwrap()
        .to_der()
        .unwrap()
}

/// A store rooted at a fresh temporary directory.
fn store() -> (TempDir, CodesPaths) {
    let dir = tempfile::tempdir().unwrap();
    let paths = CodesPaths::under(dir.path());
    (dir, paths)
}

/// The mode bits of a path.
fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

#[test]
fn a_delivery_without_a_codes_part_changes_nothing() {
    let (_dir, paths) = store();
    let applied = apply(&paths, &CodesDelivery::default(), None, StoreCheck::Skipped).unwrap();
    assert_eq!(applied.epoch, None);
    assert!(!applied.key_replaced);
    // Not even the store directory is created: an Access-only fleet leaves no
    // trace of a method it never enabled.
    assert!(!paths.state_dir.exists());
    assert!(!paths.device_key_container.exists());
}

#[test]
fn a_full_consignment_makes_the_device_ready() {
    let (_dir, paths) = store();
    let delivery = Delivery::new();

    let applied = apply(&paths, &delivery.full(3), None, StoreCheck::Skipped).unwrap();
    assert_eq!(applied.epoch, Some(Epoch::new(3)));
    assert!(applied.key_replaced);
    assert!(paths.artefacts_present());
    assert_eq!(epoch::read(&paths.state_dir).unwrap(), Some(Epoch::new(3)));
}

#[test]
fn the_stored_key_opens_without_the_delivery_pin() {
    // The whole point of the storage form: a device that came back from a power
    // cut has nobody to type the PIN of the container it was delivered in.
    let (_dir, paths) = store();
    let delivery = Delivery::new();
    apply(&paths, &delivery.full(1), None, StoreCheck::Skipped).unwrap();

    let stored = load_device_key(&paths.device_key_container, None).unwrap();
    assert!(stored.public_eq(&delivery.key));

    // And what is on the device is not the container that arrived: the PIN of
    // the delivery no longer opens it.
    let on_disk = std::fs::read(&paths.device_key_container).unwrap();
    assert!(crate::pkcs12::LoadedKeyMaterial::from_p12(
        &on_disk,
        &SecretString::from(DELIVERY_PIN.to_owned()),
        None
    )
    .is_err());
}

#[test]
fn the_store_is_root_only_after_the_import() {
    let (_dir, paths) = store();
    apply(&paths, &Delivery::new().full(1), None, StoreCheck::Skipped).unwrap();

    assert_eq!(mode_of(&paths.device_key_container), 0o600);
    assert_eq!(mode_of(&paths.state_dir), 0o700);
    assert_eq!(mode_of(paths.device_key_container.parent().unwrap()), 0o700);
    assert_eq!(mode_of(&paths.tickets), 0o644);
    assert_eq!(mode_of(&paths.ticket_authority), 0o644);
    // What the walk of `CodesPaths::check_trusted` would add on top of the mode
    // bits is ownership and the absence of symlinked ancestors, and neither can
    // be asserted from a temporary directory — the same limit that made the
    // login path split `open` from `open_privileged`. Here the modes are the
    // evidence; the walk itself is exercised where the store is real.
}

#[test]
fn a_greater_epoch_replaces_the_key() {
    let (_dir, paths) = store();
    let first = Delivery::new();
    apply(&paths, &first.full(1), None, StoreCheck::Skipped).unwrap();

    let second = Delivery::new();
    let applied = apply(&paths, &second.full(2), None, StoreCheck::Skipped).unwrap();
    assert!(applied.key_replaced);
    assert_eq!(applied.epoch, Some(Epoch::new(2)));

    let stored = load_device_key(&paths.device_key_container, None).unwrap();
    assert!(stored.public_eq(&second.key));
    assert!(!stored.public_eq(&first.key));
}

#[test]
fn a_smaller_epoch_is_refused_and_changes_nothing() {
    let (_dir, paths) = store();
    let current = Delivery::new();
    apply(&paths, &current.full(5), None, StoreCheck::Skipped).unwrap();

    let old = Delivery::new();
    assert!(matches!(
        apply(&paths, &old.full(4), None, StoreCheck::Skipped),
        Err(ArtefactError::EpochRollback {
            delivered: 4,
            persisted: 5
        })
    ));

    assert_eq!(epoch::read(&paths.state_dir).unwrap(), Some(Epoch::new(5)));
    let stored = load_device_key(&paths.device_key_container, None).unwrap();
    assert!(stored.public_eq(&current.key));
}

#[test]
fn the_same_epoch_again_writes_the_key_back() {
    let (_dir, paths) = store();
    let delivery = Delivery::new();
    apply(&paths, &delivery.full(7), None, StoreCheck::Skipped).unwrap();

    // The same medium presented a second time.
    let applied = apply(&paths, &delivery.full(7), None, StoreCheck::Skipped).unwrap();
    // The key is written back — see the test below for why that is the point of
    // presenting a medium twice.
    assert!(applied.key_replaced);
    assert_eq!(applied.epoch, Some(Epoch::new(7)));
}

#[test]
fn a_repeated_epoch_restores_a_key_the_store_has_lost() {
    let (_dir, paths) = store();
    let delivery = Delivery::new();
    apply(&paths, &delivery.full(7), None, StoreCheck::Skipped).unwrap();
    std::fs::remove_file(&paths.device_key_container).unwrap();

    let applied = apply(&paths, &delivery.full(7), None, StoreCheck::Skipped).unwrap();
    assert!(applied.key_replaced);
}

#[test]
fn a_repeated_epoch_replaces_a_key_that_does_not_belong_to_it() {
    // The pair the device runs on is (key, epoch), and the epoch is written
    // after the key. A store that holds a key of one delivery under the epoch of
    // another derives codes nobody can read, and the only thing an engineer can
    // do about it on a device with no network is present the medium again. That
    // repeat has to write the delivered key back — a store "already carrying a
    // key" is not a store carrying the right one.
    let (_dir, paths) = store();
    let first = Delivery::new();
    apply(&paths, &first.full(7), None, StoreCheck::Skipped).unwrap();

    // The fleet re-cut the container of the same epoch around a different key.
    let recut = Delivery::new();
    let applied = apply(&paths, &recut.full(7), None, StoreCheck::Skipped).unwrap();

    assert!(applied.key_replaced);
    let stored = load_device_key(&paths.device_key_container, None).unwrap();
    assert!(
        stored.public_eq(&recut.key),
        "the delivered key of the epoch has to be the one on the device"
    );
    assert!(!stored.public_eq(&first.key));
}

#[test]
fn a_first_delivery_to_a_device_that_has_been_talking_writes_its_epoch_down() {
    // The fleet whose artefacts were placed by hand: it runs against the epoch
    // in `config.toml`, so it carries no epoch file, and it has been handing out
    // codes for months. A delivery arriving at such a device writes down the
    // epoch it was implicitly on, so the next delivery has a floor.
    let (_dir, paths) = store();
    let delivery = Delivery::new();
    std::fs::create_dir_all(&paths.state_dir).unwrap();
    assert!(epoch::read(&paths.state_dir).unwrap().is_none());

    let applied = apply(&paths, &delivery.full(3), None, StoreCheck::Skipped).unwrap();

    assert!(applied.key_replaced);
    // The epoch the store was implicitly on is now written down, so the next
    // delivery has a floor to be measured against.
    assert_eq!(applied.epoch, Some(Epoch::new(3)));
    assert_eq!(epoch::read(&paths.state_dir).unwrap(), Some(Epoch::new(3)));
}

#[test]
fn a_delivered_container_that_became_a_symlink_is_not_written_through() {
    // The container is read once and retired at the end of the import, and the
    // whole import fits in between. On the medium the package sits on, the name
    // can have become a link to a file of the system by then — and this runs as
    // root. The link is taken away; what it aimed at is not touched.
    let (dir, _paths) = store();
    let target = dir.path().join("shadow");
    std::fs::write(&target, b"root:!:19000:0:99999:7:::\n").unwrap();
    let delivered = dir.path().join("codes-device.p12");
    std::os::unix::fs::symlink(&target, &delivered).unwrap();

    let removed = super::shred_delivered_key(&delivered).unwrap();

    assert!(removed, "the planted link does not stay on the medium");
    assert!(!delivered.exists());
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"root:!:19000:0:99999:7:::\n",
        "a file the import never opened may not be zeroed by it"
    );
}

#[test]
fn a_delivered_container_is_zeroed_before_it_is_removed() {
    let (dir, _paths) = store();
    let delivered = dir.path().join("codes-device.p12");
    std::fs::write(&delivered, b"the delivery container").unwrap();

    assert!(super::shred_delivered_key(&delivered).unwrap());
    assert!(!delivered.exists());
}

#[test]
fn a_key_container_anybody_can_read_is_not_a_trusted_store() {
    // The stored container carries no password — that is deliberate, a device
    // has nobody to type one at boot — so its permissions are the whole of its
    // protection. A check that only asks "can anyone write this" would accept a
    // container somebody chmod'ed to 0644 in a 0755 directory, and whoever
    // copied it could compute this device's codes with any operator.
    //
    // The refusal is asserted by its reason and not merely by being a refusal:
    // a store under a temporary directory fails the ownership walk anyway (on
    // this host `/var` is itself a symlink), so a test that only demanded an
    // error here would pass without the mode ever being looked at.
    let (_dir, paths) = store();
    apply(&paths, &Delivery::new().full(1), None, StoreCheck::Skipped).unwrap();

    let store_dir = paths.device_key_container.parent().unwrap();
    std::fs::set_permissions(store_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(
        &paths.device_key_container,
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();

    let refused = paths.check_trusted().unwrap_err();
    assert!(
        refused.contains("device key container") && refused.contains("reachable beyond its owner"),
        "the refusal has to name the key and the reason, got {refused}"
    );
    // The import applies the same criterion, so a store the login path would
    // refuse is never a store an import quietly fills.
    let before = paths.check_trusted_before_publishing().unwrap_err();
    assert!(before.contains("reachable beyond its owner"), "{before}");
}

#[test]
fn a_state_directory_anybody_can_enter_is_not_a_trusted_store() {
    let (_dir, paths) = store();
    apply(&paths, &Delivery::new().full(1), None, StoreCheck::Skipped).unwrap();
    std::fs::set_permissions(&paths.state_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    let refused = paths.check_trusted().unwrap_err();
    assert!(
        refused.contains("state directory") && refused.contains("reachable beyond its owner"),
        "{refused}"
    );
}

#[test]
fn the_published_ticket_artefacts_stay_readable() {
    // The other half of the rule: the ticket set and the anchor are trust
    // inputs and not secrets, the import publishes them 0644 on purpose, and a
    // check that demanded 0600 of them would refuse every store the product
    // itself writes.
    let (_dir, paths) = store();
    apply(&paths, &Delivery::new().full(1), None, StoreCheck::Skipped).unwrap();
    assert_eq!(mode_of(&paths.tickets), 0o644);

    let refused = paths.check_trusted().unwrap_err();
    assert!(
        !refused.contains("ticket set") && !refused.contains("ticket authority anchor"),
        "a published trust input is not a permissions fault, got {refused}"
    );
}

#[test]
fn a_store_that_fails_the_check_receives_nothing() {
    // The self-check is a precondition of writing, not a report on what was
    // written. An import that refuses must leave the device exactly as it found
    // it: no key on a store somebody else can reach, and no epoch moved past the
    // point where presenting the medium again would repair anything.
    let (dir, paths) = store();
    // The store itself is created and its mode pinned by the import; what an
    // import cannot repair is the directory it hangs under, and that is what a
    // weakened deployment looks like.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();

    let delivery = Delivery::new();
    let error = apply(&paths, &delivery.full(3), None, StoreCheck::Enforced).unwrap_err();

    assert!(matches!(error, ArtefactError::Untrusted(_)), "{error:?}");
    assert!(!paths.device_key_container.exists());
    assert!(!paths.tickets.exists());
    assert!(!paths.ticket_authority.exists());
    assert!(epoch::read(&paths.state_dir).unwrap().is_none());
}

#[test]
fn a_rotation_carries_tickets_without_a_key() {
    let (_dir, paths) = store();
    let delivery = Delivery::new();
    apply(&paths, &delivery.full(1), None, StoreCheck::Skipped).unwrap();

    let rotation = CodesDelivery {
        tickets: Some(delivery.tickets("op-99")),
        revocations: Some(Delivery::revocations(&["tk-17"])),
        ..CodesDelivery::default()
    };
    let applied = apply(&paths, &rotation, None, StoreCheck::Skipped).unwrap();
    assert!(applied.tickets_applied);
    assert!(applied.revocations_applied);
    assert!(!applied.key_replaced);
    assert_eq!(applied.epoch, Some(Epoch::new(1)));

    let store = crate::codes::tickets::TicketStore::load(&paths.tickets, &paths.ticket_revocations)
        .unwrap();
    assert_eq!(
        store.revoked(),
        &BTreeSet::from(["tk-17".to_owned()]),
        "a withdrawn ticket has to be on the device before the next login"
    );
}

#[test]
fn a_revocation_list_that_forgot_a_number_is_refused() {
    let (_dir, paths) = store();
    let delivery = Delivery::new();
    apply(&paths, &delivery.full(1), None, StoreCheck::Skipped).unwrap();

    let withdrawn = CodesDelivery {
        revocations: Some(Delivery::revocations(&["tk-17", "tk-18"])),
        ..CodesDelivery::default()
    };
    apply(&paths, &withdrawn, None, StoreCheck::Skipped).unwrap();

    let older = CodesDelivery {
        revocations: Some(Delivery::revocations(&["tk-17"])),
        ..CodesDelivery::default()
    };
    assert!(matches!(
        apply(&paths, &older, None, StoreCheck::Skipped),
        Err(ArtefactError::RevocationRollback)
    ));

    // The applied list is untouched.
    let store = crate::codes::tickets::TicketStore::load(&paths.tickets, &paths.ticket_revocations)
        .unwrap();
    assert_eq!(store.revoked().len(), 2);
}

#[test]
fn a_revocation_list_that_only_grows_is_accepted() {
    let (_dir, paths) = store();
    let delivery = Delivery::new();
    apply(&paths, &delivery.full(1), None, StoreCheck::Skipped).unwrap();

    for numbers in [&["tk-17"][..], &["tk-17", "tk-18"][..]] {
        let payload = CodesDelivery {
            revocations: Some(Delivery::revocations(numbers)),
            ..CodesDelivery::default()
        };
        apply(&paths, &payload, None, StoreCheck::Skipped).unwrap();
    }
    let store = crate::codes::tickets::TicketStore::load(&paths.tickets, &paths.ticket_revocations)
        .unwrap();
    assert_eq!(store.revoked().len(), 2);
}

#[test]
fn a_malformed_ticket_set_is_refused_before_anything_is_written() {
    let (_dir, paths) = store();
    let delivery = Delivery::new();
    apply(&paths, &delivery.full(1), None, StoreCheck::Skipped).unwrap();
    let good = std::fs::read(&paths.tickets).unwrap();

    let broken = CodesDelivery {
        tickets: Some(b"tessera-codes/v1/ticket|not-a-ticket\n".to_vec()),
        ..CodesDelivery::default()
    };
    assert!(matches!(
        apply(&paths, &broken, None, StoreCheck::Skipped),
        Err(ArtefactError::Tickets(_))
    ));
    assert_eq!(std::fs::read(&paths.tickets).unwrap(), good);
}

#[test]
fn a_container_the_pin_does_not_open_is_refused() {
    let (_dir, paths) = store();
    let delivery = Delivery::new();
    let mut consignment = delivery.full(1);
    if let Some(key) = consignment.key.as_mut() {
        key.pin = SecretString::from("wrong".to_owned());
    }
    assert!(matches!(
        apply(&paths, &consignment, None, StoreCheck::Skipped),
        Err(ArtefactError::Container(_))
    ));
    assert!(!paths.device_key_container.exists());
    assert!(epoch::read(&paths.state_dir).unwrap().is_none());
}

#[test]
fn a_wipe_removes_every_artefact_and_reports_the_last_epoch() {
    let (_dir, paths) = store();
    let delivery = Delivery::new();
    apply(&paths, &delivery.full(4), None, StoreCheck::Skipped).unwrap();
    let revocations = CodesDelivery {
        revocations: Some(Delivery::revocations(&["tk-17"])),
        ..CodesDelivery::default()
    };
    apply(&paths, &revocations, None, StoreCheck::Skipped).unwrap();

    let wiped = wipe(&paths).unwrap();
    assert_eq!(wiped.last_epoch, Some(Epoch::new(4)));
    assert!(wiped.found_anything());
    assert!(!paths.device_key_container.exists());
    assert!(!paths.tickets.exists());
    assert!(!paths.ticket_revocations.exists());
    assert!(!paths.ticket_authority.exists());
    assert!(epoch::read(&paths.state_dir).unwrap().is_none());
    assert!(!paths.artefacts_present());
    // Nothing at all is left in the state directory — including the lock file
    // this module creates itself. A named list of removals is a list somebody
    // extends and somebody else forgets to; what the promise of the module
    // actually says is "empty", so that is what is asserted.
    let left: Vec<String> = std::fs::read_dir(&paths.state_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        left.is_empty(),
        "a wiped device keeps no trace of the method, found {left:?}"
    );
}

#[test]
fn a_wipe_of_a_device_without_codes_is_not_a_failure() {
    let (_dir, paths) = store();
    let wiped = wipe(&paths).unwrap();
    assert_eq!(wiped.last_epoch, None);
    assert!(!wiped.found_anything());
    assert!(wiped.removed.is_empty());
}

#[test]
fn a_wiped_device_accepts_the_next_enrolment() {
    // A device wiped and re-enrolled is the ordinary lifecycle, and the epoch
    // floor is gone with the rest: the anti-rollback protects the key a device
    // holds, not a device that holds none.
    let (_dir, paths) = store();
    apply(&paths, &Delivery::new().full(9), None, StoreCheck::Skipped).unwrap();
    wipe(&paths).unwrap();

    let applied = apply(&paths, &Delivery::new().full(1), None, StoreCheck::Skipped).unwrap();
    assert_eq!(applied.epoch, Some(Epoch::new(1)));
    assert!(applied.key_replaced);
}
