//! Live tests for the token data-object carrier: the issuing tool writes a
//! container into a `CKO_DATA` object, the login path reads it back.
//!
//! Both halves are exercised against the same physical token on purpose. The
//! failure this carrier exists to guard against — a write the token reports as
//! successful and silently truncates — cannot be reproduced against a mock,
//! and a fixture placed by anything other than the shipping writer would prove
//! the reader works on objects nobody ships.
//!
//! Gates, like every other `pkcs11_*` file here:
//! 1. the `pkcs11-tests` Cargo feature (compile time);
//! 2. `PKCS11_MODULE_PATH` pointing at a real provider (run time).
//!
//! Configuration, matching the other live suites:
//! - `SOFTHSM_TEST_LABEL` — the token to work on. Worth setting whenever more
//!   than one token is plugged in; otherwise the first slot wins.
//! - `SOFTHSM_USER_PIN` — the user PIN (default `1234`).
//!
//! Every test takes [`TOKEN`] for its whole body. A token is one device with
//! one login state, and `C_Initialize` is process-global: `rtpkcs11ecp` 2.14.1
//! aborts the process when two threads enter it at once, and the two halves
//! under test here reach the provider through two different contexts that know
//! nothing of each other.
//!
//! The objects the tests create are destroyed as they go; a run interrupted in
//! the middle can leave one behind, and the labels below are prefixed so it is
//! recognisable.

#![cfg(feature = "pkcs11-tests")]
#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic,
    clippy::unwrap_used
)]

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, PoisonError};

use cryptoki::object::ObjectHandle;
use secrecy::SecretString;

use tessera_core::token::pkcs11::{
    test_helpers, LockingMode, Pkcs11Backend, Pkcs11Error, Pkcs11Session,
};
use tessera_issuer::carrier::{self, CarrierError, Overwrite, TokenTarget, MAX_TOKEN_OBJECT_BYTES};

/// Serializes the whole file against the single physical token.
static TOKEN: Mutex<()> = Mutex::new(());

fn token_guard() -> MutexGuard<'static, ()> {
    TOKEN.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Labels this suite writes under. Distinct per test so a leftover from an
/// interrupted run cannot be mistaken for the object under test.
const LABEL_ROUNDTRIP: &str = "tessera-test-p12-roundtrip";
const LABEL_PUBLIC: &str = "tessera-test-p12-public";
const LABEL_OVERSIZED: &str = "tessera-test-p12-oversized";
const LABEL_ABSENT: &str = "tessera-test-p12-never-written";
const LABEL_DUPLICATE: &str = "tessera-test-p12-twice";
const LABEL_HELD_LOGIN: &str = "tessera-test-p12-held-login";
/// The label the filler objects that exhaust the token's memory are written
/// under, so a run interrupted mid-fill can be cleaned up by name.
const LABEL_FILLER: &str = "tessera-test-p12-filler";
/// The prefix the writer stages a container under, mirrored here so the tests
/// can look for what a write left behind and clean it up.
const STAGING_PREFIX: &str = ".tessera-staging-";

fn module_path() -> Option<PathBuf> {
    if test_helpers::skip_if_no_module() {
        return None;
    }
    test_helpers::pkcs11_test_module_path()
}

fn token_label() -> Option<String> {
    std::env::var("SOFTHSM_TEST_LABEL").ok()
}

fn user_pin() -> SecretString {
    SecretString::from(std::env::var("SOFTHSM_USER_PIN").unwrap_or_else(|_| "1234".to_owned()))
}

fn target<'a>(
    module: &'a std::path::Path,
    label: Option<&'a str>,
    object: &'a str,
) -> TokenTarget<'a> {
    TokenTarget {
        module_path: module,
        token_label: label,
        object_label: object,
    }
}

/// A logged-in session on the token under test, through the production types.
fn open_session(module: &std::path::Path, label: Option<&str>) -> Option<Pkcs11Session> {
    let backend = Pkcs11Backend::load(module, LockingMode::Mutex).expect("load module");
    let slot = match backend.find_slot(label) {
        Ok(slot) => slot,
        Err(e) => {
            eprintln!("skipped: no usable slot ({e})");
            return None;
        }
    };
    match Pkcs11Session::open(&backend, slot, &user_pin()) {
        Ok(session) => Some(session),
        Err(Pkcs11Error::PinIncorrect) => {
            eprintln!("skipped: token PIN does not match SOFTHSM_USER_PIN");
            None
        }
        Err(e) => panic!("open session: {e}"),
    }
}

/// A container-shaped blob: the size of a real PKCS#12 envelope, with content
/// that makes a truncation or a byte swap visible.
fn container(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect()
}

/// Run `body` on a logged-in raw `cryptoki` session against the token under
/// test, or return `None` when there is no usable slot or the PIN is wrong.
///
/// Raw rather than through [`Pkcs11Session`] because what these tests need it
/// for is putting objects on the token that the shipping writer cannot produce
/// — a public one, two under one label — and taking them off again afterwards.
///
/// Every call brings up its own context and drops it at the end. That is a
/// crutch, and it is here for the reason named in `carrier::token_access`: the
/// writer's lock and `tessera_core`'s context registry are two locks around one
/// piece of provider state, so a test cannot join whichever of them the code
/// under test is using. [`TOKEN`] is the same crutch at file scope. Both go
/// away only if the two crates ever share one registry.
fn with_raw_session<T>(
    module: &std::path::Path,
    label: Option<&str>,
    body: impl FnOnce(&cryptoki::session::Session) -> T,
) -> Option<T> {
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::error::{Error as CkError, RvError};
    use cryptoki::session::UserType;

    let ctx = Pkcs11::new(module).expect("load module");
    match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(e) => panic!("initialize: {e}"),
    }
    let slots = ctx.get_slots_with_token().expect("slots");
    let slot = slots.into_iter().find(|slot| {
        let info = ctx.get_token_info(*slot).expect("token info");
        label.is_none_or(|want| info.label().trim_end() == want)
    })?;
    let session = ctx.open_rw_session(slot).expect("session");
    match session.login(UserType::User, Some(&user_pin())) {
        // The second pattern is somebody in this process still holding a login
        // on the shared `C_Initialize`; the PIN is not what is being tested
        // here, and the session is authenticated either way.
        Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
        Err(e) => {
            eprintln!("skipped: could not log in ({e})");
            return None;
        }
    }
    let out = body(&session);
    drop(session.logout());
    Some(out)
}

/// Every `CKO_DATA` handle on the token carrying `object_label`.
fn handles_for(session: &cryptoki::session::Session, object_label: &str) -> Vec<ObjectHandle> {
    use cryptoki::object::{Attribute, ObjectClass};

    session
        .find_objects(&[
            Attribute::Class(ObjectClass::DATA),
            Attribute::Label(object_label.as_bytes().to_vec()),
        ])
        .expect("search")
}

/// Put one private `CKO_DATA` object on the token, the way a tool other than
/// the shipping writer would.
fn create_data_object(
    session: &cryptoki::session::Session,
    object_label: &str,
    value: &[u8],
    private: bool,
) -> Result<ObjectHandle, cryptoki::error::Error> {
    use cryptoki::object::{Attribute, ObjectClass};

    session.create_object(&[
        Attribute::Class(ObjectClass::DATA),
        Attribute::Token(true),
        Attribute::Private(private),
        Attribute::Label(object_label.as_bytes().to_vec()),
        Attribute::Value(value.to_vec()),
    ])
}

/// Remove `label` from the token, whatever state a previous run left it in.
///
/// Each pass opens its own session, because that is what makes it work:
/// `rtpkcs11ecp` 2.14.1 reports fewer handles than the token holds once its
/// memory is full, and a second search *in the same session* keeps reporting
/// the same short list. A helper that trusted one pass would leave the leavings
/// of a fill on the token and fail every test after it for the wrong reason.
/// Bounded, so a provider that never empties does not spin.
fn destroy(module: &std::path::Path, label: Option<&str>, object_label: &str) {
    const PASSES: usize = 12;

    for _ in 0..PASSES {
        let removed = with_raw_session(module, label, |session| {
            let handles = handles_for(session, object_label);
            let found = handles.len();
            for handle in handles {
                drop(session.destroy_object(handle));
            }
            found
        });
        // Nothing found, or no token to look at: either way there is nothing
        // left for another pass to do.
        match removed {
            Some(0) | None => return,
            Some(_) => {}
        }
    }
}

/// The round trip the whole carrier rests on: a container the size of a real
/// envelope goes onto the token and comes back byte for byte, behind the PIN.
#[test]
fn live_container_survives_the_round_trip() {
    let _guard = token_guard();
    let Some(module) = module_path() else { return };
    let label = token_label();

    destroy(&module, label.as_deref(), LABEL_ROUNDTRIP);
    let bytes = container(2571);
    let written = match carrier::lay_out_token(
        &target(&module, label.as_deref(), LABEL_ROUNDTRIP),
        &bytes,
        &user_pin(),
        Overwrite::Allow,
    ) {
        Ok(written) => written,
        Err(e) => panic!("write the container: {e}"),
    };
    assert_eq!(written.bytes, bytes.len());
    assert_eq!(written.object_label, LABEL_ROUNDTRIP);
    assert!(
        !written.token_serial.is_empty(),
        "the record must name the token that received the container"
    );

    let Some(session) = open_session(&module, label.as_deref()) else {
        return;
    };
    let found = session
        .find_data_object(LABEL_ROUNDTRIP)
        .expect("read the container back");
    assert!(
        found.private,
        "a container written by this tool must need the PIN"
    );
    assert_eq!(
        found.value, bytes,
        "the container must come back byte for byte"
    );
    assert_eq!(
        session
            .read_private_data_object(LABEL_ROUNDTRIP)
            .expect("the private read path must accept it"),
        bytes
    );
    drop(session);

    // The write stages the container under a marked label before it commits.
    // Nothing may be left wearing that label: the operator has no way to tell a
    // half-written container from a credential except by the label, and the
    // next run would find it and have to guess what it was.
    let staged = with_raw_session(&module, label.as_deref(), |session| {
        handles_for(session, &format!("{STAGING_PREFIX}{LABEL_ROUNDTRIP}")).len()
    });
    assert_eq!(staged, Some(0), "a staged object was left on the token");

    destroy(&module, label.as_deref(), LABEL_ROUNDTRIP);
}

/// A label nobody wrote is "not found", not a read failure. The caller has to
/// tell an engineer whether they are holding the wrong token or a broken one.
#[test]
fn live_absent_label_is_not_found() {
    let _guard = token_guard();
    let Some(module) = module_path() else { return };
    let label = token_label();
    destroy(&module, label.as_deref(), LABEL_ABSENT);

    let Some(session) = open_session(&module, label.as_deref()) else {
        return;
    };
    let err = session
        .find_data_object(LABEL_ABSENT)
        .err()
        .expect("an absent label must not read as a container");
    assert!(
        matches!(err, Pkcs11Error::DataObjectNotFound { .. }),
        "got {err:?}"
    );
    let err = session
        .read_private_data_object(LABEL_ABSENT)
        .err()
        .expect("same through the private read path");
    assert!(
        matches!(err, Pkcs11Error::DataObjectNotFound { .. }),
        "got {err:?}"
    );
}

/// An object stored without `CKA_PRIVATE` is refused. It is written here with
/// raw cryptoki because the shipping writer cannot produce one — which is the
/// point: the object comes from some other tool, and `pkcs11-tool` makes one by
/// default.
#[test]
fn live_public_object_is_refused_by_the_reading_path() {
    let _guard = token_guard();
    let Some(module) = module_path() else { return };
    let label = token_label();
    destroy(&module, label.as_deref(), LABEL_PUBLIC);

    let bytes = container(512);
    let placed = with_raw_session(&module, label.as_deref(), |session| {
        create_data_object(session, LABEL_PUBLIC, &bytes, false)
            .expect("create a public data object");
    });
    if placed.is_none() {
        eprintln!("skipped: no usable slot");
        return;
    }

    let Some(session) = open_session(&module, label.as_deref()) else {
        return;
    };
    let found = session
        .find_data_object(LABEL_PUBLIC)
        .expect("the object is on the token");
    assert!(!found.private, "the object was deliberately created public");
    let err = session
        .read_private_data_object(LABEL_PUBLIC)
        .err()
        .expect("a container readable without the PIN must be refused");
    assert!(
        matches!(err, Pkcs11Error::DataObjectNotPrivate { .. }),
        "got {err:?}"
    );
    drop(session);

    destroy(&module, label.as_deref(), LABEL_PUBLIC);
}

/// An oversized container is refused by this code, and nothing lands on the
/// token. Left to the device it would be accepted, truncated and reported as a
/// success — the engineer would find out at the login screen.
#[test]
fn live_oversized_container_is_refused_and_writes_nothing() {
    let _guard = token_guard();
    let Some(module) = module_path() else { return };
    let label = token_label();
    destroy(&module, label.as_deref(), LABEL_OVERSIZED);

    let oversized = container(48 * 1024);
    assert!(oversized.len() > MAX_TOKEN_OBJECT_BYTES);
    let err = carrier::lay_out_token(
        &target(&module, label.as_deref(), LABEL_OVERSIZED),
        &oversized,
        &user_pin(),
        Overwrite::Allow,
    )
    .err()
    .expect("48 KiB must be refused");
    assert!(
        matches!(err, CarrierError::TokenObjectTooLarge { .. }),
        "got {err:?}"
    );

    let Some(session) = open_session(&module, label.as_deref()) else {
        return;
    };
    let err = session
        .find_data_object(LABEL_OVERSIZED)
        .err()
        .expect("a refused write must leave nothing behind");
    assert!(
        matches!(err, Pkcs11Error::DataObjectNotFound { .. }),
        "a truncated fragment on the token reads to the device as a damaged container: {err:?}"
    );
}

/// A replacement that fails on the token must leave the credential already on
/// it in place.
///
/// The token comes in carrying a working credential; the operator asks for a
/// replacement and the token has nowhere to put it. A writer that cleared the
/// old object first would hand back an empty carrier and an error, with nothing
/// to put back — the engineer's shift is gone either way, but only one of the
/// two outcomes can be retried.
///
/// The failure is produced by filling the token's memory, which is the same
/// refusal a real one gives on a carrier that is nearly full. Everything the
/// fill wrote is removed again at the end.
#[test]
fn live_a_failed_write_leaves_the_existing_credential_in_place() {
    let _guard = token_guard();
    let Some(module) = module_path() else { return };
    let label = token_label();
    destroy(&module, label.as_deref(), LABEL_ROUNDTRIP);
    destroy(&module, label.as_deref(), LABEL_FILLER);

    let first = container(2571);
    if carrier::lay_out_token(
        &target(&module, label.as_deref(), LABEL_ROUNDTRIP),
        &first,
        &user_pin(),
        Overwrite::Refuse,
    )
    .is_err()
    {
        eprintln!("skipped: could not place the credential to be protected");
        return;
    }

    let filled = fill_token(&module, label.as_deref());
    if filled == 0 {
        eprintln!("skipped: the token would not fill up");
        destroy(&module, label.as_deref(), LABEL_FILLER);
        destroy(&module, label.as_deref(), LABEL_ROUNDTRIP);
        return;
    }

    let second = container(3000);
    let err = carrier::lay_out_token(
        &target(&module, label.as_deref(), LABEL_ROUNDTRIP),
        &second,
        &user_pin(),
        Overwrite::Allow,
    )
    .err()
    .expect("a token with no room left must refuse the write");
    assert!(
        matches!(
            err,
            CarrierError::TokenWriteFailed { .. }
                | CarrierError::TokenWriteNotVerified { .. }
                | CarrierError::TokenFragmentLeft { .. }
        ),
        "got {err:?}"
    );

    // The point of the whole exercise: what the engineer arrived with is still
    // on the token, byte for byte, and still behind the PIN.
    {
        let Some(session) = open_session(&module, label.as_deref()) else {
            return;
        };
        assert_eq!(
            session
                .read_private_data_object(LABEL_ROUNDTRIP)
                .expect("the credential that was there must still be there"),
            first,
            "a failed replacement must not consume the credential it was replacing"
        );
    }
    // Whether the write's own scratch object is gone is deliberately not
    // asserted here. A token this full stops answering reliably: `rtpkcs11ecp`
    // 2.14.1 has been seen to report fewer objects than it holds and to refuse
    // `C_DestroyObject` outright once its memory is exhausted, so a search that
    // came back empty would prove nothing. What the writer owes in that state
    // is an honest report — `TokenFragmentLeft`, accepted above — and that is
    // what is checked. The scratch object is asserted gone where the token can
    // still be believed, in `live_container_survives_the_round_trip`.
    destroy(
        &module,
        label.as_deref(),
        &format!("{STAGING_PREFIX}{LABEL_ROUNDTRIP}"),
    );
    destroy(&module, label.as_deref(), LABEL_FILLER);
    destroy(&module, label.as_deref(), LABEL_ROUNDTRIP);
}

/// Fill the token's memory with objects until it refuses another, and report
/// how many went on. Zero means the token would not fill within the cap.
///
/// Capped: a token big enough to swallow the whole loop would otherwise turn a
/// test into an endurance run against flash memory.
fn fill_token(module: &std::path::Path, label: Option<&str>) -> usize {
    // Coarse first, then finer: a token that will not take another 32 KiB can
    // still have room for the few kilobytes of a container, and a fill that
    // stopped at the coarse step would leave exactly that room.
    const FILLER_SIZES: [usize; 4] = [32 * 1024, 4 * 1024, 512, 64];
    const CAP_PER_SIZE: usize = 24;

    with_raw_session(module, label, |session| {
        let mut placed = 0;
        for size in FILLER_SIZES {
            let filler = container(size);
            let mut at_this_size = 0;
            while at_this_size < CAP_PER_SIZE {
                match create_data_object(session, LABEL_FILLER, &filler, true) {
                    Ok(_) => {
                        at_this_size += 1;
                        placed += 1;
                    }
                    Err(_) => break,
                }
            }
            // The cap was reached rather than the token's limit, so the token
            // is bigger than this fill can exhaust and the refusal the caller
            // is after would never come.
            if at_this_size == CAP_PER_SIZE {
                return 0;
            }
        }
        placed
    })
    .unwrap_or(0)
}

/// A write must go through while somebody else in the process holds a login on
/// the same provider.
///
/// PKCS#11 scopes a login to the `C_Initialize`, not to the session, and the
/// issuing tool shares one: the CA token's signer runs on the same library. A
/// writer that reported `CKR_USER_ALREADY_LOGGED_IN` as a login failure would
/// tell the operator their carrier PIN is wrong when it is not.
#[test]
fn live_write_succeeds_while_a_neighbour_holds_a_login() {
    let _guard = token_guard();
    let Some(module) = module_path() else { return };
    let label = token_label();
    destroy(&module, label.as_deref(), LABEL_HELD_LOGIN);

    let Some(neighbour) = open_session(&module, label.as_deref()) else {
        return;
    };
    let bytes = container(1500);
    carrier::lay_out_token(
        &target(&module, label.as_deref(), LABEL_HELD_LOGIN),
        &bytes,
        &user_pin(),
        Overwrite::Refuse,
    )
    .expect("a login held by a neighbour must not fail the write");
    drop(neighbour);

    // And again in the same process: a login the first write failed to give up
    // would meet the second one as a refusal at the door.
    carrier::lay_out_token(
        &target(&module, label.as_deref(), LABEL_HELD_LOGIN),
        &bytes,
        &user_pin(),
        Overwrite::Allow,
    )
    .expect("a second write in the same process");

    destroy(&module, label.as_deref(), LABEL_HELD_LOGIN);
}

/// Two objects under one label are refused rather than resolved.
///
/// Nothing tells them apart — the token gives no order and no age — so picking
/// one means picking whatever the provider enumerated first, and an engineer
/// whose credential was replaced could go on authenticating with the old one.
/// The writer already treats a duplicate label as a failed write.
#[test]
fn live_two_objects_under_one_label_are_refused() {
    let _guard = token_guard();
    let Some(module) = module_path() else { return };
    let label = token_label();
    destroy(&module, label.as_deref(), LABEL_DUPLICATE);

    let bytes = container(512);
    let placed = with_raw_session(&module, label.as_deref(), |session| {
        for _ in 0..2 {
            create_data_object(session, LABEL_DUPLICATE, &bytes, true)
                .expect("create a duplicate data object");
        }
    });
    if placed.is_none() {
        eprintln!("skipped: no usable slot");
        return;
    }

    {
        let Some(session) = open_session(&module, label.as_deref()) else {
            return;
        };
        let err = session
            .find_data_object(LABEL_DUPLICATE)
            .err()
            .expect("two objects under one label must not resolve to either");
        assert!(
            matches!(err, Pkcs11Error::DataObjectAmbiguous { count: 2, .. }),
            "got {err:?}"
        );
    }

    destroy(&module, label.as_deref(), LABEL_DUPLICATE);
}

/// A label already in use is not quietly replaced: a token can hold another
/// engineer's working credential.
#[test]
fn live_existing_object_is_not_replaced_without_a_yes() {
    let _guard = token_guard();
    let Some(module) = module_path() else { return };
    let label = token_label();
    destroy(&module, label.as_deref(), LABEL_ROUNDTRIP);

    let first = container(1024);
    if carrier::lay_out_token(
        &target(&module, label.as_deref(), LABEL_ROUNDTRIP),
        &first,
        &user_pin(),
        Overwrite::Refuse,
    )
    .is_err()
    {
        eprintln!("skipped: could not place the first container");
        return;
    }

    let second = container(2048);
    let err = carrier::lay_out_token(
        &target(&module, label.as_deref(), LABEL_ROUNDTRIP),
        &second,
        &user_pin(),
        Overwrite::Refuse,
    )
    .err()
    .expect("an occupied label must be refused");
    assert!(
        matches!(err, CarrierError::TokenObjectExists(_)),
        "got {err:?}"
    );

    {
        let Some(session) = open_session(&module, label.as_deref()) else {
            return;
        };
        assert_eq!(
            session
                .read_private_data_object(LABEL_ROUNDTRIP)
                .expect("the first container is still there"),
            first,
            "a refusal must leave the credential in place untouched"
        );
    }

    carrier::lay_out_token(
        &target(&module, label.as_deref(), LABEL_ROUNDTRIP),
        &second,
        &user_pin(),
        Overwrite::Allow,
    )
    .expect("a confirmed replacement must go through");
    {
        let Some(session) = open_session(&module, label.as_deref()) else {
            return;
        };
        assert_eq!(
            session
                .read_private_data_object(LABEL_ROUNDTRIP)
                .expect("the replacement is readable"),
            second
        );
    }

    destroy(&module, label.as_deref(), LABEL_ROUNDTRIP);
}
