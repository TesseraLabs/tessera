//! The dishonest PKCS#11 module answers `C_GetFunctionList` and `cryptoki` can
//! open it. Everything else about the fixture is exercised by the read-back and
//! probe tests; this one only proves the ABI is right, so a failure elsewhere
//! is not silently a failure to load.

#![cfg(feature = "pkcs11-tests")]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

fn liar_module() -> Option<PathBuf> {
    std::env::var("TESSERA_TEST_PKCS11_LIAR")
        .ok()
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.exists())
}

/// Loads and initializes the fixture.
///
/// `C_Initialize` is process-wide, so the second test in a run finds the module
/// already open — the same thing a real provider does, and the reason
/// `tessera_core` keeps a singleton around it.
fn open(module: &std::path::Path) -> cryptoki::context::Pkcs11 {
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::error::{Error as CkError, RvError};

    let ctx = Pkcs11::new(module).expect("liar module loads");
    match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(e) => panic!("liar module initializes: {e}"),
    }
    ctx
}

#[test]
fn liar_module_loads_and_reports_one_slot() {
    let Some(module) = liar_module() else {
        println!("skipped: set TESSERA_TEST_PKCS11_LIAR to the built fixture");
        return;
    };
    let ctx = open(&module);
    let slots = ctx.get_slots_with_token().expect("slot list");
    assert_eq!(slots.len(), 1, "the fixture presents exactly one token");
}

/// The generation path the wave's tests take runs end to end through the ABI:
/// a session opens, a pair is generated, and the attributes come back. Without
/// this, a marshalling defect in the fixture would surface later as a defect in
/// the code being tested.
#[test]
fn the_control_mode_generates_a_pair_and_reports_the_template_back() {
    use cryptoki::object::{Attribute, AttributeInfo, AttributeType};

    let Some(module) = liar_module() else {
        println!("skipped: set TESSERA_TEST_PKCS11_LIAR to the built fixture");
        return;
    };
    // The mode is process-wide and read at `C_Initialize`; a harness that asked
    // for a lie is running a different test's scenario.
    if std::env::var("TESSERA_PKCS11_LIAR_MODE").is_ok_and(|mode| !mode.is_empty()) {
        println!("skipped: this test asserts the control mode's behaviour");
        return;
    }

    let ctx = open(&module);
    let slot = *ctx
        .get_slots_with_token()
        .expect("slot list")
        .first()
        .expect("one slot");
    let session = ctx.open_rw_session(slot).expect("session opens");
    session
        .login(
            cryptoki::session::UserType::User,
            Some(&cryptoki::types::AuthPin::new("1234".into())),
        )
        .expect("the fixture accepts any PIN");

    let (_public, private) = session
        .generate_key_pair(
            &cryptoki::mechanism::Mechanism::EccKeyPairGen,
            &[
                Attribute::Token(true),
                // P-256, the only curve the fixture knows.
                Attribute::EcParams(vec![
                    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
                ]),
            ],
            &[
                Attribute::Token(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
            ],
        )
        .expect("the fixture generates a real P-256 pair");

    let reported = session
        .get_attributes(private, &[AttributeType::Extractable])
        .expect("read the template back");
    assert_eq!(
        reported.first(),
        Some(&Attribute::Extractable(false)),
        "the control mode reports what the template asked for"
    );

    let value = session
        .get_attribute_info(private, &[AttributeType::Value])
        .expect("ask for the private key's value");
    assert!(
        matches!(value.first(), Some(AttributeInfo::Sensitive)),
        "outside the leaking mode the scalar stays on the token, got {value:?}"
    );
}
