//! Mode-B on live hardware: a private key found under the default policy
//! is a key the token proved it cannot export.
//!
//! The unit tests in `key_lookup.rs` feed the policy synthetic attribute
//! vectors, so they establish what the three-state logic *decides* but
//! nothing about what a real provider *answers*.  This file closes that
//! gap on the only place it can be closed: a token whose
//! `CKA_EXTRACTABLE` comes from the vendor library rather than from a
//! `Vec<Attribute>` we wrote ourselves.
//!
//! # What has to be true before anything runs
//!
//! 1. the `pkcs11-tests` Cargo feature (compile time);
//! 2. `PKCS11_MODULE_PATH` — a loadable provider;
//! 3. `SOFTHSM_USER_PIN` — the user PIN of the token named below;
//! 4. `SOFTHSM_TEST_LABEL` — the `CK_TOKEN_INFO` label of the token to
//!    use, i.e. *which* token;
//! 5. `TESSERA_PKCS11_CERT_LABEL` — the `CKA_LABEL` of the fixture
//!    certificate, i.e. *which object on it*.
//!
//! Two separate labels because they name different things and are
//! different strings in practice: a Rutoken ECP reports the token label
//! `Rutoken ECP <no label>` while the fixture objects carry
//! `tessera-modeb-ec`.  `SOFTHSM_TEST_LABEL` keeps the meaning it has in
//! every other suite in this crate (the token), so the object label needs
//! a name of its own.
//!
//! Neither label has a default, and the test refuses to choose for you.
//! Without a token label `find_slot` takes the first slot reporting a
//! token, in whatever order the provider enumerates them, and the PIN you
//! configured for one token would be presented to another — spending an
//! attempt from a counter that is hardware-backed and, once exhausted,
//! locks the token.  Without an object label `find_certificate` returns
//! the first certificate that parses, which on a personal Rutoken or a
//! shared softhsm store is very unlikely to be the fixture; the verdict
//! would then be about somebody else's key.
//!
//! # Making the fixture
//!
//! The lookup joins a certificate object to a private key by `CKA_ID`, so
//! a bare token is not enough — it needs both objects sharing one id.  How
//! the reference fixture was made on a Rutoken ECP 3.0 (`<M>` is the
//! vendor module, `rtpkcs11ecp.framework/rtpkcs11ecp` inside the Rutoken
//! macOS app bundle; `<pin>` is the token's user PIN):
//!
//! ```text
//! pkcs11-tool --module <M> --login --pin <pin> \
//!     --keypairgen --key-type EC:prime256v1 --label tessera-modeb-ec --id 01
//! # self-signed root, signed on the token by that key:
//! TESSERA_ISSUER_PIN=<pin> issuer issue-root --backend pkcs11 \
//!     --key tessera-modeb-ec --module <M> --spki <pubkey.pem> \
//!     --subject "CN=Tessera Lab Root" --not-before <unix> --not-after <unix> \
//!     --allow-role serv --journal <j.ndjson> --out root.der --der
//! pkcs11-tool --module <M> --login --pin <pin> \
//!     --write-object root.der --type cert --id 01 --label tessera-modeb-ec
//! ```
//!
//! Any cert/key pair sharing a `CKA_ID` and a `CKA_LABEL` will do; the
//! recipe is here because a skip line on its own does not tell the next
//! person how to stop the skipping.
//!
//! # Making a skip a failure
//!
//! Every skip below is also what a CI host looks like after its
//! provisioning step silently stopped creating the fixture — the suite
//! would then report success forever without ever testing anything.  Set
//! `TESSERA_REQUIRE_PKCS11_FIXTURE=1` on hosts that are supposed to have
//! the fixture and every skip becomes a failure naming what was missing.
//! Off by default, so developer machines stay green.
//!
//! # Deliberately no wrong-PIN path here
//!
//! Hardware tokens count PIN failures (Rutoken: 10, reset by a successful
//! login) and a lockout is not recoverable from a test.  Nothing in this
//! file may present a PIN it does not expect to be accepted.
//!
//! # Scope limit
//!
//! The assertion establishes the verdict, not the route to it.
//! `CKA_EXTRACTABLE = FALSE` read from the batched attribute query and
//! the same value rescued by the cold-path single-attribute re-read are
//! indistinguishable from out here — a regression that broke the batched
//! read and was quietly saved by the re-read would leave this test green.
//! Nothing in the returned [`FoundPrivateKey`] records which path
//! produced the value, so this is stated rather than asserted.
//!
//! [`FoundPrivateKey`]: tessera_core::token::pkcs11::FoundPrivateKey

#![cfg(feature = "pkcs11-tests")]
#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic,
    clippy::unwrap_used
)]

use std::path::PathBuf;

use secrecy::SecretString;
use tessera_core::token::pkcs11::{
    test_helpers, ExtractableKeyPolicy, ExtractableState, LockingMode, Pkcs11Backend, Pkcs11Error,
    Pkcs11Session,
};

/// Set to `1` on a host that is supposed to carry the fixture: every skip
/// in this file then fails instead, so a provisioning step that stopped
/// working is reported rather than absorbed.  Only the exact value `1`
/// counts, so a stray empty or `0` setting cannot arm it by accident.
const REQUIRE_FIXTURE_ENV: &str = "TESSERA_REQUIRE_PKCS11_FIXTURE";

/// Names the token; matched against `CK_TOKEN_INFO.label`.
const TOKEN_LABEL_ENV: &str = "SOFTHSM_TEST_LABEL";

/// Names the fixture certificate on that token; matched against
/// `CKA_LABEL`.
const CERT_LABEL_ENV: &str = "TESSERA_PKCS11_CERT_LABEL";

/// The token's user PIN.  Shared with the softhsm suites, which is
/// exactly why the token label above is mandatory: the same variable may
/// well be left over from a softhsm run.
const USER_PIN_ENV: &str = "SOFTHSM_USER_PIN";

fn fixture_required() -> bool {
    std::env::var(REQUIRE_FIXTURE_ENV).as_deref() == Ok("1")
}

/// Print the uniform skip line — or fail, when the host declared it has
/// the fixture.
///
/// # Panics
///
/// When `TESSERA_REQUIRE_PKCS11_FIXTURE=1`.
#[track_caller]
fn skip(reason: &str) {
    assert!(
        !fixture_required(),
        "{REQUIRE_FIXTURE_ENV}=1 says this host carries the mode-B fixture, but the test could \
         not run: {reason}"
    );
    eprintln!("skipped: {reason}");
}

/// Read a non-empty environment variable.
fn env_value(name: &str) -> Option<String> {
    let raw = std::env::var(name).ok()?;
    if raw.is_empty() {
        None
    } else {
        Some(raw)
    }
}

fn module_path() -> PathBuf {
    test_helpers::pkcs11_test_module_path().expect("checked before use")
}

/// The whole point of the mode-B policy, asserted against a real token.
///
/// Under [`ExtractableKeyPolicy::default`] — both opt-ins off — a
/// successful lookup is not merely "a key was found".  It is a statement
/// that the provider answered `CKA_EXTRACTABLE = FALSE`: a `Yes` and an
/// unreported attribute each abort the lookup on that policy.  So an `Ok`
/// carrying anything but [`ExtractableState::No`] means the gate no longer
/// gates, and this test has to say so loudly rather than be satisfied that
/// the lookup returned something.
///
/// Skips only where the host cannot pose the question: no provider, no
/// PIN, no token named, no certificate named, no such token, no such
/// certificate, or a certificate with no private key beside it.  A
/// rejected PIN, a locked token, and above all a key the extractable
/// policy refuses are failures — the last one is the defect itself.
#[test]
fn live_private_key_found_under_default_policy_is_proven_non_extractable() {
    // Everything the host has to supply is checked before the provider is
    // even loaded: each of these is a question about configuration, and
    // none of them is worth a single call to the token to answer.
    if test_helpers::pkcs11_test_module_path().is_none() {
        skip("PKCS11_MODULE_PATH not set or path missing");
        return;
    }
    let Some(pin) = env_value(USER_PIN_ENV).map(SecretString::from) else {
        skip(&format!(
            "{USER_PIN_ENV} not set — this test needs the token's user PIN and will not guess \
             one, because a wrong guess spends an attempt from a hardware-backed counter and \
             enough of them lock the token"
        ));
        return;
    };
    let Some(token_label) = env_value(TOKEN_LABEL_ENV) else {
        skip(&format!(
            "{TOKEN_LABEL_ENV} not set — this test will not pick a token for you: the PIN in \
             {USER_PIN_ENV} belongs to one specific token, and presenting it to whichever token \
             the provider happens to enumerate first spends an attempt from a hardware-backed \
             counter"
        ));
        return;
    };
    let Some(cert_label) = env_value(CERT_LABEL_ENV) else {
        skip(&format!(
            "{CERT_LABEL_ENV} not set — this test will not pick a certificate for you: an \
             unrelated certificate on the token would send the lookup to an unrelated key and \
             the verdict would be about that one"
        ));
        return;
    };

    let backend = Pkcs11Backend::load(&module_path(), LockingMode::Mutex).expect("load module");
    let slot = match backend.find_slot(Some(&token_label)) {
        Ok(slot) => slot,
        Err(Pkcs11Error::NoTokenAvailable | Pkcs11Error::TokenNotFound { .. }) => {
            skip(&format!("no token labelled {token_label:?} is present"));
            return;
        }
        Err(other) => panic!("unexpected find_slot error: {other:?}"),
    };

    // A rejected PIN is not a skip: the counter is hardware-backed, so a
    // run that quietly tolerates a refusal is a run that quietly walks
    // towards a lockout.
    let session = Pkcs11Session::open(&backend, slot, &pin)
        .unwrap_or_else(|e| panic!("the token must accept {USER_PIN_ENV}: {e:?}"));

    let cert = match session.find_certificate(Some(&cert_label)) {
        Ok(cert) => cert,
        Err(Pkcs11Error::CertificateNotFound { .. }) => {
            skip(&format!(
                "no X.509 certificate object labelled {cert_label:?} on this token — the test \
                 needs one paired with a private key by CKA_ID (see the fixture recipe at the \
                 top of this file)"
            ));
            return;
        }
        Err(other) => panic!("unexpected find_certificate error: {other:?}"),
    };

    // If the default ever stopped being the fail-closed one, the final
    // assertion would not notice: `extractable` reports what the token
    // said, and this fixture's token says FALSE, so the lookup would
    // return `Ok(No)` under an accepting policy just as it does under a
    // refusing one.  The policy decides whether to refuse, not what the
    // state is — which makes this the only check here that sees a flipped
    // default at all.
    let policy = ExtractableKeyPolicy::default();
    assert_eq!(
        policy,
        ExtractableKeyPolicy {
            allow_extractable: false,
            allow_unreported: false,
        },
        "the default policy must refuse both an extractable key and an unreported attribute"
    );

    let key = match session.find_private_key_for_cert(&cert, policy) {
        Ok(key) => key,
        // A fixture whose cert and key do not share a `CKA_ID` is a
        // broken fixture, not a broken policy: nothing was judged, so
        // there is no verdict to trust or distrust.
        Err(Pkcs11Error::PrivateKeyNotFound { .. }) => {
            skip(&format!(
                "the certificate labelled {cert_label:?} has no private key sharing its CKA_ID \
                 — the fixture recipe at the top of this file pairs them on id 01"
            ));
            return;
        }
        // Everything else, and the two extractable refusals above all,
        // is the failure this file exists to report.
        Err(other) => panic!("private-key lookup failed under the default policy: {other:?}"),
    };
    eprintln!(
        "live token: cka_id_len={} key_type={} extractable={}",
        cert.cka_id.len(),
        key.key_type,
        key.extractable
    );

    assert_eq!(
        key.extractable,
        ExtractableState::No,
        "under the fail-closed default an Ok can only mean the token answered \
         CKA_EXTRACTABLE = FALSE; {} reaching a caller means the policy gate is broken and a \
         key that may leave the token would be used for mode-B authentication",
        key.extractable
    );
}
