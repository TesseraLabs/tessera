//! Native unit tests for the binding logic.
//!
//! The logic is pure `&str` → `Result<String, String>`, so it runs on the host
//! with no `wasm-bindgen-test` harness. Fixtures are built with the core's
//! `test-support` scaffolding (a self-signed root, a mock signer) and a genuine
//! P-256 CSR, and every assertion inspects the JSON the binding returns.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use base64::Engine as _;
use der::Encode as _;
use serde_json::{json, Value};

use tessera_ext::delegation::DelegationConstraints;
use tessera_ext::der::{
    encode_oid, encode_tlv, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE,
};
use tessera_ext::ext::{encode_max_integrity, encode_profile_version, encode_seq_of_utf8};
use tessera_ext::oids::{
    ALLOWED_ROLES_OID, HOST_BINDING_OID, MAX_INTEGRITY_OID, PROFILE_VERSION_OID, USER_BINDING_OID,
};

use tessera_issuer::sign::{KeyId, MockSigner, SignatureAlgorithm, SignatureBackend};
use tessera_issuer::test_support::{self_signed_ca, spki_fixture, MemoryStorage};
use tessera_issuer::{
    assemble_signed_certificate, issue_ca, issue_leaf, CaRequest, IntegrityCeiling, Journal,
    LeafRequest, Serial, Validity,
};

use super::*;

const TS: u64 = 1_600_000_000;
const NOT_AFTER: u64 = 1_600_003_600;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn key() -> KeyId {
    KeyId::new("cabinet")
}

fn signer() -> MockSigner {
    MockSigner::ecdsa_sha256(key())
}

fn serial() -> Serial {
    Serial::from_entropy(&[0x11; 16])
}

fn journal() -> Journal<MemoryStorage> {
    Journal::load(MemoryStorage::new()).unwrap()
}

/// A self-signed fleet root (issuer == subject) allowing `oper`/`serv`.
fn root_cert() -> Vec<u8> {
    let req = CaRequest {
        subject: "CN=Tessera Root".to_owned(),
        subject_spki_der: spki_fixture(),
        validity: Validity {
            not_before: TS,
            not_after: 1_900_000_000,
        },
        constraints: DelegationConstraints {
            require_tags: vec![],
            allow_roles: vec!["oper".to_owned(), "serv".to_owned()],
            max_level: 5,
            max_ttl: 86_400,
        },
        profile_version: 1,
    };
    self_signed_ca(&signer(), &key(), &req, &serial(), &mut journal(), TS)
        .unwrap()
        .der
}

/// An organisation CA issued under the root, narrowed to `oper` only.
fn org_ca_cert(root: &[u8]) -> Vec<u8> {
    let req = CaRequest {
        subject: "CN=Org CA".to_owned(),
        subject_spki_der: spki_fixture(),
        validity: Validity {
            not_before: TS,
            not_after: 1_800_000_000,
        },
        constraints: DelegationConstraints {
            require_tags: vec![],
            allow_roles: vec!["oper".to_owned()],
            max_level: 5,
            max_ttl: 3600,
        },
        profile_version: 1,
    };
    issue_ca(&signer(), &key(), root, &req, &serial(), &mut journal(), TS)
        .unwrap()
        .der
}

/// A shift-leaf issued under the org CA (a non-CA certificate).
fn leaf_cert(org_ca: &[u8]) -> Vec<u8> {
    let req = LeafRequest {
        subject: "CN=ivanov".to_owned(),
        subject_spki_der: spki_fixture(),
        validity: Validity {
            not_before: TS,
            not_after: NOT_AFTER,
        },
        host_binding: vec!["*".to_owned()],
        user_binding: vec!["ivanov".to_owned()],
        allowed_roles: vec!["oper".to_owned()],
        max_integrity: Some(IntegrityCeiling {
            level: 5,
            categories: 0,
        }),
        profile_version: 1,
    };
    issue_leaf(
        &signer(),
        &key(),
        org_ca,
        &req,
        &serial(),
        &mut journal(),
        TS,
    )
    .unwrap()
    .der
}

/// A genuine, self-signed P-256 CSR (valid proof of possession) carrying the
/// given `attributes [0]` block verbatim.
fn build_p256_csr(subject: &str, seed: [u8; 32], attributes_ctx0: &[u8]) -> Vec<u8> {
    use core::str::FromStr as _;

    use p256::ecdsa::signature::Signer as _;
    use p256::pkcs8::EncodePublicKey as _;

    let signing_key = p256::ecdsa::SigningKey::from_slice(&seed).unwrap();
    let spki_der = signing_key
        .verifying_key()
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec();
    let subject_der = x509_cert::name::Name::from_str(subject)
        .unwrap()
        .to_der()
        .unwrap();

    let mut info = Vec::new();
    info.extend_from_slice(&encode_tlv(TAG_INTEGER, &[0x00]));
    info.extend_from_slice(&subject_der);
    info.extend_from_slice(&spki_der);
    info.extend_from_slice(attributes_ctx0);
    let info_der = encode_tlv(TAG_SEQUENCE, &info);

    let signature: p256::ecdsa::Signature = signing_key.sign(&info_der);
    assemble_signed_certificate(
        &info_der,
        SignatureAlgorithm::EcdsaWithSha256,
        signature.to_der().as_bytes(),
    )
    .unwrap()
}

/// A CSR with an empty `attributes [0]`.
fn valid_p256_csr(subject: &str, seed: [u8; 32]) -> Vec<u8> {
    build_p256_csr(subject, seed, &encode_tlv(0xA0, &[]))
}

/// Build a CSR `attributes [0]` block carrying one PKCS#9 `extensionRequest`
/// attribute with the given `(oid, extnValue)` extensions (all non-critical).
fn extension_request_attrs(extensions: &[(&str, Vec<u8>)]) -> Vec<u8> {
    const EXTENSION_REQUEST_OID: &str = "1.2.840.113549.1.9.14";
    const TAG_SET: u8 = 0x31;

    let mut ext_seq_body = Vec::new();
    for (oid, value) in extensions {
        let mut fields = encode_tlv(TAG_OID, &encode_oid(oid).unwrap());
        fields.extend_from_slice(&encode_tlv(TAG_OCTET_STRING, value));
        ext_seq_body.extend_from_slice(&encode_tlv(TAG_SEQUENCE, &fields));
    }
    let ext_request = encode_tlv(TAG_SEQUENCE, &ext_seq_body);
    let values_set = encode_tlv(TAG_SET, &ext_request);
    let mut attribute = encode_tlv(TAG_OID, &encode_oid(EXTENSION_REQUEST_OID).unwrap());
    attribute.extend_from_slice(&values_set);
    encode_tlv(0xA0, &encode_tlv(TAG_SEQUENCE, &attribute))
}

/// Parse a binding's `Ok` JSON, panicking with the error JSON on `Err`.
fn ok(result: Result<String, String>) -> Value {
    match result {
        Ok(json) => serde_json::from_str(&json).unwrap(),
        Err(err) => panic!("expected Ok, got error: {err}"),
    }
}

/// Parse a binding's `Err` JSON, panicking on an unexpected `Ok`.
fn err(result: Result<String, String>) -> Value {
    match result {
        Ok(json) => panic!("expected an error, got Ok: {json}"),
        Err(json) => serde_json::from_str(&json).unwrap(),
    }
}

fn entropy_b64() -> String {
    b64(&[0x11; 16])
}

// --- inspect_parent ---------------------------------------------------------

#[test]
fn inspect_parent_classifies_root_org_ca_and_leaf() {
    let root = root_cert();
    let org = org_ca_cert(&root);
    let leaf = leaf_cert(&org);

    let root_out = ok(inspect_parent(
        &json!({ "cert_b64": b64(&root) }).to_string(),
    ));
    assert_eq!(root_out["kind"], "root");
    assert!(root_out["subject"]
        .as_str()
        .unwrap()
        .contains("Tessera Root"));
    assert_eq!(root_out["envelope"]["allow_roles"][0], "oper");

    let org_out = ok(inspect_parent(
        &json!({ "cert_b64": b64(&org) }).to_string(),
    ));
    assert_eq!(org_out["kind"], "org_ca");
    assert_eq!(org_out["envelope"]["max_ttl"], 3600);

    let leaf_out = ok(inspect_parent(
        &json!({ "cert_b64": b64(&leaf) }).to_string(),
    ));
    assert_eq!(leaf_out["kind"], "leaf");
    assert!(leaf_out["envelope"].is_null());
}

#[test]
fn inspect_parent_reports_unusable_garbage() {
    let out = ok(inspect_parent(
        &json!({ "cert_b64": b64(b"not a cert") }).to_string(),
    ));
    assert_eq!(out["kind"], "unusable");
    assert!(out["reason"].is_string());
}

// --- build_leaf_tbs ---------------------------------------------------------

fn leaf_request_value() -> Value {
    json!({
        "subject": "CN=ivanov,O=Org",
        "spki_b64": b64(&spki_fixture()),
        "validity": { "not_before": TS, "not_after": NOT_AFTER },
        "host_binding": ["*"],
        "user_binding": ["ivanov"],
        "allowed_roles": ["oper"],
        "profile_version": 1
    })
}

#[test]
fn build_leaf_tbs_happy_path_returns_tbs_and_summary() {
    let root = root_cert();
    let org = org_ca_cert(&root);
    let input = json!({
        "parent_b64": b64(&org),
        "algorithm": "ecdsa-p256",
        "serial_entropy_b64": entropy_b64(),
        "locale": "en",
        "request": leaf_request_value(),
    });
    let out = ok(build_leaf_tbs(&input.to_string()));
    assert!(!out["tbs_b64"].as_str().unwrap().is_empty());
    assert_eq!(out["summary"]["kind"], "shift_leaf");
    assert!(out["summary"]["subject"]
        .as_str()
        .unwrap()
        .contains("ivanov"));
    assert!(out["summary"]["rendered"]
        .as_str()
        .unwrap()
        .contains("oper"));
}

#[test]
fn build_leaf_tbs_russian_locale_translates_captions() {
    let root = root_cert();
    let org = org_ca_cert(&root);
    let input = json!({
        "parent_b64": b64(&org),
        "algorithm": "ecdsa-p256",
        "serial_entropy_b64": entropy_b64(),
        "locale": "ru",
        "request": leaf_request_value(),
    });
    let out = ok(build_leaf_tbs(&input.to_string()));
    let rendered = out["summary"]["rendered"].as_str().unwrap();
    assert!(rendered.contains("сертификат смены"), "{rendered}");
    // The value is technical and unchanged across locales.
    assert!(rendered.contains("ivanov"), "{rendered}");
}

#[test]
fn build_leaf_tbs_widened_role_names_the_dimension() {
    let root = root_cert();
    let org = org_ca_cert(&root); // allows only `oper`
    let mut request = leaf_request_value();
    request["allowed_roles"] = json!(["serv"]); // in the root, not the org CA
    let input = json!({
        "parent_b64": b64(&org),
        "algorithm": "ecdsa-p256",
        "serial_entropy_b64": entropy_b64(),
        "request": request,
    });
    let out = err(build_leaf_tbs(&input.to_string()));
    assert_eq!(out["dimension"], "allow_roles");
    assert!(out["error"].is_string());
}

#[test]
fn build_leaf_tbs_requires_exactly_one_key_source() {
    let root = root_cert();
    let org = org_ca_cert(&root);
    let mut none = leaf_request_value();
    none["spki_b64"] = Value::Null;
    let input = json!({
        "parent_b64": b64(&org),
        "algorithm": "ecdsa-p256",
        "serial_entropy_b64": entropy_b64(),
        "request": none,
    });
    let out = err(build_leaf_tbs(&input.to_string()));
    assert!(out["error"]
        .as_str()
        .unwrap()
        .contains("spki_b64 or csr_b64"));
}

#[test]
fn build_leaf_tbs_rejects_short_serial_entropy() {
    let root = root_cert();
    let org = org_ca_cert(&root);
    // 15 bytes: one below the 16-byte floor, so the serial would be short and
    // guessable — the builder must refuse before assembling the TBS.
    let input = json!({
        "parent_b64": b64(&org),
        "algorithm": "ecdsa-p256",
        "serial_entropy_b64": b64(&[0x11; 15]),
        "request": leaf_request_value(),
    });
    let out = err(build_leaf_tbs(&input.to_string()));
    assert!(
        out["error"]
            .as_str()
            .unwrap()
            .contains("serial_entropy_b64"),
        "{out}"
    );
}

#[test]
fn build_ca_tbs_rejects_short_serial_entropy() {
    let root = root_cert();
    let input = json!({
        "parent_b64": b64(&root),
        "algorithm": "ecdsa-p256",
        "serial_entropy_b64": b64(&[0x11; 15]),
        "request": json!({
            "subject": "CN=Org CA,O=Org",
            "spki_b64": b64(&spki_fixture()),
            "validity": { "not_before": TS, "not_after": NOT_AFTER },
            "constraints": {
                "require_tags": [],
                "allow_roles": ["oper"],
                "max_level": 4,
                "max_ttl": 3_600
            },
            "profile_version": 1
        }),
    });
    let out = err(build_ca_tbs(&input.to_string()));
    assert!(
        out["error"]
            .as_str()
            .unwrap()
            .contains("serial_entropy_b64"),
        "{out}"
    );
}

#[test]
fn build_leaf_tbs_from_valid_csr_succeeds() {
    let root = root_cert();
    let org = org_ca_cert(&root);
    let csr = valid_p256_csr("CN=ivanov,O=Org", [0x22; 32]);
    let request = json!({
        "csr_b64": b64(&csr),
        "validity": { "not_before": TS, "not_after": NOT_AFTER },
        "host_binding": ["*"],
        "user_binding": ["ivanov"],
        "allowed_roles": ["oper"],
        "profile_version": 1
    });
    let input = json!({
        "parent_b64": b64(&org),
        "algorithm": "ecdsa-p256",
        "serial_entropy_b64": entropy_b64(),
        "request": request,
    });
    let out = ok(build_leaf_tbs(&input.to_string()));
    assert_eq!(out["summary"]["kind"], "shift_leaf");
}

#[test]
fn build_leaf_tbs_from_broken_csr_fails_before_signing() {
    let root = root_cert();
    let org = org_ca_cert(&root);
    let request = json!({
        "csr_b64": b64(b"not a CSR"),
        "validity": { "not_before": TS, "not_after": NOT_AFTER },
        "host_binding": ["*"],
        "user_binding": ["ivanov"],
        "allowed_roles": ["oper"],
        "profile_version": 1
    });
    let input = json!({
        "parent_b64": b64(&org),
        "algorithm": "ecdsa-p256",
        "serial_entropy_b64": entropy_b64(),
        "request": request,
    });
    assert!(err(build_leaf_tbs(&input.to_string()))["error"].is_string());
}

// --- build_ca_tbs -----------------------------------------------------------

#[test]
fn build_ca_tbs_happy_path_and_widening() {
    let root = root_cert();
    let ca_request = |roles: Value| {
        json!({
            "parent_b64": b64(&root),
            "algorithm": "ecdsa-p256",
            "serial_entropy_b64": entropy_b64(),
            "request": {
                "subject": "CN=Org CA 2",
                "spki_b64": b64(&spki_fixture()),
                "validity": { "not_before": TS, "not_after": 1_800_000_000u64 },
                "constraints": {
                    "require_tags": [],
                    "allow_roles": roles,
                    "max_level": 5,
                    "max_ttl": 3600
                },
                "profile_version": 1
            }
        })
    };

    let ok_out = ok(build_ca_tbs(&ca_request(json!(["oper"])).to_string()));
    assert_eq!(ok_out["summary"]["kind"], "org_ca");

    // `admin` is not in the root envelope — a widening.
    let bad = err(build_ca_tbs(&ca_request(json!(["admin"])).to_string()));
    assert_eq!(bad["dimension"], "allow_roles");
}

// --- build_crl_tbs ----------------------------------------------------------

#[test]
fn build_crl_tbs_happy_path_and_monotonicity() {
    let root = root_cert();
    let org = org_ca_cert(&root);
    let crl_input = |number: u64, last: u64| {
        json!({
            "issuer_b64": b64(&org),
            "algorithm": "ecdsa-p256",
            "request": {
                "this_update": TS,
                "next_update": 1_600_086_400u64,
                "crl_number": number,
                "revoked": [
                    { "serial_b64": b64(&[0x2a]), "revocation_date": TS, "reason": 1 }
                ]
            },
            "last_crl_number": last
        })
    };

    let out = ok(build_crl_tbs(&crl_input(7, 0).to_string()));
    assert_eq!(out["summary"]["kind"], "crl");

    let bad = err(build_crl_tbs(&crl_input(3, 5).to_string()));
    assert!(bad["error"].as_str().unwrap().contains("crlNumber"));
}

// --- inspect_csr ------------------------------------------------------------

#[test]
fn inspect_csr_reports_subject_and_valid_signature() {
    let csr = valid_p256_csr("CN=engineer,O=Org", [0x33; 32]);
    let out = ok(inspect_csr(&json!({ "csr_b64": b64(&csr) }).to_string()));
    assert_eq!(out["subject"], "CN=engineer,O=Org");
    assert_eq!(out["signature_valid"], true);
    assert!(!out["spki_b64"].as_str().unwrap().is_empty());
}

#[test]
fn inspect_csr_rejects_unparseable_input() {
    assert!(err(inspect_csr(
        &json!({ "csr_b64": b64(b"garbage") }).to_string()
    ))["error"]
        .is_string());
}

#[test]
fn inspect_csr_semantically_parses_known_tessera_extensions() {
    let attrs = extension_request_attrs(&[
        (ALLOWED_ROLES_OID, encode_seq_of_utf8(&["oper", "serv"])),
        (HOST_BINDING_OID, encode_seq_of_utf8(&["*"])),
        (USER_BINDING_OID, encode_seq_of_utf8(&["ivanov"])),
        (MAX_INTEGRITY_OID, encode_max_integrity(5, 0b101)),
        (PROFILE_VERSION_OID, encode_profile_version(2)),
    ]);
    let csr = build_p256_csr("CN=ivanov,O=Org", [0x44; 32], &attrs);
    let out = ok(inspect_csr(&json!({ "csr_b64": b64(&csr) }).to_string()));

    assert_eq!(out["signature_valid"], true);
    // Raw list carries all five, including the wide-OID Tessera extensions.
    assert_eq!(out["requested_extensions"].as_array().unwrap().len(), 5);

    let parsed = &out["requested_parsed"];
    assert_eq!(parsed["allowed_roles"], json!(["oper", "serv"]));
    assert_eq!(parsed["host_binding"], json!(["*"]));
    assert_eq!(parsed["user_binding"], json!(["ivanov"]));
    assert_eq!(parsed["max_integrity"]["level"], 5);
    assert_eq!(parsed["max_integrity"]["categories"], 5);
    assert_eq!(parsed["profile_version"], 2);
}

#[test]
fn inspect_csr_broken_known_extension_stays_in_raw_only() {
    let attrs = extension_request_attrs(&[
        // A well-framed extension whose value is not `SEQUENCE OF UTF8String`.
        (ALLOWED_ROLES_OID, b"not valid der".to_vec()),
        (PROFILE_VERSION_OID, encode_profile_version(3)),
    ]);
    let csr = build_p256_csr("CN=ivanov", [0x55; 32], &attrs);
    let out = ok(inspect_csr(&json!({ "csr_b64": b64(&csr) }).to_string()));

    // The broken extension does not crash the call and does not leak into parsed.
    assert_eq!(out["signature_valid"], true);
    assert!(out["requested_parsed"].get("allowed_roles").is_none());
    // The good sibling still parses.
    assert_eq!(out["requested_parsed"]["profile_version"], 3);
    // Both remain in the raw list.
    let raw = out["requested_extensions"].as_array().unwrap();
    assert_eq!(raw.len(), 2);
    assert!(raw.iter().any(|e| e["oid"] == ALLOWED_ROLES_OID));
}

// --- assemble_and_verify ----------------------------------------------------

/// Build a leaf TBS through the binding, then sign it with the mock signer.
fn build_and_sign_leaf(org: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let input = json!({
        "parent_b64": b64(org),
        "algorithm": "ecdsa-p256",
        "serial_entropy_b64": entropy_b64(),
        "request": leaf_request_value(),
    });
    let out = ok(build_leaf_tbs(&input.to_string()));
    let tbs = base64::engine::general_purpose::STANDARD
        .decode(out["tbs_b64"].as_str().unwrap())
        .unwrap();
    let signature = signer().sign(&tbs, &key()).unwrap();
    (tbs, signature.bytes)
}

#[test]
fn assemble_and_verify_frames_and_self_checks_a_leaf() {
    let root = root_cert();
    let org = org_ca_cert(&root);
    let (tbs, sig) = build_and_sign_leaf(&org);
    let input = json!({
        "tbs_b64": b64(&tbs),
        "signature": { "algorithm": "ecdsa-p256", "bytes_b64": b64(&sig) },
        "parent_b64": b64(&org),
    });
    let out = ok(assemble_and_verify(&input.to_string()));
    assert_eq!(out["kind"], "shift_leaf");
    assert!(out["cert_pem"]
        .as_str()
        .unwrap()
        .starts_with("-----BEGIN CERTIFICATE-----"));
}

#[test]
fn assemble_and_verify_rejects_algorithm_mismatch() {
    let root = root_cert();
    let org = org_ca_cert(&root);
    let (tbs, sig) = build_and_sign_leaf(&org);
    let input = json!({
        "tbs_b64": b64(&tbs),
        // The TBS was built for ecdsa-p256; claim ecdsa-p384 instead.
        "signature": { "algorithm": "ecdsa-p384", "bytes_b64": b64(&sig) },
        "parent_b64": b64(&org),
    });
    assert!(err(assemble_and_verify(&input.to_string()))["error"]
        .as_str()
        .unwrap()
        .contains("algorithm"));
}

#[test]
fn assemble_and_verify_frames_a_ca() {
    let root = root_cert();
    let ca_input = json!({
        "parent_b64": b64(&root),
        "algorithm": "ecdsa-p256",
        "serial_entropy_b64": entropy_b64(),
        "request": {
            "subject": "CN=Org CA 3",
            "spki_b64": b64(&spki_fixture()),
            "validity": { "not_before": TS, "not_after": 1_800_000_000u64 },
            "constraints": {
                "require_tags": [], "allow_roles": ["oper"], "max_level": 5, "max_ttl": 3600
            },
            "profile_version": 1
        }
    });
    let built = ok(build_ca_tbs(&ca_input.to_string()));
    let tbs = base64::engine::general_purpose::STANDARD
        .decode(built["tbs_b64"].as_str().unwrap())
        .unwrap();
    let sig = signer().sign(&tbs, &key()).unwrap().bytes;
    let input = json!({
        "tbs_b64": b64(&tbs),
        "signature": { "algorithm": "ecdsa-p256", "bytes_b64": b64(&sig) },
        "parent_b64": b64(&root),
    });
    let out = ok(assemble_and_verify(&input.to_string()));
    assert_eq!(out["kind"], "org_ca");
}

// --- journal ----------------------------------------------------------------

#[test]
fn journal_append_chains_and_verify_reports_intact_tail() {
    let root = root_cert();
    let org = org_ca_cert(&root);

    let first = ok(journal_append(
        &json!({
            "prev_lines": [],
            "entry": {
                "op": "issue_leaf",
                "serial_b64": b64(&[0x2a]),
                "parent_b64": b64(&org),
                "subject": "CN=ivanov"
            },
            "now_unix": TS
        })
        .to_string(),
    ));
    let line1 = first["new_line"].as_str().unwrap().to_owned();

    let second = ok(journal_append(
        &json!({
            "prev_lines": [line1.clone()],
            "entry": {
                "op": "issue_ca",
                "serial_b64": b64(&[0x2b]),
                "parent_b64": b64(&root),
                "subject": "CN=Org CA"
            },
            "now_unix": TS
        })
        .to_string(),
    ));
    let line2 = second["new_line"].as_str().unwrap().to_owned();

    let verified = ok(journal_verify(
        &json!({ "lines": [line1, line2] }).to_string(),
    ));
    assert_eq!(verified["status"], "intact_unsigned_tail");
    assert_eq!(verified["entry_count"], 2);
    assert_eq!(verified["unsigned_from_seq"], 0);
}

#[test]
fn journal_verify_flags_a_tampered_chain() {
    let root = root_cert();
    let org = org_ca_cert(&root);

    let first = ok(journal_append(
        &json!({
            "prev_lines": [],
            "entry": {
                "op": "issue_crl",
                "crl_number": 7,
                "parent_b64": b64(&org)
            },
            "now_unix": TS
        })
        .to_string(),
    ));
    let line1 = first["new_line"].as_str().unwrap().to_owned();

    let second = ok(journal_append(
        &json!({
            "prev_lines": [line1.clone()],
            "entry": {
                "op": "issue_crl",
                "crl_number": 8,
                "parent_b64": b64(&org)
            },
            "now_unix": TS
        })
        .to_string(),
    ));
    let line2 = second["new_line"].as_str().unwrap().to_owned();

    // Corrupt the first line: line 0 still chains to genesis and keeps seq 0, but
    // line 1's recorded prev_hash no longer matches the tampered line's hash — so
    // the break surfaces at position 1.
    let tampered = line1.replace("\"crl_number\":7", "\"crl_number\":9");
    let verified = ok(journal_verify(
        &json!({ "lines": [tampered, line2] }).to_string(),
    ));
    assert_eq!(verified["status"], "broken");
    assert_eq!(verified["position"], 1);
}

// --- boundary ---------------------------------------------------------------

#[test]
fn malformed_request_json_is_a_structured_error() {
    let out = err(inspect_parent("this is not json"));
    assert!(out["error"]
        .as_str()
        .unwrap()
        .contains("invalid request JSON"));
    assert!(out.get("dimension").is_none());
}
