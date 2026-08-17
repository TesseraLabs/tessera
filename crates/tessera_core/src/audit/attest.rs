//! Checking that a head signature was made by the key it claims.
//!
//! # Why the chain alone proves nothing about a whole journal
//!
//! A hash chain is not keyed. Anyone who can write the file can write a
//! different history and recompute every `prev_hash` in it — the arithmetic is
//! a few lines of any language, and the operator of the device has root. So a
//! chain that "verifies" says only that the file is internally consistent, which
//! a forgery is too.
//!
//! The one thing a forger cannot reproduce is a signature over the head made
//! with a key they do not hold. That makes the head signature the whole of the
//! evidence, and it makes checking it the whole of the verification.
//!
//! Until this module existed, nothing checked it. [`super::journal`] and
//! `tessera_hashchain` count a `head_signature` line as covering the tail
//! without looking at its bytes, which is the right division of labour — the
//! chain crate holds no keys and could not obtain one — but it means a
//! verification that stops there reports "intact, every record attested" for a
//! journal rewritten from scratch with a line of base64 nonsense at the end.
//!
//! # What is checked here
//!
//! For each `head_signature` line: the head it covers is recomputed from the
//! lines before it, and the signature is put to a [`HeadVerifier`] holding the
//! device's public attestation half. A signature that does not verify is
//! reported with its position, exactly as a broken link is.

use serde::Deserialize;
use tessera_hashchain::{sha256, ChainPayload as _, OP_HEAD_SIGNATURE};

use super::record::AuditRecord;

/// Checks a signature over a chain head against a public key.
///
/// The counterpart of [`super::HeadSigner`], and separate from it on purpose:
/// signing needs the private half and happens on the device, checking needs only
/// the public half and happens wherever the journal is read — which is normally
/// not the device, because a device that vouches for its own journal has not
/// been audited.
pub trait HeadVerifier {
    /// Whether `signature` is a valid signature over `head` by this key.
    ///
    /// A malformed signature is `false`, not an error: from the point of view of
    /// the audit there is no difference between a signature that does not check
    /// out and one that could never have.
    fn verify(&self, head: &[u8; 32], algorithm: &str, signature: &[u8]) -> bool;
}

/// What checking the attestations of a journal found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttestationStatus {
    /// The journal carries no head signature at all.
    ///
    /// Not a failure and not a pass: it is a journal nothing outside the file
    /// vouches for. On a device between attestations that is ordinary; on a
    /// journal handed in for audit it is the whole finding.
    None,
    /// Every head signature was made by the key that was offered.
    AllVerified {
        /// How many signatures were checked.
        count: u64,
    },
    /// A head signature did not verify.
    ///
    /// One is enough. A journal with a forged attestation is not "mostly
    /// attested" — the forgery is the reason to look at it.
    Failed {
        /// Zero-based position of the first signature that did not verify.
        position: u64,
        /// How many verified before it.
        verified_before: u64,
    },
    /// A line claiming to be a head signature could not be read as one.
    Malformed {
        /// Zero-based position of that line.
        position: u64,
    },
}

/// The result of checking a journal's attestations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationReport {
    /// What the check found.
    pub status: AttestationStatus,
    /// The `seq` of the last signature that verified, if any.
    pub last_verified_seq: Option<u64>,
}

/// One line, read only as far as this module needs it.
#[derive(Debug, Deserialize)]
struct SignatureLine {
    seq: u64,
    op: String,
    #[serde(default)]
    algorithm: String,
    #[serde(default)]
    signature: String,
}

/// Checks every head signature in `lines` against `verifier`.
///
/// `lines` are in append order. The head a signature covers is the hash of the
/// line before it — the value the signer was handed — so it is recomputed here
/// rather than taken from the file, and a journal whose lines were rewritten
/// gives a different head and fails.
///
/// This does **not** check the chain itself; run
/// [`tessera_hashchain::verify_lines`] for that. The two answer different
/// questions and a caller wants both: the chain says the lines were not edited
/// relative to each other, the signature says this history is the one the device
/// vouched for.
#[must_use]
pub fn verify_attestations(lines: &[String], verifier: &dyn HeadVerifier) -> AttestationReport {
    use base64::Engine as _;

    let mut expected_head = sha256(AuditRecord::GENESIS_PREIMAGE);
    let mut checked_out: u64 = 0;
    let mut last_verified_seq = None;

    for (index, line) in lines.iter().enumerate() {
        let position = index as u64;
        let parsed: Option<SignatureLine> = serde_json::from_str(line).ok();
        let is_signature = parsed
            .as_ref()
            .is_some_and(|entry| entry.op == OP_HEAD_SIGNATURE);

        if is_signature {
            // `parsed` is `Some` here: `is_signature` was derived from it.
            let Some(entry) = parsed else {
                return malformed(position, last_verified_seq);
            };
            let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&entry.signature)
            else {
                return malformed(position, last_verified_seq);
            };
            if !verifier.verify(&expected_head, &entry.algorithm, &bytes) {
                return AttestationReport {
                    status: AttestationStatus::Failed {
                        position,
                        verified_before: checked_out,
                    },
                    last_verified_seq,
                };
            }
            checked_out = checked_out.saturating_add(1);
            last_verified_seq = Some(entry.seq);
        }

        expected_head = sha256(line.as_bytes());
    }

    let status = if checked_out == 0 {
        AttestationStatus::None
    } else {
        AttestationStatus::AllVerified { count: checked_out }
    };
    AttestationReport {
        status,
        last_verified_seq,
    }
}

/// A signature line this build cannot read.
fn malformed(position: u64, last_verified_seq: Option<u64>) -> AttestationReport {
    AttestationReport {
        status: AttestationStatus::Malformed { position },
        last_verified_seq,
    }
}

/// A verifier backed by a public key in a PEM file.
#[derive(Debug)]
pub struct KeyFileVerifier {
    key: openssl::pkey::PKey<openssl::pkey::Public>,
}

impl KeyFileVerifier {
    /// Loads the device's public attestation half from `path`.
    ///
    /// # Errors
    ///
    /// A message describing why the key could not be read. A verification
    /// offered a key it cannot use is refused rather than downgraded to "not
    /// checked": the difference between the two is the whole point.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let pem = std::fs::read(path).map_err(|error| {
            format!(
                "the attestation key at {} is unreadable: {error}",
                path.display()
            )
        })?;
        // A public key file is the ordinary case; accepting a private one too
        // costs nothing and saves an operator who pointed at the wrong half.
        let key = openssl::pkey::PKey::public_key_from_pem(&pem)
            .or_else(|_| {
                openssl::pkey::PKey::private_key_from_pem(&pem).and_then(|private| {
                    openssl::pkey::PKey::public_key_from_pem(&private.public_key_to_pem()?)
                })
            })
            .map_err(|error| {
                format!(
                    "the attestation key at {} is not a PEM key: {error}",
                    path.display()
                )
            })?;
        Ok(Self { key })
    }
}

impl HeadVerifier for KeyFileVerifier {
    fn verify(&self, head: &[u8; 32], algorithm: &str, signature: &[u8]) -> bool {
        use super::signer::{ALGORITHM_ECDSA_SHA256, ALGORITHM_ED25519};
        use openssl::sign::Verifier;

        let verified = if algorithm == ALGORITHM_ED25519 {
            Verifier::new_without_digest(&self.key)
                .and_then(|mut verifier| verifier.verify_oneshot(signature, head))
        } else if algorithm == ALGORITHM_ECDSA_SHA256 {
            Verifier::new(openssl::hash::MessageDigest::sha256(), &self.key).and_then(
                |mut verifier| {
                    verifier.update(head)?;
                    verifier.verify(signature)
                },
            )
        } else {
            // An algorithm this build does not know is not "assume it is fine".
            return false;
        };
        verified.unwrap_or(false)
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
#[expect(
    clippy::indexing_slicing,
    reason = "the forgery helper indexes a JSON object it just parsed; a missing \
              field should fail the test on the spot"
)]
mod tests {
    use super::{verify_attestations, AttestationStatus, KeyFileVerifier};
    use crate::audit::{AuditJournal, AuditPolicy, AuditRecord, KeyFileSigner};

    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;

    /// Writes a P-256 pair and returns (private path, public path).
    fn key_pair(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let private = dir.join("attestation.pem");
        let public = dir.join("attestation.pub.pem");
        std::fs::write(&private, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        std::fs::write(&public, key.public_key_to_pem().unwrap()).unwrap();
        (private, public)
    }

    fn annotate(journal: &mut AuditJournal, n: u64) {
        journal
            .annotate("test.note", serde_json::json!({ "n": n }), 1_000 + n)
            .unwrap();
    }

    fn lines(path: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn a_genuine_attestation_verifies_against_the_public_half() {
        let dir = tempfile::tempdir().unwrap();
        let (private, public) = key_pair(dir.path());
        let path = dir.path().join("audit.ndjson");

        let mut journal = AuditJournal::open(AuditPolicy::new(&path)).unwrap();
        annotate(&mut journal, 1);
        journal
            .attest(&KeyFileSigner::load(&private).unwrap(), 1_100)
            .unwrap();

        let verifier = KeyFileVerifier::load(&public).unwrap();
        let report = verify_attestations(&lines(&path), &verifier);
        assert_eq!(report.status, AttestationStatus::AllVerified { count: 1 });
        assert_eq!(report.last_verified_seq, Some(1));
    }

    /// The attack the whole module exists for: an operator with root rewrites
    /// the history, recomputes every link — which is trivial, the chain is not
    /// keyed — and appends a signature line they made up. The chain verifies.
    /// Only the signature check catches it.
    #[test]
    fn a_rewritten_history_with_an_invented_signature_is_caught() {
        let dir = tempfile::tempdir().unwrap();
        let (private, public) = key_pair(dir.path());
        let path = dir.path().join("audit.ndjson");

        let mut journal = AuditJournal::open(AuditPolicy::new(&path)).unwrap();
        annotate(&mut journal, 1);
        annotate(&mut journal, 2);
        journal
            .attest(&KeyFileSigner::load(&private).unwrap(), 1_100)
            .unwrap();
        let honest = lines(&path);

        // Rewrite the first record and rebuild the chain over it, the way
        // anyone who can write the file can.
        let forged = forge(&honest);
        assert!(
            matches!(
                tessera_hashchain::verify_lines::<AuditRecord>(&forged).status,
                tessera_hashchain::ChainStatus::Intact
            ),
            "the forgery does not even look intact; the test is not testing the attack",
        );

        // …and the signature is what does not survive it.
        let verifier = KeyFileVerifier::load(&public).unwrap();
        assert!(
            matches!(
                verify_attestations(&forged, &verifier).status,
                AttestationStatus::Failed { .. }
            ),
            "a rewritten journal passed the attestation check",
        );
    }

    /// Rebuilds a chain over an edited first record, keeping the signature line
    /// byte-for-byte — exactly what a forger can do without any key.
    fn forge(honest: &[String]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut prev = tessera_hashchain::sha256(
            <AuditRecord as tessera_hashchain::ChainPayload>::GENESIS_PREIMAGE,
        );
        for (index, line) in honest.iter().enumerate() {
            let mut value: serde_json::Value = serde_json::from_str(line).unwrap();
            value["prev_hash"] = serde_json::Value::String(hex::encode(prev));
            if index == 0 {
                value["data"] = serde_json::json!({ "n": 99 });
            }
            let rebuilt = serde_json::to_string(&value).unwrap();
            prev = tessera_hashchain::sha256(rebuilt.as_bytes());
            out.push(rebuilt);
        }
        out
    }

    #[test]
    fn a_journal_with_no_attestation_says_so_rather_than_passing() {
        let dir = tempfile::tempdir().unwrap();
        let (_private, public) = key_pair(dir.path());
        let path = dir.path().join("audit.ndjson");

        let mut journal = AuditJournal::open(AuditPolicy::new(&path)).unwrap();
        annotate(&mut journal, 1);

        let verifier = KeyFileVerifier::load(&public).unwrap();
        assert_eq!(
            verify_attestations(&lines(&path), &verifier).status,
            AttestationStatus::None,
        );
    }

    #[test]
    fn an_attestation_by_a_different_key_does_not_verify() {
        let dir = tempfile::tempdir().unwrap();
        let (private, _public) = key_pair(dir.path());
        let other = tempfile::tempdir().unwrap();
        let (_other_private, other_public) = key_pair(other.path());
        let path = dir.path().join("audit.ndjson");

        let mut journal = AuditJournal::open(AuditPolicy::new(&path)).unwrap();
        annotate(&mut journal, 1);
        journal
            .attest(&KeyFileSigner::load(&private).unwrap(), 1_100)
            .unwrap();

        let verifier = KeyFileVerifier::load(&other_public).unwrap();
        assert!(matches!(
            verify_attestations(&lines(&path), &verifier).status,
            AttestationStatus::Failed { .. }
        ));
    }
}
