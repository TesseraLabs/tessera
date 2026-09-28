//! Persistent software-owned P-256 key pairs. No server key delivery or trust activation.
use super::owned_fs as disk;
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    hash::MessageDigest,
    nid::Nid,
    pkcs12::Pkcs12,
    pkey::{PKey, Private},
    sign::Signer,
    x509::{X509NameBuilder, X509Req, X509},
};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const KEY_CAP: usize = 16 * 1024;
/// Maximum generic proof message accepted by the local Codes signing primitive.
pub const MAX_PROOF_BYTES: usize = 64 * 1024;

/// Locally retained keys. Private material and containers have no public accessor.
/// File permissions provide software custody; this is not hardware protection.
pub struct LocalEnrollmentKeys {
    root: PathBuf,
    codes: PKey<Private>,
    tls: PKey<Private>,
    csr: Vec<u8>,
}
impl std::fmt::Debug for LocalEnrollmentKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalEnrollmentKeys(<private>)")
    }
}

impl LocalEnrollmentKeys {
    /// Create both keys once. The fresh parent reservation refuses concurrent,
    /// existing or partial stores. Both canonical key files become visible in
    /// one directory rename; a crash never licenses regeneration on retry.
    /// # Errors
    /// Refuses existing/unsafe paths, unsupported crypto or durable I/O failure.
    pub fn create_new(root: &Path) -> io::Result<Self> {
        disk::make_directory(root)?;
        let pending = root.join("preparing");
        disk::make_directory(&pending)?;
        let codes = generate()?;
        let tls = generate()?;
        if codes.public_eq(&tls) {
            return Err(disk::invalid("generated keys are equal"));
        }
        disk::write_new(&pending.join("codes.p12"), &container(&codes)?, 0o600)?;
        disk::write_new(&pending.join("tls.p12"), &container(&tls)?, 0o600)?;
        disk::write_new(&pending.join("tls.csr.der"), &make_csr(&tls)?, 0o644)?;
        disk::sync_directory(&pending)?;
        // root was created exclusively above and is owner-only; no other
        // create_new can enter this publication, and load never mutates it.
        fs::rename(&pending, root.join("keys"))?;
        disk::sync_directory(root)?;
        Self::load(root)
    }

    /// Reopen the exact existing pair; never repairs or generates missing keys.
    /// # Errors
    /// Refuses partial stores, symlinks, permissions, non-P256 or equal keys.
    pub fn load(root: &Path) -> io::Result<Self> {
        disk::private_directory(root)?;
        let dir = root.join("keys");
        disk::private_directory(&dir)?;
        let codes = load_key(&dir.join("codes.p12"))?;
        let tls = load_key(&dir.join("tls.p12"))?;
        if codes.public_eq(&tls) {
            return Err(disk::invalid("Codes and TLS keys must differ"));
        }
        let csr = disk::read(&dir.join("tls.csr.der"), KEY_CAP, false)?;
        let request = X509Req::from_der(&csr).map_err(crypto)?;
        let public = request.public_key().map_err(crypto)?;
        if request.to_der().map_err(crypto)? != csr
            || !public.public_eq(&tls)
            || !request.verify(&public).map_err(crypto)?
        {
            return Err(disk::invalid(
                "persisted CSR differs from the local TLS key",
            ));
        }
        Ok(Self {
            root: root.to_owned(),
            codes,
            tls,
            csr,
        })
    }

    /// Canonical uncompressed P-256 Codes point for a separately defined protocol.
    /// # Errors
    /// Propagates an OpenSSL public-key encoding failure.
    pub fn codes_public_key(&self) -> io::Result<Vec<u8>> {
        point(&self.codes)
    }
    /// Canonical SPKI for the local TLS key.
    /// # Errors
    /// Propagates an OpenSSL public-key encoding failure.
    pub fn tls_spki(&self) -> io::Result<Vec<u8>> {
        self.tls.public_key_to_der().map_err(crypto)
    }
    /// Empty-subject, extension-free P-256/SHA256 CSR with proof of possession.
    /// # Errors
    /// Propagates a CSR encoding/signature failure.
    pub fn tls_csr(&self) -> io::Result<Vec<u8>> {
        self.recheck()?;
        Ok(self.csr.clone())
    }
    /// Sign bounded protocol bytes with the persistent Codes key (DER ECDSA).
    /// The caller supplies its own canonical, domain-separated protocol message.
    /// # Errors
    /// Refuses empty/oversized messages, changed local keys or crypto failures.
    pub fn sign_codes(&self, message: &[u8]) -> io::Result<Vec<u8>> {
        if message.is_empty() || message.len() > MAX_PROOF_BYTES {
            return Err(disk::invalid("proof message bound"));
        }
        self.recheck()?;
        let mut signer = Signer::new(MessageDigest::sha256(), &self.codes).map_err(crypto)?;
        signer.update(message).map_err(crypto)?;
        signer.sign_to_vec().map_err(crypto)
    }
    /// Compare the actual Codes curve point to a public reference. This is a
    /// key match, not proof that any enclosing server document is authenticated.
    /// # Errors
    /// Refuses malformed or different P-256 public points.
    pub fn require_codes_public_key(&self, sec1: &[u8]) -> io::Result<()> {
        if sec1.len() != 33 && sec1.len() != 65 {
            return Err(disk::invalid("P-256 point width"));
        }
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(crypto)?;
        let mut context = BigNumContext::new().map_err(crypto)?;
        let p = openssl::ec::EcPoint::from_bytes(&group, sec1, &mut context).map_err(crypto)?;
        let key = PKey::from_ec_key(EcKey::from_public_key(&group, &p).map_err(crypto)?)
            .map_err(crypto)?;
        if !self.codes.public_eq(&key) {
            return Err(disk::invalid("Codes key differs"));
        }
        Ok(())
    }
    /// Check only the returned leaf's public-key binding. Chain trust, purpose,
    /// identity, validity and issuer eligibility belong to the protocol adapter.
    /// # Errors
    /// Refuses oversized/non-DER certificates or a different key.
    pub fn require_tls_leaf_key(&self, der: &[u8]) -> io::Result<()> {
        if der.is_empty() || der.len() > 64 * 1024 {
            return Err(disk::invalid("leaf size bound"));
        }
        let leaf = X509::from_der(der).map_err(crypto)?;
        let public = leaf.public_key().map_err(crypto)?;
        if leaf.to_der().map_err(crypto)? != der || !self.tls.public_eq(&public) {
            return Err(disk::invalid("TLS leaf key or DER differs"));
        }
        Ok(())
    }
    pub(super) fn recheck(&self) -> io::Result<()> {
        let current = Self::load(&self.root)?;
        if !current.codes.public_eq(&self.codes) || !current.tls.public_eq(&self.tls) {
            return Err(disk::invalid("local key pair changed"));
        }
        Ok(())
    }
    pub(super) fn root(&self) -> &Path {
        &self.root
    }
    pub(super) fn codes_key(&self) -> &PKey<Private> {
        &self.codes
    }
}
fn make_csr(key: &PKey<Private>) -> io::Result<Vec<u8>> {
    let mut request = X509Req::builder().map_err(crypto)?;
    request.set_version(0).map_err(crypto)?;
    request
        .set_subject_name(&X509NameBuilder::new().map_err(crypto)?.build())
        .map_err(crypto)?;
    request.set_pubkey(key).map_err(crypto)?;
    request.sign(key, MessageDigest::sha256()).map_err(crypto)?;
    request.build().to_der().map_err(crypto)
}

fn crypto(_: openssl::error::ErrorStack) -> io::Error {
    disk::invalid("local key cryptography failed")
}
fn generate() -> io::Result<PKey<Private>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(crypto)?;
    PKey::from_ec_key(EcKey::generate(&group).map_err(crypto)?).map_err(crypto)
}
fn load_key(path: &Path) -> io::Result<PKey<Private>> {
    let bytes = Zeroizing::new(disk::read(path, KEY_CAP, true)?);
    let parsed = Pkcs12::from_der(&bytes)
        .and_then(|p| p.parse2(""))
        .map_err(crypto)?;
    if parsed.cert.is_some() || parsed.ca.as_ref().is_some_and(|c| !c.is_empty()) {
        return Err(disk::invalid(
            "local key store must not contain certificates",
        ));
    }
    crate::pkcs12::local_private_key(&bytes, None)
        .map_err(|_| disk::invalid("local P-256 key container invalid"))
}
fn container(key: &PKey<Private>) -> io::Result<Zeroizing<Vec<u8>>> {
    let bytes = Pkcs12::builder()
        .pkey(key)
        .build2("")
        .and_then(|p| p.to_der())
        .map_err(crypto)?;
    if bytes.len() > KEY_CAP {
        return Err(disk::invalid("key container bound"));
    }
    Ok(Zeroizing::new(bytes))
}
fn point(key: &PKey<Private>) -> io::Result<Vec<u8>> {
    let ec = key.ec_key().map_err(crypto)?;
    let mut context = BigNumContext::new().map_err(crypto)?;
    ec.public_key()
        .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut context)
        .map_err(crypto)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]
    use super::*;
    use openssl::sign::Verifier;

    fn fixture() -> tempfile::TempDir {
        tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap()
    }
    #[test]
    fn key_only_openssl_round_trip_retains_two_local_keys_and_proofs() {
        let temp = fixture();
        let root = temp.path().join("owned");
        let keys = LocalEnrollmentKeys::create_new(&root).unwrap();
        let first = keys.codes_public_key().unwrap();
        let csr = keys.tls_csr().unwrap();
        let parsed = X509Req::from_der(&csr).unwrap();
        let public = parsed.public_key().unwrap();
        assert!(parsed.verify(&public).unwrap());
        assert_eq!(parsed.subject_name().entries().count(), 0);
        assert!(!keys.codes.public_eq(&keys.tls));
        let reloaded = LocalEnrollmentKeys::load(&root).unwrap();
        assert_eq!(reloaded.codes_public_key().unwrap(), first);
        assert_eq!(reloaded.tls_spki().unwrap(), keys.tls_spki().unwrap());
        assert_eq!(reloaded.tls_csr().unwrap(), csr);
        let proof = reloaded.sign_codes(b"fixture-domain/possession").unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &keys.codes).unwrap();
        verifier.update(b"fixture-domain/possession").unwrap();
        assert!(verifier.verify(&proof).unwrap());
        let bytes = disk::read(&root.join("keys/codes.p12"), KEY_CAP, true).unwrap();
        let material = Pkcs12::from_der(&bytes).unwrap().parse2("").unwrap();
        assert!(material.cert.is_none());
        assert!(material.ca.is_none());
        let loaded =
            crate::codes::store::load_device_key(&root.join("keys/codes.p12"), None).unwrap();
        assert!(loaded.public_eq(&keys.codes));
        assert!(LocalEnrollmentKeys::create_new(&root).is_err());
        assert_eq!(
            disk::read(&root.join("keys/codes.p12"), KEY_CAP, true).unwrap(),
            bytes
        );
        assert!(keys.sign_codes(&[]).is_err());
        assert!(keys.sign_codes(&vec![0; MAX_PROOF_BYTES + 1]).is_err());
        assert!(keys
            .require_codes_public_key(&point(&keys.tls).unwrap())
            .is_err());
    }
    #[test]
    fn partial_and_insecure_stores_refuse_without_regeneration() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let temp = fixture();
        let partial = temp.path().join("partial");
        disk::make_directory(&partial).unwrap();
        assert!(LocalEnrollmentKeys::load(&partial).is_err());
        assert!(LocalEnrollmentKeys::create_new(&partial).is_err());
        let root = temp.path().join("owned");
        let keys = LocalEnrollmentKeys::create_new(&root).unwrap();
        let key = root.join("keys/tls.p12");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(LocalEnrollmentKeys::load(&root).is_err());
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&key).unwrap();
        symlink(root.join("keys/codes.p12"), &key).unwrap();
        assert!(keys.sign_codes(b"changed").is_err());
        assert!(LocalEnrollmentKeys::load(&root).is_err());
    }
    #[test]
    fn legacy_certificate_container_still_uses_full_parser_and_mac_is_required() {
        use der::{Decode as _, Encode as _};
        use openssl::asn1::{Asn1Integer, Asn1Time};
        use openssl::bn::BigNum;
        use secrecy::SecretString;
        let key = generate().unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "fixture").unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        let serial = Asn1Integer::from_bn(&BigNum::from_u32(1).unwrap()).unwrap();
        cert.set_serial_number(&serial).unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.sign(&key, MessageDigest::sha256()).unwrap();
        let cert = cert.build();
        let bytes = Pkcs12::builder()
            .pkey(&key)
            .cert(&cert)
            .build2("")
            .unwrap()
            .to_der()
            .unwrap();
        let legacy = crate::pkcs12::LoadedKeyMaterial::from_p12(
            &bytes,
            &SecretString::from(String::new()),
            None,
        )
        .unwrap();
        assert!(crate::pkcs12::local_private_key(&bytes, None)
            .unwrap()
            .public_eq(&legacy.private_key().unwrap()));
        let protected = Pkcs12::builder()
            .pkey(&key)
            .build2("fixture-pin")
            .unwrap()
            .to_der()
            .unwrap();
        assert!(crate::pkcs12::local_private_key(&protected, None).is_err());
        let wrong = Pkcs12::builder()
            .pkey(&PKey::generate_ed25519().unwrap())
            .build2("")
            .unwrap()
            .to_der()
            .unwrap();
        assert!(crate::pkcs12::local_private_key(&wrong, None).is_err());
        assert!(crate::pkcs12::local_private_key(b"invalid", None).is_err());
        let valid = container(&key).unwrap();
        let mut trailing = valid.to_vec();
        trailing.push(0);
        assert!(crate::pkcs12::local_private_key(&trailing, None).is_err());
        let mut envelope = ::pkcs12::pfx::Pfx::from_der(&valid).unwrap();
        envelope.mac_data = None;
        assert!(crate::pkcs12::local_private_key(&envelope.to_der().unwrap(), None).is_err());
    }
    #[test]
    fn concurrent_creation_publishes_only_one_complete_pair() {
        let temp = fixture();
        let root = temp.path().join("concurrent");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let root = root.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    LocalEnrollmentKeys::create_new(&root)
                        .map(|keys| keys.codes_public_key().unwrap())
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        let winner = results.into_iter().find_map(Result::ok).unwrap();
        assert_eq!(
            LocalEnrollmentKeys::load(&root)
                .unwrap()
                .codes_public_key()
                .unwrap(),
            winner
        );
        assert!(root.join("keys/tls.p12").is_file());
        assert!(root.join("keys/tls.csr.der").is_file());
    }
}
