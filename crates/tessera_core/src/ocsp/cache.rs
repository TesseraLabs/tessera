//! On-disk OCSP response cache: DER files under `/var/cache/tessera/ocsp/`
//! (design Decision 3; revocation spec, requirement «OCSP-кэш»).
//!
//! # Layout and key
//!
//! One file per `(issuer, serial)` pair:
//! `<dir>/<hex(sha256(issuerNameHash ‖ issuerKeyHash ‖ serial))>.der`, where
//! the three concatenated values are the SHA-1 `CertID` fields — the same
//! identifier the OCSP request is built around (see [`OcspCacheKey`]).
//! Files are written atomically (tmp + rename in the same directory) with
//! mode `0640`; the directory itself (`0750 root:root`) is created by the
//! package postinst, not by this module.
//!
//! # Trust contract
//!
//! **A cache file is not a trusted input.**  [`OcspCache::get`] hands back
//! raw DER bytes after only a structural parse gate (an unparseable file is
//! a cache miss with a WARN, per the revocation spec — corruption must not
//! block logins by itself).  The *caller* performs the real re-verification
//! by feeding the bytes through
//! [`crate::ocsp::verify_ocsp_response`] with `request_der = None` (a cached
//! response is pre-signed and carries no nonce to match): responder
//! signature, `thisUpdate`/`nextUpdate` window, definite status.  This is
//! also what enforces the `min(nextUpdate, mtime + ttl)` validity bound —
//! the cache checks only the local `mtime + ttl` arm; the `nextUpdate` arm
//! falls out of re-verification, and on such a failure the caller SHOULD
//! evict the entry via [`OcspCache::remove`] before falling back to the
//! network.
//!
//! # What gets cached
//!
//! Only definite statuses.  [`OcspCache::put`] takes a
//! [`CertStatus`](super::CertStatus) — a type with no `unknown` variant
//! (the fail-closed verifier maps `unknown` to an error before any value
//! exists to cache), so an undeterminable status is unrepresentable here
//! rather than merely rejected at runtime.  `revoked` is cached: revocation
//! is irreversible within a response's validity window.

use crate::error::TrustError;
use crate::x509::Certificate;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use super::response::CertStatus;

/// Deterministic cache key for one `(subject, issuer)` pair:
/// `hex(sha256(issuerNameHash ‖ issuerKeyHash ‖ serial))` over the SHA-1
/// `CertID` fields (design Decision 3).
///
/// A newtype rather than a bare string so that only values derived from
/// certificates ever reach the filesystem layer — the hex digest is by
/// construction a safe file name (no separators, no traversal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcspCacheKey(String);

impl OcspCacheKey {
    /// Derives the cache key for `subject`, identified relative to its
    /// `issuer` — the same way [`super::OcspRequestData::build`] forms the
    /// request `CertID`, so cache entries and network lookups agree.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::OcspRequestBuild`] when the `CertID`
    /// primitives fail (same failure class as building the request the key
    /// mirrors).
    pub fn for_pair(subject: &Certificate, issuer: &Certificate) -> Result<Self, TrustError> {
        let material = super::sys::cert_id_cache_material(subject.der(), issuer.der())
            .map_err(|reason| TrustError::OcspRequestBuild {
                reason: format!("cache-key CertID: {reason}"),
            })?;
        Ok(Self(hex::encode(Sha256::digest(&material))))
    }

    /// Lowercase hex form of the key — the cache file stem.
    #[must_use]
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

/// On-disk OCSP response cache (see the module doc for the trust contract).
#[derive(Debug)]
pub struct OcspCache {
    dir: PathBuf,
    ttl: Duration,
}

impl OcspCache {
    /// Creates a cache over `dir` with local entry lifetime `ttl`
    /// (`ocsp_cache_ttl_seconds`).
    ///
    /// `ttl == 0` means the cache is disabled: [`Self::get`] always misses
    /// and [`Self::put`] is a no-op, exactly as the configuration key
    /// documents.  The directory is expected to exist (created `0750` by
    /// the package postinst); a missing directory surfaces as misses and
    /// failed puts, never as an authentication error.
    #[must_use]
    pub fn new(dir: PathBuf, ttl: Duration) -> Self {
        Self { dir, ttl }
    }

    /// Looks up the cached DER response for `key`.
    ///
    /// Returns `None` (a miss) when the cache is disabled, the entry is
    /// absent, its `mtime + ttl` lifetime has lapsed, the file cannot be
    /// read, or its contents do not even parse as an `OCSPResponse`
    /// (corrupted entry → WARN + miss).  A `Some` carries **unverified**
    /// bytes: the caller must re-verify them (module doc) and evict via
    /// [`Self::remove`] when re-verification fails.
    #[must_use]
    pub fn get(&self, key: &OcspCacheKey) -> Option<Vec<u8>> {
        if self.ttl.is_zero() {
            return None;
        }
        let path = self.entry_path(key);
        let mtime = fs::metadata(&path).ok()?.modified().ok()?;
        let age = SystemTime::now()
            .duration_since(mtime)
            .unwrap_or(Duration::ZERO);
        if age > self.ttl {
            return None;
        }
        let der = match fs::read(&path) {
            Ok(der) => der,
            Err(err) => {
                tracing::warn!(
                    target: "tessera.ocsp",
                    path = %path.display(),
                    error = %err,
                    "OCSP cache entry unreadable, treating as miss"
                );
                return None;
            }
        };
        if let Err(err) = openssl::ocsp::OcspResponse::from_der(&der) {
            tracing::warn!(
                target: "tessera.ocsp",
                path = %path.display(),
                error = %err,
                "OCSP cache entry does not parse, treating as miss"
            );
            return None;
        }
        Some(der)
    }

    /// Stores a verified DER response under `key`.
    ///
    /// `status` is the outcome the caller obtained from
    /// [`crate::ocsp::verify_ocsp_response`] for these very bytes; taking
    /// [`CertStatus`] (which has no `unknown` variant) makes "cache only
    /// definite statuses" a type-level guarantee.  No-op when the cache is
    /// disabled (`ttl == 0`).
    ///
    /// The write is atomic — a `0640` tmp file in the cache directory,
    /// fsync, then rename — so readers only ever observe complete entries.
    ///
    /// # Errors
    ///
    /// Propagates the underlying `io::Error` (missing directory, full disk,
    /// permissions).  Callers should WARN and continue: a failed cache
    /// write must never fail an authentication that already has a verified
    /// status in hand.
    pub fn put(
        &self,
        key: &OcspCacheKey,
        response_der: &[u8],
        status: &CertStatus,
    ) -> io::Result<()> {
        // Exhaustive without a wildcard: every representable status is
        // definite and cacheable (`unknown` never constructs a CertStatus).
        match status {
            CertStatus::Good | CertStatus::Revoked { .. } => {}
        }
        if self.ttl.is_zero() {
            return Ok(());
        }
        let path = self.entry_path(key);
        // Unique-per-process tmp name in the same directory, so the final
        // rename(2) is atomic on the same filesystem.
        let tmp = self
            .dir
            .join(format!(".{}.{}.tmp", key.as_hex(), std::process::id()));
        let result = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o640)
                .open(&tmp)?;
            file.write_all(response_der)?;
            file.sync_all()?;
            // The open(2) mode is filtered through the umask; pin the spec
            // mode explicitly before the entry becomes visible.
            fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o640))?;
            fs::rename(&tmp, &path)
        })();
        if result.is_err() {
            if let Err(cleanup) = fs::remove_file(&tmp) {
                if cleanup.kind() != io::ErrorKind::NotFound {
                    tracing::warn!(
                        target: "tessera.ocsp",
                        path = %tmp.display(),
                        error = %cleanup,
                        "failed to clean up OCSP cache tmp file"
                    );
                }
            }
        }
        result
    }

    /// Evicts the entry for `key`, if present.
    ///
    /// Called when a cached response failed re-verification (typically its
    /// `nextUpdate` lapsed before the local `mtime + ttl` did) so the stale
    /// file does not get re-read on every login.  Best-effort: a failed
    /// unlink is WARN-logged, never an error — the entry would be ignored
    /// or overwritten anyway.
    pub fn remove(&self, key: &OcspCacheKey) {
        let path = self.entry_path(key);
        if let Err(err) = fs::remove_file(&path) {
            if err.kind() != io::ErrorKind::NotFound {
                tracing::warn!(
                    target: "tessera.ocsp",
                    path = %path.display(),
                    error = %err,
                    "failed to evict OCSP cache entry"
                );
            }
        }
    }

    fn entry_path(&self, key: &OcspCacheKey) -> PathBuf {
        self.dir.join(format!("{}.der", key.as_hex()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::duration_suboptimal_units)]

    use super::{OcspCache, OcspCacheKey};
    use crate::ocsp::response::CertStatus;
    use crate::x509::Certificate;
    use openssl::ocsp::{OcspResponse, OcspResponseStatus};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    fn load_cert(name: &str) -> Certificate {
        let pem = fs::read(fixture_path(name)).expect("fixture readable");
        Certificate::from_pem(&pem).expect("fixture parses")
    }

    fn key() -> OcspCacheKey {
        OcspCacheKey::for_pair(&load_cert("leaf_rsa.pem"), &load_cert("int.pem")).expect("key")
    }

    /// Any structurally valid `OCSPResponse` DER; status-only responses can
    /// be built without fixtures (`OcspResponse::create`), and `get`'s parse
    /// gate accepts them.
    fn response_der() -> Vec<u8> {
        OcspResponse::create(OcspResponseStatus::TRY_LATER, None)
            .expect("status-only response")
            .to_der()
            .expect("encodes")
    }

    fn cache_in(dir: &tempfile::TempDir, ttl_secs: u64) -> OcspCache {
        OcspCache::new(dir.path().to_path_buf(), Duration::from_secs(ttl_secs))
    }

    #[test]
    fn cache_key_is_deterministic_and_distinct_per_subject() {
        let a = key();
        let b = key();
        assert_eq!(a, b);
        assert_eq!(a.as_hex().len(), 64, "sha256 hex");
        assert!(a.as_hex().chars().all(|c| c.is_ascii_hexdigit()));
        let other = OcspCacheKey::for_pair(&load_cert("leaf_ecdsa.pem"), &load_cert("int.pem"))
            .expect("key");
        assert_ne!(a, other, "different serial → different key");
    }

    #[test]
    fn put_get_roundtrip_good() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(&dir, 3600);
        let key = key();
        let der = response_der();
        cache.put(&key, &der, &CertStatus::Good).expect("put");
        assert_eq!(cache.get(&key), Some(der));
    }

    #[test]
    fn put_get_roundtrip_revoked() {
        // `revoked` is cached too: the status is irreversible within the
        // response's validity window.
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(&dir, 3600);
        let key = key();
        let der = response_der();
        let status = CertStatus::Revoked {
            revocation_time: Some("Jun 11 00:00:00 2026 GMT".to_string()),
            reason: Some("keyCompromise"),
        };
        cache.put(&key, &der, &status).expect("put");
        assert_eq!(cache.get(&key), Some(der));
    }

    /// `CertStatus` is the entire `put` status surface and has no `unknown`
    /// variant — the exhaustive match below needs no wildcard arm, so an
    /// undeterminable status cannot reach the cache by construction (the
    /// verifier maps `unknown` to `TrustError::OcspStatusUnknown` instead
    /// of producing a value).
    #[test]
    fn put_accepts_only_definite_statuses_by_type() {
        fn assert_definite(status: &CertStatus) {
            match status {
                CertStatus::Good | CertStatus::Revoked { .. } => {}
            }
        }
        assert_definite(&CertStatus::Good);
        assert_definite(&CertStatus::Revoked {
            revocation_time: None,
            reason: None,
        });
    }

    #[test]
    fn entry_expired_by_mtime_plus_ttl_is_miss() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(&dir, 60);
        let key = key();
        cache.put(&key, &response_der(), &CertStatus::Good).expect("put");
        assert!(cache.get(&key).is_some(), "fresh entry hits");
        // Age the entry past the ttl by rewinding its mtime.
        let path = dir.path().join(format!("{}.der", key.as_hex()));
        let file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.set_modified(SystemTime::now() - Duration::from_secs(120))
            .unwrap();
        drop(file);
        assert_eq!(cache.get(&key), None, "expired by mtime + ttl");
    }

    #[test]
    fn ttl_zero_disables_get_and_put() {
        let dir = tempfile::tempdir().unwrap();
        let disabled = cache_in(&dir, 0);
        let key = key();
        disabled
            .put(&key, &response_der(), &CertStatus::Good)
            .expect("disabled put is a no-op");
        let path = dir.path().join(format!("{}.der", key.as_hex()));
        assert!(!path.exists(), "disabled put writes nothing");
        // Even a manually planted valid entry stays invisible.
        cache_in(&dir, 3600)
            .put(&key, &response_der(), &CertStatus::Good)
            .expect("seed entry");
        assert!(path.exists());
        assert_eq!(disabled.get(&key), None, "disabled get always misses");
    }

    #[test]
    fn corrupted_entry_is_miss_and_removable() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(&dir, 3600);
        let key = key();
        let path = dir.path().join(format!("{}.der", key.as_hex()));
        fs::write(&path, b"definitely not an OCSPResponse").unwrap();
        assert_eq!(cache.get(&key), None, "corrupted entry is a miss");
        assert!(path.exists(), "get itself does not unlink");
        cache.remove(&key);
        assert!(!path.exists(), "remove evicts the entry");
    }

    #[test]
    fn remove_then_get_is_miss_and_missing_key_is_quiet() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(&dir, 3600);
        let key = key();
        cache.remove(&key); // absent entry: no panic, no error
        assert_eq!(cache.get(&key), None);
        cache.put(&key, &response_der(), &CertStatus::Good).expect("put");
        cache.remove(&key);
        assert_eq!(cache.get(&key), None);
    }

    #[test]
    fn entry_mode_is_0640_and_no_tmp_leftovers() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let cache = cache_in(&dir, 3600);
        let key = key();
        cache.put(&key, &response_der(), &CertStatus::Good).expect("put");
        let path = dir.path().join(format!("{}.der", key.as_hex()));
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o640, "spec mode regardless of umask");
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "tmp file renamed away: {leftovers:?}");
    }

    #[test]
    fn put_into_missing_directory_fails_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        let cache = OcspCache::new(missing, Duration::from_secs(3600));
        let key = key();
        assert!(cache.put(&key, &response_der(), &CertStatus::Good).is_err());
        assert_eq!(cache.get(&key), None);
    }
}
