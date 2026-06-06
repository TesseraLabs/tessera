//! CRL parsing and revocation-check implementation.

use crate::gost::engine::ensure_loaded_if_signature_alg_gost;
use crate::x509::{Certificate, SignatureAlg, TrustError};
use openssl::asn1::Asn1TimeRef;
use openssl::pkey::{PKey, Public};
use openssl::x509::X509Crl;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A parsed CRL plus pre-computed metadata needed by [`check_revocation`].
///
/// The original `X509Crl` is retained so the signature can be re-verified
/// against an issuer's public key on demand.
pub struct Crl {
    inner: X509Crl,
    this_update: SystemTime,
    next_update: Option<SystemTime>,
    /// Revoked serial numbers as lowercase hex (matches [`Certificate::serial_hex`]
    /// after `.to_lowercase()`).
    revoked: Vec<String>,
    /// DER-encoded issuer name; matched against
    /// [`openssl::x509::X509Ref::issuer_name`] of certificates being checked.
    issuer_dn_der: Vec<u8>,
}

impl std::fmt::Debug for Crl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Crl")
            .field("this_update", &self.this_update)
            .field("next_update", &self.next_update)
            .field("revoked_count", &self.revoked.len())
            .field("issuer_dn_len", &self.issuer_dn_der.len())
            .finish_non_exhaustive()
    }
}

/// A bag of CRLs.  Constructed once at verifier-startup time.
#[derive(Debug, Default)]
pub struct CrlStore {
    crls: Vec<Crl>,
}

/// Configuration knobs for [`check_revocation`].
#[derive(Debug, Clone, Copy)]
pub struct RevocationConfig {
    /// When `true`, expired CRLs are a hard error.  When `false`, they are
    /// logged and skipped.
    pub crl_strict: bool,
}

impl Crl {
    /// Parses a PEM-encoded CRL.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::Crl`] when the input is not a valid CRL or
    /// when its `lastUpdate` field is malformed.
    pub fn from_pem(pem: &[u8]) -> Result<Self, TrustError> {
        let inner = X509Crl::from_pem(pem).map_err(|e| TrustError::Crl(e.to_string()))?;
        Self::from_inner(inner)
    }

    /// Parses a DER-encoded CRL.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::Crl`] when the input is not a valid CRL or
    /// when its `lastUpdate` field is malformed.
    pub fn from_der(der: &[u8]) -> Result<Self, TrustError> {
        let inner = X509Crl::from_der(der).map_err(|e| TrustError::Crl(e.to_string()))?;
        Self::from_inner(inner)
    }

    fn from_inner(inner: X509Crl) -> Result<Self, TrustError> {
        let this_update = asn1_to_system(inner.last_update())?;
        let next_update = match inner.next_update() {
            Some(t) => Some(asn1_to_system(t)?),
            None => None,
        };
        let revoked = inner
            .get_revoked()
            .map(|stack| {
                stack
                    .iter()
                    .filter_map(|r| r.serial_number().to_bn().ok())
                    .filter_map(|bn| bn.to_hex_str().ok().map(|s| s.to_string().to_lowercase()))
                    .collect()
            })
            .unwrap_or_default();
        let issuer_dn_der = inner
            .issuer_name()
            .to_der()
            .map_err(|e| TrustError::Crl(e.to_string()))?;
        Ok(Self {
            inner,
            this_update,
            next_update,
            revoked,
            issuer_dn_der,
        })
    }

    /// `thisUpdate` from the CRL (RFC 5280 § 5.1.2.4).
    #[must_use]
    pub fn this_update(&self) -> SystemTime {
        self.this_update
    }

    /// `nextUpdate` from the CRL, if present.  Falls back to `thisUpdate` for
    /// callers that prefer a non-`Option` accessor.
    #[must_use]
    pub fn next_update(&self) -> SystemTime {
        self.next_update.unwrap_or(self.this_update)
    }

    /// Lowercase-hex revoked serials.
    #[must_use]
    pub fn revoked_serials(&self) -> &[String] {
        &self.revoked
    }

    /// DER-encoded issuer DN.
    #[must_use]
    pub fn issuer_dn_der(&self) -> &[u8] {
        &self.issuer_dn_der
    }

    /// Verifies the CRL's signature against `key`.
    ///
    /// # Errors
    ///
    /// * [`TrustError::Openssl`] on libcrypto failures.
    /// * [`TrustError::Crl`] when the signature is syntactically invalid.
    pub fn verify_signature(&self, key: &PKey<Public>) -> Result<(), TrustError> {
        let ok = self
            .inner
            .verify(key)
            .map_err(|e| TrustError::Crl(format!("CRL signature: {e}")))?;
        if ok {
            Ok(())
        } else {
            Err(TrustError::Crl("CRL signature does not validate".into()))
        }
    }

    /// Verifies the CRL's signature against the issuer certificate, loading
    /// the gost-engine first if the issuer is a GOST CA.
    ///
    /// `gost_engine_path` is forwarded verbatim to
    /// [`crate::gost::engine::ensure_loaded_with_path`] when needed.  For
    /// non-GOST issuers the engine is left untouched.
    ///
    /// `issuer.signature_alg()` is used as the proxy for "this issuer's
    /// public key is GOST-typed", based on the contract that GOST CAs
    /// invariably sign themselves with GOST.
    ///
    /// # Errors
    ///
    /// * [`TrustError::EngineLoadFailed`] when the issuer is GOST-typed
    ///   but the engine cannot be pinned.
    /// * Same set as [`Self::verify_signature`] otherwise.
    pub fn verify_signature_with_issuer(
        &self,
        issuer: &Certificate,
        gost_engine_path: Option<&Path>,
    ) -> Result<(), TrustError> {
        let sig_alg: SignatureAlg = issuer.signature_alg();
        ensure_loaded_if_signature_alg_gost(&sig_alg, gost_engine_path)
            .map_err(|source| TrustError::EngineLoadFailed { source })?;
        let key = issuer.public_key()?;
        self.verify_signature(&key)
    }
}

impl CrlStore {
    /// Builds a store from a slice of PEM blobs.
    ///
    /// # Errors
    ///
    /// Propagates [`TrustError::Crl`] from any failing CRL.
    pub fn from_pems(pems: &[&[u8]]) -> Result<Self, TrustError> {
        let mut crls = Vec::with_capacity(pems.len());
        for pem in pems {
            crls.push(Crl::from_pem(pem)?);
        }
        Ok(Self { crls })
    }

    /// Returns an empty store; equivalent to "no CRLs configured".
    #[must_use]
    pub fn empty() -> Self {
        Self { crls: Vec::new() }
    }

    /// Iterates the stored CRLs.
    pub fn iter(&self) -> impl Iterator<Item = &Crl> {
        self.crls.iter()
    }

    /// Number of stored CRLs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.crls.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.crls.is_empty()
    }
}

/// Walks a leaf-first chain and rejects revoked certificates.
///
/// For each certificate in the chain (excluding the anchor), this function
/// checks every CRL in the store; if any CRL lists the certificate's serial
/// as lowercase hex, it returns [`TrustError::Revoked`].
///
/// CRLs whose `nextUpdate` has passed are treated according to
/// [`RevocationConfig::crl_strict`]:
///
/// * `true`  — return [`TrustError::Crl`].
/// * `false` — log a warning via `tracing` and skip the CRL.
///
/// An empty store is treated as "no CRLs configured" and returns `Ok`.
///
/// # Errors
///
/// * [`TrustError::Revoked`] when a serial matches.
/// * [`TrustError::Crl`] when an expired CRL is encountered in strict mode.
pub fn check_revocation(
    chain: &[Certificate],
    store: &CrlStore,
    cfg: &RevocationConfig,
    now: SystemTime,
) -> Result<(), TrustError> {
    if store.is_empty() {
        return Ok(());
    }
    for crl in store.iter() {
        if let Some(nu) = crl.next_update {
            if nu <= now {
                if cfg.crl_strict {
                    return Err(TrustError::Crl("CRL expired".into()));
                }
                tracing::warn!(target: "tessera.crl", "skipping expired CRL");
                continue;
            }
        }
        for cert in chain {
            // RFC 5280 § 6.3.3: a CRL only covers certificates issued by the
            // CRL issuer.  Compare the certificate's issuer DN against the
            // CRL's issuer DN byte-for-byte; on mismatch (or on a DER-encode
            // failure that leaves the scope unprovable) this CRL is not
            // applicable to this certificate.
            match cert.x509().issuer_name().to_der() {
                Ok(issuer_der) if issuer_der == crl.issuer_dn_der => {}
                _ => continue,
            }
            let serial = cert.serial_hex().to_lowercase();
            if crl.revoked.iter().any(|s| s == &serial) {
                return Err(TrustError::Revoked(serial));
            }
        }
    }
    Ok(())
}

fn asn1_to_system(t: &Asn1TimeRef) -> Result<SystemTime, TrustError> {
    let epoch =
        openssl::asn1::Asn1Time::from_unix(0).map_err(|e| TrustError::Crl(e.to_string()))?;
    let diff = epoch.diff(t).map_err(|e| TrustError::Crl(e.to_string()))?;
    let secs = i64::from(diff.days) * 86_400 + i64::from(diff.secs);
    if secs >= 0 {
        let unsigned = u64::try_from(secs).unwrap_or(0);
        Ok(UNIX_EPOCH + Duration::from_secs(unsigned))
    } else {
        let unsigned = u64::try_from(-secs).unwrap_or(0);
        Ok(UNIX_EPOCH - Duration::from_secs(unsigned))
    }
}
