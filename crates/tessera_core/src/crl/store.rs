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
#[derive(Debug, Clone, Default)]
pub struct RevocationConfig {
    /// When `true`, stale CRLs are a hard error.  When `false`, they are
    /// logged and skipped.
    pub crl_strict: bool,
    /// Maximum accepted CRL age, measured from `thisUpdate`.
    ///
    /// A CRL is considered stale when `now > thisUpdate + crl_max_age`,
    /// in addition to the `nextUpdate <= now` rule.  `None` disables the
    /// age cap; CRLs that also lack `nextUpdate` then have no verifiable
    /// freshness at all (logged as a warning).
    pub crl_max_age: Option<Duration>,
    /// Optional path to the gost-engine .so/.dylib, forwarded to
    /// [`Crl::verify_signature_with_issuer`] when a CRL issuer is
    /// GOST-signed.  `None` uses libcrypto's standard engine search path.
    pub gost_engine_path: Option<std::path::PathBuf>,
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
    /// * [`TrustError::CrlSignatureInvalid`] when the signature does not
    ///   validate under `key` or libcrypto fails to process it.
    pub fn verify_signature(&self, key: &PKey<Public>) -> Result<(), TrustError> {
        let ok = self
            .inner
            .verify(key)
            .map_err(|e| TrustError::CrlSignatureInvalid(format!("CRL signature: {e}")))?;
        if ok {
            Ok(())
        } else {
            Err(TrustError::CrlSignatureInvalid(
                "CRL signature does not validate".into(),
            ))
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

    /// Builds a store from already-parsed CRLs.
    #[must_use]
    pub fn from_crls(crls: Vec<Crl>) -> Self {
        Self { crls }
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
/// For each certificate in the chain (anchor included), this function checks
/// every CRL in the store; if any applicable CRL lists the certificate's
/// serial as lowercase hex, it returns [`TrustError::Revoked`].
///
/// Before a CRL is allowed to vouch for (or revoke) a certificate, its
/// signature is verified against the public key of the certificate's issuer
/// found in `chain` (the chain is leaf-first and complete up to the
/// self-signed anchor, so the issuer is always present in a verified chain).
/// A CRL whose signature does not validate fails closed with
/// [`TrustError::CrlSignatureInvalid`] — the same refusal class as a revoked
/// certificate.
///
/// Stale CRLs are treated according to [`RevocationConfig::crl_strict`].
/// A CRL is stale when either condition holds:
///
/// * `nextUpdate` is present and `nextUpdate <= now`, or
/// * [`RevocationConfig::crl_max_age`] is set and
///   `now > thisUpdate + crl_max_age`.
///
/// * `crl_strict = true`  — return [`TrustError::Crl`].
/// * `crl_strict = false` — log a warning via `tracing` and skip the CRL.
///
/// A CRL with no `nextUpdate` while `crl_max_age` is unset has no verifiable
/// freshness; this is logged as a warning (target `tessera.crl`) and the CRL
/// is still used — documented behaviour for operators that cannot set either
/// bound.
///
/// An empty store is treated as "no CRLs configured" and returns `Ok`.
///
/// # Errors
///
/// * [`TrustError::Revoked`] when a serial matches.
/// * [`TrustError::CrlSignatureInvalid`] when an applicable CRL's signature
///   does not validate under its issuer's key (or the issuer certificate is
///   not present in `chain`, leaving the signature unverifiable).
/// * [`TrustError::Crl`] when a stale CRL is encountered in strict mode.
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
        if crl_is_stale(crl, cfg, now) {
            if cfg.crl_strict {
                return Err(TrustError::Crl("CRL stale".into()));
            }
            tracing::warn!(target: "tessera.crl", "skipping stale CRL");
            continue;
        }
        if crl.next_update.is_none() && cfg.crl_max_age.is_none() {
            tracing::warn!(
                target: "tessera.crl",
                "CRL has no nextUpdate and crl_max_age_hours is not configured; \
                 CRL freshness cannot be verified"
            );
        }
        // Verify the CRL signature at most once per CRL per call.
        let mut signature_checked = false;
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
            if !signature_checked {
                // Defensive; unreachable for chains produced by
                // `build_chain` (every issuer up to the self-signed anchor
                // is guaranteed present) — kept fail-closed in case callers
                // pass partial chains.
                let issuer = find_issuer(chain, &crl.issuer_dn_der).ok_or_else(|| {
                    TrustError::CrlSignatureInvalid(
                        "CRL issuer certificate not present in verified chain; \
                         signature cannot be verified"
                            .into(),
                    )
                })?;
                crl.verify_signature_with_issuer(issuer, cfg.gost_engine_path.as_deref())?;
                signature_checked = true;
            }
            let serial = cert.serial_hex().to_lowercase();
            if crl.revoked.iter().any(|s| s == &serial) {
                return Err(TrustError::Revoked(serial));
            }
        }
    }
    Ok(())
}

/// Whether a fresh CRL in the store covers a given certificate, and the
/// resulting status when it does.  Used by the `crl_then_ocsp` revocation
/// mode to decide between an offline CRL verdict and a network OCSP call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlCoverage {
    /// A fresh CRL issued by the certificate's issuer covers it; the bool is
    /// `true` when the certificate's serial is listed (revoked).
    Covered(bool),
    /// No fresh CRL whose issuer DN matches the certificate's issuer DN is
    /// present (none configured, all stale, or none in scope) — the caller
    /// must fall back to OCSP.
    NotCovered,
}

/// Returns whether a fresh, in-scope CRL covers `cert` and its revocation
/// verdict, for the `crl_then_ocsp` mode's "CRL first, OCSP only on miss"
/// rule (delta-spec `revocation`).
///
/// `cert`'s issuer DN is matched byte-for-byte against each CRL's issuer DN
/// (RFC 5280 § 6.3.3).  A matching CRL is consulted only when it is fresh
/// (same staleness rule as [`check_revocation`]: `nextUpdate <= now`, or
/// `thisUpdate + crl_max_age < now` when the cap is set); a stale CRL yields
/// [`CrlCoverage::NotCovered`] so the caller falls back to OCSP rather than
/// failing — staleness is not fatal in this mode.
///
/// Before a CRL's verdict is trusted its signature is verified against the
/// issuer certificate found in `chain` (by subject DN); a signature that
/// does not validate fails closed.
///
/// # Errors
///
/// * [`TrustError::CrlSignatureInvalid`] when an in-scope fresh CRL's
///   signature does not validate under its issuer's key, or the issuer
///   certificate is absent from `chain`.
pub fn crl_status_for(
    cert: &Certificate,
    chain: &[Certificate],
    store: &CrlStore,
    cfg: &RevocationConfig,
    now: SystemTime,
) -> Result<CrlCoverage, TrustError> {
    let Ok(cert_issuer_der) = cert.x509().issuer_name().to_der() else {
        // Issuer DN cannot be encoded: no CRL can be proven in scope.
        return Ok(CrlCoverage::NotCovered);
    };
    let serial = cert.serial_hex().to_lowercase();
    for crl in store.iter() {
        if crl.issuer_dn_der() != cert_issuer_der.as_slice() {
            continue;
        }
        if crl_is_stale(crl, cfg, now) {
            // Stale CRL: not a usable offline source -> fall back to OCSP.
            continue;
        }
        // In scope and fresh: verify its signature before trusting it.
        let issuer = find_issuer(chain, crl.issuer_dn_der()).ok_or_else(|| {
            TrustError::CrlSignatureInvalid(
                "CRL issuer certificate not present in verified chain; \
                 signature cannot be verified"
                    .into(),
            )
        })?;
        crl.verify_signature_with_issuer(issuer, cfg.gost_engine_path.as_deref())?;
        let revoked = crl.revoked_serials().iter().any(|s| s == &serial);
        return Ok(CrlCoverage::Covered(revoked));
    }
    Ok(CrlCoverage::NotCovered)
}

/// Whether `crl` is stale at `now` under `cfg` (RFC 5280 freshness).
fn crl_is_stale(crl: &Crl, cfg: &RevocationConfig, now: SystemTime) -> bool {
    let stale_by_next_update = crl.next_update.is_some_and(|nu| nu <= now);
    // `thisUpdate` near the upper bound of `SystemTime` can overflow on
    // `+ max_age` (which panics); a deadline past that bound is infinitely
    // far in the future, so overflow means "not stale".
    let stale_by_max_age = cfg.crl_max_age.is_some_and(|max_age| {
        crl.this_update
            .checked_add(max_age)
            .is_some_and(|deadline| now > deadline)
    });
    stale_by_next_update || stale_by_max_age
}

/// Finds the chain certificate whose subject DN (DER) equals `issuer_dn_der`.
///
/// In a verified leaf-first chain every certificate's issuer is a later chain
/// element (the anchor is self-signed), so the CRL issuer is found whenever
/// the CRL is in scope for some chain certificate.
fn find_issuer<'a>(chain: &'a [Certificate], issuer_dn_der: &[u8]) -> Option<&'a Certificate> {
    chain.iter().find(|cert| {
        cert.x509()
            .subject_name()
            .to_der()
            .is_ok_and(|subject| subject == issuer_dn_der)
    })
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
