//! Stage-2 trust verifier: an `OpensslVerifier` that orchestrates the
//! T03 → T04 → T05 → T06 → T07 → T08 pipeline.
//!
//! The stage-1 [`crate::trust::TrustVerifier`] uses a different
//! signature (it takes a `host_id` and returns a stage-1 `VerifiedChain`).
//! Until the two type families are unified in a later stage, this verifier
//! exposes its own [`Stage2TrustVerifier`] trait and emits its own
//! [`Stage2VerifiedChain`].

use crate::config::validated::RevocationMode;
use crate::crl::{check_revocation, crl_status_for, CrlCoverage, CrlStore, RevocationConfig};
use crate::gost::engine::ensure_loaded_if_any_gost;
use crate::ocsp::{
    post_ocsp_request, verify_ocsp_response, CertStatus, OcspCache, OcspCacheKey, OcspRequestData,
    OcspUrl, OcspVerifyContext,
};
use crate::x509::basic_constraints::{verify_basic_constraints, verify_intermediate_constraints};
use crate::x509::chain::build_chain;
use crate::x509::pinning::{verify_pinning, SpkiPin};
use crate::x509::pre_validate::{pre_validate_end_entity, PreValidateConfig};
use crate::x509::signatures::verify_chain_signatures;
use crate::x509::{Certificate, TrustError};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// On-disk OCSP response cache directory (design Decision 3).  The package
/// postinst creates it `0750 root:root`; a missing directory degrades to
/// cache misses, never to an auth error.
pub const OCSP_CACHE_DIR: &str = "/var/cache/tessera/ocsp";

/// Bridges an OCSP-subsystem error into the chain verifier's error type,
/// keeping the OCSP path fail-closed: any OCSP failure becomes
/// [`TrustError::Ocsp`] and thus refuses authentication.
///
/// Takes the error by value so it can be used directly as `.map_err(ocsp_err)`
/// (which hands the closure an owned error); the value is dropped after its
/// `Display` form is captured.
#[allow(clippy::needless_pass_by_value)]
fn ocsp_err(err: crate::error::TrustError) -> TrustError {
    TrustError::Ocsp(err.to_string())
}

/// Result of a successful stage-2 verification.
#[derive(Debug, Clone)]
pub struct Stage2VerifiedChain {
    /// End-entity (leaf) certificate.
    pub end_entity: Certificate,
    /// Intermediate certificates between the leaf and the anchor (may be empty).
    pub chain: Vec<Certificate>,
    /// Trust anchor that terminates the chain.
    pub anchor: Certificate,
}

impl Stage2VerifiedChain {
    /// Wrap the verified leaf as a [`crate::x509::VerifiedX509`].  Safe
    /// because the chain succeeded validation before this struct could
    /// be constructed.
    #[must_use]
    pub fn verified_leaf(&self) -> crate::x509::VerifiedX509 {
        crate::x509::VerifiedX509::new(self.end_entity.x509().clone())
    }

    /// The full ordered chain `[end_entity] ++ intermediates ++ [anchor]`
    /// (leaf → anchor), matching the ordering [`crate::x509::chain::build_chain`]
    /// produces and the ordering [`crate::trust::enforce_delegation`] expects.
    ///
    /// Reconstructed by cloning the three stored parts; the verifier does not
    /// retain the original `Vec`, and re-verifying to obtain it would be both
    /// wasteful and a TOCTOU risk, so this minimal accessor rebuilds it.
    #[must_use]
    pub fn full_chain(&self) -> Vec<Certificate> {
        let mut out = Vec::with_capacity(self.chain.len() + 2);
        out.push(self.end_entity.clone());
        out.extend(self.chain.iter().cloned());
        out.push(self.anchor.clone());
        out
    }
}

/// Stage-2 trust verifier interface.
///
/// Distinct from [`crate::trust::TrustVerifier`] (stage 1) — they will be
/// merged once the rest of the crate migrates onto stage-2 types.
pub trait Stage2TrustVerifier: Send + Sync {
    /// Verifies an end-entity certificate against this verifier's anchors.
    ///
    /// `presented` are the intermediate certs supplied by the client (they
    /// supplement the verifier's local pool).
    ///
    /// # Errors
    ///
    /// Propagates any [`TrustError`] raised by the underlying steps.
    fn verify(
        &self,
        leaf: &Certificate,
        presented: &[Certificate],
    ) -> Result<Stage2VerifiedChain, TrustError>;
}

/// Default `max_supported_profile_version` used until the `[trust]` config key
/// (section 5.2) is wired through. Baseline format = 0; an absent
/// `pam_cert_profile_version` extension is also treated as 0, so this default
/// accepts only baseline certs and is fail-closed against any newer format.
pub const DEFAULT_MAX_SUPPORTED_PROFILE_VERSION: u32 = 0;

/// Builder/constructor configuration for [`OpensslVerifier`].
pub struct OpensslVerifierConfig {
    /// Trusted self-signed roots.
    pub anchors: Vec<Certificate>,
    /// Local intermediate trust pool (in addition to those presented over the wire).
    pub intermediates: Vec<Certificate>,
    /// CRLs (PEM) configured at startup.  May be empty.
    pub crl_pems: Vec<Vec<u8>>,
    /// When `true`, stale CRLs are a hard error.
    pub crl_strict: bool,
    /// Maximum accepted CRL age measured from `thisUpdate`; `None`
    /// disables the cap.  See [`RevocationConfig::crl_max_age`].
    pub crl_max_age: Option<Duration>,
    /// Permissible clock skew when comparing `notBefore`/`notAfter` against `now`.
    pub clock_skew: Duration,
    /// Permissible signature-algorithm names.  Each entry is compared for
    /// exact, case-sensitive equality against the algorithm's `Display`
    /// form (substring matching was removed on purpose — it let
    /// `sha1WithRSAEncryption` slip past a `sha` entry).  An empty list
    /// means "no constraint"; see [`PreValidateConfig`].
    pub signature_alg_whitelist: Vec<String>,
    /// SPKI pins.  Empty = disabled.
    pub spki_pins: Vec<SpkiPin>,
    /// Maximum allowed chain length (including leaf and anchor).
    pub max_depth: usize,
    /// Highest `pam_cert_profile_version` this Engine understands. Any chain
    /// cert declaring a higher version rejects the whole chain (fail-closed
    /// version gate, task 4.1). Section 5.2 wires this from
    /// `[trust].max_supported_profile_version`; until then construct with
    /// [`DEFAULT_MAX_SUPPORTED_PROFILE_VERSION`].
    pub max_supported_profile_version: u32,
    /// Optional path to the gost-engine .so/.dylib.  When `None` the engine
    /// is located via libcrypto's standard `OPENSSL_ENGINES` search path.
    ///
    /// Forwarded verbatim from [`crate::config::ValidatedConfig::gost_engine_path`].
    pub gost_engine_path: Option<PathBuf>,
    /// Revocation mode dispatcher selector.  Replaces the previous
    /// collapse of mode into a single `crl_strict` bool.
    pub revocation_mode: RevocationMode,
    /// Parsed OCSP responder URL.  `Some` exactly in the `ocsp` /
    /// `crl_then_ocsp` modes (validation guarantees the config key is
    /// present there and absent otherwise).
    pub ocsp_responder_url: Option<OcspUrl>,
    /// Overall deadline for one OCSP exchange (connect + write + read).
    pub ocsp_timeout: Duration,
    /// OCSP response cache directory.
    pub ocsp_cache_dir: PathBuf,
    /// Upper bound on a cache entry's local lifetime; `Duration::ZERO`
    /// disables the cache.
    pub ocsp_cache_ttl: Duration,
}

/// Stage-2 OpenSSL-backed trust verifier.
///
/// Construct once at startup and reuse across authentication attempts.
/// `verify` is `&self` and stateless apart from the cached config and stores.
pub struct OpensslVerifier {
    anchors: Vec<Certificate>,
    intermediates: Vec<Certificate>,
    crl_store: CrlStore,
    rev_cfg: RevocationConfig,
    pre_cfg: PreValidateConfig,
    pins: Vec<SpkiPin>,
    max_depth: usize,
    max_supported_profile_version: u32,
    gost_engine_path: Option<PathBuf>,
    revocation_mode: RevocationMode,
    ocsp_responder_url: Option<OcspUrl>,
    ocsp_timeout: Duration,
    ocsp_cache: OcspCache,
    clock_skew: Duration,
}

impl std::fmt::Debug for OpensslVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpensslVerifier")
            .field("anchors", &self.anchors.len())
            .field("intermediates", &self.intermediates.len())
            .field("crl_store_len", &self.crl_store.len())
            .field("crl_strict", &self.rev_cfg.crl_strict)
            .field("revocation_mode", &self.revocation_mode)
            .field("max_depth", &self.max_depth)
            .field("pinning_enabled", &!self.pins.is_empty())
            .finish_non_exhaustive()
    }
}

impl OpensslVerifier {
    /// Constructs a verifier from a config blob.
    ///
    /// # Errors
    ///
    /// * [`TrustError::PathBuild`] when `max_depth == 0` or when no anchors
    ///   are supplied.
    /// * [`TrustError::Crl`] when any of the CRL PEM blobs fails to parse.
    pub fn new(cfg: OpensslVerifierConfig) -> Result<Self, TrustError> {
        if cfg.anchors.is_empty() {
            return Err(TrustError::PathBuild("no anchors configured"));
        }
        if cfg.max_depth == 0 {
            return Err(TrustError::PathBuild("max_depth must be at least 1"));
        }
        // Defense-in-depth: the OCSP-capable modes are unusable without a
        // responder URL.  Config validation already guarantees the URL is
        // present in these modes, but refuse construction rather than risk a
        // silently skipped revocation check at auth time.
        if matches!(
            cfg.revocation_mode,
            RevocationMode::Ocsp | RevocationMode::CrlThenOcsp
        ) && cfg.ocsp_responder_url.is_none()
        {
            return Err(TrustError::PathBuild("ocsp mode requires a responder URL"));
        }
        let crl_refs: Vec<&[u8]> = cfg.crl_pems.iter().map(Vec::as_slice).collect();
        let crl_store = CrlStore::from_pems(&crl_refs)?;
        // Defense-in-depth: `crl` mode with an empty store makes the
        // revocation check short-circuit to Ok for every certificate. Config
        // validation already rejects this, but refuse construction rather
        // than risk a silently disabled revocation check at auth time.
        if matches!(cfg.revocation_mode, RevocationMode::Crl) && crl_store.is_empty() {
            return Err(TrustError::PathBuild("crl mode requires at least one CRL"));
        }
        let ocsp_cache = OcspCache::new(cfg.ocsp_cache_dir, cfg.ocsp_cache_ttl);
        Ok(Self {
            anchors: cfg.anchors,
            intermediates: cfg.intermediates,
            crl_store,
            rev_cfg: RevocationConfig {
                crl_strict: cfg.crl_strict,
                crl_max_age: cfg.crl_max_age,
                gost_engine_path: cfg.gost_engine_path.clone(),
            },
            pre_cfg: PreValidateConfig {
                clock_skew: cfg.clock_skew,
                signature_alg_whitelist: cfg.signature_alg_whitelist,
            },
            pins: cfg.spki_pins,
            max_depth: cfg.max_depth,
            max_supported_profile_version: cfg.max_supported_profile_version,
            gost_engine_path: cfg.gost_engine_path,
            revocation_mode: cfg.revocation_mode,
            ocsp_responder_url: cfg.ocsp_responder_url,
            ocsp_timeout: cfg.ocsp_timeout,
            ocsp_cache,
            clock_skew: cfg.clock_skew,
        })
    }

    /// Verifies `leaf` at the supplied wall-clock instant.
    ///
    /// Useful for tests that want a fixed `now`; in production callers may
    /// prefer the [`Stage2TrustVerifier::verify`] entrypoint which uses
    /// `SystemTime::now()`.
    ///
    /// # Errors
    ///
    /// Propagates [`TrustError`] from any pipeline step.
    pub fn verify_at(
        &self,
        leaf: &Certificate,
        presented: &[Certificate],
        now: SystemTime,
    ) -> Result<Stage2VerifiedChain, TrustError> {
        // 0. Engine wiring: if any cert involved (leaf, presented, local
        //    intermediates, configured anchors) is GOST-signed, load the
        //    gost-engine before any libcrypto signature path is exercised.
        //    No-op for pure RSA/ECDSA chains — the OnceLock stays cold.
        let mut all_certs: Vec<&Certificate> =
            Vec::with_capacity(1 + presented.len() + self.intermediates.len() + self.anchors.len());
        all_certs.push(leaf);
        all_certs.extend(presented.iter());
        all_certs.extend(self.intermediates.iter());
        all_certs.extend(self.anchors.iter());
        ensure_loaded_if_any_gost(&all_certs, self.gost_engine_path.as_deref())
            .map_err(|source| TrustError::EngineLoadFailed { source })?;

        // 1. Pre-validate the leaf (cheap, rejects obvious garbage early).
        pre_validate_end_entity(leaf, &self.pre_cfg, now)?;

        // 2. Build a chain to a known anchor.
        let chain = build_chain(
            leaf,
            presented,
            &self.intermediates,
            &self.anchors,
            self.max_depth,
        )?;

        // 3. Cryptographically verify each link.
        verify_chain_signatures(&chain)?;

        // 4. BasicConstraints on internal links.
        verify_basic_constraints(&chain)?;

        // 4b. Per-link RFC 5280 checks on intermediates/anchor: validity
        //     window, BC=CA=TRUE, KU(keyCertSign). This complements the leaf
        //     pre-validation by ensuring no expired intermediate or
        //     intermediate without keyCertSign slips through.
        verify_intermediate_constraints(&chain, now, self.pre_cfg.clock_skew)?;

        // 4c. Profile version-gate (4.1) + unknown-critical-extension scan
        //     (2.3) over every cert in the chain (fail-closed). The
        //     delegation-envelope checks (4.2-4.4, device.tags ⊇ requireTags +
        //     role/level/TTL ceilings) run in the PAM flow via
        //     `trust::enforce_delegation`, where the requested role/level and
        //     device tags are known — see openspec change tags-delegation §4.
        crate::x509::profile_validation::verify_profile_and_criticals(
            &chain,
            self.max_supported_profile_version,
        )?;

        // 5. Revocation — dispatched by configured mode (fail-closed in the
        //    OCSP modes: an undeterminable status refuses authentication).
        self.check_revocation_dispatch(&chain, now)?;

        // 6. SPKI pinning of the anchor.
        let Some(anchor_ref) = chain.last() else {
            return Err(TrustError::PathBuild("internal: empty verified chain"));
        };
        verify_pinning(anchor_ref, &self.pins)?;

        // 7. Compose the result.
        let Some(end_entity_ref) = chain.first() else {
            return Err(TrustError::PathBuild("internal: empty verified chain"));
        };
        let end_entity = end_entity_ref.clone();
        let anchor = anchor_ref.clone();
        // intermediates: chain[1..len-1]
        // Ветка достижима только при chain.len() > 2, поэтому диапазон
        // 1..len-1 всегда в границах.
        #[allow(clippy::indexing_slicing)]
        let middle: Vec<Certificate> = if chain.len() > 2 {
            chain[1..chain.len() - 1].to_vec()
        } else {
            Vec::new()
        };
        Ok(Stage2VerifiedChain {
            end_entity,
            chain: middle,
            anchor,
        })
    }

    /// Revocation dispatch over the configured [`RevocationMode`].
    ///
    /// * `None`  — no revocation check.
    /// * `Crl`   — strict offline CRL (unchanged behaviour).
    /// * `Ocsp`  — every non-anchor cert is checked via OCSP; the CRL store
    ///   is not consulted.
    /// * `CrlThenOcsp` — a fresh covering CRL gives the verdict offline;
    ///   otherwise OCSP is mandatory.
    ///
    /// Anchors are never OCSP-checked (trust in an anchor is the trust store
    /// itself; responders do not answer for it).
    fn check_revocation_dispatch(
        &self,
        chain: &[Certificate],
        now: SystemTime,
    ) -> Result<(), TrustError> {
        match self.revocation_mode {
            RevocationMode::None => Ok(()),
            RevocationMode::Crl => check_revocation(chain, &self.crl_store, &self.rev_cfg, now),
            RevocationMode::Ocsp => self.check_revocation_ocsp(chain, now, false),
            RevocationMode::CrlThenOcsp => self.check_revocation_ocsp(chain, now, true),
        }
    }

    /// OCSP path for the `ocsp` and `crl_then_ocsp` modes.
    ///
    /// Walks every non-anchor certificate (`chain[0..len-1]`), pairing each
    /// with its issuer (the next chain element).  When `crl_first` is set a
    /// fresh covering CRL short-circuits the network call for that cert.
    fn check_revocation_ocsp(
        &self,
        chain: &[Certificate],
        now: SystemTime,
        crl_first: bool,
    ) -> Result<(), TrustError> {
        // The anchor (last element) is never OCSP-checked.
        let last = chain.len().saturating_sub(1);
        for idx in 0..last {
            let Some(subject) = chain.get(idx) else { break };
            let Some(issuer) = chain.get(idx + 1) else {
                break;
            };

            if crl_first {
                match crl_status_for(subject, chain, &self.crl_store, &self.rev_cfg, now)? {
                    CrlCoverage::Covered(true) => {
                        return Err(TrustError::Revoked(subject.serial_hex().to_lowercase()));
                    }
                    CrlCoverage::Covered(false) => {
                        tracing::debug!(
                            target: "tessera.ocsp",
                            serial = %subject.serial_hex().to_lowercase(),
                            "revocation status from fresh CRL; OCSP skipped"
                        );
                        continue;
                    }
                    CrlCoverage::NotCovered => {}
                }
            }

            self.check_one_ocsp(subject, issuer)?;
        }
        Ok(())
    }

    /// Runs the cache → network → verify flow for one (subject, issuer)
    /// pair and maps every failure to a fail-closed [`TrustError`].
    ///
    /// The validity window of both the cached and freshly fetched responses
    /// is re-checked inside [`verify_ocsp_response`] against the real wall
    /// clock, so no `now` is threaded here.
    fn check_one_ocsp(
        &self,
        subject: &Certificate,
        issuer: &Certificate,
    ) -> Result<(), TrustError> {
        let Some(url) = self.ocsp_responder_url.as_ref() else {
            return Err(TrustError::Ocsp(
                "ocsp mode active but no responder URL configured".to_string(),
            ));
        };
        let serial = subject.serial_hex().to_lowercase();

        // Untrusted helpers for responder-chain building: configured
        // intermediates plus the certificate's own issuer.
        let mut untrusted: Vec<Certificate> = Vec::with_capacity(self.intermediates.len() + 1);
        untrusted.extend(self.intermediates.iter().cloned());
        untrusted.push(issuer.clone());
        let ctx = OcspVerifyContext {
            anchors: &self.anchors,
            untrusted: &untrusted,
            clock_skew: self.clock_skew,
            gost_engine_path: self.gost_engine_path.as_deref(),
        };

        let cache_key = OcspCacheKey::for_pair(subject, issuer).map_err(ocsp_err)?;

        // 1. Cache: a hit is re-verified (pre-signed -> request_der = None).
        if let Some(der) = self.ocsp_cache.get(&cache_key) {
            match verify_ocsp_response(&der, subject, issuer, None, &ctx) {
                Ok(status) => {
                    tracing::debug!(
                        target: "tessera.ocsp",
                        serial = %serial,
                        source = "cache",
                        "OCSP status from cache"
                    );
                    return Self::apply_status(&status, &serial);
                }
                Err(_) => {
                    // Stale/invalid cache entry: evict and fall through to net.
                    self.ocsp_cache.remove(&cache_key);
                }
            }
        }

        // 2. Network: build request, POST, verify (request_der = Some).
        let request = OcspRequestData::build(subject.x509(), issuer.x509()).map_err(ocsp_err)?;
        tracing::debug!(
            target: "tessera.ocsp",
            serial = %serial,
            responder = %url.host,
            "issuing OCSP request"
        );
        let response_der =
            post_ocsp_request(url, request.der(), self.ocsp_timeout).map_err(ocsp_err)?;
        let status =
            verify_ocsp_response(&response_der, subject, issuer, Some(request.der()), &ctx)
                .map_err(ocsp_err)?;
        tracing::debug!(
            target: "tessera.ocsp",
            serial = %serial,
            source = "network",
            "OCSP status from responder"
        );

        // 3. Cache definite statuses; a cache-write failure is non-fatal.
        if let Err(err) = self.ocsp_cache.put(&cache_key, &response_der, &status) {
            tracing::warn!(
                target: "tessera.ocsp",
                serial = %serial,
                error = %err,
                "failed to write OCSP cache entry"
            );
        }
        Self::apply_status(&status, &serial)
    }

    /// Maps a verified [`CertStatus`] to the fail-closed chain verdict.
    fn apply_status(status: &CertStatus, serial: &str) -> Result<(), TrustError> {
        match status {
            CertStatus::Good => Ok(()),
            CertStatus::Revoked { .. } => {
                tracing::warn!(
                    target: "tessera.ocsp",
                    serial = %serial,
                    "certificate revoked per OCSP responder"
                );
                Err(TrustError::Revoked(serial.to_string()))
            }
        }
    }
}

impl Stage2TrustVerifier for OpensslVerifier {
    fn verify(
        &self,
        leaf: &Certificate,
        presented: &[Certificate],
    ) -> Result<Stage2VerifiedChain, TrustError> {
        self.verify_at(leaf, presented, SystemTime::now())
    }
}
