//! Stage-2 trust verifier: an `OpensslVerifier` that orchestrates the
//! T03 → T04 → T05 → T06 → T07 → T08 pipeline.
//!
//! The stage-1 [`crate::trust::TrustVerifier`] uses a different
//! signature (it takes a `host_id` and returns a stage-1 `VerifiedChain`).
//! Until the two type families are unified in a later stage, this verifier
//! exposes its own [`Stage2TrustVerifier`] trait and emits its own
//! [`Stage2VerifiedChain`].

use crate::crl::{check_revocation, CrlStore, RevocationConfig};
use crate::gost::engine::ensure_loaded_if_any_gost;
use crate::x509::basic_constraints::{verify_basic_constraints, verify_intermediate_constraints};
use crate::x509::chain::build_chain;
use crate::x509::pinning::{verify_pinning, SpkiPin};
use crate::x509::pre_validate::{pre_validate_end_entity, PreValidateConfig};
use crate::x509::signatures::verify_chain_signatures;
use crate::x509::{Certificate, TrustError};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

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

/// Builder/constructor configuration for [`OpensslVerifier`].
pub struct OpensslVerifierConfig {
    /// Trusted self-signed roots.
    pub anchors: Vec<Certificate>,
    /// Local intermediate trust pool (in addition to those presented over the wire).
    pub intermediates: Vec<Certificate>,
    /// CRLs (PEM) configured at startup.  May be empty.
    pub crl_pems: Vec<Vec<u8>>,
    /// When `true`, expired CRLs are a hard error.
    pub crl_strict: bool,
    /// Permissible clock skew when comparing `notBefore`/`notAfter` against `now`.
    pub clock_skew: Duration,
    /// Permissible signature-algorithm OIDs (substring match against the
    /// algorithm's `Display` form).
    pub signature_alg_whitelist: Vec<String>,
    /// SPKI pins.  Empty = disabled.
    pub spki_pins: Vec<SpkiPin>,
    /// Maximum allowed chain length (including leaf and anchor).
    pub max_depth: usize,
    /// Optional path to the gost-engine .so/.dylib.  When `None` the engine
    /// is located via libcrypto's standard `OPENSSL_ENGINES` search path.
    ///
    /// Forwarded verbatim from [`crate::config::ValidatedConfig::gost_engine_path`].
    pub gost_engine_path: Option<PathBuf>,
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
    gost_engine_path: Option<PathBuf>,
}

impl std::fmt::Debug for OpensslVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpensslVerifier")
            .field("anchors", &self.anchors.len())
            .field("intermediates", &self.intermediates.len())
            .field("crl_store_len", &self.crl_store.len())
            .field("crl_strict", &self.rev_cfg.crl_strict)
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
        let crl_refs: Vec<&[u8]> = cfg.crl_pems.iter().map(Vec::as_slice).collect();
        let crl_store = CrlStore::from_pems(&crl_refs)?;
        Ok(Self {
            anchors: cfg.anchors,
            intermediates: cfg.intermediates,
            crl_store,
            rev_cfg: RevocationConfig {
                crl_strict: cfg.crl_strict,
            },
            pre_cfg: PreValidateConfig {
                clock_skew: cfg.clock_skew,
                signature_alg_whitelist: cfg.signature_alg_whitelist,
            },
            pins: cfg.spki_pins,
            max_depth: cfg.max_depth,
            gost_engine_path: cfg.gost_engine_path,
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

        // 5. Revocation.
        check_revocation(&chain, &self.crl_store, &self.rev_cfg, now)?;

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
