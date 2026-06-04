//! Path building: walk from a leaf certificate to a known trust anchor.
//! See `T04` in the stage-2 plan.

use super::{Certificate, TrustError};

/// Builds a leaf-first certificate chain ending in a trust anchor.
///
/// The returned vector starts with the leaf and ends with the anchor; each
/// intermediate is an issuer of the previous element, located by matching
/// the AKI `keyIdentifier` against a candidate's SKI.  When the AKI is
/// absent we fall back to a strict subject == issuer DN match.
///
/// # Parameters
///
/// * `leaf` — end-entity certificate to anchor from.
/// * `presented` — extra certificates that came over the wire (excluding the leaf).
/// * `pool` — local intermediate trust store.
/// * `anchors` — trusted self-signed roots.  An anchor is acceptable only if
///   it is self-issued (`subject == issuer`) and either has no AKI or its
///   AKI `keyIdentifier` equals its own SKI.
/// * `max_depth` — maximum chain length (including leaf and anchor).  A
///   typical operational value is 4–6.
///
/// # Errors
///
/// * [`TrustError::PathBuild`] when no candidate issuer is found in
///   `presented` / `pool` / `anchors`, or when the anchor candidate is not
///   self-signed.
/// * [`TrustError::DepthExceeded`] when the chain length exceeds `max_depth`.
pub fn build_chain(
    leaf: &Certificate,
    presented: &[Certificate],
    pool: &[Certificate],
    anchors: &[Certificate],
    max_depth: usize,
) -> Result<Vec<Certificate>, TrustError> {
    if max_depth == 0 {
        return Err(TrustError::DepthExceeded(1, 0));
    }
    let mut chain: Vec<Certificate> = Vec::with_capacity(max_depth);
    chain.push(leaf.clone());

    loop {
        // Defensive: chain is never empty here because we just pushed the leaf.
        let Some(current) = chain.last() else {
            return Err(TrustError::PathBuild("internal: empty chain"));
        };

        if let Some(anchor) = find_issuer(current, anchors) {
            // Anchor must be self-signed: subject == issuer AND
            // (no AKI OR AKI keyIdentifier == own SKI).
            if !is_self_signed(anchor) {
                return Err(TrustError::PathBuild("anchor not self-signed"));
            }
            chain.push(anchor.clone());
            return Ok(chain);
        }

        if let Some(parent) = find_issuer(current, presented).or_else(|| find_issuer(current, pool))
        {
            chain.push(parent.clone());
            if chain.len() > max_depth {
                return Err(TrustError::DepthExceeded(chain.len(), max_depth));
            }
            continue;
        }

        return Err(TrustError::PathBuild("no issuer found"));
    }
}

fn is_self_signed(cert: &Certificate) -> bool {
    let subject_eq_issuer = cert
        .x509()
        .issuer_name()
        .try_cmp(cert.x509().subject_name())
        .is_ok_and(|o| o == std::cmp::Ordering::Equal);
    if !subject_eq_issuer {
        return false;
    }
    match (cert.aki(), cert.ski()) {
        (Some(aki), Some(ski)) => aki == ski,
        (None, _) => true,
        _ => false,
    }
}

fn find_issuer<'a>(cert: &Certificate, haystack: &'a [Certificate]) -> Option<&'a Certificate> {
    let target_aki = cert.aki();
    for cand in haystack {
        let aki_ski_ok = match (&target_aki, cand.ski()) {
            (Some(a), Some(s)) => a == &s,
            _ => false,
        };
        let dn_ok = cert
            .x509()
            .issuer_name()
            .try_cmp(cand.x509().subject_name())
            .is_ok_and(|o| o == std::cmp::Ordering::Equal);
        if dn_ok && (target_aki.is_none() || aki_ski_ok) {
            return Some(cand);
        }
    }
    None
}
