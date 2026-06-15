//! Session-policy orchestrator — decides which [`IntegrityLabel`] to
//! apply (or skip) given a [`MacBackend`], the validated [`MacPolicy`],
//! the cert's `MAX_INTEGRITY` (when present), and the live PAM
//! session context.
//!
//! The orchestrator is feature-agnostic: it takes the backend by `&dyn`
//! so the stub, the mock, and the real `ParsecBackend` all flow through
//! the same decision tree.

use std::path::PathBuf;

use crate::config::validated::{CertIntegrityMode, MacPolicy};
use crate::mac::audit;
use crate::mac::backend::{MacBackend, MacError, MacRuntime};
use crate::mac::IntegrityLabel;
use crate::x509::CertIdent;

/// Per-session inputs (PAM user, service, cert identity, optional
/// `$HOME`).
#[derive(Debug, Clone)]
pub struct SessionContext {
    /// PAM user being authenticated.
    pub pam_user: String,
    /// PAM service name (e.g. `login`, `sudo`).
    pub pam_service: String,
    /// Cert identifiers, for audit events.
    pub cert_ident: CertIdent,
    /// Resolved `$HOME` if the caller has it, for the home-label
    /// mismatch warning.
    pub home_dir: Option<PathBuf>,
}

/// What happened inside [`apply_session_policy`].
#[derive(Debug, Clone)]
pub struct Outcome {
    /// Kind of outcome — see [`OutcomeKind`].
    pub kind: OutcomeKind,
}

/// Discriminator for [`Outcome`].
#[derive(Debug, Clone)]
pub enum OutcomeKind {
    /// Backend was called and accepted `label`.
    Applied(IntegrityLabel),
    /// No backend call was made; `reason` is a short stable tag for
    /// dashboards.
    Skipped(&'static str),
}

/// Orchestrator errors — represent policy or backend failures that
/// MUST translate to a PAM authentication failure.
#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    /// `cert_integrity=required` but the cert has no `MAX_INTEGRITY`
    /// extension.
    #[error("cert lacks MAX_INTEGRITY extension")]
    CertLacksExt,
    /// `cert_integrity=required` but the runtime probe reports the
    /// kernel/library is not active.
    #[error("MAC runtime required but not active: {0:?}")]
    RuntimeRequired(MacRuntime),
    /// Backend call (`get_user_mnkc` / `apply_session`) failed.
    #[error("MAC backend failure: {0}")]
    ApplyFailed(#[from] MacError),
    /// The role's requested `mac_mask` is not covered by the cert ceiling
    /// (`(ceiling & mask) != mask`). The role demands a label the cert does
    /// not authorise; per the mac-integrity spec this is an explicit deny,
    /// never a silent narrowing of the requested label.
    #[error("role mac_mask exceeds cert integrity ceiling")]
    MaskExceedsCeiling,
}

/// PAM services that warrant the home-dir label-mismatch warning.
fn is_interactive_service(svc: &str) -> bool {
    matches!(
        svc,
        "login" | "gdm-password" | "lightdm" | "sddm" | "kdm" | "sshd" | "fly-dm"
    )
}

/// Compute the effective integrity label for a session (orchestrator step 5).
///
/// The ceiling is the cert `MAX_INTEGRITY` extension, else the admin
/// `fallback_max_integrity`, else none. When `role_mac_mask` is `Some`, the
/// ceiling MUST cover it or the session is denied; the effective label is then
/// `mask ∩ ceiling ∩ user МНКЦ`. When `None`, the prior `min(ceiling, МНКЦ)`
/// semantics apply.
///
/// # Errors
///
/// [`OrchestratorError::MaskExceedsCeiling`] when `role_mac_mask` is set and
/// the cert ceiling does not cover it (no silent narrowing — mac-integrity
/// spec).
fn compute_effective_label(
    policy: &MacPolicy,
    cert_max: Option<IntegrityLabel>,
    role_mac_mask: Option<IntegrityLabel>,
    user_mnkc: &IntegrityLabel,
    ctx: &SessionContext,
) -> Result<IntegrityLabel, OrchestratorError> {
    // Determine the cert ceiling: cert ext, else admin fallback, else none.
    let ceiling = if let Some(cert_bound) = cert_max {
        Some(cert_bound)
    } else if let Some(fallback) = policy.fallback_max_integrity {
        audit::emit_fallback_used(&ctx.pam_user, &ctx.pam_service, fallback);
        Some(fallback)
    } else {
        None
    };

    let Some(mask) = role_mac_mask else {
        // No role mask → prior semantics.
        return Ok(match ceiling {
            Some(ceiling) => ceiling.intersect_cert_with_user(user_mnkc),
            // Cert imposes no bound, no admin fallback → user МНКЦ unbounded.
            None => *user_mnkc,
        });
    };

    // Role requests an explicit label. It MUST be covered by the cert ceiling —
    // the role gets exactly what it asks for or the login is denied; never a
    // silent narrowing (mac-integrity spec).
    let Some(ceiling) = ceiling else {
        // No cert ceiling and no admin fallback: nothing constrains the mask
        // from above, so it is bounded only by the user МНКЦ.
        return Ok(user_mnkc.intersect(&mask));
    };
    if !ceiling.covers(&mask) {
        audit::emit_mask_exceeds_ceiling(
            &ctx.cert_ident,
            &ctx.pam_user,
            &ctx.pam_service,
            mask,
            ceiling,
        );
        return Err(OrchestratorError::MaskExceedsCeiling);
    }
    // effective = mask ∩ ceiling ∩ user МНКЦ.
    Ok(ceiling.intersect_cert_with_user(user_mnkc).intersect(&mask))
}

/// Resolve and apply the effective integrity label for a PAM session.
///
/// See the module-level docs for the decision tree.
///
/// `role_mac_mask` is the requested label derived from the selected role's
/// `mac_mask` (role-format). When `Some`, the cert ceiling MUST cover it
/// (`ceiling.covers(mask)`) or the session is denied with
/// [`OrchestratorError::MaskExceedsCeiling`]; when covered, the effective
/// label is the intersection of the mask, the cert ceiling and the user МНКЦ.
/// When `None`, the prior `min(ceiling, МНКЦ)` semantics apply unchanged.
///
/// # Errors
///
/// * [`OrchestratorError::CertLacksExt`] — `Required` policy but the
///   cert is missing the extension.
/// * [`OrchestratorError::RuntimeRequired`] — `Required` policy but
///   the backend probe reports non-Active.
/// * [`OrchestratorError::ApplyFailed`] — backend MNKC lookup or
///   `apply_session` failed.
/// * [`OrchestratorError::MaskExceedsCeiling`] — `role_mac_mask` is set
///   and the cert ceiling does not cover it.
pub fn apply_session_policy(
    backend: &dyn MacBackend,
    policy: &MacPolicy,
    cert_max: Option<IntegrityLabel>,
    role_mac_mask: Option<IntegrityLabel>,
    ctx: &SessionContext,
) -> Result<Outcome, OrchestratorError> {
    // (1) explicit ignore wins.
    if matches!(policy.cert_integrity, CertIntegrityMode::Ignore) {
        audit::emit_mac_skipped("policy_ignore");
        return Ok(Outcome {
            kind: OutcomeKind::Skipped("policy_ignore"),
        });
    }

    // (2) probe runtime.
    let runtime = backend.probe();
    if runtime != MacRuntime::Active {
        match policy.cert_integrity {
            CertIntegrityMode::Required => {
                audit::emit_mac_runtime_required(&format!("{runtime:?}"));
                return Err(OrchestratorError::RuntimeRequired(runtime));
            }
            CertIntegrityMode::Optional => {
                audit::emit_mac_skipped("runtime_inactive");
                return Ok(Outcome {
                    kind: OutcomeKind::Skipped("runtime_inactive"),
                });
            }
            CertIntegrityMode::Ignore => {
                // Unreachable: step (1) already returned for `Ignore`.
                unreachable!("policy=Ignore handled in step (1)");
            }
        }
    }

    // (3) cert extension presence vs Required.
    if cert_max.is_none() && matches!(policy.cert_integrity, CertIntegrityMode::Required) {
        audit::emit_cert_lacks_ext(&ctx.cert_ident, &ctx.pam_user, &ctx.pam_service);
        return Err(OrchestratorError::CertLacksExt);
    }

    // (4) user MNKC.
    let user_mnkc = match backend.get_user_mnkc(&ctx.pam_user) {
        Ok(m) => m,
        Err(MacError::UserUnknown { .. }) => {
            audit::emit_user_unknown(&ctx.pam_user, &ctx.pam_service);
            return Err(OrchestratorError::ApplyFailed(MacError::UserUnknown {
                user: ctx.pam_user.clone(),
            }));
        }
        Err(e) => return Err(OrchestratorError::ApplyFailed(e)),
    };

    // (5) compute the effective label from the ceiling, user МНКЦ and the
    // optional role mask (may deny — see `compute_effective_label`).
    let effective = compute_effective_label(policy, cert_max, role_mac_mask, &user_mnkc, ctx)?;

    // (6) capping audit.
    if effective.strictly_below(&user_mnkc) {
        audit::emit_integrity_capped(
            &ctx.cert_ident,
            &ctx.pam_user,
            &ctx.pam_service,
            effective,
            user_mnkc,
        );
    }

    // (7) home-dir advisory.
    if policy.warn_on_homedir_label_mismatch && is_interactive_service(&ctx.pam_service) {
        if let Some(home) = ctx.home_dir.as_deref() {
            if let Ok(home_label) = backend.get_file_label(home) {
                if home_label.level > effective.level {
                    audit::emit_homedir_label_above(
                        &ctx.pam_user,
                        &ctx.pam_service,
                        home,
                        home_label,
                        effective,
                    );
                }
            }
        }
    }

    // (8) apply.
    match backend.apply_session(effective) {
        Ok(()) => {
            audit::emit_integrity_applied(
                &ctx.cert_ident,
                &ctx.pam_user,
                &ctx.pam_service,
                effective,
            );
            Ok(Outcome {
                kind: OutcomeKind::Applied(effective),
            })
        }
        Err(e) => {
            audit::emit_apply_failed(
                &ctx.cert_ident,
                &ctx.pam_user,
                &ctx.pam_service,
                &format!("{e}"),
            );
            Err(OrchestratorError::ApplyFailed(e))
        }
    }
}
