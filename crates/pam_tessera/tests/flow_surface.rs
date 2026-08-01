//! The flow surface a non-PAM host needs must survive the platform gates.
//!
//! The Windows service does not go through `pam_sm_*`: it implements
//! [`pam_tessera::flow::FlowIo`] over removable volumes and calls
//! [`pam_tessera::flow::authenticate_pkcs12`] directly, so the same code
//! decides trust on both platforms. This file pins that surface at compile
//! time — building it for a Windows target is what proves the entry point
//! survived the gating, and on Unix it costs a type check.

#![allow(missing_docs, clippy::unwrap_used)]

use secrecy::SecretString;
use tessera_core::pam_conv::PamConvError;

use pam_tessera::flow::{
    authenticate_pkcs12, Deps, FlowError, FlowIo, FlowOutcome, InMemoryFlowIo, NoopMountOps,
};

/// A PIN prompter the caller supplies; a plain `fn` satisfies the bound.
type Prompter = fn(&str) -> Result<SecretString, PamConvError>;

/// Signature of the entry point, spelled out so a change to it breaks here.
type AuthenticatePkcs12 = for<'a> fn(
    Deps<'a>,
    &InMemoryFlowIo,
    &str,
    &str,
    String,
    Prompter,
) -> Result<FlowOutcome<NoopMountOps>, FlowError>;

/// The associated mount-ops type has to be nameable too — `FlowOutcome` is
/// generic over it, so a caller cannot spell the return type without it.
type _Ops = <InMemoryFlowIo as FlowIo>::Ops;

#[test]
fn authenticate_pkcs12_is_callable_without_pam() {
    let entry: AuthenticatePkcs12 = authenticate_pkcs12;
    // Comparing against a null pointer would be a tautology; taking the
    // address is enough to force the coercion above to be real code.
    assert!(std::ptr::fn_addr_eq(
        entry,
        authenticate_pkcs12 as AuthenticatePkcs12
    ));
}
