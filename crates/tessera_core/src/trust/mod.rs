//! Trust verification traits and stubs.

pub mod delegation;
pub mod delegation_audit;
pub mod openssl_verifier;
pub mod stub;
pub mod types;

pub use delegation::{
    chain_carries_constraints, enforce_delegation, enforce_delegation_opt, DelegationError,
};
pub use openssl_verifier::{
    OpensslVerifier, OpensslVerifierConfig, Stage2TrustVerifier, Stage2VerifiedChain,
};
pub use stub::StubVerifier;
pub use types::{Certificate, HostIdHash, TrustVerifier, VerifiedChain};
