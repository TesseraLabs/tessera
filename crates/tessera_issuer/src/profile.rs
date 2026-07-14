//! Issuance request profiles: the two certificate shapes the core builds.
//!
//! A [`LeafRequest`] is an engineer shift-leaf; a [`CaRequest`] is an
//! organisation CA. Each names exactly the inputs its profile needs; the core
//! turns them into the mandatory extension set, rejecting an incomplete request
//! before any signing (`cert-issuance`: fail-closed on a missing mandatory
//! extension).

use tessera_ext::delegation::DelegationConstraints;

/// A certificate validity window, in Unix seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    /// `notBefore`, Unix seconds.
    pub not_before: u64,
    /// `notAfter`, Unix seconds.
    pub not_after: u64,
}

impl Validity {
    /// The window length in seconds, saturating at zero for an inverted window.
    #[must_use]
    pub fn duration_secs(self) -> u64 {
        self.not_after.saturating_sub(self.not_before)
    }
}

/// The integrity ceiling carried by the optional leaf `max_integrity` extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntegrityCeiling {
    /// Astra МКЦ linear integrity level (`i8`, −128..=127).
    pub level: i8,
    /// Category bitmask (up to 64 bits).
    pub categories: u64,
}

/// A request to issue an engineer shift-leaf.
///
/// `host_binding` and `user_binding` MUST be non-empty; `allowed_roles` and
/// `profile_version` are always emitted (an empty role list is a valid "grants
/// no roles" leaf). `max_integrity` is optional.
#[derive(Debug, Clone)]
pub struct LeafRequest {
    /// Subject distinguished name, RFC 4514 (e.g. `CN=ivanov,O=Org`).
    pub subject: String,
    /// Subject public key info, DER (`SubjectPublicKeyInfo`).
    pub subject_spki_der: Vec<u8>,
    /// Validity window.
    pub validity: Validity,
    /// Host descriptors (`"*"`, `"sha256:<hex>"`, or a raw `machine_id`).
    pub host_binding: Vec<String>,
    /// User descriptors (`"*"` or exact PAM usernames).
    pub user_binding: Vec<String>,
    /// Roles the leaf may activate.
    pub allowed_roles: Vec<String>,
    /// Optional integrity ceiling.
    pub max_integrity: Option<IntegrityCeiling>,
    /// Certificate-format version.
    pub profile_version: u32,
}

/// A request to issue an organisation CA, carrying the delegation envelope it
/// assigns to certificates beneath it.
#[derive(Debug, Clone)]
pub struct CaRequest {
    /// Subject distinguished name, RFC 4514.
    pub subject: String,
    /// Subject public key info, DER (`SubjectPublicKeyInfo`).
    pub subject_spki_der: Vec<u8>,
    /// Validity window.
    pub validity: Validity,
    /// The delegation envelope assigned to this CA.
    pub constraints: DelegationConstraints,
    /// Certificate-format version.
    pub profile_version: u32,
}

/// A request to issue a self-signed fleet root.
///
/// A root is a CA whose issuer equals its subject and which establishes the
/// fleet's first delegation envelope; it carries exactly the same fields as a
/// [`CaRequest`], so it is that request shape (the distinction is the issuance
/// operation — [`crate::issue_root`] takes no parent — not the request data).
pub type RootRequest = CaRequest;
