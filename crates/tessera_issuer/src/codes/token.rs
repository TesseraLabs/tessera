//! The operator key on a PKCS#11 token.
//!
//! The default place for an operator key: the private half never leaves the
//! token, and the shared secret is computed there with `CKM_ECDH1_DERIVE`.
//!
//! # Addressing
//!
//! The key is found by `CKA_ID`, not by `CKA_LABEL` as the issuance keys of
//! this crate are. An operator token carries one key pair per epoch of the
//! operator's own credential, and the two halves of a pair share their `CKA_ID`
//! — which is exactly what this module needs, since the public half is read from
//! the token to check that the key agreeing the secret is the key the operator
//! ticket names. Labels are free text a token owner sets; the id is what pairs
//! the halves.
//!
//! # What the token is not trusted to do
//!
//! The peer point is validated here, before it is handed to the token. The
//! contract puts that obligation on every implementation of
//! [`KeyAgreement`](tessera_codes_contract::key::KeyAgreement), and a token that
//! quietly accepts a point off the curve would leak the operator key through
//! codes nobody could tell from correct ones. Doing it twice costs one point
//! decompression per call.

use std::path::PathBuf;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};

use tessera_codes_contract::key::{KeyAgreement, KeyAgreementError, SharedSecret};
use tessera_codes_contract::profile::AlgorithmProfile;

use crate::codes::agreement::{require_p256, OperatorKey};
use crate::codes::annex::KeyStorage;
use crate::pkcs11::{find_slot_in, PinSource, Pkcs11SignError};

/// Length of the shared secret of the P-256 profile, in bytes.
///
/// The null key derivation function of `CKM_ECDH1_DERIVE` takes the agreed
/// value as it is, and on P-256 that is the x coordinate — the same 32 bytes
/// the device's OpenSSL derivation produces.
const P256_SECRET_LEN: u64 = 32;

/// Length of an uncompressed SEC1 point on P-256, in bytes.
const P256_UNCOMPRESSED_LEN: usize = 65;

/// Length of a compressed SEC1 point on P-256, in bytes.
const P256_COMPRESSED_LEN: usize = 33;

/// DER tag of an `OCTET STRING`, which `CKA_EC_POINT` wraps its point in.
const DER_OCTET_STRING: u8 = 0x04;

/// How to reach the operator key inside a PKCS#11 module.
#[derive(Debug, Clone)]
pub struct TokenKeyConfig {
    /// Path of the PKCS#11 module.
    pub module_path: PathBuf,
    /// Token label to select, or the first token present.
    pub token_label: Option<String>,
    /// `CKA_ID` of the operator key pair.
    pub key_id: Vec<u8>,
}

/// The operator key, on a token.
pub struct TokenOperatorKey<P: PinSource> {
    ctx: Pkcs11,
    config: TokenKeyConfig,
    pin_source: P,
    public_point: Vec<u8>,
}

impl<P: PinSource> core::fmt::Debug for TokenOperatorKey<P> {
    /// Names the module and the key id; there is no PIN field to leak, and the
    /// key material never enters this process.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TokenOperatorKey")
            .field("module", &self.config.module_path)
            .field("key_id", &hex::encode(&self.config.key_id))
            .finish_non_exhaustive()
    }
}

impl<P: PinSource> TokenOperatorKey<P> {
    /// Opens the module and reads the public half of the operator key.
    ///
    /// The public half is read at open time rather than at the first agreement:
    /// a token that carries no key of that `CKA_ID` should be reported before
    /// the operator has read a challenge out loud, not in the middle of a call.
    ///
    /// # Errors
    ///
    /// [`TokenKeyError::Profile`] when the fleet profile is not one this build
    /// computes, and the [`TokenKeyError`] of the first token operation that
    /// failed — a module that will not load, a token that is not there, a key id
    /// no object carries, or a public point the token reports in a shape this
    /// module cannot read.
    pub fn open(
        config: TokenKeyConfig,
        pin_source: P,
        profile: AlgorithmProfile,
    ) -> Result<Self, TokenKeyError> {
        require_p256(profile).map_err(TokenKeyError::Profile)?;
        if config.key_id.is_empty() {
            return Err(TokenKeyError::NoKeyId);
        }
        if !config.module_path.exists() {
            return Err(TokenKeyError::Pkcs11(Pkcs11SignError::ModulePathMissing(
                config.module_path.clone(),
            )));
        }

        let ctx = Pkcs11::new(&config.module_path)
            .map_err(|e| TokenKeyError::Pkcs11(Pkcs11SignError::ModuleLoad(e.to_string())))?;
        ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| TokenKeyError::Pkcs11(Pkcs11SignError::Init(e.to_string())))?;

        let mut key = Self {
            ctx,
            config,
            pin_source,
            public_point: Vec::new(),
        };
        key.public_point = key.read_public_point()?;
        Ok(key)
    }

    /// Reads `CKA_EC_POINT` of the public object carrying the configured id.
    ///
    /// A public key object is readable without a login on every token that has
    /// one; when it is absent the module cannot answer which key the operator is
    /// about to derive with, and the refusal says so rather than deriving with
    /// whatever the id happens to reach.
    fn read_public_point(&self) -> Result<Vec<u8>, TokenKeyError> {
        let session = self.open_session()?;
        let handle = self
            .find_by_id(&session, ObjectClass::PUBLIC_KEY)?
            .ok_or(TokenKeyError::PublicKeyNotFound)?;
        let attributes = session
            .get_attributes(handle, &[AttributeType::EcPoint])
            .map_err(|e| TokenKeyError::Pkcs11(Pkcs11SignError::Session(e.to_string())))?;
        let raw = attributes
            .into_iter()
            .find_map(|attribute| match attribute {
                Attribute::EcPoint(value) => Some(value),
                _ => None,
            })
            .ok_or(TokenKeyError::UnusablePublicPoint)?;
        sec1_point(&raw).ok_or(TokenKeyError::UnusablePublicPoint)
    }

    /// Opens a read-write session on the configured token.
    fn open_session(&self) -> Result<Session, TokenKeyError> {
        let slot = find_slot_in(&self.ctx, self.config.token_label.as_deref())
            .map_err(TokenKeyError::Pkcs11)?;
        self.ctx
            .open_rw_session(slot)
            .map_err(|e| TokenKeyError::Pkcs11(Pkcs11SignError::Session(e.to_string())))
    }

    /// Finds the object of `class` carrying the configured `CKA_ID`.
    ///
    /// Exactly one, or none. A token carrying two objects of one class under one
    /// id cannot answer which key the operator is about to derive with, and
    /// taking whichever came first would make the answer depend on the order a
    /// driver happens to enumerate objects in — an operator would agree keys
    /// with one key today and another tomorrow, and the only symptom would be a
    /// code that does not fit.
    fn find_by_id(
        &self,
        session: &Session,
        class: ObjectClass,
    ) -> Result<Option<ObjectHandle>, TokenKeyError> {
        let template = [
            Attribute::Class(class),
            Attribute::Id(self.config.key_id.clone()),
        ];
        let found = session
            .find_objects(&template)
            .map_err(|e| TokenKeyError::Pkcs11(Pkcs11SignError::Session(e.to_string())))?;
        if found.len() > 1 {
            return Err(TokenKeyError::AmbiguousKeyId {
                found: found.len(),
                id: hex::encode(&self.config.key_id),
            });
        }
        Ok(found.into_iter().next())
    }

    /// Performs the exchange on the token and reads the agreed value back.
    fn derive_on_token(&self, peer_public: &[u8]) -> Result<Vec<u8>, TokenKeyError> {
        let session = self.open_session()?;
        {
            // The PIN exists only across `C_Login`, as everywhere else in this
            // crate: fetched here, dropped at the end of this block.
            let pin = self.pin_source.pin().map_err(TokenKeyError::Pkcs11)?;
            session
                .login(UserType::User, Some(&pin))
                .map_err(|e| TokenKeyError::Pkcs11(Pkcs11SignError::Login(e.to_string())))?;
        }

        let private = self
            .find_by_id(&session, ObjectClass::PRIVATE_KEY)?
            .ok_or(TokenKeyError::PrivateKeyNotFound)?;
        let params = Ecdh1DeriveParams::new(EcKdf::null(), peer_public);
        // The derived value is a session object that must come back into this
        // process: it is the input of the contract's own derivation, and the
        // contract runs here, not on the token.
        let template = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::Token(false),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
            Attribute::ValueLen(P256_SECRET_LEN.into()),
        ];
        let derived = session
            .derive_key(&Mechanism::Ecdh1Derive(params), private, &template)
            .map_err(|e| TokenKeyError::Derive(e.to_string()))?;

        let attributes = session
            .get_attributes(derived, &[AttributeType::Value])
            .map_err(|e| TokenKeyError::Derive(e.to_string()))?;
        let value = attributes
            .into_iter()
            .find_map(|attribute| match attribute {
                Attribute::Value(value) => Some(value),
                _ => None,
            })
            .ok_or(TokenKeyError::SecretNotReadable)?;

        // The agreed value has one right length on this profile. A token that
        // returns fewer bytes has not agreed the secret the other side has: the
        // contract would accept anything non-empty, the derivation would run,
        // and the result would be a code computed from a shortened key — weaker
        // than the channel promises, and indistinguishable afterwards from a
        // correct one.
        let expected = usize::try_from(P256_SECRET_LEN).unwrap_or(usize::MAX);
        if value.len() != expected {
            return Err(TokenKeyError::UnusableSecretLength {
                expected,
                got: value.len(),
            });
        }

        // The derived object is a session object and would go with the session,
        // but the secret it holds is the whole strength of this call: it is
        // destroyed here rather than left to a driver's housekeeping.
        if let Err(error) = session.destroy_object(derived) {
            return Err(TokenKeyError::Derive(format!(
                "the agreed value could not be destroyed on the token: {error}"
            )));
        }

        // Best-effort logout; the session's Drop closes it regardless.
        if session.logout().is_err() {
            // Nothing actionable on a failed logout — the handle is dropped next.
        }
        Ok(value)
    }
}

impl<P: PinSource> KeyAgreement for TokenOperatorKey<P> {
    fn agree(&self, peer_public: &[u8]) -> Result<SharedSecret, KeyAgreementError> {
        // The obligation of the trait, discharged before the token sees the
        // point: on the curve, in the prime-order subgroup, not the identity.
        let _validated = p256::PublicKey::from_sec1_bytes(peer_public)
            .map_err(|_| KeyAgreementError::InvalidPublicPoint)?;
        let secret = self
            .derive_on_token(peer_public)
            .map_err(|error| KeyAgreementError::Backend(error.to_string()))?;
        SharedSecret::new(secret).map_err(|error| KeyAgreementError::Backend(error.to_string()))
    }
}

impl<P: PinSource> OperatorKey for TokenOperatorKey<P> {
    fn public_point(&self) -> Vec<u8> {
        self.public_point.clone()
    }

    fn storage(&self) -> KeyStorage {
        KeyStorage::Token
    }
}

/// Reads a `CKA_EC_POINT` value as a SEC1 point.
///
/// The attribute is specified as a DER `OCTET STRING` wrapping the point, and
/// most tokens write it that way; some report the bare point. Both are accepted,
/// and they are told apart by length rather than by the leading byte — an
/// uncompressed point opens with `0x04` too, which is also the tag of an
/// `OCTET STRING`.
fn sec1_point(raw: &[u8]) -> Option<Vec<u8>> {
    if matches!(raw.len(), P256_UNCOMPRESSED_LEN | P256_COMPRESSED_LEN) {
        return Some(raw.to_vec());
    }
    let (tag, rest) = raw.split_first()?;
    if *tag != DER_OCTET_STRING {
        return None;
    }
    // Short form only: a point of either curve fits well under 128 bytes, so a
    // long-form length here is not a point this module should be reading.
    let (length, body) = rest.split_first()?;
    let length = usize::from(*length);
    if length > body.len() || !matches!(length, P256_UNCOMPRESSED_LEN | P256_COMPRESSED_LEN) {
        return None;
    }
    body.get(..length).map(<[u8]>::to_vec)
}

/// Failure of the operator key on a token.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TokenKeyError {
    /// The fleet profile is not one this build computes.
    #[error(transparent)]
    Profile(KeyAgreementError),
    /// No `CKA_ID` was configured.
    #[error("the operator key is addressed by its CKA_ID, and none was given")]
    NoKeyId,
    /// The module, the token or the session failed.
    #[error(transparent)]
    Pkcs11(Pkcs11SignError),
    /// More than one object of one class carries the configured id.
    #[error("{found} objects on the token carry the CKA_ID {id}; the id has to name one key")]
    AmbiguousKeyId {
        /// How many objects matched.
        found: usize,
        /// The id that matched them, in hexadecimal.
        id: String,
    },
    /// The token returned an agreed value of the wrong length.
    #[error("the token returned {got} bytes of agreed value where the profile has {expected}: a shortened secret is a weakened code")]
    UnusableSecretLength {
        /// Length the profile has.
        expected: usize,
        /// Length the token returned.
        got: usize,
    },
    /// No public key object carries the configured id.
    #[error("no public key object on the token carries that CKA_ID")]
    PublicKeyNotFound,
    /// No private key object carries the configured id.
    #[error("no private key object on the token carries that CKA_ID")]
    PrivateKeyNotFound,
    /// The public point is not in a shape this module reads.
    #[error("the token reports a public point this build cannot read")]
    UnusablePublicPoint,
    /// The token refused the derivation.
    #[error("the token refused the key agreement: {0}")]
    Derive(String),
    /// The token computed the secret and would not hand it back.
    #[error("the token would not release the agreed value; the derived key template asks for an extractable session object")]
    SecretNotReadable,
}

#[cfg(test)]
mod tests {
    use super::{sec1_point, P256_UNCOMPRESSED_LEN};

    #[test]
    fn a_bare_point_is_taken_as_it_is() {
        let point = vec![0x04; P256_UNCOMPRESSED_LEN];
        assert_eq!(sec1_point(&point), Some(point));
    }

    #[test]
    fn a_point_wrapped_in_an_octet_string_is_unwrapped() {
        let point = vec![0x04; P256_UNCOMPRESSED_LEN];
        let mut wrapped = vec![0x04, 0x41];
        wrapped.extend_from_slice(&point);
        assert_eq!(sec1_point(&wrapped), Some(point));
    }

    #[test]
    fn anything_else_is_refused_rather_than_guessed() {
        assert_eq!(sec1_point(&[]), None);
        assert_eq!(sec1_point(&[0x30, 0x41]), None);
        // An OCTET STRING whose length does not describe a point of either
        // curve: a value that is something else entirely.
        let mut wrapped = vec![0x04, 0x08];
        wrapped.extend_from_slice(&[0x00; 8]);
        assert_eq!(sec1_point(&wrapped), None);
    }
}
