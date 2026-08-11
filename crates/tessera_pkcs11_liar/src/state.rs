//! What the module lies about, and what it tells the truth about.
//!
//! Everything here is plain Rust: the token's object store, the key material,
//! and the answer each mode gives to an attribute query. The C ABI in
//! [`crate`] does nothing but marshal pointers into these calls, so the
//! behaviour under test is reachable from ordinary unit tests.

use cryptoki_sys::{
    CKA_ALWAYS_SENSITIVE, CKA_CLASS, CKA_EC_PARAMS, CKA_EC_POINT, CKA_EXTRACTABLE, CKA_ID,
    CKA_KEY_TYPE, CKA_LABEL, CKA_NEVER_EXTRACTABLE, CKA_PRIVATE, CKA_SENSITIVE, CKA_SIGN,
    CKA_TOKEN, CKA_VALUE, CKA_VERIFY, CKK_EC, CKM_ECDSA, CKM_ECDSA_SHA256, CKM_EC_KEY_PAIR_GEN,
    CKO_DATA, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKR_DEVICE_ERROR, CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCONSISTENT, CK_ATTRIBUTE_TYPE, CK_BBOOL, CK_FALSE, CK_KEY_TYPE,
    CK_MECHANISM_TYPE, CK_OBJECT_CLASS, CK_RV, CK_TRUE, CK_ULONG,
};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;

/// GOST R 34.10-2012 512-bit key pair generation, as the TC26 vendor block
/// numbers it (`NSSCK_VENDOR_PKCS11_RU_TEAM` `0xD432_1000` + `0x005`). Taken
/// from `pkcs11tc26_12.h` in the Rutoken PKCS#11 framework, so a caller that
/// recognises the mechanism on a real Rutoken recognises it here too.
///
/// The fixture announces it and cannot perform it — that pairing is the point:
/// a device may declare a national-standard mechanism the tooling must still
/// refuse to use.
pub const CKM_GOSTR3410_512_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0xD432_1005;

/// The mechanisms the fixture announces in every mode but [`Mode::NoMechanisms`].
pub const ANNOUNCED_MECHANISMS: [CK_MECHANISM_TYPE; 4] = [
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDSA,
    CKM_ECDSA_SHA256,
    CKM_GOSTR3410_512_KEY_PAIR_GEN,
];

/// The environment variable the mode is read from.
pub const MODE_VAR: &str = "TESSERA_PKCS11_LIAR_MODE";

/// `id-ecPublicKey` P-256 named curve, DER: `OBJECT IDENTIFIER 1.2.840.10045.3.1.7`.
const P256_EC_PARAMS: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// The behaviour the fixture was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Applies the template and reports it back; `CKA_VALUE` is sensitive.
    /// The control: a test that fails here found a bug in the caller.
    #[default]
    Honest,
    /// Accepts `CKA_EXTRACTABLE` = `FALSE` and reports `TRUE`. The provider that
    /// says "done" and did something else.
    IgnoresTemplate,
    /// Reports `CKA_EXTRACTABLE` = `FALSE`, `CKA_SENSITIVE` = `TRUE`,
    /// `CKA_NEVER_EXTRACTABLE` = `TRUE` — and hands out `CKA_VALUE` anyway.
    /// Read-back alone cannot see this one; only the probe can.
    Leaks,
    /// Returns `CK_UNAVAILABLE_INFORMATION` for `CKA_EXTRACTABLE`. Absence must
    /// not be read as `FALSE`.
    AttributesAbsent,
    /// `C_GetMechanismList` returns an empty list: a carrier-only device.
    NoMechanisms,
    /// `CKA_EXTRACTABLE` = `FALSE` but `CKA_NEVER_EXTRACTABLE` = `FALSE`: the key is
    /// unextractable now and was not always.
    WasExtractable,
}

impl Mode {
    /// Reads the mode from `TESSERA_PKCS11_LIAR_MODE`; anything unrecognised
    /// is [`Mode::Honest`], so a typo in a test yields the control behaviour
    /// rather than a silently different lie.
    #[must_use]
    pub fn from_env() -> Self {
        std::env::var(MODE_VAR)
            .ok()
            .as_deref()
            .map_or(Self::Honest, Self::from_name)
    }

    /// Maps a mode name to a mode; unknown names are [`Mode::Honest`].
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        match name {
            "ignores-template" => Self::IgnoresTemplate,
            "leaks" => Self::Leaks,
            "attributes-absent" => Self::AttributesAbsent,
            "no-mechanisms" => Self::NoMechanisms,
            "was-extractable" => Self::WasExtractable,
            _ => Self::Honest,
        }
    }

    /// The mechanism list this mode announces.
    #[must_use]
    pub fn mechanisms(self) -> &'static [CK_MECHANISM_TYPE] {
        match self {
            Self::NoMechanisms => &[],
            _ => &ANNOUNCED_MECHANISMS,
        }
    }
}

/// What a `C_GetAttributeValue` query yields for one attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The attribute exists and these are its bytes.
    Value(Vec<u8>),
    /// The attribute exists but the token refuses to reveal it
    /// (`CKR_ATTRIBUTE_SENSITIVE`).
    Sensitive,
    /// The object has no such attribute (`CKR_ATTRIBUTE_TYPE_INVALID`).
    TypeInvalid,
}

/// The key material or payload behind an object handle.
#[derive(Debug, Clone)]
pub enum Material {
    /// A P-256 private key, held as its scalar.
    EcPrivate {
        /// The scalar, big-endian, exactly as `CKA_VALUE` would carry it.
        scalar: [u8; 32],
    },
    /// A P-256 public key, held as its uncompressed SEC1 point.
    EcPublic {
        /// The `0x04 || X || Y` encoding, without the DER `OCTET STRING` wrapper.
        point: Vec<u8>,
    },
    /// A data object's contents.
    Data {
        /// The bytes handed to `C_CreateObject` as `CKA_VALUE`.
        value: Vec<u8>,
    },
}

/// One object in the fixture's store.
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the fields are PKCS#11 CK_BBOOL attributes; grouping them into \
              enums would hide which attribute each one answers"
)]
pub struct StoredObject {
    /// `CKA_CLASS`.
    pub class: CK_OBJECT_CLASS,
    /// `CKA_KEY_TYPE`, for key objects.
    pub key_type: Option<CK_KEY_TYPE>,
    /// `CKA_LABEL`.
    pub label: Vec<u8>,
    /// `CKA_ID`.
    pub id: Vec<u8>,
    /// `CKA_TOKEN`.
    pub token: bool,
    /// `CKA_PRIVATE`.
    pub private: bool,
    /// `CKA_EXTRACTABLE` as the template asked for it — not necessarily as the
    /// module reports it.
    pub requested_extractable: bool,
    /// `CKA_SENSITIVE` as the template asked for it.
    pub requested_sensitive: bool,
    /// The key material or payload.
    pub material: Material,
}

impl StoredObject {
    /// Answers one attribute query the way `mode` has the module answer it.
    ///
    /// The mode only reaches the four hardware-guarantee booleans and
    /// `CKA_VALUE` of a private key; every other attribute is reported as
    /// stored, because a module that lied about `CKA_CLASS` would fail the
    /// caller before the interesting question is ever asked.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn attribute(&self, mode: Mode, attribute: CK_ATTRIBUTE_TYPE) -> Answer {
        match attribute {
            CKA_CLASS => Answer::Value(ulong_bytes(self.class)),
            CKA_TOKEN => Answer::Value(bbool_bytes(self.token)),
            CKA_PRIVATE => Answer::Value(bbool_bytes(self.private)),
            CKA_LABEL => Answer::Value(self.label.clone()),
            CKA_ID => Answer::Value(self.id.clone()),
            CKA_KEY_TYPE => self
                .key_type
                .map_or(Answer::TypeInvalid, |t| Answer::Value(ulong_bytes(t))),
            _ => self.class_specific_attribute(mode, attribute),
        }
    }

    fn class_specific_attribute(&self, mode: Mode, attribute: CK_ATTRIBUTE_TYPE) -> Answer {
        match &self.material {
            Material::EcPrivate { scalar } => self.private_key_attribute(mode, attribute, scalar),
            Material::EcPublic { point } => match attribute {
                CKA_EC_PARAMS => Answer::Value(P256_EC_PARAMS.to_vec()),
                CKA_EC_POINT => Answer::Value(der_octet_string(point)),
                // A public key is public: no mode makes it otherwise.
                CKA_VERIFY | CKA_EXTRACTABLE => Answer::Value(bbool_bytes(true)),
                CKA_SENSITIVE => Answer::Value(bbool_bytes(false)),
                _ => Answer::TypeInvalid,
            },
            Material::Data { value } => match attribute {
                CKA_VALUE => Answer::Value(value.clone()),
                _ => Answer::TypeInvalid,
            },
        }
    }

    fn private_key_attribute(
        &self,
        mode: Mode,
        attribute: CK_ATTRIBUTE_TYPE,
        scalar: &[u8; 32],
    ) -> Answer {
        match attribute {
            CKA_EC_PARAMS => Answer::Value(P256_EC_PARAMS.to_vec()),
            CKA_SIGN => Answer::Value(bbool_bytes(true)),
            CKA_EXTRACTABLE => match mode {
                Mode::IgnoresTemplate => Answer::Value(bbool_bytes(true)),
                Mode::Leaks | Mode::WasExtractable => Answer::Value(bbool_bytes(false)),
                Mode::AttributesAbsent => Answer::TypeInvalid,
                Mode::Honest | Mode::NoMechanisms => {
                    Answer::Value(bbool_bytes(self.requested_extractable))
                }
            },
            CKA_SENSITIVE => match mode {
                Mode::IgnoresTemplate => Answer::Value(bbool_bytes(false)),
                Mode::Leaks | Mode::WasExtractable => Answer::Value(bbool_bytes(true)),
                Mode::Honest | Mode::NoMechanisms | Mode::AttributesAbsent => {
                    Answer::Value(bbool_bytes(self.requested_sensitive))
                }
            },
            // The history attributes. `WasExtractable` is the only mode that
            // reports a key locked down after the fact: unextractable now,
            // extractable at some point before.
            CKA_NEVER_EXTRACTABLE => match mode {
                Mode::IgnoresTemplate | Mode::WasExtractable => Answer::Value(bbool_bytes(false)),
                Mode::Leaks | Mode::AttributesAbsent => Answer::Value(bbool_bytes(true)),
                Mode::Honest | Mode::NoMechanisms => {
                    Answer::Value(bbool_bytes(!self.requested_extractable))
                }
            },
            CKA_ALWAYS_SENSITIVE => match mode {
                Mode::IgnoresTemplate => Answer::Value(bbool_bytes(false)),
                Mode::Leaks | Mode::AttributesAbsent | Mode::WasExtractable => {
                    Answer::Value(bbool_bytes(true))
                }
                Mode::Honest | Mode::NoMechanisms => {
                    Answer::Value(bbool_bytes(self.requested_sensitive))
                }
            },
            // The whole reason the fixture exists: `Leaks` reports the key as
            // unextractable and hands the scalar over anyway, which no amount
            // of reading attributes back can detect.
            CKA_VALUE => match mode {
                Mode::Leaks => Answer::Value(scalar.to_vec()),
                _ => Answer::Sensitive,
            },
            _ => Answer::TypeInvalid,
        }
    }
}

/// A `C_SignInit` that has not yet been consumed by `C_Sign`.
#[derive(Debug, Clone, Copy)]
struct SignOperation {
    mechanism: CK_MECHANISM_TYPE,
    key: u64,
}

/// One open session.
#[derive(Debug, Default)]
struct Session {
    logged_in: bool,
    /// Handles left to hand out from the running `C_FindObjects`, newest last.
    find: Option<Vec<u64>>,
    sign: Option<SignOperation>,
}

/// The whole token: one slot, one store, a handful of sessions.
#[derive(Debug)]
pub struct State {
    mode: Mode,
    initialized: bool,
    objects: Vec<StoredObject>,
    sessions: Vec<Option<Session>>,
    /// How many pairs have been generated; feeds the key derivation so a second
    /// generation in one process yields a second, still reproducible, key.
    generated: u8,
}

impl State {
    /// An uninitialized token with an empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            mode: Mode::Honest,
            initialized: false,
            objects: Vec::new(),
            sessions: Vec::new(),
            generated: 0,
        }
    }

    /// The mode in force since `C_Initialize`.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// Whether `C_Initialize` has run and `C_Finalize` has not.
    #[must_use]
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Reads the mode from the environment and opens the token.
    pub fn initialize(&mut self) {
        self.mode = Mode::from_env();
        self.initialized = true;
    }

    /// Drops every session and object; the mode is re-read on the next
    /// `C_Initialize`.
    pub fn finalize(&mut self) {
        self.initialized = false;
        self.objects.clear();
        self.sessions.clear();
        self.generated = 0;
    }

    /// Opens a session and returns its handle.
    pub fn open_session(&mut self) -> u64 {
        self.sessions.push(Some(Session::default()));
        self.sessions.len() as u64
    }

    /// Closes a session; false when the handle was never open.
    pub fn close_session(&mut self, handle: u64) -> bool {
        match self.session_slot_mut(handle) {
            Some(slot) if slot.is_some() => {
                *slot = None;
                true
            }
            _ => false,
        }
    }

    /// Marks the session logged in; false when the handle is not open.
    pub fn login(&mut self, handle: u64) -> bool {
        self.session_mut(handle).is_some_and(|session| {
            session.logged_in = true;
            true
        })
    }

    /// Marks the session logged out; false when the handle is not open.
    pub fn logout(&mut self, handle: u64) -> bool {
        self.session_mut(handle).is_some_and(|session| {
            session.logged_in = false;
            true
        })
    }

    /// Whether the session exists.
    #[must_use]
    pub fn has_session(&self, handle: u64) -> bool {
        self.session(handle).is_some()
    }

    /// The object behind a handle.
    #[must_use]
    pub fn object(&self, handle: u64) -> Option<&StoredObject> {
        let index = usize::try_from(handle.checked_sub(1)?).ok()?;
        self.objects.get(index)
    }

    /// Stores an object and returns its handle.
    pub fn add_object(&mut self, object: StoredObject) -> u64 {
        self.objects.push(object);
        self.objects.len() as u64
    }

    /// Removes an object from the store; false when the handle is unknown.
    ///
    /// The slot is emptied rather than shifted — handles handed out earlier
    /// must keep pointing at the same objects.
    pub fn destroy_object(&mut self, handle: u64) -> bool {
        let Ok(index) = usize::try_from(handle.wrapping_sub(1)) else {
            return false;
        };
        match self.objects.get_mut(index) {
            Some(object) => {
                object.material = Material::Data { value: Vec::new() };
                object.class = CKO_DATA;
                object.key_type = None;
                true
            }
            None => false,
        }
    }

    /// Generates a real, reproducible P-256 pair and stores both halves.
    ///
    /// The scalar is derived from a fixed constant and the number of pairs
    /// generated so far: a fixture whose key changed per run could not be
    /// compared against a recorded request.
    ///
    /// # Errors
    ///
    /// `CKR_MECHANISM_INVALID` for anything but `CKM_EC_KEY_PAIR_GEN` — the
    /// announced GOST mechanism included. `CKR_TEMPLATE_INCONSISTENT` when the
    /// public template names a curve other than P-256.
    pub fn generate_key_pair(
        &mut self,
        mechanism: CK_MECHANISM_TYPE,
        public_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
        private_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> Result<(u64, u64), CK_RV> {
        if mechanism != CKM_EC_KEY_PAIR_GEN {
            return Err(CKR_MECHANISM_INVALID);
        }
        if let Some((_, params)) = public_template
            .iter()
            .find(|(type_, _)| *type_ == CKA_EC_PARAMS)
        {
            if params.as_slice() != P256_EC_PARAMS {
                return Err(CKR_TEMPLATE_INCONSISTENT);
            }
        }

        let scalar = derive_scalar(self.generated);
        self.generated = self.generated.wrapping_add(1);
        let secret = SecretKey::from_slice(&scalar).map_err(|_| CKR_DEVICE_ERROR)?;
        let point = secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let public = StoredObject {
            class: CKO_PUBLIC_KEY,
            key_type: Some(CKK_EC),
            label: template_bytes(public_template, CKA_LABEL).unwrap_or_default(),
            id: template_bytes(public_template, CKA_ID).unwrap_or_default(),
            token: template_bool(public_template, CKA_TOKEN).unwrap_or(false),
            private: template_bool(public_template, CKA_PRIVATE).unwrap_or(false),
            requested_extractable: true,
            requested_sensitive: false,
            material: Material::EcPublic { point },
        };
        let private = StoredObject {
            class: CKO_PRIVATE_KEY,
            key_type: Some(CKK_EC),
            label: template_bytes(private_template, CKA_LABEL).unwrap_or_default(),
            id: template_bytes(private_template, CKA_ID).unwrap_or_default(),
            token: template_bool(private_template, CKA_TOKEN).unwrap_or(false),
            private: template_bool(private_template, CKA_PRIVATE).unwrap_or(true),
            // An omitted `CKA_EXTRACTABLE` defaults to the permissive value:
            // the caller that never asked must not be handed the safe answer.
            requested_extractable: template_bool(private_template, CKA_EXTRACTABLE).unwrap_or(true),
            requested_sensitive: template_bool(private_template, CKA_SENSITIVE).unwrap_or(false),
            material: Material::EcPrivate { scalar },
        };

        let public_handle = self.add_object(public);
        let private_handle = self.add_object(private);
        Ok((public_handle, private_handle))
    }

    /// Starts a search; the matches are the objects whose reported attributes
    /// equal every entry of the template.
    ///
    /// Matching against the *reported* attributes, not the stored ones, keeps
    /// a search consistent with what the same caller reads back.
    ///
    /// # Errors
    ///
    /// `CKR_SESSION_HANDLE_INVALID` when the session is not open.
    pub fn find_objects_init(
        &mut self,
        session: u64,
        template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> Result<(), CK_RV> {
        let mode = self.mode;
        let mut matches: Vec<u64> = self
            .objects
            .iter()
            .enumerate()
            .filter(|(_, object)| {
                template.iter().all(|(type_, expected)| {
                    object.attribute(mode, *type_) == Answer::Value(expected.clone())
                })
            })
            .map(|(index, _)| index as u64 + 1)
            .collect();
        // Handed out from the back, so the first match leaves first.
        matches.reverse();
        let session = self
            .session_mut(session)
            .ok_or(cryptoki_sys::CKR_SESSION_HANDLE_INVALID)?;
        session.find = Some(matches);
        Ok(())
    }

    /// Takes up to `max` handles from the running search.
    ///
    /// # Errors
    ///
    /// `CKR_OPERATION_NOT_INITIALIZED` when no search is running.
    pub fn find_objects(&mut self, session: u64, max: usize) -> Result<Vec<u64>, CK_RV> {
        let session = self
            .session_mut(session)
            .ok_or(cryptoki_sys::CKR_SESSION_HANDLE_INVALID)?;
        let remaining = session
            .find
            .as_mut()
            .ok_or(cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED)?;
        let taken = remaining.len().min(max);
        Ok(remaining.split_off(remaining.len() - taken))
    }

    /// Ends the running search.
    ///
    /// # Errors
    ///
    /// `CKR_OPERATION_NOT_INITIALIZED` when no search is running.
    pub fn find_objects_final(&mut self, session: u64) -> Result<(), CK_RV> {
        let session = self
            .session_mut(session)
            .ok_or(cryptoki_sys::CKR_SESSION_HANDLE_INVALID)?;
        session
            .find
            .take()
            .map(|_| ())
            .ok_or(cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED)
    }

    /// Records the signing operation the session is about to perform.
    ///
    /// # Errors
    ///
    /// `CKR_MECHANISM_INVALID` for a mechanism the fixture cannot perform,
    /// `CKR_KEY_HANDLE_INVALID` when the handle is not a private key.
    pub fn sign_init(
        &mut self,
        session: u64,
        mechanism: CK_MECHANISM_TYPE,
        key: u64,
    ) -> Result<(), CK_RV> {
        if mechanism != CKM_ECDSA && mechanism != CKM_ECDSA_SHA256 {
            return Err(CKR_MECHANISM_INVALID);
        }
        if !matches!(
            self.object(key).map(|object| &object.material),
            Some(Material::EcPrivate { .. })
        ) {
            return Err(cryptoki_sys::CKR_KEY_HANDLE_INVALID);
        }
        let session = self
            .session_mut(session)
            .ok_or(cryptoki_sys::CKR_SESSION_HANDLE_INVALID)?;
        session.sign = Some(SignOperation { mechanism, key });
        Ok(())
    }

    /// The signature the pending operation produces over `data`, without
    /// consuming the operation — the caller may query the length first.
    ///
    /// # Errors
    ///
    /// `CKR_OPERATION_NOT_INITIALIZED` without a preceding `sign_init`,
    /// `CKR_DEVICE_ERROR` if the stored scalar will not make a signing key.
    pub fn sign_peek(&self, session: u64, data: &[u8]) -> Result<Vec<u8>, CK_RV> {
        let operation = self
            .session(session)
            .ok_or(cryptoki_sys::CKR_SESSION_HANDLE_INVALID)?
            .sign
            .ok_or(cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED)?;
        let Some(Material::EcPrivate { scalar }) =
            self.object(operation.key).map(|object| &object.material)
        else {
            return Err(cryptoki_sys::CKR_KEY_HANDLE_INVALID);
        };
        let key = SigningKey::from_slice(scalar).map_err(|_| CKR_DEVICE_ERROR)?;
        // `CKM_ECDSA` takes the digest already computed; `CKM_ECDSA_SHA256`
        // takes the message. Either way the signature is real: a request the
        // fixture signed must verify against the public key it reported.
        let signature: Signature = if operation.mechanism == CKM_ECDSA {
            key.sign_prehash(data).map_err(|_| CKR_DEVICE_ERROR)?
        } else {
            key.sign(data)
        };
        Ok(signature.to_bytes().to_vec())
    }

    /// Ends the pending signing operation.
    pub fn sign_finish(&mut self, session: u64) {
        if let Some(session) = self.session_mut(session) {
            session.sign = None;
        }
    }

    fn session(&self, handle: u64) -> Option<&Session> {
        let index = usize::try_from(handle.checked_sub(1)?).ok()?;
        self.sessions.get(index)?.as_ref()
    }

    fn session_mut(&mut self, handle: u64) -> Option<&mut Session> {
        self.session_slot_mut(handle)?.as_mut()
    }

    fn session_slot_mut(&mut self, handle: u64) -> Option<&mut Option<Session>> {
        let index = usize::try_from(handle.checked_sub(1)?).ok()?;
        self.sessions.get_mut(index)
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

/// The scalar for the `n`-th generated pair: fixed bytes with the counter in
/// the last one, so every run of a test sees the same key.
fn derive_scalar(counter: u8) -> [u8; 32] {
    let mut scalar = [0x42_u8; 32];
    if let Some(last) = scalar.last_mut() {
        *last = 0x42_u8.wrapping_add(counter);
    }
    scalar
}

/// Wraps bytes in a DER `OCTET STRING`, the form `CKA_EC_POINT` travels in.
fn der_octet_string(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 2);
    out.push(0x04);
    // The fixture's only point is 65 bytes, well inside the short form.
    out.push(u8::try_from(bytes.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(bytes);
    out
}

fn template_bytes(
    template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    attribute: CK_ATTRIBUTE_TYPE,
) -> Option<Vec<u8>> {
    template
        .iter()
        .find(|(type_, _)| *type_ == attribute)
        .map(|(_, value)| value.clone())
}

fn template_bool(
    template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    attribute: CK_ATTRIBUTE_TYPE,
) -> Option<bool> {
    template
        .iter()
        .find(|(type_, _)| *type_ == attribute)
        .and_then(|(_, value)| value.first().copied())
        .map(|byte| byte != CK_FALSE)
}

/// A `CK_BBOOL` as the single byte a caller's buffer expects.
#[must_use]
pub fn bbool_bytes(value: bool) -> Vec<u8> {
    vec![if value { CK_TRUE } else { CK_FALSE } as CK_BBOOL]
}

/// A `CK_ULONG` in the platform's own byte order, as PKCS#11 passes it.
#[must_use]
pub fn ulong_bytes(value: CK_ULONG) -> Vec<u8> {
    value.to_ne_bytes().to_vec()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::{Answer, Material, Mode, State, StoredObject};
    use cryptoki_sys::{
        CKA_EXTRACTABLE, CKA_NEVER_EXTRACTABLE, CKA_VALUE, CKK_EC, CKM_ECDSA, CKM_EC_KEY_PAIR_GEN,
        CKO_PRIVATE_KEY,
    };

    fn locked_key() -> StoredObject {
        StoredObject {
            class: CKO_PRIVATE_KEY,
            key_type: Some(CKK_EC),
            label: b"liar".to_vec(),
            id: vec![1],
            token: true,
            private: true,
            requested_extractable: false,
            requested_sensitive: true,
            material: Material::EcPrivate { scalar: [0x42; 32] },
        }
    }

    #[test]
    fn an_unknown_mode_name_is_the_control_mode() {
        assert_eq!(Mode::from_name("ignores-templat"), Mode::Honest);
        assert_eq!(Mode::from_name(""), Mode::Honest);
        assert_eq!(Mode::from_name("leaks"), Mode::Leaks);
    }

    #[test]
    fn honest_mode_reports_the_template_back() {
        let key = locked_key();
        assert_eq!(
            key.attribute(Mode::Honest, CKA_EXTRACTABLE),
            Answer::Value(vec![0])
        );
        assert_eq!(key.attribute(Mode::Honest, CKA_VALUE), Answer::Sensitive);
    }

    #[test]
    fn ignores_template_reports_the_opposite_of_the_template() {
        let key = locked_key();
        assert_eq!(
            key.attribute(Mode::IgnoresTemplate, CKA_EXTRACTABLE),
            Answer::Value(vec![1])
        );
    }

    #[test]
    fn leaks_reports_a_locked_key_and_hands_out_the_scalar() {
        let key = locked_key();
        assert_eq!(
            key.attribute(Mode::Leaks, CKA_EXTRACTABLE),
            Answer::Value(vec![0]),
            "read-back must see nothing wrong"
        );
        assert_eq!(
            key.attribute(Mode::Leaks, CKA_NEVER_EXTRACTABLE),
            Answer::Value(vec![1])
        );
        assert_eq!(
            key.attribute(Mode::Leaks, CKA_VALUE),
            Answer::Value(vec![0x42; 32]),
            "only an active probe can catch this"
        );
    }

    #[test]
    fn attributes_absent_reports_no_such_attribute() {
        assert_eq!(
            locked_key().attribute(Mode::AttributesAbsent, CKA_EXTRACTABLE),
            Answer::TypeInvalid
        );
    }

    #[test]
    fn was_extractable_admits_the_key_was_not_always_locked() {
        let key = locked_key();
        assert_eq!(
            key.attribute(Mode::WasExtractable, CKA_EXTRACTABLE),
            Answer::Value(vec![0])
        );
        assert_eq!(
            key.attribute(Mode::WasExtractable, CKA_NEVER_EXTRACTABLE),
            Answer::Value(vec![0])
        );
    }

    #[test]
    fn no_mechanisms_announces_an_empty_list() {
        assert!(Mode::NoMechanisms.mechanisms().is_empty());
        assert_eq!(Mode::Honest.mechanisms().len(), 4);
    }

    #[test]
    fn the_generated_pair_is_the_same_pair_every_run() {
        let mut first = State::new();
        let mut second = State::new();
        let (pub_a, _) = first
            .generate_key_pair(CKM_EC_KEY_PAIR_GEN, &[], &[])
            .expect("generation succeeds");
        let (pub_b, _) = second
            .generate_key_pair(CKM_EC_KEY_PAIR_GEN, &[], &[])
            .expect("generation succeeds");
        let point_a = first.object(pub_a).map(|o| o.material.clone());
        let point_b = second.object(pub_b).map(|o| o.material.clone());
        let (Some(Material::EcPublic { point: a }), Some(Material::EcPublic { point: b })) =
            (point_a, point_b)
        else {
            panic!("both halves must be public keys");
        };
        assert_eq!(a, b);
        assert_eq!(a.len(), 65, "uncompressed SEC1 point");
    }

    #[test]
    fn the_announced_gost_mechanism_cannot_be_performed() {
        let mut state = State::new();
        let result = state.generate_key_pair(super::CKM_GOSTR3410_512_KEY_PAIR_GEN, &[], &[]);
        assert_eq!(result, Err(cryptoki_sys::CKR_MECHANISM_INVALID));
    }

    #[test]
    fn the_signature_verifies_against_the_reported_public_key() {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;

        let mut state = State::new();
        let (public, private) = state
            .generate_key_pair(CKM_EC_KEY_PAIR_GEN, &[], &[])
            .expect("generation succeeds");
        let session = state.open_session();
        state
            .sign_init(session, CKM_ECDSA, private)
            .expect("sign init");
        let digest = [0x11_u8; 32];
        let signature = state.sign_peek(session, &digest).expect("sign");

        let Some(Material::EcPublic { point }) = state.object(public).map(|o| o.material.clone())
        else {
            panic!("the public half must be a public key");
        };
        let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).expect("public key");
        let parsed = p256::ecdsa::Signature::from_slice(&signature).expect("signature");
        verifying
            .verify_prehash(&digest, &parsed)
            .expect("the fixture signs honestly");
    }
}
