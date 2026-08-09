//! Reading the certificates a PKCS#12 container carries in the clear.
//!
//! The container's private key is encrypted in every issuance, so a reader that
//! walks the container through `PKCS12_parse` gets nothing: that routine stops
//! at the first shrouded key bag it cannot open and drops the certificates it
//! had already recovered. The login screen's "wrong drive against wrong
//! password" diagnostic rests on those certificates, so this module walks the
//! `AuthenticatedSafe` itself instead.
//!
//! What it reads is deliberately narrow: the bags of the *unencrypted* `id-data`
//! safes, and among them the certificate bags plus the *attributes* of the key
//! bag. Encrypted safes are stepped over rather than decrypted. No password is
//! consulted anywhere on this path, and no key material is interpreted.
//!
//! What the ASN.1 decoder does with a key bag, precisely: decoding a safe
//! decodes *all* of its bags, so a shrouded key bag's value is copied as an
//! opaque TLV and its bag attributes (`friendlyName`, `localKeyID`) are decoded
//! with it. The walk reads the attributes — `localKeyID` is the token that pairs
//! a key with its certificate, and reading it is what lets a caller name the
//! certificate the device will actually authenticate with. The bag's *value*,
//! the password-encrypted key blob, is never looked into: this path holds no
//! password, and the copy the decoder made of it is dropped with the rest.
//!
//! Nothing here decides anything. A malformed container, an unreadable safe or a
//! bag that does not decode all yield "no certificate": this is a diagnostic
//! path and its failure mode is silence, not an error the caller has to handle.
//!
//! What the limits below do, and what they do not: the decoder is handed a
//! whole section at a time, so every safe of the container and every bag of a
//! section is decoded and copied *before* any count is looked at. The limits
//! therefore do not bound the memory the walk touches — they bound what it
//! hands back, and they turn a container too large to be one of ours into "no
//! certificate" instead of a truncated list the caller would read as a definite
//! answer. The transient cost is a small multiple of the input, which the
//! discovery step has already capped, and all of it is dropped when this
//! function returns; the bytes arrive on a device nobody has authenticated, but
//! nothing here grows without bound or outlives the attempt.

use cms::content_info::ContentInfo;
use der::asn1::{ObjectIdentifier, OctetString};
use der::{Decode as _, Encode as _};
use pkcs12::cert_type::CertBag;
use pkcs12::pfx::Pfx;
use pkcs12::safe_bag::SafeBag;

/// `id-data` (PKCS#7): the content type of a safe whose bags lie in the clear.
const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

/// PKCS#9 `localKeyId`: the token that pairs a certificate bag with a key bag.
const OID_LOCAL_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.21");

/// Safes a container may hold and still be answered about.
///
/// An issued container has two (certificates in the clear, key encrypted);
/// anything beyond a handful is not a bundle this Engine was given, and this
/// path would rather say nothing about it than pick a certificate out of it.
const MAX_SAFES: usize = 16;

/// Certificates a container may hold and still be answered about.
///
/// A chain longer than this is not one the trust path could build over anyway,
/// and the diagnostic needs only the leaf.
const MAX_CERTIFICATES: usize = 16;

/// Total certificate bytes a container may hold and still be answered about.
///
/// Certificates run to a few kilobytes, so this leaves ample room for any chain
/// an issuance produces while keeping the answer to an implausible container the
/// same as to an ambiguous one: nothing.
const MAX_CERTIFICATE_BYTES: usize = 256 * 1024;

/// A certificate read in the clear, together with the pairing token its bag
/// carried.
pub(super) struct ClearCertificate {
    /// The certificate itself, DER.
    pub der: Vec<u8>,
    /// The bag's `localKeyId` attribute value as it was encoded, or `None` when
    /// the bag carried none. The token is opaque — nothing derives or verifies
    /// it, it is only compared with the key bag's.
    pub local_key_id: Option<Vec<u8>>,
}

/// What one walk over a container's unencrypted safes found.
#[derive(Default)]
pub(super) struct ClearBags {
    /// Every certificate reachable without the container's password, in
    /// container order.
    ///
    /// Certificates that sit in an encrypted safe are not among them —
    /// reaching those would need the password, which is exactly what this path
    /// must not touch.
    pub certificates: Vec<ClearCertificate>,
    /// The `localKeyId` of the container's key bag, when exactly one key bag
    /// lies in the clear and carries one.
    ///
    /// Two key bags leave no single "the container's key" to pair against, so
    /// the token is dropped and the caller is left without a pairing rather
    /// than with one of two.
    pub key_local_key_id: Option<Vec<u8>>,
}

/// Walks the container's unencrypted safes.
pub(super) fn bags_in_clear(bytes: &[u8]) -> ClearBags {
    let Ok(pfx) = Pfx::from_der(bytes) else {
        return ClearBags::default();
    };
    // A container in public-key privacy mode wraps its authenticated safe in
    // `signedData` instead of `id-data`. Its content is not octets this path can
    // read, and refusing it on its declared type says so, rather than leaving it
    // to whether the octet-string decode happens to fail on the bytes inside.
    let Some(auth_safe) = data_payload(&pfx.auth_safe) else {
        return ClearBags::default();
    };
    let Ok(safes) = Vec::<ContentInfo>::from_der(&auth_safe) else {
        return ClearBags::default();
    };

    if safes.len() > MAX_SAFES {
        return ClearBags::default();
    }

    let mut out = ClearBags::default();
    let mut collected_bytes = 0usize;
    let mut key_bags = 0usize;
    for safe in &safes {
        // An `id-encryptedData` safe is stepped over: opening it needs the
        // password. A container that hides its certificates that way simply has
        // none to show here, and `data_payload` turns it away on its declared
        // content type.
        let Some(payload) = data_payload(safe) else {
            continue;
        };
        // A safe decodes whole or not at all, so one unreadable bag costs the
        // certificates of every bag beside it. Recovering them would mean
        // walking the bags by hand, and a container assembled well enough to
        // reach here yet holding a bag this decoder rejects is not the case the
        // diagnostic is for.
        let Ok(bags) = Vec::<SafeBag>::from_der(&payload) else {
            continue;
        };
        for bag in &bags {
            if is_key_bag(bag.bag_id) {
                // Only the bag's attributes are read. Its value — the
                // password-encrypted key — is left where it is; nothing here
                // holds a password, and nothing here would know what to do with
                // the plaintext if it did.
                key_bags = key_bags.saturating_add(1);
                out.key_local_key_id = local_key_id(bag);
                continue;
            }
            if bag.bag_id != pkcs12::PKCS_12_CERT_BAG_OID {
                continue;
            }
            let Some(content) = bag_content(bag) else {
                continue;
            };
            let Ok(cert) = CertBag::from_der(&content) else {
                continue;
            };
            let der = cert.cert_value.as_bytes();
            collected_bytes = collected_bytes.saturating_add(der.len());
            if out.certificates.len() >= MAX_CERTIFICATES || collected_bytes > MAX_CERTIFICATE_BYTES
            {
                // Nothing, rather than what was gathered so far: the caller
                // names a certificate only when the container leaves no doubt
                // which one it is, and a truncated list could remove the very
                // certificate that made the choice ambiguous.
                return ClearBags::default();
            }
            out.certificates.push(ClearCertificate {
                der: der.to_vec(),
                local_key_id: local_key_id(bag),
            });
        }
    }

    if key_bags != 1 {
        out.key_local_key_id = None;
    }
    out
}

/// Every certificate reachable without the container's password, in container
/// order.
pub(super) fn certificates_in_clear(bytes: &[u8]) -> Vec<Vec<u8>> {
    bags_in_clear(bytes)
        .certificates
        .into_iter()
        .map(|cert| cert.der)
        .collect()
}

/// Whether a bag identifier is one of the two bag types that carry a private
/// key.
///
/// An issued container shrouds its key, and so does every writer this Engine
/// has met; the plain key bag is accepted alongside it because a container that
/// carries one still pairs its certificate the same way, and refusing it would
/// silently drop the pairing rather than say anything about it.
fn is_key_bag(bag_id: ObjectIdentifier) -> bool {
    bag_id == pkcs12::PKCS_12_PKCS8_KEY_BAG_OID || bag_id == pkcs12::PKCS_12_KEY_BAG_OID
}

/// The bag's `localKeyId` attribute value, encoded, or `None` when the bag
/// carries no such attribute.
///
/// The value is handed back as its DER rather than as a parsed token: it is
/// opaque by definition — RFC 7292 requires only that the paired bags carry the
/// *same* value — so comparing the encodings is exactly the question that has
/// to be answered, and no shape has to be assumed of what is inside.
fn local_key_id(bag: &SafeBag) -> Option<Vec<u8>> {
    bag.bag_attributes
        .as_ref()?
        .iter()
        .find(|attribute| attribute.oid == OID_LOCAL_KEY_ID)
        .and_then(|attribute| attribute.values.to_der().ok())
}

/// The bag's value with the mandatory `[0] EXPLICIT` wrapper removed.
///
/// The bag codec is asymmetric: decoding leaves the wrapper in place, so every
/// bag that came out of a decode carries it. A bag without it is malformed and
/// is dropped rather than guessed at from whatever tag is there.
fn bag_content(bag: &SafeBag) -> Option<Vec<u8>> {
    let any = der::asn1::AnyRef::from_der(&bag.bag_value).ok()?;
    if der::Tagged::tag(&any)
        != (der::Tag::ContextSpecific {
            constructed: true,
            number: der::TagNumber::N0,
        })
    {
        return None;
    }
    Some(any.value().to_vec())
}

/// The octets an `id-data` `ContentInfo` carries, or `None` for any other
/// content type.
///
/// The type is checked rather than inferred from whether the octet-string decode
/// succeeds: an `id-signedData` or `id-encryptedData` content is a structure this
/// path must not read, and that has to be the stated reason for turning it away,
/// not a side effect of the decoder's tag mismatch.
fn data_payload(content_info: &ContentInfo) -> Option<Vec<u8>> {
    if content_info.content_type != ID_DATA {
        return None;
    }
    let der = content_info.content.to_der().ok()?;
    let octets = OctetString::from_der(&der).ok()?;
    Some(octets.as_bytes().to_vec())
}
