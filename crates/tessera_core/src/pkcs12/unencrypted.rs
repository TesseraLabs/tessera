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
//! safes, and among them only the certificate bags. Encrypted safes are stepped
//! over rather than decrypted, and a key bag is dropped on its bag identifier.
//! No password is consulted anywhere on this path.
//!
//! What the ASN.1 decoder does with a key bag before that, precisely: decoding a
//! safe decodes *all* of its bags, so a shrouded key bag's value is copied as an
//! opaque TLV and its bag attributes (`friendlyName`, `localKeyID`) are decoded
//! with it. Nothing interprets that value or reaches into it: it is the
//! password-encrypted blob, and this path holds no password. What the code then
//! discards on the bag identifier is a copy it already made.
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

/// Every certificate reachable without the container's password, in container
/// order.
///
/// Certificates that sit in an encrypted safe are not among them — reaching
/// those would need the password, which is exactly what this path must not
/// touch.
pub(super) fn certificates_in_clear(bytes: &[u8]) -> Vec<Vec<u8>> {
    let Ok(pfx) = Pfx::from_der(bytes) else {
        return Vec::new();
    };
    let Some(auth_safe) = data_payload(&pfx.auth_safe) else {
        return Vec::new();
    };
    let Ok(safes) = Vec::<ContentInfo>::from_der(&auth_safe) else {
        return Vec::new();
    };

    if safes.len() > MAX_SAFES {
        return Vec::new();
    }

    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut collected_bytes = 0usize;
    for safe in &safes {
        // An `id-encryptedData` safe is stepped over: opening it needs the
        // password. A container that hides its certificates that way simply has
        // none to show here.
        if safe.content_type != ID_DATA {
            continue;
        }
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
            // The one bag type this path reads. Everything else — a shrouded
            // key bag above all — is dropped on its identifier, without its
            // content being looked into.
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
            if out.len() >= MAX_CERTIFICATES || collected_bytes > MAX_CERTIFICATE_BYTES {
                // Nothing, rather than what was gathered so far: the caller
                // names a certificate only when the container leaves no doubt
                // which one it is, and a truncated list could remove the very
                // certificate that made the choice ambiguous.
                return Vec::new();
            }
            out.push(der.to_vec());
        }
    }
    out
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

/// The octets an `id-data` `ContentInfo` carries.
fn data_payload(content_info: &ContentInfo) -> Option<Vec<u8>> {
    let der = content_info.content.to_der().ok()?;
    let octets = OctetString::from_der(&der).ok()?;
    Some(octets.as_bytes().to_vec())
}
