//! Reading the certificates a PKCS#12 container carries in the clear.
//!
//! The container's private key is encrypted in every issuance, so a reader that
//! walks the container through `PKCS12_parse` gets nothing: that routine stops
//! at the first shrouded key bag it cannot open and drops the certificates it
//! had already recovered. The login screen's "wrong drive against wrong
//! password" diagnostic rests on those certificates, so this module walks the
//! `AuthenticatedSafe` itself instead.
//!
//! What it reads is deliberately narrow: the certificate bags of the
//! *unencrypted* `id-data` safes, and nothing else. Encrypted safes are stepped
//! over rather than decrypted. No password is consulted anywhere on this path,
//! and no key material is interpreted.
//!
//! What the ASN.1 decoder does with a key bag, precisely: decoding a safe
//! decodes *all* of its bags, so a shrouded key bag's value is copied as an
//! opaque TLV along the way. Nothing here looks into it — that value is the
//! password-encrypted key, this path holds no password, and the copy the
//! decoder made is dropped with the rest of the walk.
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

/// Levels of `safeContentsBag` nesting the walk descends through.
///
/// RFC 7292 lets a bag list hold a bag list, and OpenSSL follows that with no
/// stated bound. Here the bytes arrive on a device nobody has authenticated, so
/// the descent is bounded outright; an issued container nests not at all, and
/// two levels of slack cover a writer that wraps its bags for its own reasons.
/// Deeper than this is not read, and the certificates above it still answer the
/// diagnostic.
const MAX_BAG_DEPTH: usize = 4;

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
    // A container in public-key privacy mode wraps its authenticated safe in
    // `signedData` instead of `id-data`. Its content is not octets this path can
    // read, and refusing it on its declared type says so, rather than leaving it
    // to whether the octet-string decode happens to fail on the bytes inside.
    let Some(auth_safe) = data_payload(&pfx.auth_safe) else {
        return Vec::new();
    };
    let Ok(safes) = Vec::<ContentInfo>::from_der(&auth_safe) else {
        return Vec::new();
    };

    if safes.len() > MAX_SAFES {
        return Vec::new();
    }

    let mut walk = Walk::default();
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
        walk.visit(&bags, 1);
    }

    if walk.past_a_limit {
        // Nothing, rather than what was gathered so far: the caller names a
        // certificate only when the container leaves no doubt which one it is,
        // and a truncated list could have lost the very certificate that made
        // the choice ambiguous.
        return Vec::new();
    }
    walk.certificates
}

/// One walk in progress over a container's bags.
#[derive(Default)]
struct Walk {
    /// Certificates read so far, in container order.
    certificates: Vec<Vec<u8>>,
    /// Certificate bytes collected so far, against [`MAX_CERTIFICATE_BYTES`].
    collected_bytes: usize,
    /// Whether a count or a byte cap was passed, which discards the whole walk.
    past_a_limit: bool,
}

impl Walk {
    /// Reads one bag list, descending into the `safeContentsBag`s among them.
    ///
    /// `depth` counts the bag lists already entered, the container's own safe
    /// being the first.
    fn visit(&mut self, bags: &[SafeBag], depth: usize) {
        for bag in bags {
            if self.past_a_limit {
                return;
            }
            if bag.bag_id == pkcs12::PKCS_12_SAFE_CONTENTS_BAG_OID {
                self.visit_nested(bag, depth);
                continue;
            }
            // Every other bag type is passed over by its identifier — a key bag
            // above all. Its value, the password-encrypted key, is left where it
            // is; nothing here holds a password, and nothing here would know
            // what to do with the plaintext if it did.
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
            self.collected_bytes = self.collected_bytes.saturating_add(der.len());
            if self.certificates.len() >= MAX_CERTIFICATES
                || self.collected_bytes > MAX_CERTIFICATE_BYTES
            {
                self.past_a_limit = true;
                return;
            }
            self.certificates.push(der.to_vec());
        }
    }

    /// Descends into a `safeContentsBag`.
    ///
    /// A bag list is a place a certificate can sit, and OpenSSL reads it, so a
    /// walk that stopped at the outer level would miss a container whose writer
    /// wrapped its bags. Past the depth limit, or on a nested list that does not
    /// decode, the descent simply stops: what the levels above it hold still
    /// answers the diagnostic.
    fn visit_nested(&mut self, bag: &SafeBag, depth: usize) {
        if depth >= MAX_BAG_DEPTH {
            return;
        }
        let Some(content) = bag_content(bag) else {
            return;
        };
        let Ok(inner) = Vec::<SafeBag>::from_der(&content) else {
            return;
        };
        self.visit(&inner, depth.saturating_add(1));
    }
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
