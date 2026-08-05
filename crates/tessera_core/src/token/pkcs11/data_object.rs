//! Reading `CKO_DATA` objects from a token.
//!
//! A passive token — one whose `C_GetMechanismList` is empty — cannot sign and
//! will not take a private-key object, but it does store arbitrary byte blobs
//! as data objects.  That makes it a carrier: the PKCS#12 envelope travels in
//! a data object instead of a partition on a USB stick, and everything after
//! the envelope is reached (the PIN loop, the challenge, the chain) is the same
//! code as before.
//!
//! Two properties this module is responsible for:
//!
//! * **"not found" is not "unreadable".**  A missing label means the operator
//!   named the wrong object or handed out the wrong token; an attribute that
//!   cannot be read means the object is there and something else is wrong.
//!   The caller has to tell an engineer which, so the two are separate errors.
//! * **privacy is reported, and the reading path insists on it.**  The
//!   envelope holds an extractable private key.  `pkcs11-tool` and every other
//!   general-purpose writer create data objects public by default, and a public
//!   object is readable off the token without the PIN — so
//!   [`Pkcs11Session::read_private_data_object`] refuses one rather than
//!   letting a container that anybody can lift look like a working carrier.
//!
//! The bytes are returned uninterpreted: parsing PKCS#12 is not this layer's
//! business, and the token is not trusted to have stored anything in
//! particular.

use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use tracing::{info, warn};

use super::error::Pkcs11Error;
use super::locking::with_global_lock;
use super::session::Pkcs11Session;

/// A `CKO_DATA` object read off a token.
pub struct FoundDataObject {
    /// `CKA_VALUE`, exactly as the token returned it.
    pub value: Vec<u8>,
    /// `CKA_PRIVATE`: whether reading the object required the PIN.
    pub private: bool,
}

// Manual `Debug`: the value is a PKCS#12 envelope with an extractable private
// key inside it, and this type is handled on the authentication path, where a
// `debug!(?found)` would put the container into the journal of `sshd` or the
// display manager.  Size and privacy are what a diagnostic actually needs.
impl core::fmt::Debug for FoundDataObject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FoundDataObject")
            .field("bytes", &self.value.len())
            .field("private", &self.private)
            .finish()
    }
}

/// Turn the attributes of one candidate object into a [`FoundDataObject`].
///
/// Pure: no PKCS#11 calls, so every rejection path is unit-testable without a
/// provider.  Both attributes are mandatory here even though PKCS#11 lets a
/// provider decline to report them — an object whose privacy cannot be
/// established is treated as unreadable rather than as public, so a provider
/// that says nothing cannot talk us into accepting a container that was never
/// behind a PIN.
///
/// # Errors
///
/// [`Pkcs11Error::DataObjectUnreadable`] naming the attribute that was absent.
pub(crate) fn read_data_object_attributes(
    label: &str,
    value: Option<Vec<u8>>,
    private: Option<bool>,
) -> Result<FoundDataObject, Pkcs11Error> {
    let unreadable = |attribute: &'static str| Pkcs11Error::DataObjectUnreadable {
        label: label.to_owned(),
        attribute,
    };
    let Some(value) = value else {
        return Err(unreadable("CKA_VALUE"));
    };
    let Some(private) = private else {
        return Err(unreadable("CKA_PRIVATE"));
    };
    Ok(FoundDataObject { value, private })
}

/// Decide which of the objects found under one label is the carrier.
///
/// Pure, so every branch is testable without a provider.
///
/// `first_failure` is an object that carried the label and whose attributes
/// could not be read. It is not a detail to be dropped once something else was
/// read successfully: the guarantee this function owes its caller is that the
/// label identified exactly one credential, and an object nobody could read
/// might have been a second private one. Answering with the readable object
/// would let the provider's luck decide which credential an engineer
/// authenticates with — the very thing the duplicate check exists to prevent —
/// so an unreadable sibling refuses the whole search whether or not a good
/// candidate was also found.
///
/// # Errors
///
/// - [`Pkcs11Error::DataObjectAmbiguous`] when several equally private objects
///   carry the label.
/// - The recorded failure when any object under the label could not be read.
/// - [`Pkcs11Error::DataObjectNotFound`] when nothing usable carried it.
fn choose_data_object(
    label: &str,
    mut private_candidates: Vec<FoundDataObject>,
    mut public_candidates: Vec<FoundDataObject>,
    first_failure: Option<Pkcs11Error>,
) -> Result<FoundDataObject, Pkcs11Error> {
    let ambiguous = |count: usize| Pkcs11Error::DataObjectAmbiguous {
        label: label.to_owned(),
        count,
    };
    if private_candidates.len() > 1 {
        return Err(ambiguous(private_candidates.len()));
    }
    if let Some(failure) = first_failure {
        warn!(
            target: "tessera.pkcs11",
            label,
            error = %failure,
            "another object under this label could not be read, so the label cannot be shown \
             to identify one credential"
        );
        return Err(failure);
    }
    if let Some(found) = private_candidates.pop() {
        if !public_candidates.is_empty() {
            warn!(
                target: "tessera.pkcs11",
                label,
                "a second data object with this label is stored without CKA_PRIVATE, so a \
                 copy of these contents can be read off the token without the PIN"
            );
        }
        return Ok(found);
    }
    if public_candidates.len() > 1 {
        return Err(ambiguous(public_candidates.len()));
    }
    match public_candidates.pop() {
        Some(found) => {
            warn!(
                target: "tessera.pkcs11",
                label,
                "a data object with this label is stored without CKA_PRIVATE, so its \
                 contents can be read off the token without the PIN"
            );
            Ok(found)
        }
        None => Err(Pkcs11Error::DataObjectNotFound {
            label: label.to_owned(),
        }),
    }
}

impl Pkcs11Session {
    /// Read the `CKO_DATA` object labelled `label`.
    ///
    /// The search is by label and class only — deliberately not narrowed to
    /// `CKA_PRIVATE = TRUE`.  Narrowing would turn a container someone stored
    /// publicly into "no such object", which sends the operator looking for a
    /// missing envelope instead of telling them the one on the token is
    /// readable without a PIN.  The privacy flag comes back with the bytes and
    /// [`Self::read_private_data_object`] is what acts on it.
    ///
    /// A public object beside the real envelope loses to it: a decoy planted
    /// on the token must not be able to shadow the container.  The decoy is
    /// logged, because a copy of the container that needs no PIN is worth an
    /// operator's attention whether or not it was used.
    ///
    /// Two objects of the *same* privacy under one label are refused instead.
    /// There is nothing to choose between them — the token gives no order and
    /// no age — so one of them would be picked by whatever the provider
    /// happened to enumerate first, and an engineer whose credential was
    /// replaced could go on authenticating with the old one.  The tool that
    /// writes the envelope treats a duplicate label as a failed write for the
    /// same reason; the reading side has no business being the more forgiving
    /// of the two.
    ///
    /// # Errors
    ///
    /// - [`Pkcs11Error::DataObjectNotFound`] when no object carries the label.
    /// - [`Pkcs11Error::DataObjectAmbiguous`] when several equally private
    ///   objects carry it.
    /// - [`Pkcs11Error::DataObjectUnreadable`] when an object carries it but a
    ///   mandatory attribute could not be read.
    /// - [`Pkcs11Error::Cryptoki`] for any FFI failure during the search.
    pub fn find_data_object(&self, label: &str) -> Result<FoundDataObject, Pkcs11Error> {
        let not_found = || Pkcs11Error::DataObjectNotFound {
            label: label.to_owned(),
        };
        let session = self.raw().ok_or_else(not_found)?;

        let template = [
            Attribute::Class(ObjectClass::DATA),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        let mode = self.locking_mode();
        let handles = with_global_lock(mode, || session.find_objects(&template))?;
        if handles.is_empty() {
            info!(
                target: "tessera.pkcs11",
                label,
                "pkcs11_data_object_search_empty"
            );
            return Err(not_found());
        }

        let want_attrs = [AttributeType::Value, AttributeType::Private];
        let mut private_candidates: Vec<FoundDataObject> = Vec::new();
        let mut public_candidates: Vec<FoundDataObject> = Vec::new();
        let mut first_failure: Option<Pkcs11Error> = None;
        for handle in handles {
            let attrs = match with_global_lock(mode, || session.get_attributes(handle, &want_attrs))
            {
                Ok(attrs) => attrs,
                Err(e) => {
                    warn!(
                        target: "tessera.pkcs11",
                        label,
                        error = %e,
                        "pkcs11_data_object_get_attrs_failed"
                    );
                    first_failure.get_or_insert(Pkcs11Error::Cryptoki(e));
                    continue;
                }
            };
            let mut value = None;
            let mut private = None;
            for attr in attrs {
                match attr {
                    Attribute::Value(v) => value = Some(v),
                    Attribute::Private(p) => private = Some(p),
                    _ => {}
                }
            }
            match read_data_object_attributes(label, value, private) {
                Ok(found) if found.private => private_candidates.push(found),
                Ok(found) => public_candidates.push(found),
                Err(e) => {
                    first_failure.get_or_insert(e);
                }
            }
        }

        choose_data_object(label, private_candidates, public_candidates, first_failure)
    }

    /// Read the `CKO_DATA` object labelled `label`, refusing a public one.
    ///
    /// This is the entry point for anything that carries a secret — the
    /// PKCS#12 envelope above all, whose private key is extractable once the
    /// container password is known.  A public object holding one is not a
    /// weaker carrier but a different thing entirely: it is a container
    /// anybody who holds the token for a moment can copy, so it is refused
    /// instead of used with a warning.
    ///
    /// # Errors
    ///
    /// - [`Pkcs11Error::DataObjectNotPrivate`] when the object was found but
    ///   is readable without the PIN.
    /// - Anything [`Self::find_data_object`] returns.
    pub fn read_private_data_object(&self, label: &str) -> Result<Vec<u8>, Pkcs11Error> {
        let found = self.find_data_object(label)?;
        if !found.private {
            return Err(Pkcs11Error::DataObjectNotPrivate {
                label: label.to_owned(),
            });
        }
        Ok(found.value)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn found(private: bool, value: &[u8]) -> FoundDataObject {
        FoundDataObject {
            value: value.to_vec(),
            private,
        }
    }

    fn unreadable() -> Pkcs11Error {
        Pkcs11Error::DataObjectUnreadable {
            label: "tessera-p12".to_owned(),
            attribute: "CKA_VALUE",
        }
    }

    /// A sibling under the same label that could not be read might have been a
    /// second private object. Returning the one that happened to read leaves
    /// the provider's luck deciding which credential an engineer enters with —
    /// exactly what the duplicate refusal exists to prevent.
    #[test]
    fn an_unreadable_sibling_refuses_a_readable_private_object() {
        let err = choose_data_object(
            "tessera-p12",
            vec![found(true, b"envelope")],
            Vec::new(),
            Some(unreadable()),
        )
        .unwrap_err();
        assert!(
            matches!(err, Pkcs11Error::DataObjectUnreadable { .. }),
            "got {err:?}"
        );
    }

    /// The public branch already refused in this situation; the private branch
    /// has no reason to be the more forgiving of the two.
    #[test]
    fn an_unreadable_sibling_refuses_a_public_object_too() {
        let err = choose_data_object(
            "tessera-p12",
            Vec::new(),
            vec![found(false, b"envelope")],
            Some(unreadable()),
        )
        .unwrap_err();
        assert!(
            matches!(err, Pkcs11Error::DataObjectUnreadable { .. }),
            "got {err:?}"
        );
    }

    /// Without a sibling failure the private object is the carrier, and a
    /// public decoy beside it does not shadow it.
    #[test]
    fn a_lone_private_object_wins_over_a_public_decoy() {
        let chosen = choose_data_object(
            "tessera-p12",
            vec![found(true, b"envelope")],
            vec![found(false, b"decoy")],
            None,
        )
        .expect("the private object is the carrier");
        assert!(chosen.private);
        assert_eq!(chosen.value, b"envelope");
    }

    /// Two equally private objects are refused before anything else is
    /// considered: there is nothing to choose between them.
    #[test]
    fn two_private_objects_are_ambiguous() {
        let err = choose_data_object(
            "tessera-p12",
            vec![found(true, b"one"), found(true, b"two")],
            Vec::new(),
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, Pkcs11Error::DataObjectAmbiguous { count: 2, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn nothing_under_the_label_is_not_found() {
        let err = choose_data_object("tessera-p12", Vec::new(), Vec::new(), None).unwrap_err();
        assert!(
            matches!(err, Pkcs11Error::DataObjectNotFound { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn reports_the_value_and_the_privacy_flag() {
        let found = read_data_object_attributes("tessera-p12", Some(vec![1, 2, 3]), Some(true))
            .expect("attributes are complete");
        assert_eq!(found.value, vec![1, 2, 3]);
        assert!(found.private);
    }

    #[test]
    fn an_empty_value_is_a_value() {
        // A zero-length CKA_VALUE is what a token returns for an object whose
        // write was silently dropped.  It is not a read failure, and calling it
        // one would hide the write defect behind a provider error.
        let found = read_data_object_attributes("tessera-p12", Some(Vec::new()), Some(true))
            .expect("an empty value is still a value");
        assert!(found.value.is_empty());
    }

    #[test]
    fn a_missing_value_names_the_attribute() {
        let err = read_data_object_attributes("tessera-p12", None, Some(true)).unwrap_err();
        assert!(
            matches!(
                err,
                Pkcs11Error::DataObjectUnreadable {
                    attribute: "CKA_VALUE",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn unknown_privacy_is_unreadable_rather_than_public() {
        let err =
            read_data_object_attributes("tessera-p12", Some(vec![0x30, 0x82]), None).unwrap_err();
        assert!(
            matches!(
                err,
                Pkcs11Error::DataObjectUnreadable {
                    attribute: "CKA_PRIVATE",
                    ..
                }
            ),
            "a provider that will not say whether the object needs a PIN must not be read \
             as saying it does not: got {err:?}"
        );
    }

    /// The container is a PKCS#12 envelope whose private key comes out with the
    /// container password.  This type is handled on the authentication path, so
    /// a `Debug` that printed the value would put the envelope into the journal
    /// of whatever process is serving the login.
    #[test]
    fn debug_shows_the_size_and_not_the_container() {
        let found = read_data_object_attributes(
            "tessera-p12",
            Some(vec![0x42, 0x42, 0x42, 0x42, 0x42, 0x42]),
            Some(true),
        )
        .expect("attributes are complete");
        let shown = format!("{found:?}");
        assert!(
            shown.contains("bytes: 6"),
            "the size is what a diagnostic needs: {shown}"
        );
        assert!(shown.contains("private: true"), "{shown}");
        assert!(!shown.contains("66"), "the contents must not show: {shown}");
        assert!(!shown.contains("value"), "{shown}");
    }

    /// The two failures a caller has to tell apart carry different variants,
    /// and neither carries the object's contents.
    #[test]
    fn not_found_and_unreadable_are_distinct_and_carry_no_payload() {
        let not_found = Pkcs11Error::DataObjectNotFound {
            label: "tessera-p12".to_owned(),
        };
        let unreadable = Pkcs11Error::DataObjectUnreadable {
            label: "tessera-p12".to_owned(),
            attribute: "CKA_VALUE",
        };
        assert!(matches!(not_found, Pkcs11Error::DataObjectNotFound { .. }));
        assert!(!matches!(
            unreadable,
            Pkcs11Error::DataObjectNotFound { .. }
        ));
        assert_ne!(not_found.to_string(), unreadable.to_string());
    }
}
