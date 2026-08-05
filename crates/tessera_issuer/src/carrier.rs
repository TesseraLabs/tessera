//! Laying issued artifacts out on a carrier, where the device's check looks for
//! them.
//!
//! The paths below are not a convention this module invents: they are what the
//! login path opens. Leaving the layout to a written instruction makes every
//! mistyped directory look like a product failure at the login screen, which is
//! the worst place to find one — the engineer is at the device, usually without
//! the issuing operator and often without a network.
//!
//! Two rules the module enforces beyond copying bytes:
//!
//! * an existing container is not overwritten without an explicit yes. A
//!   carrier can already hold a working credential belonging to somebody else,
//!   and overwriting one silently destroys a shift;
//! * the container's password is never written next to it. Container and
//!   password travel by separate channels, and a file holding both on one
//!   carrier collapses that separation — so no call here takes a password at
//!   all.

use std::path::{Path, PathBuf};

/// Where the device's check looks for the container, relative to the mounted
/// carrier.
pub const CONTAINER_RELATIVE_PATH: &str = "certs/user.p12";
/// Where the device's check looks for the trust chain, relative to the mounted
/// carrier. Fixed, deliberately not following the container path.
pub const CHAIN_RELATIVE_PATH: &str = "certs/chain.pem";

/// A failure laying artifacts out on a carrier.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CarrierError {
    /// A filesystem operation failed; the path is named.
    #[error("{path}: {source}")]
    Io {
        /// The path the operation was on.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// A container already sits at the target path and the caller did not
    /// confirm the overwrite.
    #[error("{0} already holds a container; confirm the overwrite before replacing it")]
    WouldOverwrite(PathBuf),
    /// The carrier kind asked for is not implemented yet.
    #[error("{0}")]
    Unsupported(&'static str),
    /// The operator-supplied container path would land outside the carrier.
    #[error(
        "container path '{path}' must be relative to the carrier and must not contain '..' or a \
         root: {reason}"
    )]
    PathEscapesCarrier {
        /// The path as the operator wrote it.
        path: String,
        /// Which rule it broke.
        reason: &'static str,
    },
    /// The container is bigger than a token data object is known to hold.
    #[error(
        "the container is {bytes} bytes and a token data object is only known to hold {limit}; \
         a token accepts the write and truncates it without saying so, so it is refused here"
    )]
    TokenObjectTooLarge {
        /// The container's size.
        bytes: usize,
        /// The largest size this tool will attempt.
        limit: usize,
    },
    /// The label naming the data object is not one a device can look up.
    #[error("the token object label is unusable: {0}")]
    TokenObjectLabel(&'static str),
    /// The token already holds a data object under that label and the caller
    /// did not confirm the replacement.
    #[error("the token already holds an object labelled '{0}'; confirm before replacing it")]
    TokenObjectExists(String),
    /// Creating or destroying the object on the token failed. The message is
    /// the PKCS#11 status, never the container's contents.
    #[error("writing the object labelled '{label}' to the token failed: {status}")]
    TokenWriteFailed {
        /// The object's `CKA_LABEL`.
        label: String,
        /// The PKCS#11 status text.
        status: String,
    },
    /// What came back off the token is not what was written. Carries sizes and
    /// a description, never bytes: the container holds a private key.
    #[error("the object labelled '{label}' did not survive the write: {detail}")]
    TokenWriteNotVerified {
        /// The object's `CKA_LABEL`.
        label: String,
        /// How the read-back differed.
        detail: String,
    },
    /// A write failed and the object it had already put on the token could not
    /// be removed again.
    ///
    /// Separate from the failure that caused it because it asks something of
    /// the operator: the token now holds an object nobody verified, and the
    /// device would find it and report a damaged container.
    #[error(
        "{source}; the object labelled '{label}' left behind could not be removed either \
         ({status}), so the token needs clearing by hand before it is handed out"
    )]
    TokenFragmentLeft {
        /// The `CKA_LABEL` the leftover object carries.
        label: String,
        /// The PKCS#11 status of the failed removal.
        status: String,
        /// The failure that made the write stop.
        #[source]
        source: Box<CarrierError>,
    },
    /// Reaching the token failed — the module, the slot, the session, the PIN.
    #[cfg(feature = "pkcs11")]
    #[error(transparent)]
    Token(#[from] crate::pkcs11::Pkcs11SignError),
}

/// The largest container this tool will offer a token data object.
///
/// Measured on a Rutoken Lite (`rtpkcs11ecp` 2.14.1): objects up to 32 KiB
/// survive a round trip, 48 KiB comes back truncated to 32768 bytes and 64 KiB
/// comes back empty — in both cases after `C_CreateObject` reported success.
/// The number is therefore one device's ceiling rather than a rule, which is
/// why it never stands alone: every write is verified by reading it back, and
/// that catches a lower ceiling on a model nobody has measured.
pub const MAX_TOKEN_OBJECT_BYTES: usize = 32 * 1024;

/// Refuse a container that is too large for a token data object.
///
/// Runs before the module is even loaded. The order is the point: a token
/// answers an oversized `C_CreateObject` with success and stores a fragment, so
/// an engineer would leave with a token that opens nothing and a tool that said
/// it worked.
///
/// # Errors
///
/// [`CarrierError::TokenObjectTooLarge`] naming both sizes.
pub fn check_container_fits(bytes: usize) -> Result<(), CarrierError> {
    if bytes > MAX_TOKEN_OBJECT_BYTES {
        return Err(CarrierError::TokenObjectTooLarge {
            bytes,
            limit: MAX_TOKEN_OBJECT_BYTES,
        });
    }
    Ok(())
}

/// Refuse a label the device's lookup could not use.
///
/// The device finds the envelope by `CKA_LABEL` and by nothing else, so a label
/// that cannot be searched for produces a token whose contents are unreachable
/// even though everything was written.
///
/// # Errors
///
/// [`CarrierError::TokenObjectLabel`] naming the rule the label broke.
pub fn check_object_label(label: &str) -> Result<(), CarrierError> {
    if label.is_empty() {
        return Err(CarrierError::TokenObjectLabel("it is empty"));
    }
    if label.len() > MAX_OPERATOR_LABEL_BYTES {
        return Err(CarrierError::TokenObjectLabel(
            "it is longer than a token label field holds once the write's staging prefix is \
             added to it",
        ));
    }
    Ok(())
}

/// Longest `CKA_LABEL` this tool writes.
///
/// PKCS#11 puts no limit on the attribute, but tokens do, and one that trims
/// the label stores an object the device then cannot find. The bound is
/// generous next to the labels an operator actually types.
const MAX_OBJECT_LABEL_BYTES: usize = 128;

/// Longest object label an operator may ask for.
///
/// Shorter than what the field holds, because the write puts the object on the
/// token under [`STAGING_LABEL_PREFIX`] first and a prefix that did not fit
/// would be trimmed by the token — leaving the staged object under a label the
/// cleanup then does not find.
const MAX_OPERATOR_LABEL_BYTES: usize = MAX_OBJECT_LABEL_BYTES - STAGING_LABEL_PREFIX.len();

/// Prefix marking the label a token write is staged under.
///
/// Recognisable on sight, so an object a run interrupted mid-write left behind
/// can be told apart from a credential by looking at the token's contents.
const STAGING_LABEL_PREFIX: &str = ".tessera-staging-";

/// The label a write to `label` is staged under.
#[cfg(feature = "pkcs11")]
fn staging_label(label: &str) -> String {
    format!("{STAGING_LABEL_PREFIX}{label}")
}

/// Judge a read-back against what was written.
///
/// Separate from the token call so the judgement can be exercised without one:
/// the failure it exists to catch — a write the token reported as successful
/// and truncated anyway — has no error code to test against.
///
/// The privacy flag is checked here too. A token that stored the object public
/// after being asked for a private one has produced a container readable
/// without the PIN, and that is a failed write in exactly the same sense as a
/// truncated one.
///
/// # Errors
///
/// [`CarrierError::TokenWriteNotVerified`] describing the difference in sizes
/// and flags — never in contents.
#[cfg(feature = "pkcs11")]
pub(crate) fn verify_read_back(
    label: &str,
    written: &[u8],
    read_back: &[u8],
    private: bool,
) -> Result<(), CarrierError> {
    let failed = |detail: String| CarrierError::TokenWriteNotVerified {
        label: label.to_owned(),
        detail,
    };
    if written.len() != read_back.len() {
        return Err(failed(format!(
            "wrote {} bytes and read back {}",
            written.len(),
            read_back.len()
        )));
    }
    if written != read_back {
        return Err(failed(format!(
            "the {} bytes read back differ from the ones written",
            written.len()
        )));
    }
    if !private {
        return Err(failed(
            "the object came back readable without the PIN".to_owned(),
        ));
    }
    Ok(())
}

/// Validates an operator-supplied container path against the carrier.
///
/// `Path::join` replaces the whole path when given an absolute one and does not
/// collapse `..`, so an unvalidated override does not merely miss the carrier —
/// it writes wherever it points, and the overwrite gate ahead of it is asking
/// about a different file than the one that gets written. The rules here are
/// the device's own rules for `pkcs12_path_pattern`: relative, no traversal.
///
/// This runs *before* any `join`, and every caller goes through it — the
/// layout, the presence check and the overwrite prompt must agree on one path.
///
/// # Errors
///
/// [`CarrierError::PathEscapesCarrier`] naming the rule the path broke.
pub fn check_container_path(relative: &str) -> Result<(), CarrierError> {
    use std::path::Component;

    let escapes = |reason: &'static str| CarrierError::PathEscapesCarrier {
        path: relative.to_owned(),
        reason,
    };

    if relative.is_empty() {
        return Err(escapes("it is empty"));
    }
    let path = Path::new(relative);
    if path.is_absolute() {
        return Err(escapes("it is absolute"));
    }
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            Component::ParentDir => return Err(escapes("it walks up out of the carrier")),
            Component::RootDir | Component::Prefix(_) => return Err(escapes("it names a root")),
            Component::CurDir => return Err(escapes("it contains a '.' segment")),
        }
    }
    Ok(())
}

/// The absolute path a container takes on `media_root`, validated.
fn container_path(media_root: &Path, relative: Option<&str>) -> Result<PathBuf, CarrierError> {
    let relative = relative.unwrap_or(CONTAINER_RELATIVE_PATH);
    check_container_path(relative)?;
    Ok(media_root.join(relative))
}

/// What a caller decided about replacing an existing container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overwrite {
    /// Refuse if the target already holds a container.
    Refuse,
    /// Replace it; the operator has confirmed.
    Allow,
}

/// The artifacts a carrier receives.
#[derive(Debug, Clone, Copy)]
pub struct CarrierPayload<'a> {
    /// The PKCS#12 container bytes.
    pub container: &'a [u8],
    /// The trust chain in PEM form, or `None` to leave the carrier's chain
    /// alone.
    pub chain_pem: Option<&'a [u8]>,
}

/// The paths a layout wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenPaths {
    /// Where the container was written.
    pub container: PathBuf,
    /// Where the chain was written, if one was supplied.
    pub chain: Option<PathBuf>,
}

/// Lays the payload out under `media_root`, creating the directories the layout
/// needs.
///
/// `container_relative` overrides [`CONTAINER_RELATIVE_PATH`] for a fleet whose
/// device configuration names a different container path; the chain path is
/// fixed either way, matching what the device's discovery does.
///
/// # Errors
///
/// [`CarrierError::WouldOverwrite`] when a container is already in place and
/// `overwrite` is [`Overwrite::Refuse`]; [`CarrierError::Io`] for any
/// filesystem failure, naming the path it happened on.
pub fn lay_out_media(
    media_root: &Path,
    payload: &CarrierPayload<'_>,
    container_relative: Option<&str>,
    overwrite: Overwrite,
) -> Result<WrittenPaths, CarrierError> {
    let container_path = container_path(media_root, container_relative)?;
    let chain_path = payload
        .chain_pem
        .map(|_| media_root.join(CHAIN_RELATIVE_PATH));

    if overwrite == Overwrite::Refuse {
        // The chain counts as much as the container: replacing one engineer's
        // chain with another's leaves a carrier whose two halves disagree, and
        // that surfaces as a chain failure at the login screen.
        for existing in [Some(&container_path), chain_path.as_ref()]
            .into_iter()
            .flatten()
        {
            if existing.exists() {
                return Err(CarrierError::WouldOverwrite(existing.clone()));
            }
        }
    }

    write_under(&container_path, payload.container)?;
    if let (Some(path), Some(chain)) = (chain_path.as_ref(), payload.chain_pem) {
        write_under(path, chain)?;
    }
    Ok(WrittenPaths {
        container: container_path,
        chain: chain_path,
    })
}

/// The first artifact the layout would replace, if any.
///
/// Callers ask this before prompting, so the operator is only interrupted when
/// there is something to lose — and so the question names the file that is
/// actually at stake rather than the one that usually is. Covers both artifacts
/// for the reason [`lay_out_media`] gives.
///
/// # Errors
///
/// [`CarrierError::PathEscapesCarrier`] when the operator-supplied container
/// path is not one the carrier can hold.
pub fn artifact_at_risk(
    media_root: &Path,
    container_relative: Option<&str>,
    with_chain: bool,
) -> Result<Option<PathBuf>, CarrierError> {
    let container = container_path(media_root, container_relative)?;
    if container.exists() {
        return Ok(Some(container));
    }
    if with_chain {
        let chain = media_root.join(CHAIN_RELATIVE_PATH);
        if chain.exists() {
            return Ok(Some(chain));
        }
    }
    Ok(None)
}

/// Writes `bytes` to `path`, owner-only, atomically.
///
/// Three properties, each for its own reason:
///
/// * **owner-only.** The container carries a private key; the platform default
///   would leave it readable by every local account on the machine preparing
///   the carrier.
/// * **written through a fresh file, then renamed.** `create_new` refuses to
///   follow a symlink or reuse an existing file, so neither the mode of a file
///   already in place nor a link planted at the target decides where the bytes
///   land or who can read them.
/// * **flushed before the rename returns.** A carrier pulled out between the
///   write and the kernel's own flush leaves a truncated container, which the
///   device reports as a damaged file rather than as the wrong carrier — the
///   diagnostic this whole layout exists to keep meaningful.
fn write_under(path: &Path, bytes: &[u8]) -> Result<(), CarrierError> {
    use std::io::Write as _;

    let io = |path: &Path, source: std::io::Error| CarrierError::Io {
        path: path.to_path_buf(),
        source,
    };

    let parent = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;

    let staged = staging_path(path);
    // A leftover from an interrupted earlier run would make `create_new` fail;
    // removing it is safe because the name is ours and holds nothing anybody
    // asked to keep.
    drop(std::fs::remove_file(&staged));

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&staged).map_err(|e| io(&staged, e))?;
    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| io(&staged, e));
    drop(file);
    if let Err(e) = written {
        drop(std::fs::remove_file(&staged));
        return Err(e);
    }

    std::fs::rename(&staged, path).map_err(|e| io(path, e))?;
    // The rename itself is metadata: without flushing the directory the entry
    // can outlive the data on a carrier that is pulled out.
    if let Ok(dir) = std::fs::File::open(parent) {
        drop(dir.sync_all());
    }
    Ok(())
}

/// The temporary name a write stages through, beside its target.
///
/// Beside, not in a temp directory: a rename is only atomic within one
/// filesystem, and the carrier is a different one from the host's.
fn staging_path(path: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(".tessera-staging-");
    name.push(path.file_name().unwrap_or_else(|| "artifact".as_ref()));
    path.with_file_name(name)
}

/// The refusal returned for a passive-token carrier by a build without the
/// PKCS#11 feature.
///
/// # Errors
///
/// Always [`CarrierError::Unsupported`].
#[cfg(not(feature = "pkcs11"))]
pub fn lay_out_token() -> Result<TokenObjectWritten, CarrierError> {
    Err(CarrierError::Unsupported(
        "this build cannot reach a token; rebuild with the `pkcs11` feature, or lay the \
         credential out on a USB carrier instead",
    ))
}

/// Which token, and which object on it, a container is written to.
#[derive(Debug, Clone, Copy)]
pub struct TokenTarget<'a> {
    /// Filesystem path to the token's PKCS#11 module.
    pub module_path: &'a Path,
    /// The token's label, or `None` to take the first slot with a token.
    ///
    /// Naming one is worth the trouble: an operator preparing a credential
    /// usually has the CA token plugged in as well, and the first slot is then
    /// the wrong token.
    pub token_label: Option<&'a str>,
    /// The `CKA_LABEL` the device's check looks the container up by.
    pub object_label: &'a str,
}

/// What a token write put where, for the operator's record.
///
/// The token is identified by what it says about itself rather than by the slot
/// index, so a record made with two tokens plugged in still says which one
/// received the container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenObjectWritten {
    /// The object's `CKA_LABEL`.
    pub object_label: String,
    /// The receiving token's label, trailing blanks trimmed.
    pub token_label: String,
    /// The receiving token's serial number, trailing blanks trimmed.
    pub token_serial: String,
    /// How many bytes were written and read back.
    pub bytes: usize,
}

/// Writes `container` into a private data object on a passive token.
///
/// The carrier is a passive token: it stores the container but cannot sign with
/// the key inside it, so this is a removable carrier plus a PIN and not
/// hardware protection of the key.
///
/// Four things happen that a plain `C_CreateObject` would not do:
///
/// * the size is refused up front. A token accepts an oversized object,
///   reports success and stores a fragment;
/// * the object is created with `CKA_PRIVATE`. General-purpose writers default
///   to public, and a public object holding the container hands its extractable
///   private key to anybody who holds the token for a moment;
/// * the object is read back and compared byte for byte before the write is
///   called successful, and destroyed again when it does not match. A fragment
///   left behind would be found by the device and reported as a damaged
///   container rather than as a failed issuance;
/// * a replacement is staged and only then committed. The token that comes in
///   for a replacement usually carries a working credential, and a write that
///   destroyed it first would answer a refused `C_CreateObject` — a full token,
///   a token pulled out mid-write — with an empty carrier and nothing to put
///   back. So the new container goes on under a staging label, is verified
///   there, and only a verified object is renamed into place over the old one.
///
/// The one window that remains is between the old object's removal and the
/// read-back under the real label: the rename has already succeeded by then, so
/// what is left to fail is the token's own lookup of a label it just accepted.
///
/// # Errors
///
/// - [`CarrierError::TokenObjectTooLarge`] / [`CarrierError::TokenObjectLabel`]
///   before the module is loaded.
/// - [`CarrierError::TokenObjectExists`] when the label is taken and
///   `overwrite` is [`Overwrite::Refuse`].
/// - [`CarrierError::TokenWriteFailed`] when the token refuses the object.
/// - [`CarrierError::TokenWriteNotVerified`] when the read-back differs.
/// - [`CarrierError::TokenFragmentLeft`] when a failed write could not be
///   cleaned up after.
/// - [`CarrierError::Token`] for a module, slot, session or PIN failure.
#[cfg(feature = "pkcs11")]
pub fn lay_out_token(
    target: &TokenTarget<'_>,
    container: &[u8],
    pin: &secrecy::SecretString,
    overwrite: Overwrite,
) -> Result<TokenObjectWritten, CarrierError> {
    use cryptoki::object::{Attribute, ObjectClass};
    use zeroize::Zeroize as _;

    use crate::pkcs11::Pkcs11SignError;

    check_container_fits(container.len())?;
    check_object_label(target.object_label)?;

    let label = target.object_label;
    let write_failed = |e: cryptoki::error::Error| CarrierError::TokenWriteFailed {
        label: label.to_owned(),
        status: e.to_string(),
    };

    // Held for the whole operation: `C_Initialize` is process-global state, and
    // on `rtpkcs11ecp` two threads inside it abort the process outright.
    let _guard = token_access();
    let ctx = open_context(target.module_path)?;
    let slot = crate::pkcs11::find_slot_in(&ctx, target.token_label)?;
    let info = ctx
        .get_token_info(slot)
        .map_err(|e| Pkcs11SignError::Session(e.to_string()))?;
    let raw_session = ctx
        .open_rw_session(slot)
        .map_err(|e| Pkcs11SignError::Session(e.to_string()))?;
    let logged_in = LoggedInSession::open(raw_session, pin)?;
    let session = logged_in.raw();

    // After the login, so an existing private object is visible: searching
    // before it would report a free label and then collide.
    let existing = find_data_objects(session, label)?;
    if !existing.is_empty() && overwrite == Overwrite::Refuse {
        return Err(CarrierError::TokenObjectExists(label.to_owned()));
    }

    let staged_label = staging_label(label);
    // A run interrupted mid-write leaves its staged object behind. Clearing it
    // first is safe — the name is this tool's own and holds nothing anybody
    // asked to keep — and leaving it would make the read-back below find two
    // objects under one label.
    for handle in find_data_objects(session, &staged_label)? {
        session
            .destroy_object(handle)
            .map_err(|e| CarrierError::TokenWriteFailed {
                label: staged_label.clone(),
                status: e.to_string(),
            })?;
    }

    let mut template = [
        Attribute::Class(ObjectClass::DATA),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Label(staged_label.as_bytes().to_vec()),
        Attribute::Value(container.to_vec()),
    ];
    let created = session.create_object(&template);
    // The provider's copy of the container is beyond reach; this one is not,
    // and it holds an extractable private key.
    for attribute in &mut template {
        if let Attribute::Value(value) = attribute {
            value.zeroize();
        }
    }
    let staged = created.map_err(write_failed)?;

    // Verified where it cannot be confused with what the token already holds,
    // and before any of that is touched.
    if let Err(e) = read_back_and_verify(session, &staged_label, container) {
        return Err(discard_fragment(session, staged, &staged_label, e));
    }

    // The rename comes before the removal: a token that will not rename the
    // object leaves the old credential in place, which is the outcome to
    // prefer when something has to fail.
    if let Err(e) =
        session.update_attributes(staged, &[Attribute::Label(label.as_bytes().to_vec())])
    {
        return Err(discard_fragment(
            session,
            staged,
            &staged_label,
            write_failed(e),
        ));
    }

    // Every one of them, not just the first: two objects sharing a label leave
    // the device's lookup deciding between an old credential and a new one.
    // Until this finishes the new object shares the label with them, so a
    // failure here is cleared by removing ours rather than theirs.
    for handle in existing {
        if let Err(e) = session.destroy_object(handle) {
            return Err(discard_fragment(session, staged, label, write_failed(e)));
        }
    }

    // Once more under the real label, which is the only question the device
    // ever asks: the read above proved the bytes, this one proves the rename
    // put them where the lookup finds exactly one object.
    if let Err(e) = read_back_and_verify(session, label, container) {
        return Err(discard_fragment(session, staged, label, e));
    }

    Ok(TokenObjectWritten {
        object_label: label.to_owned(),
        token_label: info.label().trim_end().to_owned(),
        token_serial: info.serial_number().trim_end().to_owned(),
        bytes: container.len(),
    })
}

/// A session whose PKCS#11 login is given up on every exit path.
///
/// PKCS#11 scopes a login to the *application* — the `C_Initialize` — rather
/// than to the session that presented the PIN, so a login left behind outlives
/// this call and reaches anyone else holding a session on the same provider.
/// The issuing tool is exactly such a process: the CA token's signer runs on
/// the same library. `cryptoki`'s own `Drop` closes the session and says
/// nothing about the login, which is why this guard exists.
#[cfg(feature = "pkcs11")]
struct LoggedInSession {
    /// The session the login belongs to.
    session: cryptoki::session::Session,
}

#[cfg(feature = "pkcs11")]
impl LoggedInSession {
    /// Log in as `CKU_USER`, displacing a login somebody else left in place.
    ///
    /// `CKR_USER_ALREADY_LOGGED_IN` is not an answer about the PIN: nothing was
    /// checked. Returning it as a login failure would make a correct PIN look
    /// wrong for the rest of the process's life — every later run against the
    /// same context would fail the same way — so the residual login is dropped
    /// and the PIN presented for real, and a wrong one then fails exactly as it
    /// would have on a logged-out token. The cost is that a neighbour sharing
    /// the context has to authenticate again.
    ///
    /// Only one displacement is attempted: a second refusal means something is
    /// putting the login back, and looping would spin inside an authentication.
    ///
    /// # Errors
    ///
    /// [`crate::pkcs11::Pkcs11SignError::Login`] carrying the PKCS#11 status,
    /// never the PIN.
    fn open(
        session: cryptoki::session::Session,
        pin: &secrecy::SecretString,
    ) -> Result<Self, crate::pkcs11::Pkcs11SignError> {
        use cryptoki::error::{Error as CkError, RvError};
        use cryptoki::session::UserType;

        use crate::pkcs11::Pkcs11SignError;

        let failed = |e: CkError| Pkcs11SignError::Login(e.to_string());
        match session.login(UserType::User, Some(pin)) {
            Ok(()) => {}
            Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {
                session.logout().map_err(failed)?;
                session.login(UserType::User, Some(pin)).map_err(failed)?;
            }
            Err(e) => return Err(failed(e)),
        }
        Ok(Self { session })
    }

    /// Borrow the session underneath.
    fn raw(&self) -> &cryptoki::session::Session {
        &self.session
    }
}

#[cfg(feature = "pkcs11")]
impl Drop for LoggedInSession {
    fn drop(&mut self) {
        // There is nobody left to return an error to — the call this guard
        // belongs to has already produced its answer — but a refusal is worth
        // saying out loud: it leaves the token authenticated for whoever holds
        // this context next.
        if let Err(e) = self.session.logout() {
            eprintln!(
                "warning: the token could not be logged out ({e}); it may stay authenticated \
                 until this program exits"
            );
        }
    }
}

/// Read the object back under `label` and judge it against what was written.
#[cfg(feature = "pkcs11")]
fn read_back_and_verify(
    session: &cryptoki::session::Session,
    label: &str,
    written: &[u8],
) -> Result<(), CarrierError> {
    use cryptoki::object::AttributeType;

    let (value, private) = read_back_object(
        session,
        label,
        &[AttributeType::Value, AttributeType::Private],
    )?;
    verify_read_back(label, written, &value, private)
}

/// Remove the object a failed write left on the token, folding a failed removal
/// into the error the caller is about to see.
///
/// A fragment left behind is worse than an empty carrier: the device finds it
/// and reports a damaged container, which reads like a bad issuance rather than
/// a carrier that never took the write. When the removal itself fails the
/// operator has to hear it — the alternative is a verification error that says
/// nothing about the object still sitting on the token.
#[cfg(feature = "pkcs11")]
fn discard_fragment(
    session: &cryptoki::session::Session,
    handle: cryptoki::object::ObjectHandle,
    label: &str,
    cause: CarrierError,
) -> CarrierError {
    let first = match session.destroy_object(handle) {
        Ok(()) => return cause,
        Err(e) => e,
    };
    // Tried once more because the failures seen here are the ones the provider
    // itself describes as worth retrying: `CKR_FUNCTION_FAILED` off a token
    // that has just refused a write for want of memory. A durable refusal fails
    // the same way a second time, at the cost of one call on a path that is
    // already returning an error.
    match session.destroy_object(handle) {
        Ok(()) => cause,
        Err(_) => CarrierError::TokenFragmentLeft {
            label: label.to_owned(),
            status: first.to_string(),
            source: Box::new(cause),
        },
    }
}

/// Serializes every token operation *this crate* performs.
///
/// `C_Initialize` is process-global inside the provider, and `rtpkcs11ecp`
/// 2.14.1 aborts the process when two threads enter it at once. The issuing CLI
/// is single-threaded and never contends for this; a test binary running its
/// cases in parallel does.
///
/// The lock is local to this crate, and that is a real limit rather than an
/// oversight: `tessera_core` keeps its own registry of PKCS#11 contexts behind
/// its own lock, and the two know nothing of each other. A process that runs a
/// carrier write and a `tessera_core` backend at the same time therefore has
/// two locks guarding one piece of provider state, and the invariant does not
/// hold between them. It is not fixed here because the crates cannot share the
/// lock: `tessera_issuer` deliberately does not depend on `tessera_core` (the
/// dependency runs the other way, in `tessera_core`'s dev-dependencies), and
/// the only crate below both is `tessera_ext`, which is pure, dependency-free
/// and compiled for `wasm32` — a PKCS#11 registry does not belong in it.
///
/// What holds it in practice is that the two never run together: the issuing
/// tool has no `tessera_core` backend in it, and the device side has no writer.
#[cfg(feature = "pkcs11")]
fn token_access() -> std::sync::MutexGuard<'static, ()> {
    static TOKEN_ACCESS: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // A poisoned lock means some other token operation panicked. The data
    // behind it is a unit, so there is no corrupt state to protect and refusing
    // the write would only turn one failure into every later one.
    TOKEN_ACCESS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Loads the PKCS#11 module at `path` and makes sure it is initialized.
///
/// `CKR_CRYPTOKI_ALREADY_INITIALIZED` is success: the library is up, which is
/// all this needs, and it may have been brought up by a signer in the same
/// process or by an earlier carrier write — nothing here ever finalizes it, so
/// adopting takes nothing away from whoever did.
#[cfg(feature = "pkcs11")]
fn open_context(path: &Path) -> Result<cryptoki::context::Pkcs11, crate::pkcs11::Pkcs11SignError> {
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::error::{Error as CkError, RvError};

    use crate::pkcs11::Pkcs11SignError;

    if !path.exists() {
        return Err(Pkcs11SignError::ModulePathMissing(path.to_path_buf()));
    }
    let ctx = Pkcs11::new(path).map_err(|e| Pkcs11SignError::ModuleLoad(e.to_string()))?;
    match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => Ok(ctx),
        Err(e) => Err(Pkcs11SignError::Init(e.to_string())),
    }
}

/// Every `CKO_DATA` object on the token carrying `label`.
#[cfg(feature = "pkcs11")]
fn find_data_objects(
    session: &cryptoki::session::Session,
    label: &str,
) -> Result<Vec<cryptoki::object::ObjectHandle>, CarrierError> {
    use cryptoki::object::{Attribute, ObjectClass};

    let template = [
        Attribute::Class(ObjectClass::DATA),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    session
        .find_objects(&template)
        .map_err(|e| CarrierError::TokenWriteFailed {
            label: label.to_owned(),
            status: e.to_string(),
        })
}

/// Read the object back the way the device will: by searching for the label,
/// not by re-using the handle the write returned.
///
/// The handle would answer from whatever the provider has in hand; the search
/// is the question the device actually asks, and it also catches a write that
/// left the token holding two objects under one label.
///
/// The value comes back wiped on drop: it is the container, and a copy of an
/// extractable private key left in freed memory is one the tool made.
#[cfg(feature = "pkcs11")]
fn read_back_object(
    session: &cryptoki::session::Session,
    label: &str,
    want: &[cryptoki::object::AttributeType],
) -> Result<(zeroize::Zeroizing<Vec<u8>>, bool), CarrierError> {
    use cryptoki::object::Attribute;

    let not_verified = |detail: String| CarrierError::TokenWriteNotVerified {
        label: label.to_owned(),
        detail,
    };

    let handles = find_data_objects(session, label)?;
    let handle = match handles.as_slice() {
        [only] => *only,
        [] => return Err(not_verified("the object is not on the token".to_owned())),
        several => {
            return Err(not_verified(format!(
                "the token holds {} objects under this label",
                several.len()
            )))
        }
    };
    let attrs =
        session
            .get_attributes(handle, want)
            .map_err(|e| CarrierError::TokenWriteFailed {
                label: label.to_owned(),
                status: e.to_string(),
            })?;
    let mut value = None;
    let mut private = None;
    for attr in attrs {
        match attr {
            Attribute::Value(v) => value = Some(zeroize::Zeroizing::new(v)),
            Attribute::Private(p) => private = Some(p),
            _ => {}
        }
    }
    match (value, private) {
        (Some(value), Some(private)) => Ok((value, private)),
        (None, _) => Err(not_verified(
            "the token would not say what the object holds".to_owned(),
        )),
        (_, None) => Err(not_verified(
            "the token would not say whether the object needs the PIN".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;

    fn payload<'a>(container: &'a [u8], chain: Option<&'a [u8]>) -> CarrierPayload<'a> {
        CarrierPayload {
            container,
            chain_pem: chain,
        }
    }

    #[test]
    fn writes_where_the_device_looks_and_creates_directories() {
        let media = tempfile::tempdir().unwrap();
        let written = lay_out_media(
            media.path(),
            &payload(b"container", Some(b"chain")),
            None,
            Overwrite::Refuse,
        )
        .unwrap();

        assert_eq!(written.container, media.path().join("certs/user.p12"));
        assert_eq!(written.chain, Some(media.path().join("certs/chain.pem")));
        assert_eq!(
            std::fs::read(media.path().join("certs/user.p12")).unwrap(),
            b"container"
        );
        assert_eq!(
            std::fs::read(media.path().join("certs/chain.pem")).unwrap(),
            b"chain"
        );
    }

    #[test]
    fn honours_an_operator_container_path() {
        let media = tempfile::tempdir().unwrap();
        let written = lay_out_media(
            media.path(),
            &payload(b"container", None),
            Some("tessera/alice.p12"),
            Overwrite::Refuse,
        )
        .unwrap();

        assert_eq!(written.container, media.path().join("tessera/alice.p12"));
        assert_eq!(written.chain, None);
    }

    #[test]
    fn refuses_to_replace_an_existing_container() {
        let media = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(media.path().join("certs")).unwrap();
        std::fs::write(media.path().join("certs/user.p12"), b"someone-else").unwrap();

        let err = lay_out_media(
            media.path(),
            &payload(b"mine", None),
            None,
            Overwrite::Refuse,
        )
        .unwrap_err();

        assert!(
            matches!(err, CarrierError::WouldOverwrite(_)),
            "got {err:?}"
        );
        assert_eq!(
            std::fs::read(media.path().join("certs/user.p12")).unwrap(),
            b"someone-else",
            "the refusal must leave the existing container untouched"
        );
    }

    #[test]
    fn replaces_an_existing_container_once_confirmed() {
        let media = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(media.path().join("certs")).unwrap();
        std::fs::write(media.path().join("certs/user.p12"), b"old").unwrap();

        lay_out_media(media.path(), &payload(b"new", None), None, Overwrite::Allow).unwrap();

        assert_eq!(
            std::fs::read(media.path().join("certs/user.p12")).unwrap(),
            b"new"
        );
    }

    #[test]
    fn artifact_at_risk_names_the_file_that_is_at_stake() {
        let media = tempfile::tempdir().unwrap();
        assert_eq!(artifact_at_risk(media.path(), None, true).unwrap(), None);
        std::fs::create_dir_all(media.path().join("certs")).unwrap();

        // A chain alone is enough to warn about — and the warning must name the
        // chain, not the container that is not there.
        std::fs::write(media.path().join("certs/chain.pem"), b"x").unwrap();
        assert_eq!(
            artifact_at_risk(media.path(), None, true).unwrap(),
            Some(media.path().join("certs/chain.pem"))
        );
        assert_eq!(artifact_at_risk(media.path(), None, false).unwrap(), None);

        std::fs::write(media.path().join("certs/user.p12"), b"x").unwrap();
        assert_eq!(
            artifact_at_risk(media.path(), None, false).unwrap(),
            Some(media.path().join("certs/user.p12"))
        );
    }

    #[test]
    fn refuses_to_replace_an_existing_chain() {
        let media = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(media.path().join("certs")).unwrap();
        std::fs::write(media.path().join("certs/chain.pem"), b"someone-else").unwrap();

        let err = lay_out_media(
            media.path(),
            &payload(b"mine", Some(b"my-chain")),
            None,
            Overwrite::Refuse,
        )
        .unwrap_err();

        assert!(
            matches!(err, CarrierError::WouldOverwrite(_)),
            "got {err:?}"
        );
        assert_eq!(
            std::fs::read(media.path().join("certs/chain.pem")).unwrap(),
            b"someone-else"
        );
        assert!(
            !media.path().join("certs/user.p12").exists(),
            "a refusal must write nothing at all"
        );
    }

    #[test]
    fn refuses_a_container_path_that_leaves_the_carrier() {
        let media = tempfile::tempdir().unwrap();
        for escape in [
            "../outside.p12",
            "certs/../../outside.p12",
            "/etc/tessera/user.p12",
            "",
        ] {
            let err = lay_out_media(
                media.path(),
                &payload(b"container", None),
                Some(escape),
                Overwrite::Allow,
            )
            .unwrap_err();
            assert!(
                matches!(err, CarrierError::PathEscapesCarrier { .. }),
                "'{escape}' must be refused, got {err:?}"
            );
        }
        // And the same rule answers the question the overwrite prompt asks, so
        // the two cannot disagree about which file is at stake.
        assert!(artifact_at_risk(media.path(), Some("../outside.p12"), false).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn artifacts_are_owner_only_even_when_replacing_a_wider_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let media = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(media.path().join("certs")).unwrap();
        let target = media.path().join("certs/user.p12");
        std::fs::write(&target, b"old").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o666)).unwrap();

        lay_out_media(media.path(), &payload(b"new", None), None, Overwrite::Allow).unwrap();

        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "replacing a file must not inherit its mode");
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_target_is_not_followed() {
        let media = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(media.path().join("certs")).unwrap();
        let elsewhere = media.path().join("elsewhere.txt");
        std::fs::write(&elsewhere, b"untouched").unwrap();
        std::os::unix::fs::symlink(&elsewhere, media.path().join("certs/user.p12")).unwrap();

        lay_out_media(
            media.path(),
            &payload(b"container", None),
            None,
            Overwrite::Allow,
        )
        .unwrap();

        assert_eq!(
            std::fs::read(&elsewhere).unwrap(),
            b"untouched",
            "the write must not travel down a planted symlink"
        );
        assert_eq!(
            std::fs::read(media.path().join("certs/user.p12")).unwrap(),
            b"container"
        );
        assert!(!media.path().join("certs/user.p12").is_symlink());
    }

    #[test]
    fn leaves_no_staging_file_behind() {
        let media = tempfile::tempdir().unwrap();
        lay_out_media(
            media.path(),
            &payload(b"container", Some(b"chain")),
            None,
            Overwrite::Refuse,
        )
        .unwrap();
        let leftovers: Vec<String> = std::fs::read_dir(media.path().join("certs"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".tessera-staging-"))
            .collect();
        assert!(leftovers.is_empty(), "got {leftovers:?}");
    }

    #[test]
    fn a_container_within_the_measured_ceiling_is_offered_to_the_token() {
        assert!(check_container_fits(0).is_ok());
        assert!(check_container_fits(3 * 1024).is_ok());
        assert!(check_container_fits(MAX_TOKEN_OBJECT_BYTES).is_ok());
    }

    #[test]
    fn an_oversized_container_is_refused_with_both_sizes() {
        let err = check_container_fits(48 * 1024).unwrap_err();
        match err {
            CarrierError::TokenObjectTooLarge { bytes, limit } => {
                assert_eq!(bytes, 48 * 1024);
                assert_eq!(limit, MAX_TOKEN_OBJECT_BYTES);
            }
            other => panic!("got {other:?}"),
        }
    }

    /// The size is judged before anything reaches the token. The proof is the
    /// error: the module path here does not exist, so a check made in the wrong
    /// order would fail on the module instead — and on a real token the wrong
    /// order does not fail at all, it truncates.
    #[cfg(feature = "pkcs11")]
    #[test]
    fn an_oversized_container_is_refused_before_the_module_is_touched() {
        let err = lay_out_token(
            &TokenTarget {
                module_path: Path::new("/nonexistent/__tessera_no_module__.so"),
                token_label: None,
                object_label: "tessera-p12",
            },
            &vec![0xAB; 48 * 1024],
            &secrecy::SecretString::from("12345678".to_owned()),
            Overwrite::Allow,
        )
        .unwrap_err();
        assert!(
            matches!(err, CarrierError::TokenObjectTooLarge { .. }),
            "got {err:?}"
        );
    }

    /// Same order argument for the label: a token reached with an unusable one
    /// would store an object the device cannot look up.
    #[cfg(feature = "pkcs11")]
    #[test]
    fn an_empty_object_label_is_refused_before_the_module_is_touched() {
        let err = lay_out_token(
            &TokenTarget {
                module_path: Path::new("/nonexistent/__tessera_no_module__.so"),
                token_label: None,
                object_label: "",
            },
            b"container",
            &secrecy::SecretString::from("12345678".to_owned()),
            Overwrite::Allow,
        )
        .unwrap_err();
        assert!(
            matches!(err, CarrierError::TokenObjectLabel(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn an_unusable_object_label_is_refused() {
        assert!(check_object_label("tessera-p12").is_ok());
        assert!(check_object_label("").is_err());
        assert!(check_object_label(&"x".repeat(MAX_OPERATOR_LABEL_BYTES)).is_ok());
        assert!(check_object_label(&"x".repeat(MAX_OPERATOR_LABEL_BYTES + 1)).is_err());
    }

    /// The staged label goes onto the token like any other, so it has to fit
    /// the same field. A label the token trimmed would leave the staged object
    /// under a name the cleanup does not find — and the cleanup is what keeps a
    /// half-written container off the carrier.
    #[cfg(feature = "pkcs11")]
    #[test]
    fn the_longest_accepted_label_still_fits_once_it_is_staged() {
        let longest = "x".repeat(MAX_OPERATOR_LABEL_BYTES);
        assert!(check_object_label(&longest).is_ok());
        assert!(
            staging_label(&longest).len() <= MAX_OBJECT_LABEL_BYTES,
            "staged form is {} bytes",
            staging_label(&longest).len()
        );
    }

    /// The staging label is recognisable on a token: an operator looking at
    /// what a run left behind has to be able to tell it from a credential.
    #[cfg(feature = "pkcs11")]
    #[test]
    fn a_staged_label_is_marked_as_one() {
        let staged = staging_label("tessera-p12");
        assert!(staged.starts_with(STAGING_LABEL_PREFIX), "{staged}");
        assert!(staged.ends_with("tessera-p12"), "{staged}");
        assert_ne!(staged, "tessera-p12");
    }

    /// The failure that names a leftover object must say what went wrong *and*
    /// that the token needs clearing; a caller shown only one of the two either
    /// hands out a token with a fragment on it or cannot tell why.
    #[test]
    fn a_leftover_fragment_is_reported_with_its_cause() {
        let err = CarrierError::TokenFragmentLeft {
            label: ".tessera-staging-tessera-p12".to_owned(),
            status: "CKR_DEVICE_ERROR".to_owned(),
            source: Box::new(CarrierError::TokenWriteNotVerified {
                label: ".tessera-staging-tessera-p12".to_owned(),
                detail: "wrote 4096 bytes and read back 2048".to_owned(),
            }),
        };
        let shown = err.to_string();
        assert!(shown.contains("read back 2048"), "{shown}");
        assert!(shown.contains("CKR_DEVICE_ERROR"), "{shown}");
        assert!(shown.contains(".tessera-staging-tessera-p12"), "{shown}");
        assert!(shown.contains("by hand"), "{shown}");
    }

    /// The failure this whole path exists for: the token reported success and
    /// stored a fragment. There is no status code for it, so the read-back is
    /// the only evidence, and it has to be treated as a failed write.
    #[cfg(feature = "pkcs11")]
    #[test]
    fn a_truncated_read_back_is_a_failed_write() {
        let written = vec![0xAB; 4096];
        let err = verify_read_back("tessera-p12", &written, &written[..2048], true).unwrap_err();
        match err {
            CarrierError::TokenWriteNotVerified { label, detail } => {
                assert_eq!(label, "tessera-p12");
                assert!(
                    detail.contains("4096") && detail.contains("2048"),
                    "{detail}"
                );
            }
            other => panic!("got {other:?}"),
        }
    }

    #[cfg(feature = "pkcs11")]
    #[test]
    fn a_read_back_of_the_right_length_but_the_wrong_bytes_is_a_failed_write() {
        let written = vec![0xAB; 512];
        let mut read_back = written.clone();
        read_back[0] = 0x00;
        let err = verify_read_back("tessera-p12", &written, &read_back, true).unwrap_err();
        assert!(
            matches!(err, CarrierError::TokenWriteNotVerified { .. }),
            "got {err:?}"
        );
    }

    #[cfg(feature = "pkcs11")]
    #[test]
    fn an_object_that_came_back_public_is_a_failed_write() {
        let written = vec![0xAB; 512];
        let err = verify_read_back("tessera-p12", &written, &written, false).unwrap_err();
        match err {
            CarrierError::TokenWriteNotVerified { detail, .. } => {
                assert!(detail.contains("PIN"), "{detail}");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[cfg(feature = "pkcs11")]
    #[test]
    fn an_identical_private_read_back_confirms_the_write() {
        let written = vec![0xAB; 2571];
        assert!(verify_read_back("tessera-p12", &written, &written, true).is_ok());
    }

    /// No error on this path may carry the container: it holds a private key,
    /// and these messages go to an operator's terminal and their logs.
    #[test]
    fn token_errors_never_carry_the_container() {
        let secret = vec![0x42; 64];
        let errors = [
            CarrierError::TokenObjectTooLarge {
                bytes: 48 * 1024,
                limit: MAX_TOKEN_OBJECT_BYTES,
            },
            CarrierError::TokenObjectExists("tessera-p12".to_owned()),
            CarrierError::TokenWriteFailed {
                label: "tessera-p12".to_owned(),
                status: "CKR_DEVICE_ERROR".to_owned(),
            },
            CarrierError::TokenWriteNotVerified {
                label: "tessera-p12".to_owned(),
                detail: "wrote 64 bytes and read back 8".to_owned(),
            },
        ];
        let hex = hex::encode(&secret);
        for err in errors {
            let shown = format!("{err} | {err:?}");
            assert!(!shown.contains(&hex), "{shown}");
            assert!(!shown.contains("BBBB"), "{shown}");
        }
    }

    /// The read-back judgement composes its own detail out of what it was
    /// handed, so the rule that no message carries the container has to be
    /// checked against what it produces, not only against handwritten variants.
    #[cfg(feature = "pkcs11")]
    #[test]
    fn a_read_back_failure_never_carries_the_container() {
        let secret = vec![0x42; 64];
        let err = verify_read_back("tessera-p12", &secret, &secret[..8], true).unwrap_err();
        let shown = format!("{err} | {err:?}");
        assert!(!shown.contains(&hex::encode(&secret)), "{shown}");
        assert!(!shown.contains("BBBB"), "{shown}");
    }
}
