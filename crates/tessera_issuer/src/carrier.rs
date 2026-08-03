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

/// The refusal returned for a passive-token carrier.
///
/// Writing a container into a token data object is a separate piece of work
/// with its own verify-by-reading requirement. Until it exists the operation
/// says so plainly: a stub that appeared to write would leave an engineer
/// travelling to a device with an empty token.
///
/// # Errors
///
/// Always [`CarrierError::Unsupported`].
pub fn lay_out_token() -> Result<WrittenPaths, CarrierError> {
    Err(CarrierError::Unsupported(
        "writing a container to a passive token is not implemented yet; \
         lay the credential out on a USB carrier instead",
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

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
    fn token_layout_refuses_rather_than_pretending() {
        let err = lay_out_token().unwrap_err();
        assert!(matches!(err, CarrierError::Unsupported(_)), "got {err:?}");
    }
}
