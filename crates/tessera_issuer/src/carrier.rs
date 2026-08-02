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
    let container_path = media_root.join(container_relative.unwrap_or(CONTAINER_RELATIVE_PATH));
    if overwrite == Overwrite::Refuse && container_path.exists() {
        return Err(CarrierError::WouldOverwrite(container_path));
    }

    write_under(&container_path, payload.container)?;
    let chain_path = match payload.chain_pem {
        Some(chain) => {
            let path = media_root.join(CHAIN_RELATIVE_PATH);
            write_under(&path, chain)?;
            Some(path)
        }
        None => None,
    };
    Ok(WrittenPaths {
        container: container_path,
        chain: chain_path,
    })
}

/// Whether a container already sits at the layout's target path.
///
/// Callers ask this before prompting, so the operator is only interrupted when
/// there is something to lose.
#[must_use]
pub fn container_present(media_root: &Path, container_relative: Option<&str>) -> bool {
    media_root
        .join(container_relative.unwrap_or(CONTAINER_RELATIVE_PATH))
        .exists()
}

/// Writes `bytes` to `path`, creating the parent directories first.
fn write_under(path: &Path, bytes: &[u8]) -> Result<(), CarrierError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| CarrierError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    std::fs::write(path, bytes).map_err(|source| CarrierError::Io {
        path: path.to_path_buf(),
        source,
    })
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
    fn container_present_reports_the_target_path() {
        let media = tempfile::tempdir().unwrap();
        assert!(!container_present(media.path(), None));
        std::fs::create_dir_all(media.path().join("certs")).unwrap();
        std::fs::write(media.path().join("certs/user.p12"), b"x").unwrap();
        assert!(container_present(media.path(), None));
    }

    #[test]
    fn token_layout_refuses_rather_than_pretending() {
        let err = lay_out_token().unwrap_err();
        assert!(matches!(err, CarrierError::Unsupported(_)), "got {err:?}");
    }
}
