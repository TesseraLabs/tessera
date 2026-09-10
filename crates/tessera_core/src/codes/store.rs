//! Where the device keeps what the code method needs.
//!
//! Four artefacts, all of them delivered by enrolment and none of them written
//! by this code: the container holding the device private key, the ticket set,
//! the revocation list of those tickets, and the anchor the tickets are checked
//! against. Beside them sits a state directory this module does write — the
//! throttle of the device and the file its attempt lock is held on.
//!
//! A device missing any of the four does not offer the code method. That is not
//! the same as a configuration error: a fleet that never issued this device a
//! key container has not misconfigured anything, and a PAM stack meeting the
//! method there should fall through to the next one rather than fail the login.
//! The distinction lives in [`CodesPaths::artefacts_present`].

use std::path::{Path, PathBuf};

use openssl::pkey::{PKey, Private};
use secrecy::SecretString;

use crate::pkcs12::{LoadedKeyMaterial, Pkcs12Error};

/// Default directory the artefacts of the code method are delivered to.
pub const DEFAULT_CODES_DIR: &str = "/var/lib/tessera/codes";

/// Default name of the container holding the device private key.
pub const DEVICE_KEY_FILENAME: &str = "device.p12";

/// Default name of the ticket set.
pub const TICKETS_FILENAME: &str = "tickets.txt";

/// Default name of the ticket revocation list.
pub const TICKET_REVOCATIONS_FILENAME: &str = "tickets.revoked";

/// Default name of the ticket authority anchor.
pub const TICKET_ANCHOR_FILENAME: &str = "ticket-authority.pem";

/// Addresses of the engineer's page this device may show, one per line.
///
/// Delivered by the enrollment package and by nothing else. The device shows
/// one of them in front of the challenge and composes no address of its own:
/// whoever could talk a device into showing an address of their choosing would
/// be sending the engineer to a page that collects challenges.
pub const PAGE_URLS_FILENAME: &str = "page-urls.txt";

/// Default name of the directory holding the state this module writes.
pub const STATE_DIRNAME: &str = "state";

/// Sanity cap on a device key container (256 KiB): one key and one chain.
///
/// One value for the delivered container and the stored one, because the stored
/// container is re-written from the delivered material: two limits could only
/// ever disagree, and the disagreement would be a device that accepted a key at
/// enrolment and refused it at every login afterwards.
pub const MAX_KEY_CONTAINER_BYTES: usize = 256 * 1024;

/// Where each artefact of the code method lives.
///
/// The struct is a plain set of paths rather than a parsed configuration
/// section: the PAM branch reads the deployment's configuration and hands the
/// paths over, and this module never has to know how a fleet spells them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodesPaths {
    /// Directory this module writes the throttle and the lock file to.
    pub state_dir: PathBuf,
    /// Container holding the device private key, opened with a PIN.
    pub device_key_container: PathBuf,
    /// The operator tickets the device holds.
    pub tickets: PathBuf,
    /// The revocation list of those tickets.
    pub ticket_revocations: PathBuf,
    /// The anchor every ticket is verified against.
    pub ticket_authority: PathBuf,
    /// Addresses of the engineer's page the fleet allows this device to show.
    pub page_urls: PathBuf,
}

impl CodesPaths {
    /// Returns the default layout under `root`.
    #[must_use]
    pub fn under(root: &Path) -> Self {
        Self {
            state_dir: root.join(STATE_DIRNAME),
            device_key_container: root.join(DEVICE_KEY_FILENAME),
            tickets: root.join(TICKETS_FILENAME),
            ticket_revocations: root.join(TICKET_REVOCATIONS_FILENAME),
            ticket_authority: root.join(TICKET_ANCHOR_FILENAME),
            page_urls: root.join(PAGE_URLS_FILENAME),
        }
    }

    /// Reports whether the device carries the artefacts of the method.
    ///
    /// The revocation list is not among them: a fleet that has withdrawn no
    /// ticket ships no list, and demanding an empty file would turn "nothing to
    /// revoke" into "no code logins".
    #[must_use]
    pub fn artefacts_present(&self) -> bool {
        self.device_key_container.is_file()
            && self.tickets.is_file()
            && self.ticket_authority.is_file()
    }

    /// Reports whether nothing in the path of the artefacts has been weakened.
    ///
    /// Presence is not trust. The artefacts are the whole of what the method
    /// believes: the container holds the key a code is derived from, the anchor
    /// decides which operator tickets are real, and the state directory holds
    /// the record of which nonces are spent. Anybody who can rewrite one of
    /// them can mint codes or replay them, so the ownership and mode of every
    /// component of every path is part of the precondition, not a hardening
    /// nicety.
    ///
    /// The policy is [`ExecTrust::User`] against the account the process is
    /// actually running as, which on a device is root: every component owned by
    /// root or by that account, nothing group- or other-writable. Naming the
    /// running account rather than hard-coding UID 0 is what lets the same
    /// check run in a test without weakening what it demands on a device.
    ///
    /// The revocation list is checked only when it is there — a fleet that has
    /// withdrawn no ticket ships none, and demanding the file would turn
    /// "nothing to revoke" into "no code logins".
    ///
    /// # Errors
    ///
    /// A description of the first path that failed, suitable for the audit
    /// journal. It names the path and the violation, because an administrator
    /// has to be able to fix it without a second tool.
    pub fn check_trusted(&self) -> Result<(), String> {
        self.walk(Presence::Required)
    }

    /// Reports whether the store may be written to at all.
    ///
    /// The same walk as [`Self::check_trusted`], made on a store that is about
    /// to receive a delivery rather than one that already holds it: the
    /// directories are checked, and so is every artefact the device already
    /// carries, while the ones the import is about to publish are simply not
    /// there yet.
    ///
    /// It exists because the check has to run *before* anything is published. A
    /// store whose permissions were weakened is not a store the artefacts may
    /// be written into, and saying so after the write has happened states a
    /// true fact too late: the key would already be on a store somebody else
    /// can read, and the epoch would already have moved past the point where
    /// repeating the import repairs anything.
    ///
    /// What the published files themselves get is not a second walk but the
    /// directory they are written into and the modes they are written with —
    /// both settled here.
    ///
    /// # Errors
    ///
    /// A description of the first path that failed, in the same shape
    /// [`Self::check_trusted`] returns.
    pub fn check_trusted_before_publishing(&self) -> Result<(), String> {
        self.walk(Presence::WhateverIsThere)
    }

    /// Walks the store under the ownership policy of the running account.
    fn walk(&self, presence: Presence) -> Result<(), String> {
        use crate::privileged_path::{validate_directory, validate_file};

        let trust = running_trust();
        let mut paths: Vec<(&str, &Path, bool)> = vec![
            (
                "[codes] device key container",
                &self.device_key_container,
                true,
            ),
            ("[codes] ticket set", &self.tickets, true),
            (
                "[codes] ticket authority anchor",
                &self.ticket_authority,
                true,
            ),
            ("[codes] state directory", &self.state_dir, false),
        ];
        if self.ticket_revocations.exists() {
            paths.push((
                "[codes] ticket revocation list",
                &self.ticket_revocations,
                true,
            ));
        }
        if presence == Presence::WhateverIsThere {
            paths.retain(|(_, path, is_file)| !is_file || path.exists());
        }

        // The reach of the mode comes first, and it is asked of this store
        // rather than of the ownership walk below. That walk answers "who may
        // write this", which is the right question for the ticket set and the
        // anchor — they are trust inputs, published `0644` on purpose. It is
        // not the whole question for the key: the stored container carries no
        // password, deliberately, because a device coming back from a power cut
        // has nobody to type one. Its permissions are therefore the entire
        // protection, and a container left `0644` in a `0755` directory is one
        // `cp` away from an unprivileged account that can then compute this
        // device's codes with any operator it likes.
        for (what, path) in self.owner_only_paths() {
            if !path.exists() {
                continue;
            }
            let mode = owner_only_violation(path).map_err(|error| {
                format!("{what} at {} could not be read: {error}", path.display())
            })?;
            if let Some(mode) = mode {
                return Err(format!(
                    "{what} at {} is reachable beyond its owner (mode {mode:04o})",
                    path.display()
                ));
            }
        }

        for (what, path, is_file) in paths {
            let checked = if is_file {
                validate_file(path, trust).map(|_| ())
            } else {
                validate_directory(path, trust).map(|_| ())
            };
            checked.map_err(|error| {
                format!("{what} at {} is not trustworthy: {error}", path.display())
            })?;
        }
        Ok(())
    }
}

impl CodesPaths {
    /// The parts of the store whose mode has to end at the owner.
    ///
    /// The key container because it is a secret with no password in front of
    /// it, and the two directories because a store somebody made traversable is
    /// a store whose next weakened file nobody notices. The ticket set, the
    /// anchor and the revocation list are deliberately not here: they are trust
    /// inputs rather than secrets, and the import publishes them `0644`.
    fn owner_only_paths(&self) -> Vec<(&'static str, &Path)> {
        let mut paths: Vec<(&'static str, &Path)> = vec![
            ("[codes] device key container", &self.device_key_container),
            ("[codes] state directory", &self.state_dir),
        ];
        if let Some(root) = self.device_key_container.parent() {
            paths.push(("[codes] store directory", root));
        }
        paths
    }
}

/// Reports the mode of `path` when it reaches past its owner, and `None` when
/// it does not.
#[cfg(unix)]
fn owner_only_violation(path: &Path) -> std::io::Result<Option<u32>> {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = std::fs::metadata(path)?.permissions().mode() & 0o7777;
    Ok((mode & 0o077 != 0).then_some(mode))
}

/// Off Unix the mode word does not exist; the walk refuses on its own there.
///
/// What this arm does *not* say is that the store is safe there. The same
/// question on Windows is a DACL, which belongs with the privileged-path
/// machinery that already does DACL work and not with a mode word this file
/// would have to invent. Named here so the `None` is not mistaken for a check
/// that passed.
#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the Result is not spurious: it is the signature the unix arm has, \
              and the shared caller reaches both arms with `?`. Narrowing this \
              arm to `Option<u32>` would move the platform difference from one \
              `cfg` here into every call site of the walk"
)]
fn owner_only_violation(_path: &Path) -> std::io::Result<Option<u32>> {
    Ok(None)
}

/// Which artefacts a walk of the store insists on finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presence {
    /// Every artefact of a ready device has to be there.
    Required,
    /// Only what the device already carries is walked.
    WhateverIsThere,
}

/// The ownership policy of the account this process is running as.
#[cfg(unix)]
fn running_trust() -> crate::privileged_path::ExecTrust {
    crate::privileged_path::ExecTrust::User {
        uid: nix::unistd::geteuid().as_raw(),
        gid: nix::unistd::getegid().as_raw(),
    }
}

/// The ownership policy off Unix, where the walk refuses on its own.
#[cfg(not(unix))]
fn running_trust() -> crate::privileged_path::ExecTrust {
    crate::privileged_path::ExecTrust::Root
}

impl Default for CodesPaths {
    fn default() -> Self {
        Self::under(Path::new(DEFAULT_CODES_DIR))
    }
}

/// Failure of opening the device key container.
#[derive(Debug, thiserror::Error)]
pub enum DeviceKeyError {
    /// The container could not be read.
    #[error("the device key container could not be read: {0}")]
    Io(#[from] std::io::Error),
    /// The container did not open, or held no key.
    #[error(transparent)]
    Container(#[from] Pkcs12Error),
}

/// Reads the addresses of the engineer's page the fleet allows this device to
/// show.
///
/// One address per line; blank lines and lines opening with `#` are comments.
/// An absent file is an empty allowlist and not an error: a fleet that
/// published no page shows the challenge alone, which still scans.
///
/// The list is the fleet's, delivered by the enrollment package. Nothing here
/// composes an address, and nothing accepts one from the configuration that the
/// list does not carry — see [`page_url_is_allowed`].
///
/// # Errors
///
/// [`DeviceKeyError::Io`] when the file cannot be read or is not UTF-8. Read
/// under the same cap as every other artefact: this runs at login, so it may
/// never size a buffer from what is on disk.
pub fn load_page_urls(path: &Path) -> Result<Vec<String>, DeviceKeyError> {
    let bytes = match crate::fs_mode::read_capped_regular(path, MAX_KEY_CONTAINER_BYTES) {
        Ok(crate::fs_mode::CappedRead::Whole(bytes)) => bytes,
        Ok(crate::fs_mode::CappedRead::TooLarge) => {
            return Err(DeviceKeyError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{} is larger than the artefact cap", path.display()),
            )))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(DeviceKeyError::Io(error)),
    };
    let text = String::from_utf8(bytes).map_err(|_| {
        DeviceKeyError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is not valid UTF-8", path.display()),
        ))
    })?;
    Ok(parse_page_urls(&text))
}

/// Reads the addresses out of the text of the list.
///
/// Split out and made public so that the import of an enrolment package can ask
/// THIS question — "how many addresses does the device get out of this file?" —
/// instead of asking a similar one of its own. A file of nothing but comments
/// is the case that made the difference: a second reader that only looked for
/// non-blank lines called it a list, the device read no address from it, and the
/// device then refused its own configuration in the field, hours after the
/// operator who could have fixed it had gone.
#[must_use]
pub fn parse_page_urls(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

/// Reports whether an address is one the fleet delivered.
///
/// Byte equality, not a prefix match and not a host comparison. A prefix rule
/// would admit `https://codes.fleet.example.attacker.test/e` under an entry for
/// `https://codes.fleet.example`, and a host rule would admit any path on the
/// host — including one somebody else controls on a shared domain.
#[must_use]
pub fn page_url_is_allowed(allowlist: &[String], candidate: &str) -> bool {
    allowlist.iter().any(|allowed| allowed == candidate)
}

/// Opens the stored device key container and returns the private key.
///
/// The container is the same PKCS#12 envelope the rest of the engine reads, so
/// it carries the device certificate beside the key; only the key is used here.
///
/// # Why no password is taken
///
/// The stored container carries none, by construction: a container arrives
/// PIN-protected because that is how key material travels through an operator's
/// hands, and the import opens it once and re-writes the key into this store
/// without one — see [`super::artefacts`]. What guards the key here is the
/// ownership and mode of the file and of the directory above it, checked by
/// [`CodesPaths::check_trusted`] before the method opens at all, plus the
/// integrity of the environment around them.
///
/// A password held anywhere the device can read it unattended is not protection
/// against anyone who can read this file: the device has to come back from a
/// power cut on its own, with nobody in the room to type anything, so whatever
/// opens the container has to be within reach of the process — and therefore
/// within reach of whoever the file permissions already admit. Keeping such a
/// value in the configuration beside the key it opens said "protected by a
/// password" while protecting nothing, so the configuration no longer has one.
///
/// # Errors
///
/// [`DeviceKeyError::Io`] when the file cannot be read, and
/// [`DeviceKeyError::Container`] — [`Pkcs12Error::WrongPin`] among its
/// variants — when the container does not open or holds no key.
pub fn load_device_key(
    container: &Path,
    gost_engine_path: Option<&Path>,
) -> Result<PKey<Private>, DeviceKeyError> {
    // Read under the cap the delivery container is accepted at, and as a
    // regular file decided on the descriptor: this runs at every login, so the
    // one thing it may never do is size a buffer from what is on disk.
    let bytes = match crate::fs_mode::read_capped_regular(container, MAX_KEY_CONTAINER_BYTES)? {
        crate::fs_mode::CappedRead::Whole(bytes) => bytes,
        crate::fs_mode::CappedRead::TooLarge => {
            return Err(DeviceKeyError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "the stored device key container is larger than the {MAX_KEY_CONTAINER_BYTES}-byte cap"
                ),
            )))
        }
    };
    let material =
        LoadedKeyMaterial::from_p12(&bytes, &SecretString::from(String::new()), gost_engine_path)?;
    Ok(material.private_key()?)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use std::path::Path;

    use super::{load_page_urls, page_url_is_allowed, CodesPaths, DEFAULT_CODES_DIR};

    #[test]
    fn the_default_layout_sits_under_the_default_directory() {
        let paths = CodesPaths::default();
        assert!(paths.device_key_container.starts_with(DEFAULT_CODES_DIR));
        assert_eq!(paths.state_dir, Path::new(DEFAULT_CODES_DIR).join("state"));
    }

    /// Writes a list of addresses and reads it back through the product.
    fn addresses(contents: &str) -> (tempfile::TempDir, Vec<String>) {
        let dir = tempfile::tempdir().unwrap();
        let paths = CodesPaths::under(dir.path());
        std::fs::write(&paths.page_urls, contents).unwrap();
        let read = load_page_urls(&paths.page_urls).unwrap();
        (dir, read)
    }

    #[test]
    fn an_address_outside_the_list_is_not_allowed() {
        // The whole control, and until this test it was held by nothing: a
        // mutation turning the answer into `true` left the suite green. What it
        // guards is an engineer being sent, by their own device, to a page
        // nobody in the fleet published.
        let (_dir, allowed) = addresses("https://codes.fleet.example/e\n");

        assert!(page_url_is_allowed(
            &allowed,
            "https://codes.fleet.example/e"
        ));
        assert!(!page_url_is_allowed(
            &allowed,
            "https://codes.fleet.example/f"
        ));
        // Neither a prefix nor a host match: both would admit an address on a
        // name somebody else controls.
        assert!(!page_url_is_allowed(
            &allowed,
            "https://codes.fleet.example.attacker.test/e"
        ));
        assert!(!page_url_is_allowed(
            &allowed,
            "https://codes.fleet.example"
        ));
        assert!(!page_url_is_allowed(&allowed, ""));
    }

    #[test]
    fn an_empty_list_allows_nothing() {
        // The direction a mistake would take: a fleet that delivered no list
        // must not thereby allow every address.
        let (_dir, allowed) = addresses("");
        assert!(allowed.is_empty());
        assert!(!page_url_is_allowed(
            &allowed,
            "https://codes.fleet.example/e"
        ));
    }

    #[test]
    fn the_list_ignores_blank_lines_comments_and_surrounding_space() {
        // The file is written by whoever assembles an enrolment package, and it
        // will carry a header line and a stray space. What must NOT happen is
        // an address being admitted because of the space around it, or a
        // commented-out address being admitted at all.
        let (_dir, allowed) = addresses(
            "# addresses of this fleet\n\
             \n\
             \thttps://codes.fleet.example/e  \n\
             #https://retired.fleet.example/e\n\
             https://second.fleet.example/e\n",
        );

        assert_eq!(
            allowed,
            vec![
                "https://codes.fleet.example/e".to_owned(),
                "https://second.fleet.example/e".to_owned(),
            ]
        );
        assert!(page_url_is_allowed(
            &allowed,
            "https://codes.fleet.example/e"
        ));
        // The commented-out one is gone, not merely unlisted-looking.
        assert!(!page_url_is_allowed(
            &allowed,
            "https://retired.fleet.example/e"
        ));
        assert!(!page_url_is_allowed(
            &allowed,
            "#https://retired.fleet.example/e"
        ));
    }

    #[test]
    fn a_missing_list_reads_as_no_addresses_rather_than_a_failure() {
        // A device of a fleet that published no page has no such file, and that
        // is not a fault: it shows the challenge alone. What it must not do is
        // allow an address.
        let dir = tempfile::tempdir().unwrap();
        let paths = CodesPaths::under(dir.path());
        assert!(!paths.page_urls.exists());

        let allowed = load_page_urls(&paths.page_urls).unwrap();
        assert!(allowed.is_empty());
        assert!(!page_url_is_allowed(
            &allowed,
            "https://codes.fleet.example/e"
        ));
    }

    #[test]
    fn a_list_that_is_not_utf8_is_refused_rather_than_read_as_empty() {
        // Read as empty, it would look exactly like a fleet that published no
        // page — and the configuration naming an address would be refused for
        // the wrong reason, sending whoever debugs it to the wrong file.
        let dir = tempfile::tempdir().unwrap();
        let paths = CodesPaths::under(dir.path());
        std::fs::write(&paths.page_urls, [0xff_u8, 0xfe, 0xfd]).unwrap();

        assert!(load_page_urls(&paths.page_urls).is_err());
    }

    #[test]
    fn a_device_without_artefacts_does_not_offer_the_method() {
        let dir = tempfile::tempdir().unwrap();
        let paths = CodesPaths::under(dir.path());
        assert!(!paths.artefacts_present());

        std::fs::write(&paths.device_key_container, b"container").unwrap();
        std::fs::write(&paths.tickets, b"ticket").unwrap();
        assert!(!paths.artefacts_present());

        std::fs::write(&paths.ticket_authority, b"anchor").unwrap();
        // The revocation list stays absent on purpose: a fleet that has
        // withdrawn nothing ships none.
        assert!(paths.artefacts_present());
        assert!(!paths.ticket_revocations.exists());
    }
}
