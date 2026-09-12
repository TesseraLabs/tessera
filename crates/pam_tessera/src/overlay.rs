//! Starting and stopping the QR overlay of a graphical login.
//!
//! The module of an attempt runs as root inside the greeter's process. The
//! overlay does not: it is an unprivileged X client that draws one symbol and
//! goes away. This module is the join between them — a socket, a child process
//! and one frame — and the rule it exists to keep is that none of it may change
//! what the login decides.
//!
//! # Everything here is best effort, and that is the design
//!
//! No display manager, no greeter, no X server, an overlay binary nobody
//! installed, a socket that could not be created, a child that never connected:
//! every one of those ends the same way, with the challenge shown in the prompt
//! where it was going anyway. There is no error return, because there is no
//! action a caller is allowed to take — see [`OverlayPresenter`].
//!
//! # The wire runs one way, except for one byte
//!
//! The module writes; the overlay draws. What comes back is a single byte,
//! [`DRAWN`], sent once the first symbol is on the screen; the read
//! half of the socket is shut down the moment it arrives, or the moment the
//! deadline for it passes.
//!
//! The direction is worth the most in this file, so the exception is stated
//! precisely. The module is a cdylib inside `sshd`, `login` or a display
//! manager and runs as root; the overlay is unprivileged code on a machine
//! anybody can walk up to. A reverse direction carrying MESSAGES would be the
//! one place where root parses a stream that side produced, and it would exist
//! so that a journal could say *why* a symbol was not drawn — the overlay says
//! that on its own standard error instead.
//!
//! This byte is not that. It is read once, with a fixed length, compared with a
//! constant, and never used as data: anything other than exactly that value —
//! silence, a different byte, a closed socket — means "no overlay", which is
//! the same answer as a device that has none. What it buys is the difference
//! between "a process connected" and "a symbol is on a screen": the overlay
//! opens the display AFTER connecting, and without the byte the module would
//! take the challenge out of the prompt for an overlay that never drew it,
//! leaving the engineer a bare code prompt with the challenge nowhere.
//!
//! # The socket
//!
//! Created by the module as root in a directory the package makes root-owned
//! and traversable-but-not-listable, under a name derived from sixteen random
//! bytes. Then given to the account the greeter runs as, mode `0600`. Then one
//! connection is accepted and its peer credentials are checked; every later
//! connection is refused by there being nobody left to accept it.
//!
//! Four properties, and each one closes a different door. The random name
//! cannot be occupied in advance by a process that guessed it. The directory
//! cannot be listed, so the name cannot be found by looking. The mode and the
//! owner keep every other account off it. The credential check is the only one
//! of the four that says who actually connected rather than who was allowed to.
//!
//! # The child
//!
//! Started with the uid and gid of the greeter's account, so that a pre-auth
//! process on a machine anybody can walk up to holds nothing.
//!
//! What it is given, exactly: the path of the socket, a working directory of
//! `/`, closed standard input and output, and three names of the environment —
//! `DISPLAY`, `XAUTHORITY`, `PATH`. Everything else of the host's environment
//! is cleared. That matters more than it looks: this module is a cdylib inside
//! `sshd`, `login` or the display manager, so an inherited environment is THAT
//! process's — `SSH_AUTH_SOCK`, `SUDO_*`, whatever a fleet exports into its
//! login shells.
//!
//! It is given no code, no nonce, no key and no secret of any kind, because
//! the payload it draws is about to be photographed off a screen by a
//! stranger's telephone.
//!
//! ## What it does NOT inherit, and on whose word
//!
//! **The supplementary groups of the host.** `root` inside a display manager
//! carries whatever groups that unit was given, and a child that kept them
//! would hold rights its uid says it does not have. They are dropped, but not
//! by a line in this file: the standard library, asked for a uid without being
//! given an explicit group list, calls `setgroups(0, NULL)` before `setuid`.
//! In the pinned toolchain that is `library/std/src/sys/process/unix/unix.rs`,
//! line 315, guarded by `if self.get_groups().is_none()` — and the fast
//! `posix_spawn` path, which would not do it, is refused for any command that
//! sets a uid or a gid (same file, line 460).
//!
//! So the guarantee holds and it is BORROWED. Two things follow, and both are
//! stated because a borrowed guarantee is the kind that changes under you: a
//! future standard library could drop the call, and no test here would notice —
//! checking it needs a process running as root, which no unit test is. The
//! stand is where it is observed; `tests/e2e/BASELINE.md` carries the item.
//! `std::os::unix::process::CommandExt::groups`, which would say it here rather
//! than rely on it, is still unstable (rust-lang/rust#90747).
//!
//! ## What it may still inherit, stated rather than implied
//!
//! **File descriptors of the host process that were opened without
//! `FD_CLOEXEC`.** Everything this module opens is closed on exec by
//! construction — the standard library sets the flag on what it creates — but
//! a descriptor `sshd` or the display manager left open without it passes
//! through, and this module does not close it.
//!
//! Closing them would mean walking `/proc/self/fd` and setting the flag on
//! descriptors belonging to the HOST process, which is a change to a process
//! this code is a guest in: `sshd` opens descriptors it means to pass to the
//! shell it will exec later, and a module that marked them close-on-exec would
//! break the login it was supposed to help. The alternative is `pre_exec`,
//! which runs between fork and exec, where the child of a multithreaded host
//! may call almost nothing safely: the host's allocator and locks are in
//! whatever state its other threads left them in, and this module is a guest in
//! `sshd`, `login` and a display manager, all of which have other threads.
//!
//! So the limit stands and is named here instead of being described as closed.
//! What bounds it: the overlay runs as an unprivileged account, and a
//! descriptor it inherits it can only read or write, not re-open with more
//! rights than the host had.

#![cfg(unix)]

use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tessera_core::codes::overlay_ipc::{
    module, AttemptId, ATTEMPT_ID_LEN, DRAWN, SOCKET_DIRECTORY, SOCKET_DIRECTORY_MODE,
};
use tessera_core::codes::OverlaySettings;

use crate::codes_flow::{NoOverlay, OverlayHandle, OverlayPresenter};

/// Makes sure the directory of the attempt sockets exists and is safe to use.
///
/// The package creates it — through `tmpfiles.d` under systemd, through the
/// init script elsewhere — and this creates it anyway, because the login path
/// and the packaging path are not the same path. A host booted without the
/// tmpfiles run, an init script that was edited, a `/run` wiped by something:
/// each of them ends with a graphical login quietly falling back to text, and
/// the fall-back is silent by design, which is exactly what makes it worth
/// closing here.
///
/// # What it refuses
///
/// A directory it did not make and cannot vouch for. Owned by this process —
/// root, in production — or nothing: a directory somebody else owns is a
/// directory they can put a socket in before the overlay reaches it, and a
/// directory writable by group or other is the same thing said differently. A
/// path that is not a directory at all — a symlink into somebody's home, say —
/// is refused without being followed.
///
/// # Errors
///
/// The underlying failure to create, and [`std::io::ErrorKind::PermissionDenied`]
/// for a directory whose ownership or mode this module will not accept.
fn ensure_socket_directory(path: &Path) -> Result<(), std::io::Error> {
    ensure_socket_directory_owned_by(path, nix::unistd::Uid::effective().as_raw())
}

/// The same check, told which owner to insist on.
///
/// The owner is a parameter for one reason: without it the refusal cannot be
/// tested anywhere. Feeding the check a directory owned by somebody else means
/// making one, and making one means being root — so under an ordinary runner
/// the branch would be reached by no test at all, and a check no test reaches
/// is a check that can be deleted without anything going red. The fault goes
/// into the CODE, through this parameter, rather than into the file system.
///
/// Production has exactly one caller and it passes the effective uid, which is
/// root: nothing here widens what the module accepts.
///
/// # Errors
///
/// As [`ensure_socket_directory`].
fn ensure_socket_directory_owned_by(path: &Path, mine: u32) -> Result<(), std::io::Error> {
    // `symlink_metadata`, not `metadata`: the question is what the NAME is, and
    // following a link would answer about its target.
    match std::fs::symlink_metadata(path) {
        Ok(found) => {
            if !found.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("{} is not a directory", path.display()),
                ));
            }
            let mode = found.permissions().mode() & 0o777;
            // Owned by THE ACCOUNT THIS PROCESS RUNS AS, which in production is
            // root. Stated as an owner to insist on rather than as a literal
            // zero: what matters is that the account about to create sockets in
            // it is the account that owns it.
            if found.uid() != mine {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "{} belongs to uid {} and this process runs as {mine}: a directory of \
                         attempt sockets somebody else owns is one they can put a socket in \
                         first",
                        path.display(),
                        found.uid()
                    ),
                ));
            }
            if mode & 0o022 != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "{} is mode {mode:04o} and writable beyond its owner",
                        path.display()
                    ),
                ));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // The mode is given to the creation rather than set afterwards.
            // `create_dir_all` applies the umask of the host process — this
            // module is a guest, and a display manager's umask is not this
            // module's to predict — so between the two calls the directory
            // stood open to whatever that umask allowed. The window was short
            // and real: an attempt socket is created in it moments later.
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(SOCKET_DIRECTORY_MODE)
                .create(path)?;
            // And set once more, because `recursive(true)` does not apply the
            // mode to a directory that already existed a moment ago — two
            // logins starting together is enough — and because the umask still
            // masks the bits the builder asks for.
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_DIRECTORY_MODE))
        }
        Err(error) => Err(error),
    }
}

/// Names which step failed, so a journal line says what to look at.
///
/// Every one of these ends the same way — the login goes on without an overlay
/// — but "the overlay did not come up" is useless to somebody standing at a
/// machine trying to find out why. A step name costs one word and answers it.
fn context(step: &'static str, error: &std::io::Error) -> std::io::Error {
    std::io::Error::new(error.kind(), format!("{step}: {error}"))
}

/// The only names of the host's environment the overlay is given.
///
/// An X client cannot find a display without the first two, and cannot find a
/// program without the third. Everything else the host process carries stays
/// with the host process.
///
/// The first two are the FALLBACK, taken from the environment only when the
/// application named no display of its own — `sshd` with a forwarded display,
/// a test driver, `login` under an X session. A display manager names the
/// display through PAM instead, and then [`XChannel`] supplies both values and
/// the host's environment is not consulted for them at all.
const PASSED_ENV: [&str; 3] = ["DISPLAY", "XAUTHORITY", "PATH"];

/// The display of a graphical login and the credential that opens it.
///
/// Comes from the items `PAM_XDISPLAY` and `PAM_XAUTHDATA`, which is the only
/// channel a display manager has for saying it: the process the module is
/// loaded into — `fly-dm` on the target fleet — carries neither `DISPLAY` nor
/// `XAUTHORITY` in its own environment. Those two variables belong to the
/// greeter's child process, which is not where PAM runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XChannel {
    /// Value of `PAM_XDISPLAY`, e.g. `:0`.
    pub display: String,
    /// Scheme name of `PAM_XAUTHDATA`, e.g. `MIT-MAGIC-COOKIE-1`.
    pub scheme: String,
    /// The credential bytes. Not a string: a cookie is binary.
    pub cookie: Vec<u8>,
}

/// Family of an `Xauthority` entry that matches any display address.
///
/// `FamilyWild` of the X protocol. The entry the module writes carries no
/// address and no display number, and libXau's matching treats both as
/// wildcards — so the cookie is found whichever way the client spells the
/// display it was given (`:0`, `unix/:0`, the host's own name). Spelling the
/// address out instead would mean guessing the hostname the X client is about
/// to compute, and a guess that misses reads to everyone as "the overlay did
/// not come up".
///
/// The file this goes into is readable by one account, holds one cookie and
/// is removed with the attempt, so the wildcard widens nothing that the file
/// itself does not already bound.
const XAUTH_FAMILY_WILD: u16 = 0xFFFF;

/// Lay out one `Xauthority` entry the way the format wants it.
///
/// Five fields, each a big-endian length followed by its bytes, with the
/// family first: family, address, display number, scheme name, credential.
/// Address and number are left empty on purpose — see [`XAUTH_FAMILY_WILD`].
fn xauth_entry(scheme: &str, cookie: &[u8]) -> Vec<u8> {
    fn put(out: &mut Vec<u8>, bytes: &[u8]) {
        // Truncation is impossible for the values this is called with — a
        // scheme name and a cookie, both well under 64 KiB — and saturating
        // keeps the function total rather than adding a panic to a path that
        // runs inside a login.
        let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(bytes.get(..len as usize).unwrap_or_default());
    }
    let mut out = Vec::new();
    out.extend_from_slice(&XAUTH_FAMILY_WILD.to_be_bytes());
    put(&mut out, b"");
    put(&mut out, b"");
    put(&mut out, scheme.as_bytes());
    put(&mut out, cookie);
    out
}

/// How long the module waits for the overlay to connect.
///
/// Short on purpose: it is time added to every graphical login before the
/// engineer sees a prompt, and the thing being waited for is a process that
/// either starts immediately or is not going to start at all.
const HANDSHAKE: Duration = Duration::from_secs(2);

/// How often the wait for a connection looks again.
const POLL: Duration = Duration::from_millis(20);

/// How long the module waits for the overlay to exit after being told to.
///
/// Also short, and for a harder reason: this wait happens on the way out of an
/// attempt, and an attempt that has been decided must not be held open by a
/// process that will not leave. Whatever is still running when it expires is
/// killed.
const SHUTDOWN: Duration = Duration::from_millis(500);

/// Starts the overlay for the length of one attempt.
#[derive(Debug, Clone)]
pub struct SpawningOverlay {
    binary: PathBuf,
    socket_dir: PathBuf,
    owner: Owner,
    handshake: Duration,
    x: Option<XChannel>,
}

/// The account the overlay runs as, and the socket belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owner {
    /// User id of the greeter's account.
    pub uid: u32,
    /// Group id of the greeter's account.
    pub gid: u32,
}

impl SpawningOverlay {
    /// An overlay started from `binary`, served from `socket_dir`, running as
    /// `owner`.
    #[must_use]
    pub fn new(binary: PathBuf, socket_dir: PathBuf, owner: Owner) -> Self {
        Self {
            binary,
            socket_dir,
            owner,
            handshake: HANDSHAKE,
            x: None,
        }
    }

    /// The same overlay, told which display to draw on.
    ///
    /// Without this the overlay looks for a display in the host's environment,
    /// which is right for `sshd` and a test driver and wrong for every display
    /// manager — see [`XChannel`].
    #[must_use]
    pub fn with_x_channel(mut self, x: Option<XChannel>) -> Self {
        self.x = x;
        self
    }

    /// The same overlay, waiting a different length of time to be connected to.
    ///
    /// The default is short because the wait is added to every graphical login
    /// (see `HANDSHAKE`). It is adjustable for two reasons that are really
    /// one: a machine under load starts processes slowly, and a test harness
    /// running eight of them at once is such a machine.
    #[must_use]
    pub fn with_handshake(mut self, handshake: Duration) -> Self {
        self.handshake = handshake;
        self
    }

    /// The process identifier of the overlay, once it is running.
    #[must_use]
    fn wait_for_connection(&self) -> Duration {
        self.handshake
    }

    /// Everything that can go wrong, in one place, so that the caller's side
    /// has nothing to decide.
    fn try_present(&self, payload: &str) -> Result<SpawnedOverlay, std::io::Error> {
        ensure_socket_directory(&self.socket_dir)
            .map_err(|error| context("socket-directory", &error))?;
        let attempt = AttemptId::from_bytes(rand::random::<[u8; ATTEMPT_ID_LEN]>());
        let path = self.socket_dir.join(attempt.socket_name());

        // A name this random is not going to exist, and if it does, something
        // is waiting on it that should not be.
        if path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "the socket of a fresh attempt already exists",
            ));
        }
        let listener = UnixListener::bind(&path).map_err(|error| context("bind", &error))?;
        let guard = PathGuard { path: path.clone() };

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| context("mode", &error))?;
        chown(&path, self.owner).map_err(|error| context("chown", &error))?;

        // The credential of the display, when the application named one. It
        // goes to disk because that is the only way an X client takes it: the
        // client reads `XAUTHORITY`. It lands beside the socket — a directory
        // this module has already vouched for — with the mode and the owner of
        // the socket, and it is removed when the attempt ends, whichever way it
        // ends (`PathGuard`).
        let xauth = match self.x.as_ref() {
            Some(channel) => Some(
                self.write_xauth(&attempt, channel)
                    .map_err(|error| context("xauth", &error))?,
            ),
            None => None,
        };

        let mut command = Command::new(&self.binary);
        command
            .arg("--socket")
            .arg(&path)
            // The overlay holds no privilege of the process that started it.
            .uid(self.owner.uid)
            .gid(self.owner.gid)
            // Nothing of the host's environment travels except the three names
            // an X client cannot start without. The module lives as a cdylib
            // inside `sshd`, `login` or the display manager, so an inherited
            // environment is THAT process's environment: `SSH_AUTH_SOCK`,
            // `SUDO_*`, a `XAUTHORITY` pointing at somebody else's cookie, and
            // whatever a fleet exports into its login shells. An unprivileged
            // pre-auth process on a machine anybody can walk up to has no use
            // for any of it.
            .env_clear()
            // The working directory too. Inherited, it is whatever the host
            // process happened to be in — for `sshd` a directory the login is
            // about to change out of, and for a display manager a mount a wipe
            // could be waiting on.
            .current_dir("/")
            // Its standard error is inherited, and that is deliberate: it is
            // the ONLY way the reason a symbol could not be drawn reaches a
            // person. It lands where the host process's own does — for a
            // display manager under systemd, that unit's journal — and not in
            // the module's journal, which nothing here can reach from a child.
            // Its input is closed: nothing is ever typed at it.
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        let display = xauth
            .as_ref()
            .and_then(|file| self.x.as_ref().map(|channel| (channel, file)));
        for (name, value) in child_environment(display, |name| std::env::var(name).ok()) {
            command.env(name, value);
        }
        let child = command.spawn().map_err(|error| context("spawn", &error))?;
        let mut child = ChildGuard { child: Some(child) };

        let stream = accept_one(&listener, child.child.as_mut(), self.wait_for_connection())
            .map_err(|error| context("accept", &error))?;
        check_peer(&stream, self.owner).map_err(|error| context("peer", &error))?;
        let frame = module::challenge(attempt, payload)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        send_frame(&stream, &frame).map_err(|error| context("write", &error))?;

        // The symbol has to be ON A SCREEN before the caller may leave it out
        // of the prompt, and only the overlay can say that: it opens the
        // display after connecting, so everything up to this line is true of an
        // overlay that never drew anything. An overlay that does not answer is
        // treated exactly as an absent one.
        wait_for_drawn(&stream, self.wait_for_connection())
            .map_err(|error| context("ack", &error))?;
        // Down for good now, and this is where the one-way rule resumes: the
        // byte above is the whole of what this direction ever carries.
        stream
            .shutdown(std::net::Shutdown::Read)
            .map_err(|error| context("shutdown-read", &error))?;

        // Taken out of the guard now that the handle owns it. The guard is what
        // kills a child that was started and then could not be handed on — a
        // socket that never accepted, a peer that was not the overlay — and it
        // has to stop being responsible for one that was handed on.
        let child = child
            .child
            .take()
            .ok_or_else(|| std::io::Error::other("the child of the attempt went missing"))?;

        Ok(SpawnedOverlay {
            attempt,
            stream,
            child,
            _path: guard,
            _xauth: xauth,
        })
    }

    /// Writes the credential of the display where the overlay can read it.
    ///
    /// One entry, one file, one attempt. Created with the mode BEFORE anything
    /// is written to it — a file that is briefly world-readable and holds a
    /// cookie is a cookie anybody on the machine has — and handed to the
    /// account the overlay runs as, which is the only account that reads it.
    ///
    /// # Errors
    ///
    /// The underlying failure to create, write or hand over the file. Every one
    /// of them ends as every other overlay failure does: the challenge stays in
    /// the prompt and the login proceeds.
    fn write_xauth(
        &self,
        attempt: &AttemptId,
        channel: &XChannel,
    ) -> Result<PathGuard, std::io::Error> {
        use std::io::Write as _;

        let path = self
            .socket_dir
            .join(format!("{}.xauth", attempt.socket_name()));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let guard = PathGuard { path: path.clone() };
        file.write_all(&xauth_entry(&channel.scheme, &channel.cookie))?;
        file.sync_all()?;
        drop(file);
        chown(&path, self.owner)?;
        Ok(guard)
    }
}

/// What the overlay is started with, given a display and a host environment.
///
/// A function of its two inputs and nothing else, because the rule it holds is
/// worth a test and the process environment is not something a test may set:
/// `DISPLAY` and `XAUTHORITY` come from the display the APPLICATION named, when
/// it named one, and from the host's environment only when it did not. An
/// inherited `DISPLAY` — `sshd` with a forwarded display, a developer's shell —
/// beside a greeter's own would send the symbol to the wrong screen, and that
/// screen belongs to somebody else.
///
/// `PATH` always comes from the host: it is how a process finds a program, and
/// no display names it.
fn child_environment(
    display: Option<(&XChannel, &PathGuard)>,
    host: impl Fn(&str) -> Option<String>,
) -> Vec<(&'static str, String)> {
    let mut out = Vec::with_capacity(PASSED_ENV.len());
    for name in PASSED_ENV {
        let named_by_application = display.is_some() && (name == "DISPLAY" || name == "XAUTHORITY");
        if named_by_application {
            continue;
        }
        if let Some(value) = host(name) {
            out.push((name, value));
        }
    }
    if let Some((channel, file)) = display {
        out.push(("DISPLAY", channel.display.clone()));
        out.push(("XAUTHORITY", file.path.to_string_lossy().into_owned()));
    }
    out
}

/// Waits for the overlay to say the symbol is on the screen.
///
/// One byte, fixed length, compared with a constant. Nothing about the value is
/// interpreted: it either is [`DRAWN`] or the overlay is treated as
/// absent — see the module docs for what bounds this direction.
///
/// # Errors
///
/// [`std::io::ErrorKind::TimedOut`] when the deadline passed with nothing on
/// the socket (which is also what a `WouldBlock` from the read timeout means),
/// [`std::io::ErrorKind::InvalidData`] for any other byte, and
/// [`std::io::ErrorKind::UnexpectedEof`] for an overlay that closed instead of
/// answering. Every one of them ends the same way for the caller.
fn wait_for_drawn(stream: &UnixStream, budget: Duration) -> Result<(), std::io::Error> {
    use std::io::Read as _;

    stream.set_read_timeout(Some(budget))?;
    let mut byte = [0u8; 1];
    let read = (&*stream).read(&mut byte);
    // The timeout is cleared whatever happened: the same socket carries the
    // cancel frame on the way out, and a read timeout left on it belongs to
    // nothing.
    let _ignored = stream.set_read_timeout(None);
    match read {
        Ok(1) if byte.first() == Some(&DRAWN) => Ok(()),
        Ok(1) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the overlay answered with something other than the drawn byte",
        )),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "the overlay closed the socket instead of drawing",
        )),
        Err(error)
            if error.kind() == std::io::ErrorKind::WouldBlock
                || error.kind() == std::io::ErrorKind::TimedOut =>
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the overlay did not say the symbol was drawn",
            ))
        }
        Err(error) => Err(error),
    }
}

/// Writes one frame to the overlay without the process being signalled.
///
/// This is not a style preference over [`std::io::Write::write_all`], and the
/// difference is the life of the process the module lives in.
///
/// A write to a socket whose peer has gone raises `SIGPIPE`, and a process that
/// has not said otherwise dies of it. `pam_tessera` is a cdylib: it is loaded
/// into `sshd`, `login` or a display manager, the Rust runtime start-up that
/// would have set the signal aside never runs, and the disposition is whatever
/// the host left it as. `sshd` ignores it; a display manager need not, and a
/// display manager is the only thing that ever raises this overlay.
///
/// The peer going away first is not an edge case but the ordinary failure this
/// whole path documents as harmless: the overlay connects to the socket before
/// it opens the display, so a wrong `XAUTHORITY` or a dead X server exits it
/// between the module's `accept` and the module's first byte. Dying there would
/// take down the login the fallback to the text path exists to save.
///
/// `MSG_NOSIGNAL` turns that into an `EPIPE` this function returns. Where the
/// flag does not exist — a developer's macOS, never a device — the write goes
/// out plain and the guarantee falls back to the host's disposition; the
/// integration test that proves the behaviour is bounded the same way.
///
/// # Errors
///
/// Whatever the socket answered, `EPIPE` for a peer that has gone included.
/// A partial write is continued rather than reported: a frame is a frame only
/// whole, and half of one on the wire is a frame the overlay would refuse.
pub fn send_frame(stream: &UnixStream, frame: &[u8]) -> std::io::Result<()> {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "illumos",
        target_os = "solaris"
    ))]
    let flags = nix::sys::socket::MsgFlags::MSG_NOSIGNAL;
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "illumos",
        target_os = "solaris"
    )))]
    let flags = nix::sys::socket::MsgFlags::empty();

    let fd = stream.as_raw_fd();
    let mut sent = 0_usize;
    while sent < frame.len() {
        let rest = frame.get(sent..).unwrap_or_default();
        match nix::sys::socket::send(fd, rest, flags) {
            // Nothing accepted and no error: the peer is not taking bytes and
            // never will. Reported rather than spun on.
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "the overlay accepted none of the frame",
                ))
            }
            Ok(written) => sent = sent.saturating_add(written),
            // A signal arrived while the call was in flight. Not the peer
            // saying anything, so the frame is continued where it stopped.
            Err(nix::errno::Errno::EINTR) => {}
            Err(error) => return Err(std::io::Error::from(error)),
        }
    }
    Ok(())
}

/// What a device will show its challenges on.
///
/// A type rather than an `Option` handed back to the caller, and the reason is
/// where the caller lives: the PAM entry point is compiled only for Linux, so
/// every line written there is a line no build on a developer's machine ever
/// type-checks. Choosing the overlay and lending it out as a trait object
/// happens HERE, where it compiles on any unix and is covered by tests; what is
/// left at the entry point is two lines with nothing in them to get wrong.
pub enum Chosen {
    /// The fleet named an account and this device has it.
    Spawning(SpawningOverlay),
    /// Everything else, which is the ordinary case.
    Absent(NoOverlay),
}

impl Chosen {
    /// Lends the choice out as the dependency the login flow takes.
    #[must_use]
    pub fn presenter(&self) -> &dyn OverlayPresenter {
        match self {
            Self::Spawning(overlay) => overlay,
            Self::Absent(absent) => absent,
        }
    }
}

/// Chooses what this device shows its challenges on.
///
/// Never fails: a fleet that named no account, and a device that does not have
/// the account a fleet named, both get [`Chosen::Absent`] — and so does every
/// device without a display manager, which is most of them.
#[must_use]
pub fn choose(settings: Option<&OverlaySettings>, x: Option<XChannel>) -> Chosen {
    from_settings(settings, x).map_or(Chosen::Absent(NoOverlay), Chosen::Spawning)
}

/// Builds the overlay a fleet configured, if it configured one.
///
/// [`None`] when the fleet named no account, and also when it named one this
/// device does not have. The second is a misconfiguration and it is reported —
/// but it is reported to a journal, not to a login: a device whose overlay
/// account was deleted still lets its engineers in through the prompt.
#[must_use]
pub fn from_settings(
    settings: Option<&OverlaySettings>,
    x: Option<XChannel>,
) -> Option<SpawningOverlay> {
    let settings = settings?;
    let account = match nix::unistd::User::from_name(&settings.user) {
        Ok(Some(account)) => account,
        Ok(None) => {
            tracing::warn!(
                target: "tessera.codes",
                user = settings.user,
                "the configured overlay account does not exist on this device; the challenge \
                 will be shown in the prompt only"
            );
            return None;
        }
        Err(error) => {
            tracing::warn!(
                target: "tessera.codes",
                user = settings.user,
                error = %error,
                "the overlay account could not be looked up; the challenge will be shown in \
                 the prompt only"
            );
            return None;
        }
    };

    Some(
        SpawningOverlay::new(
            settings.binary.clone(),
            PathBuf::from(SOCKET_DIRECTORY),
            Owner {
                uid: account.uid.as_raw(),
                gid: account.gid.as_raw(),
            },
        )
        .with_x_channel(x),
    )
}

impl OverlayPresenter for SpawningOverlay {
    fn present(&self, payload: &str) -> Option<Box<dyn OverlayHandle>> {
        match self.try_present(payload) {
            Ok(overlay) => Some(Box::new(overlay)),
            Err(error) => {
                // A WARNING, not a debug line, and the distinction was got
                // wrong here once. A device with no graphical login never
                // reaches this code at all — it has no overlay account and gets
                // `NoOverlay` — so arriving here means the fleet DID configure
                // an overlay and it did not come up. The login carries on
                // without it, silently by design, and a silent fall-back that
                // said nothing anywhere is a fleet that thinks it has a QR on
                // its screens and has not.
                tracing::warn!(
                    target: "tessera.codes",
                    error = %error,
                    "the challenge is shown in the prompt only: the overlay did not come up"
                );
                None
            }
        }
    }
}

/// The overlay that is currently drawing.
struct SpawnedOverlay {
    attempt: AttemptId,
    stream: UnixStream,
    child: Child,
    _path: PathGuard,
    /// The credential file of the display, for as long as the attempt lasts.
    /// Held rather than used: dropping it removes the cookie from disk.
    _xauth: Option<PathGuard>,
}

impl SpawnedOverlay {
    /// The process identifier of the overlay while it is running.
    ///
    /// For a test that has to say whether *this* child outlived the attempt.
    /// Asking the question about children in general is a different question,
    /// and in a test binary running eight attempts at once it is the wrong one.
    #[cfg(test)]
    fn child_id(&self) -> u32 {
        self.child.id()
    }

    /// Tries to read from the overlay, for the one test that says it cannot.
    ///
    /// There is no production caller and there must not be: the read half of
    /// this socket is shut down when the attempt starts.
    ///
    /// A short read timeout is set first, so that the answer distinguishes the
    /// two cases the test is about. A socket whose read half is down answers
    /// `Ok(0)` at once; one that is merely quiet BLOCKS, and without the
    /// timeout the test would wait for it and then accept the wait as proof.
    #[cfg(test)]
    fn read_from_overlay(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        use std::io::Read as _;
        self.stream
            .set_read_timeout(Some(Duration::from_millis(200)))?;
        self.stream.read(buffer)
    }
}

impl OverlayHandle for SpawnedOverlay {}

impl Drop for SpawnedOverlay {
    fn drop(&mut self) {
        // Told, then closed, then killed if it is still there. The first is
        // polite and the last is the guarantee: a QR left on the screen of a
        // machine anybody can walk up to is what this sequence exists to
        // prevent, and an overlay that ignores the frame must not survive the
        // socket closing under it.
        if let Ok(frame) = module::cancel(self.attempt) {
            let _ignored = send_frame(&self.stream, &frame);
        }
        let _ignored = self.stream.shutdown(std::net::Shutdown::Both);

        let deadline = Instant::now() + SHUTDOWN;
        loop {
            // `Ok(Some(_))` is a child that left; `Err` is a child that was
            // never there to wait for. Both mean there is nothing to kill.
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => {}
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(POLL);
        }
        let _ignored = self.child.kill();
        let _ignored = self.child.wait();
    }
}

/// Removes the file it names when the attempt is over, whichever way it ended.
///
/// Two of them exist per graphical attempt: the socket and the credential of
/// the display. Neither outlives the login it belongs to.
struct PathGuard {
    path: PathBuf,
}

impl Drop for PathGuard {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_file(&self.path);
    }
}

/// Kills a child that was started but never handed on.
///
/// Empty once the handle has taken it: a guard that killed a child somebody
/// else now owns would take the overlay down at the moment it came up.
struct ChildGuard {
    child: Option<Child>,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ignored = child.kill();
            let _ignored = child.wait();
        }
    }
}

/// Accepts exactly one connection, or gives up.
///
/// Non-blocking with a deadline rather than a blocking accept: this runs inside
/// the authentication of a login, and a blocking call here would hold a greeter
/// open for as long as nothing connected — which, on a device where the overlay
/// is not installed, is forever.
fn accept_one(
    listener: &UnixListener,
    mut child: Option<&mut Child>,
    wait: Duration,
) -> Result<UnixStream, std::io::Error> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + wait;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // The connection itself goes back to blocking: the frames on it
                // are small and written immediately, and a non-blocking write
                // here would have to be retried by hand for no gain.
                stream.set_nonblocking(false)?;
                return Ok(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }

        // An overlay that has already exited is not going to connect, and
        // waiting out the deadline for it would add the whole wait to a login
        // on every device where the binary refuses to start — a missing X
        // display is exactly that case, and it is the common one.
        if let Some(child) = child.as_mut() {
            if let Ok(Some(status)) = child.try_wait() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("the overlay exited before connecting: {status}"),
                ));
            }
        }

        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the overlay did not connect",
            ));
        }
        std::thread::sleep(POLL);
    }
}

/// Refuses a peer that is not the account the overlay was started as.
///
/// The mode and the owner of the socket say who *may* connect. This says who
/// did, and it is the only one of the two that survives a mistake in the other
/// — a directory whose permissions were widened by hand, a socket whose owner
/// did not take.
fn check_peer(stream: &UnixStream, owner: Owner) -> Result<(), std::io::Error> {
    let uid = peer_uid(stream)?;
    if uid == owner.uid {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "the overlay socket was opened by uid {uid}, not by {}",
            owner.uid
        ),
    ))
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Result<u32, std::io::Error> {
    let credentials =
        nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
    Ok(credentials.uid())
}

#[cfg(not(target_os = "linux"))]
fn peer_uid(stream: &UnixStream) -> Result<u32, std::io::Error> {
    // The same question, a different name for it. Kept compiling away from
    // Linux so that the socket path of this module can be exercised on a
    // developer's machine instead of only on a stand with a greeter.
    let credentials =
        nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::LocalPeerCred)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
    Ok(credentials.uid())
}

/// Gives the socket to the account the overlay runs as.
fn chown(path: &Path, owner: Owner) -> Result<(), std::io::Error> {
    nix::unistd::chown(
        path,
        Some(nix::unistd::Uid::from_raw(owner.uid)),
        Some(nix::unistd::Gid::from_raw(owner.gid)),
    )
    .map_err(|error| std::io::Error::other(error.to_string()))
}

#[cfg(test)]
mod tests;
