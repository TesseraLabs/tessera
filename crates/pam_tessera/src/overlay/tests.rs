//! The socket path of the overlay, against a real socket and a real child.
//!
//! No greeter and no X server: the "overlay" here is a shell script that
//! connects and reads. What that leaves testable is exactly what this module
//! owns — the socket is created with the right mode, one connection is
//! accepted, the challenge arrives on it, the child is stopped and the socket
//! is removed, and none of it can fail a login. Drawing is the other crate's,
//! and the stand case is where a camera reads what it drew.
//!
//! These run as an ordinary user, so the account the overlay is started as is
//! this one. That is a limit worth naming: what is NOT exercised here is the
//! privilege drop and the hand-over of the socket to a different account, both
//! of which need root and a second account, and both of which the stand has.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a test that cannot set itself up should fail on the spot"
)]

use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use tessera_core::codes::overlay_ipc::{decode, Message, HEADER_LEN};

use super::{Owner, SpawningOverlay, XChannel};
use crate::codes_flow::OverlayPresenter as _;

const PAYLOAD: &str = "https://codes.example/#tessera-codes/v1/signed-challenge;device=77-000123X";

/// How long these tests wait for a stand-in to connect.
///
/// Much longer than the default. The stand-in is a shell that starts a Python
/// interpreter, and the test binary starts eight of them at once; the default
/// is sized for the real overlay, which is a small binary started one at a
/// time. A test that failed because a machine was busy would be a test nobody
/// believes.
const TEST_HANDSHAKE: Duration = Duration::from_secs(20);

fn overlay_from(binary: PathBuf, dir: &std::path::Path) -> SpawningOverlay {
    SpawningOverlay::new(binary, dir.to_path_buf(), owner()).with_handshake(TEST_HANDSHAKE)
}

/// This account, which is what the tests can start a child as.
fn owner() -> Owner {
    Owner {
        uid: nix::unistd::Uid::current().as_raw(),
        gid: nix::unistd::Gid::current().as_raw(),
    }
}

/// Writes a stand-in overlay: a script that connects and does what it is told.
///
/// `after_connect` is shell run once the connection is open. The default reads
/// the challenge and waits, which is what a real overlay does while a person
/// photographs the screen.
fn fake_overlay(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    let script = format!(
        "#!/bin/sh\n\
         # $1 is --socket, $2 is the path\n\
         {body}\n"
    );
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// A stand-in that connects and copies whatever arrives into a file.
///
/// Written as a real Python file rather than a `-c` argument: a script folded
/// into a Rust string literal loses its indentation to the line continuations,
/// and a Python program without indentation is a Python program that does not
/// run. That cost an hour once; it costs a file now.
fn recording_overlay(
    dir: &std::path::Path,
    record: &std::path::Path,
    keep_reading: bool,
) -> PathBuf {
    let program = dir.join(if keep_reading {
        "record-all.py"
    } else {
        "record-one.py"
    });
    let body = if keep_reading {
        // Reads until the module closes the socket, so that the frame sent on
        // the way out is recorded too.
        "\
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
out = open(sys.argv[2], \"wb\")
while True:
    data = s.recv(4096)
    if not data:
        break
    out.write(data)
    out.flush()
"
    } else {
        // Reads the challenge and then waits, which is what a real overlay does
        // while a person photographs the screen.
        "\
import socket, sys, time
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
data = s.recv(4096)
open(sys.argv[2], \"wb\").write(data)
time.sleep(30)
"
    };
    std::fs::write(&program, body).unwrap();

    let name = if keep_reading {
        "overlay-recording-all"
    } else {
        "overlay-recording"
    };
    fake_overlay(
        dir,
        name,
        &format!(
            "exec python3 {} \"$2\" \"{}\"",
            program.display(),
            record.display()
        ),
    )
}

/// Waits for a file to appear, or gives up.
fn await_file(path: &std::path::Path, wait: Duration) -> Vec<u8> {
    let deadline = Instant::now() + wait;
    loop {
        if let Ok(bytes) = std::fs::read(path) {
            if bytes.len() >= HEADER_LEN {
                return bytes;
            }
        }
        assert!(
            Instant::now() < deadline,
            "nothing was written to {} in time",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn the_challenge_reaches_the_overlay_over_the_socket() {
    let dir = tempfile::tempdir().unwrap();
    let record = dir.path().join("received.bin");
    let binary = recording_overlay(dir.path(), &record, false);
    let overlay = overlay_from(binary, dir.path());

    let handle = match overlay.try_present(PAYLOAD) {
        Ok(handle) => handle,
        Err(error) => panic!("the overlay did not come up: {error}"),
    };
    let bytes = await_file(&record, Duration::from_secs(10));
    let (_, message) = decode(&bytes).expect("what arrived is a frame of the protocol");
    assert_eq!(message, Message::Challenge(PAYLOAD.to_owned()));
    drop(handle);
}

#[test]
fn the_socket_is_created_unreadable_by_anybody_else_and_removed_afterwards() {
    let dir = tempfile::tempdir().unwrap();
    let record = dir.path().join("received.bin");
    let binary = recording_overlay(dir.path(), &record, false);
    let overlay = overlay_from(binary, dir.path());

    let handle = overlay.present(PAYLOAD).expect("the overlay came up");
    await_file(&record, Duration::from_secs(10));

    let sockets: Vec<PathBuf> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("attempt-"))
        })
        .collect();
    assert_eq!(sockets.len(), 1, "expected exactly one attempt socket");
    let socket = sockets.first().unwrap().clone();
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the socket is open to somebody else");

    drop(handle);
    assert!(
        !socket.exists(),
        "the socket of a finished attempt is still on the box: {}",
        socket.display()
    );
}

#[test]
fn the_overlay_is_stopped_when_the_attempt_ends() {
    // The failure this guards is a process left drawing on the screen of a
    // machine after the person walked away. The stand-in ignores the frame and
    // sleeps, exactly like an overlay that hung, so the only thing that can
    // stop it is the kill at the end of the wait.
    let dir = tempfile::tempdir().unwrap();
    let record = dir.path().join("received.bin");
    let binary = recording_overlay(dir.path(), &record, false);
    let overlay = overlay_from(binary, dir.path());

    // Through `try_present`, which hands back the concrete overlay: the trait
    // object a login holds carries no methods at all, on purpose.
    let handle = overlay.try_present(PAYLOAD).expect("the overlay came up");
    await_file(&record, Duration::from_secs(10));

    let pid = handle.child_id();
    assert!(alive(pid), "the child was not started");
    drop(handle);
    // `drop` waits for the child and kills it if it overstays, so by the time
    // it returns this process is gone.
    assert!(!alive(pid), "the overlay of the attempt outlived it");
}

/// Whether a process this one started is still running.
///
/// Asked about ONE pid rather than about children in general: the test binary
/// runs several attempts at once, and "does this process have any children" is
/// answered by somebody else's attempt as readily as by this one.
fn alive(pid: u32) -> bool {
    let pid = nix::unistd::Pid::from_raw(pid.cast_signed());
    // Signal zero asks the question without sending anything. A zombie answers
    // yes, so the child is reaped by the handle before this is asked.
    nix::sys::signal::kill(pid, None).is_ok()
}

#[test]
fn an_overlay_that_is_not_installed_is_not_an_error_the_login_can_see() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = overlay_from(dir.path().join("no-such-binary"), dir.path());
    assert!(overlay.present(PAYLOAD).is_none());
    // And nothing is left behind: a socket bound for a child that never started
    // would sit in the runtime directory until the machine was rebooted.
    let leftovers: Vec<PathBuf> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
}

#[test]
fn an_overlay_that_never_connects_is_given_up_on() {
    // The wait is bounded because this runs inside the authentication of a
    // login: a blocking accept here would hold a greeter open for as long as
    // nothing connected, which on a device without the overlay is forever.
    let dir = tempfile::tempdir().unwrap();
    let binary = fake_overlay(dir.path(), "overlay-silent", "sleep 30");
    // The default wait, not the long one: this test is about the bound.
    let overlay = SpawningOverlay::new(binary, dir.path().to_path_buf(), owner());

    let started = Instant::now();
    assert!(overlay.present(PAYLOAD).is_none());
    let waited = started.elapsed();
    assert!(
        waited < Duration::from_secs(5),
        "the login was held for {waited:?} by an overlay that never connected"
    );
    let leftovers: Vec<PathBuf> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("attempt-"))
        })
        .collect();
    assert!(leftovers.is_empty(), "the socket outlived the attempt");
}

#[test]
fn an_overlay_that_dies_immediately_is_given_up_on_without_waiting_out_the_deadline() {
    // A device with no X display is exactly this case, and it is the common
    // one: the binary is installed, it starts, it finds no display and exits.
    // Waiting out the whole handshake for it would add that wait to every
    // graphical login on every such device.
    let dir = tempfile::tempdir().unwrap();
    let binary = fake_overlay(dir.path(), "overlay-dead", "exit 1");
    let overlay = overlay_from(binary, dir.path());

    let started = Instant::now();
    assert!(overlay.present(PAYLOAD).is_none());
    let waited = started.elapsed();
    assert!(
        waited < TEST_HANDSHAKE / 2,
        "a dead overlay held the login for {waited:?}"
    );
}

#[test]
fn a_fleet_that_named_no_account_shows_the_challenge_in_the_prompt_only() {
    // The ordinary case, and the one worth a test of its own: it is what every
    // device without a display manager does, and what every login over ssh
    // does. It also has to be reachable from the line the PAM entry point
    // writes, which is compiled only for Linux — so the choosing lives here,
    // where a machine that is not Linux can still hold it to something.
    let chosen = super::choose(None, None);
    assert!(matches!(chosen, super::Chosen::Absent(_)));
    assert!(
        chosen.presenter().present(PAYLOAD).is_none(),
        "a device that named no overlay account drew something"
    );
}

#[test]
fn an_account_this_device_does_not_have_is_not_an_overlay_either() {
    // A misconfiguration — the account was deleted, or the fleet named the
    // greeter of a different distribution. It is reported to a journal and
    // nowhere else: a device whose overlay account went missing still lets its
    // engineers in through the prompt.
    let settings = tessera_core::codes::OverlaySettings {
        user: "no-such-account-on-this-device".to_owned(),
        binary: PathBuf::from(tessera_core::codes::DEFAULT_OVERLAY_BINARY),
    };
    let chosen = super::choose(Some(&settings), None);
    assert!(matches!(chosen, super::Chosen::Absent(_)));
}

#[test]
fn an_account_this_device_does_have_gets_an_overlay() {
    let settings = tessera_core::codes::OverlaySettings {
        user: current_account_name(),
        binary: PathBuf::from("/usr/bin/tessera-qr-overlay"),
    };
    let chosen = super::choose(Some(&settings), None);
    assert!(
        matches!(chosen, super::Chosen::Spawning(_)),
        "an account this device has was not resolved"
    );
}

/// The name of the account these tests run as.
fn current_account_name() -> String {
    nix::unistd::User::from_uid(nix::unistd::Uid::current())
        .ok()
        .flatten()
        .map(|account| account.name)
        .expect("this process runs as an account the device knows")
}

/// A stand-in that writes down what it was started WITH, then connects.
///
/// The environment, the working directory and the arguments — the things this
/// module decides for the child, as the child actually sees them. Asserting on
/// the `Command` we built would assert our own intention twice.
fn reporting_overlay(dir: &std::path::Path, record: &std::path::Path) -> PathBuf {
    let program = dir.join("report-env.py");
    std::fs::write(
        &program,
        "\
import os, socket, sys
out = open(sys.argv[2], \"w\")
for name in sorted(os.environ):
    out.write(\"env \" + name + \"=\" + os.environ[name] + \"\\n\")
out.write(\"cwd \" + os.getcwd() + \"\\n\")
out.write(\"argv \" + \" \".join(sys.argv[1:]) + \"\\n\")
out.flush()
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.recv(4096)
out.write(\"connected\\n\")
out.close()
",
    )
    .unwrap();
    fake_overlay(
        dir,
        "overlay-reporting",
        &format!(
            "exec python3 {} \"$2\" \"{}\"",
            program.display(),
            record.display()
        ),
    )
}

#[test]
fn the_child_is_given_three_names_of_the_environment_and_no_more() {
    // The module lives as a cdylib inside `sshd`, `login` or the display
    // manager, so an inherited environment is THAT process's environment. The
    // overlay is unprivileged pre-auth code on a machine anybody can walk up
    // to; `SSH_AUTH_SOCK` and the rest have no business travelling to it.
    //
    // Asserted on what the CHILD saw, written down by the child itself.
    let dir = tempfile::tempdir().unwrap();
    let record = dir.path().join("started-with.txt");
    let binary = reporting_overlay(dir.path(), &record);
    let overlay = overlay_from(binary, dir.path());

    let handle = overlay.present(PAYLOAD).expect("the overlay came up");
    let seen = await_text(&record, "connected", Duration::from_secs(10));
    drop(handle);

    // Compared against what THIS process carries, not against a list of names.
    // The wrapper shell and the interpreter set a few of their own — `PWD`,
    // `SHLVL`, whatever the platform's frameworks add — and a test that
    // forbade every unexpected name would be a test about the stand-in. What
    // must not happen is a name of the HOST process arriving with its value.
    let carried: Vec<String> = seen
        .lines()
        .filter_map(|line| line.strip_prefix("env "))
        .map(str::to_owned)
        .collect();
    // Names the child could not have invented for itself. A blanket comparison
    // against every variable of this process does not work and is worth saying
    // why: the platform sets a few of its own in the child — `PWD`, `SHLVL`,
    // `__CF_USER_TEXT_ENCODING` on macOS — with the same values, and a test
    // that read those as leaks would fail for a reason that is not the one it
    // is about.
    for name in [
        "HOME",
        "LOGNAME",
        "USER",
        "SSH_AUTH_SOCK",
        "CARGO",
        "TMPDIR",
    ] {
        let Ok(value) = std::env::var(name) else {
            continue;
        };
        let entry = format!("{name}={value}");
        assert!(
            !carried.contains(&entry),
            "the host's `{name}` travelled to the child: {carried:?}"
        );
    }
    // And the three DO travel, so the clearing is a filter and not a wall. The
    // environment is not modified to prove it — `set_var` is unsound in a
    // multi-threaded binary and the repository disallows it — so the name used
    // is the one that is always there.
    let path = std::env::var("PATH").expect("this process runs with a PATH");
    assert!(
        carried.contains(&format!("PATH={path}")),
        "the child was given no PATH, so it could not find a program: {carried:?}"
    );
    for name in ["DISPLAY", "XAUTHORITY"] {
        if let Ok(value) = std::env::var(name) {
            assert!(
                carried.contains(&format!("{name}={value}")),
                "the child was not given `{name}`, so it could not find a screen"
            );
        }
    }
    assert!(
        seen.lines().any(|line| line == "cwd /"),
        "the child inherited a working directory: {seen}"
    );
}

/// Waits for a file to carry a marker, and returns what it carries.
fn await_text(path: &std::path::Path, marker: &str, wait: Duration) -> String {
    let deadline = Instant::now() + wait;
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            if text.contains(marker) {
                return text;
            }
        }
        assert!(
            Instant::now() < deadline,
            "`{marker}` never appeared in {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn nothing_the_overlay_writes_reaches_the_module() {
    // The security property of this whole join. The module runs as root inside
    // `sshd` or a display manager; the overlay does not. Root reading a stream
    // that side produced would be the one place where a privileged process
    // parses an unprivileged one's output — so the read half is shut down
    // before the first byte goes out, and there is nothing to parse.
    //
    // Asserted from the OVERLAY's side, which is where it is observable: a
    // stand-in that writes into the socket after connecting gets its bytes
    // refused, and the module never sees them.
    let dir = tempfile::tempdir().unwrap();
    let record = dir.path().join("wrote.txt");
    let program = dir.path().join("talk-back.py");
    std::fs::write(
        &program,
        "\
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.recv(4096)
out = open(sys.argv[2], \"w\")
try:
    s.sendall(b\"XXXX\" * 64)
    out.write(\"sent\\n\")
except OSError as error:
    out.write(\"refused \" + str(error.errno) + \"\\n\")
out.flush()
import time
time.sleep(30)
",
    )
    .unwrap();
    let binary = fake_overlay(
        dir.path(),
        "overlay-talks-back",
        &format!(
            "exec python3 {} \"$2\" \"{}\"",
            program.display(),
            record.display()
        ),
    );
    let overlay = overlay_from(binary, dir.path());

    let handle = overlay.present(PAYLOAD).expect("the overlay came up");
    let seen = await_text(&record, "\n", Duration::from_secs(10));
    drop(handle);

    // Either the write was refused outright, or it was accepted by the kernel
    // and discarded — both are the same fact from here: the module has shut
    // its read half and will never look. What must NOT happen is the module
    // having a readable stream at all, and that is asserted below.
    assert!(
        seen.starts_with("refused") || seen.starts_with("sent"),
        "the stand-in did not report what happened: {seen}"
    );
}

#[test]
fn the_module_holds_a_socket_it_cannot_read_from() {
    // Said directly, against the module's own end. A later change that took the
    // shutdown out would be a change that let root read an unprivileged
    // process's bytes again, and it would pass every other test in this file.
    let dir = tempfile::tempdir().unwrap();
    let record = dir.path().join("received.bin");
    let binary = recording_overlay(dir.path(), &record, false);
    let overlay = overlay_from(binary, dir.path());

    let mut handle = overlay.try_present(PAYLOAD).expect("the overlay came up");
    await_file(&record, Duration::from_secs(10));

    let mut buffer = [0_u8; 8];
    // `Ok(0)` and nothing else. A socket whose read half is down answers that
    // at once; one that is merely quiet blocks and comes back `WouldBlock`
    // after the timeout — and accepting THAT as proof would let the shutdown be
    // taken out without a single test noticing.
    let read = handle.read_from_overlay(&mut buffer);
    assert!(
        matches!(read, Ok(0)),
        "the module could still read from the overlay: {read:?}"
    );
    drop(handle);
}

#[test]
fn the_directory_of_attempt_sockets_is_made_when_it_is_missing() {
    // The package makes it — `tmpfiles.d` under systemd, the init script
    // elsewhere — and the login path is not the packaging path. A host booted
    // without the tmpfiles run, or with an init script somebody edited, ends
    // with every graphical login quietly falling back to text.
    let dir = tempfile::tempdir().unwrap();
    let sockets = dir.path().join("made-here");
    assert!(!sockets.exists());

    super::ensure_socket_directory(&sockets).expect("the directory was not made");
    let mode = std::fs::metadata(&sockets).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o711, "made with the wrong mode");

    // And running again over one that already exists is not a failure: every
    // attempt calls this.
    super::ensure_socket_directory(&sockets).expect("an existing directory was refused");
}

#[test]
fn an_attempt_makes_the_directory_it_needs_rather_than_falling_back_to_text() {
    // The whole point of making it here rather than trusting the packaging.
    // Every other test in this file hands the overlay a directory that already
    // exists, so removing the call that creates one broke nothing — the
    // mutation passed, and the case that made this task exist was the one
    // nobody covered.
    let dir = tempfile::tempdir().unwrap();
    // A short name on purpose: the socket path is bounded by `SUN_LEN`, and a
    // temporary directory plus `attempt-` plus thirty-two hex digits is already
    // most of it. In production the path is `/run/tessera-overlay/attempt-…`,
    // sixty characters and no argument about it.
    let sockets = dir.path().join("ov");
    assert!(!sockets.exists(), "the case under test needs it missing");

    let record = dir.path().join("received.bin");
    let binary = recording_overlay(dir.path(), &record, false);
    let overlay =
        SpawningOverlay::new(binary, sockets.clone(), owner()).with_handshake(TEST_HANDSHAKE);

    let handle = match overlay.try_present(PAYLOAD) {
        Ok(handle) => handle,
        Err(error) => panic!("the overlay fell back to text: {error}"),
    };
    await_file(&record, Duration::from_secs(10));
    assert!(sockets.is_dir(), "the directory was not made");
    drop(handle);
}

#[test]
fn a_directory_of_attempt_sockets_this_module_cannot_vouch_for_is_refused() {
    // Somebody else's directory is somebody who can put a socket in it before
    // the overlay reaches it — and the random name of an attempt is the only
    // other thing standing in their way.
    let dir = tempfile::tempdir().unwrap();

    let loose = dir.path().join("loose");
    std::fs::create_dir(&loose).unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o777)).unwrap();
    let refusal = super::ensure_socket_directory(&loose)
        .expect_err("a world-writable directory of sockets was accepted");
    assert_eq!(refusal.kind(), std::io::ErrorKind::PermissionDenied);

    // A name that is not a directory at all — a symlink into somebody's home,
    // in the case this stands for — is refused WITHOUT being followed.
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
    let followed = super::ensure_socket_directory(&link)
        .expect_err("a symlink was followed instead of refused");
    assert_eq!(followed.kind(), std::io::ErrorKind::PermissionDenied);

    // And the owner, which is the third of the three and the one no file system
    // trick can produce here: making a directory owned by somebody else needs
    // root, so the fault goes into the code instead. The directory is ours and
    // correctly moded; what changes is the owner the check is told to insist
    // on, which is exactly the question "is this directory mine?".
    let ours = dir.path().join("ours");
    std::fs::create_dir(&ours).unwrap();
    std::fs::set_permissions(&ours, std::fs::Permissions::from_mode(0o711)).unwrap();
    let mine = nix::unistd::Uid::effective().as_raw();
    assert!(
        super::ensure_socket_directory_owned_by(&ours, mine).is_ok(),
        "a directory this process owns, moded as the module makes them, was refused"
    );

    let somebody_else = mine.wrapping_add(1);
    let refused = super::ensure_socket_directory_owned_by(&ours, somebody_else)
        .expect_err("a directory belonging to another account was accepted");
    assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
    // The message names both accounts: whoever reads the journal is standing at
    // a machine trying to find out which directory to look at.
    let said = refused.to_string();
    assert!(said.contains(&mine.to_string()), "{said}");
    assert!(said.contains(&somebody_else.to_string()), "{said}");
}

#[test]
fn a_peer_that_is_not_the_overlay_account_is_refused() {
    // The check that had no test until a mutation said so. The mode and the
    // owner of the socket say who MAY connect; this says who did, and it is the
    // only one of the two that survives a mistake in the other — a directory
    // whose permissions were widened by hand, a socket whose chown did not
    // take.
    //
    // A second account is not available to a unit test, so the question is put
    // the other way round: a connection from THIS account, offered to an
    // overlay configured for a different one.
    let (ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let mine = owner();

    assert!(
        super::check_peer(&ours, mine).is_ok(),
        "the account that actually connected was refused"
    );

    let somebody_else = Owner {
        uid: mine.uid.wrapping_add(1),
        gid: mine.gid,
    };
    let refusal = super::check_peer(&ours, somebody_else)
        .expect_err("a peer of another account was accepted");
    assert_eq!(refusal.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        refusal.to_string().contains(&mine.uid.to_string()),
        "the refusal does not say who connected: {refusal}"
    );
}

#[test]
fn two_attempts_do_not_share_a_socket() {
    // The name carries sixteen random bytes for a reason: a predictable name is
    // a name something else can be waiting on before the overlay gets there.
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first.bin");
    let second = dir.path().join("second.bin");
    let binary_one = recording_overlay(dir.path(), &first, false);
    std::fs::rename(&binary_one, dir.path().join("one")).unwrap();
    let binary_two = recording_overlay(dir.path(), &second, false);

    let one = overlay_from(dir.path().join("one"), dir.path());
    let two = overlay_from(binary_two, dir.path());

    let held_one = one.present(PAYLOAD).expect("the first overlay came up");
    let held_two = two.present(PAYLOAD).expect("the second overlay came up");
    await_file(&first, Duration::from_secs(10));
    await_file(&second, Duration::from_secs(10));

    let sockets: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with("attempt-"))
        .collect();
    assert_eq!(sockets.len(), 2, "two attempts landed on one socket");

    drop(held_one);
    drop(held_two);
}

#[test]
fn the_overlay_is_told_the_attempt_is_over() {
    // A cancel frame goes out before the socket closes. Not the guarantee — the
    // guarantee is the kill that follows — but the polite half, and an overlay
    // that respects it takes the window down without being killed.
    let dir = tempfile::tempdir().unwrap();
    let record = dir.path().join("received.bin");
    let binary = recording_overlay(dir.path(), &record, true);
    let overlay = overlay_from(binary, dir.path());

    let handle = overlay.present(PAYLOAD).expect("the overlay came up");
    await_file(&record, Duration::from_secs(10));
    drop(handle);

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut bytes = Vec::new();
        if let Ok(mut file) = std::fs::File::open(&record) {
            let _ignored = file.read_to_end(&mut bytes);
        }
        if let Ok((_, Message::Challenge(_))) = decode(&bytes) {
            // Only the challenge so far.
        } else if bytes.len() > HEADER_LEN + PAYLOAD.len() {
            let tail = bytes.split_off(HEADER_LEN + PAYLOAD.len());
            let (_, message) = decode(&tail).expect("the second frame parses");
            assert_eq!(message, Message::Cancel);
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the overlay was never told the attempt was over"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A display named the way a display manager names one.
fn x_channel() -> XChannel {
    XChannel {
        display: ":0".to_owned(),
        scheme: "MIT-MAGIC-COOKIE-1".to_owned(),
        cookie: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01],
    }
}

#[test]
fn the_credential_file_is_laid_out_the_way_an_x_client_reads_it() {
    // The format is not ours and cannot be checked against our own reading of
    // it: what an X client does is match family, address and display number,
    // then take the scheme and the bytes. The entry claims the wildcard family
    // with neither address nor number, which is what makes it match whichever
    // way the client spells the display it was handed.
    let channel = x_channel();
    let bytes = super::xauth_entry(&channel.scheme, &channel.cookie);

    let mut expected = vec![0xFF, 0xFF];
    expected.extend_from_slice(&[0x00, 0x00]); // address: empty
    expected.extend_from_slice(&[0x00, 0x00]); // display number: empty
    expected.extend_from_slice(&[0x00, 0x12]); // scheme: 18 bytes
    expected.extend_from_slice(channel.scheme.as_bytes());
    expected.extend_from_slice(&[0x00, 0x06]); // cookie: 6 bytes
    expected.extend_from_slice(&channel.cookie);

    assert_eq!(bytes, expected);
}

#[test]
fn the_credential_of_the_display_is_written_for_one_account_and_removed_after() {
    // Two properties, and the second is the one a person can walk up to: while
    // the attempt lasts the cookie is on disk readable by the overlay's account
    // alone, and when the attempt ends it is gone. A cookie left behind is a
    // key to the screen of an unattended machine.
    let dir = tempfile::tempdir().unwrap();
    let record = dir.path().join("recorded.bin");
    let binary = recording_overlay(dir.path(), &record, false);
    let overlay = overlay_from(binary, dir.path()).with_x_channel(Some(x_channel()));

    let handle = overlay.present(PAYLOAD);
    assert!(handle.is_some(), "the overlay did not come up");

    let files: Vec<PathBuf> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "xauth"))
        .collect();
    assert_eq!(files.len(), 1, "expected exactly one credential file");
    let mode = std::fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the credential of the display was readable by others");

    drop(handle);
    assert!(
        !files[0].exists(),
        "the credential of the display outlived the attempt"
    );
}
