//! Name resolution asked of a separate process.
//!
//! The additive source of the account check ([`super::system_account`]) has to
//! answer about names no local file holds — systemd's `DynamicUser=` accounts
//! exist only through `nss-systemd` — and it has to do so under a time bound,
//! because it is consulted on every login attempt before any credential is
//! presented.
//!
//! Both requirements together rule out asking the C library directly.
//! `getpwnam` cannot be cancelled: once a resolver module is inside its own
//! timeouts, the only way to stop waiting is to stop looking at the caller that
//! waits, and the call keeps running. In a PAM module that is not merely
//! wasteful — `pam_tessera.so` is a dynamically loaded library, the application
//! may call `pam_end` and have Linux-PAM unload it the moment authentication
//! ends, and work still outstanding inside this crate would then return into an
//! address range that is no longer mapped and take the authenticating process
//! down with it. It would happen precisely when a directory is unreachable,
//! which is the case the bound exists for.
//!
//! So the question is put to a child process instead. `getent passwd` asks the
//! same NSS stack the rest of the system uses, so `DynamicUser=` accounts and
//! directory entries are visible; and a child can be **killed and reaped**,
//! which makes an unfinished lookup genuinely cancelled rather than abandoned.
//! After the bound runs out nothing of this crate's code is left running
//! anywhere, and the module may be unloaded safely.
//!
//! A plain `fork()` without `execve` would not do: `getpwnam` is not
//! async-signal-safe, and a fork from the multi-threaded process a PAM host is
//! permits only async-signal-safe calls in the child. The child therefore does
//! nothing but the shared post-fork setup and `execve`.
//!
//! Every failure here — no `getent` on the system, a fork that fails, an
//! unparseable answer, an unexpected status — is *silence*, never a refusal.
//! The verdict then stays the one the local account database reached, because a
//! device without a network must still let its engineer in.

use std::ffi::CString;
use std::io::Read as _;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{ForkResult, Pid};

use crate::hooks::child_setup::child_setup;
use crate::hooks::rlimit::default_caps_for_timeout;
use crate::privileged_path::{validate_path, ExecTrust};

use super::system_account::{lookup_in_passwd_bytes, NameResolution};

/// Where `getent` lives on the distributions this product targets.
///
/// `/usr/bin` comes first: on a merged-`/usr` system `/bin` is a symlink, and
/// the path check every executable run at root privilege goes through rejects
/// symlinked components.
const GETENT_CANDIDATES: [&str; 2] = ["/usr/bin/getent", "/bin/getent"];

/// The database `getent` is asked about; the one that answers with uids.
const PASSWD_DATABASE: &str = "passwd";

/// `getent`'s status for "one or more of the requested keys was not found".
///
/// Asking about several names at once makes this status ordinary rather than
/// exceptional: any name the directory does not serve produces it while the
/// names it does serve are printed as usual. The lines that *are* there are
/// exactly as trustworthy as under a zero status.
const KEY_NOT_FOUND: i32 = 2;

/// Largest answer that still counts as an answer.
///
/// One `passwd` record per name asked about is a few dozen bytes; the whole
/// role base cannot exceed a few hundred names. The cap is far above that and
/// exists only so a resolver that streams without end cannot make the login
/// path allocate without bound.
const MAX_ANSWER_BYTES: usize = 256 * 1024;

/// How often the parent looks at the child while the bound runs.
///
/// Short enough that the answer is not held back noticeably on a healthy
/// device, long enough that the wait costs no measurable CPU.
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Ask the name service about `accounts`, in one child process, under `timeout`.
///
/// The whole set is asked in a single run: this runs on the login path, once
/// per role-store load, and one process per name would put the cost of a fork
/// on every slice in the base.
pub(super) fn resolve(accounts: &[&str], timeout: Duration) -> NameResolution {
    let Some(program) = program() else {
        tracing::warn!(
            target: "tessera.role",
            "no usable getent on this system; \
             the local account database decides on its own"
        );
        return NameResolution::silent();
    };
    resolve_with(&program, accounts, timeout)
}

/// The `getent` this device will run, or `None` when there is none to trust.
///
/// The candidate has to pass the same ownership walk `sudo` and `ssh` perform
/// before running anything: this child is spawned from a process authenticating
/// at root, so a binary — or a directory on its path — an unprivileged user
/// could rewrite would be a way to have that user's code run as root. A
/// candidate that does not pass is not run, and the check falls back on the
/// local file alone.
fn program() -> Option<PathBuf> {
    GETENT_CANDIDATES.iter().find_map(|candidate| {
        match validate_path(Path::new(candidate), ExecTrust::Root) {
            Ok(validated) => Some(validated.canonical().to_path_buf()),
            Err(error) => {
                tracing::debug!(
                    target: "tessera.role",
                    candidate,
                    error = %error,
                    "this getent cannot be used for the account check"
                );
                None
            }
        }
    })
}

/// [`resolve`] against a named program, so the shape of every failure can be
/// exercised without the machine's own `getent`.
fn resolve_with(program: &Path, accounts: &[&str], timeout: Duration) -> NameResolution {
    let mut args: Vec<&str> = Vec::with_capacity(accounts.len() + 1);
    args.push(PASSWD_DATABASE);
    args.extend_from_slice(accounts);

    interpret(&run(program, &args, timeout), accounts)
}

/// Turn one run of the resolver into what it said about each name.
fn interpret(run: &Run, accounts: &[&str]) -> NameResolution {
    match run.outcome {
        // A name the answer does not mention resolves to "no entry", which is
        // as harmless to the verdict as silence: only a uid outside the
        // regular range can add a refusal.
        Outcome::Exited(0 | KEY_NOT_FOUND) => NameResolution::answered(
            accounts
                .iter()
                .map(|account| {
                    (
                        (*account).to_owned(),
                        lookup_in_passwd_bytes(&run.stdout, account, &"getent passwd"),
                    )
                })
                .collect(),
        ),
        Outcome::TimedOut => NameResolution::stopped(),
        Outcome::Exited(code) => {
            tracing::warn!(
                target: "tessera.role",
                exit_code = code,
                "name resolution ended with an unexpected status; \
                 the local account database decides on its own"
            );
            NameResolution::silent()
        }
        Outcome::Unstartable => {
            tracing::warn!(
                target: "tessera.role",
                "name resolution could not be run to an end; \
                 the local account database decides on its own"
            );
            NameResolution::silent()
        }
    }
}

/// How one run of the resolver ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The program ran to its own end and left this status.
    Exited(i32),
    /// The bound ran out; the child was killed and reaped.
    TimedOut,
    /// The program could not be started, or its end could not be established.
    Unstartable,
}

/// One run of the resolver: what it wrote and how it ended.
#[derive(Debug)]
struct Run {
    /// Everything the program wrote to its standard output.
    stdout: Vec<u8>,
    /// How the run ended.
    outcome: Outcome,
}

impl Run {
    /// A run that never got off the ground.
    const fn unstartable() -> Self {
        Self {
            stdout: Vec::new(),
            outcome: Outcome::Unstartable,
        }
    }
}

/// Run `program` with `args`, collect its standard output, and give it at most
/// `timeout` to finish.
///
/// The program is left holding no environment and no standard input, its
/// standard error goes to `/dev/null`, and it inherits none of the calling
/// process's descriptors — the shared post-fork child path
/// ([`child_setup`]) does all of that, plus the resource caps that bound the
/// child a second way if the wall clock somehow does not.
///
/// Output is read only after the child has ended, which is safe because the
/// answer to a `passwd` query is far smaller than a pipe buffer: a child that
/// nevertheless wrote enough to fill the pipe would block, run out of its
/// bound, and be killed — silence, which is the safe direction.
fn run(program: &Path, args: &[&str], timeout: Duration) -> Run {
    let Some(storage) = argv_storage(program, args) else {
        return Run::unstartable();
    };
    let argv_ptrs: Vec<*const c_char> = storage
        .iter()
        .map(|arg| arg.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    // The resolver is handed no environment at all. Nothing a `passwd` lookup
    // does needs one, and passing the calling application's environment on
    // would hand it a way to steer code that runs at root here.
    let env_ptrs: [*const c_char; 1] = [std::ptr::null()];

    let Ok((answer_read, answer_write)) = cloexec_pipe() else {
        return Run::unstartable();
    };
    let Ok(discard) = std::fs::OpenOptions::new().write(true).open("/dev/null") else {
        return Run::unstartable();
    };
    let answer_write_fd = answer_write.as_raw_fd();
    let discard_fd = discard.as_raw_fd();
    let caps = default_caps_for_timeout(timeout);

    // SAFETY: this is the fork itself. The child path below calls only
    // async-signal-safe functions (through `child_setup`) and never returns
    // through Rust; the argv/env pointer arrays it reads point into `storage`,
    // which lives in this stack frame and stays where it is until the child
    // either execs or exits.
    #[allow(unsafe_code)]
    let forked = unsafe { nix::unistd::fork() };

    match forked {
        Err(_) => Run::unstartable(),
        // SAFETY: the child path, immediately after fork, single-threaded.
        // `argv_ptrs`/`env_ptrs` are NUL-terminated and point into parent-owned
        // `CString` storage; both descriptors are open; there is no user to
        // switch to, so the group pointer is null with a zero length.
        #[allow(unsafe_code)]
        Ok(ForkResult::Child) => unsafe {
            child_setup(
                &argv_ptrs,
                &env_ptrs,
                None,
                &caps,
                answer_write_fd,
                discard_fd,
                std::ptr::null(),
                0,
            )
        },
        Ok(ForkResult::Parent { child }) => {
            // The parent's copy of the write end has to go, or the pipe never
            // reaches end-of-file.
            drop(answer_write);
            drop(discard);
            supervise(child, answer_read, timeout)
        }
    }
}

/// Build the `CString` storage `execve` will read `argv` from.
///
/// Returns `None` for a name that cannot be one — a NUL byte inside it — rather
/// than truncating it into a different name.
fn argv_storage(program: &Path, args: &[&str]) -> Option<Vec<CString>> {
    let mut storage = Vec::with_capacity(args.len() + 1);
    storage.push(CString::new(program.as_os_str().as_bytes()).ok()?);
    for arg in args {
        storage.push(CString::new(*arg).ok()?);
    }
    Some(storage)
}

/// A pipe whose both ends carry `O_CLOEXEC`.
///
/// Without it a sibling thread that forks and execs in the window before this
/// module's own fork would inherit the write end, and the pipe would then never
/// reach end-of-file after the resolver exits.
fn cloexec_pipe() -> nix::Result<(OwnedFd, OwnedFd)> {
    #[cfg(target_os = "linux")]
    {
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)
    }
    #[cfg(not(target_os = "linux"))]
    {
        use nix::fcntl::{fcntl, FcntlArg, FdFlag};
        let (read_end, write_end) = nix::unistd::pipe()?;
        fcntl(&read_end, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
        fcntl(&write_end, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
        Ok((read_end, write_end))
    }
}

/// Wait for `child` up to `timeout`, then read what it left behind.
///
/// Exhausting the bound kills the child and reaps it. That is the whole point
/// of running the lookup elsewhere: the request stops, rather than being left
/// to finish in a library the caller may already have unloaded.
fn supervise(child: Pid, answer: OwnedFd, timeout: Duration) -> Run {
    let deadline = Instant::now() + timeout;
    loop {
        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                if Instant::now() >= deadline {
                    kill_and_reap(child);
                    return Run {
                        stdout: Vec::new(),
                        outcome: Outcome::TimedOut,
                    };
                }
                std::thread::sleep(CHILD_POLL_INTERVAL);
            }
            Ok(WaitStatus::Exited(_, code)) => {
                return Run {
                    stdout: drain(answer),
                    outcome: Outcome::Exited(code),
                }
            }
            Err(Errno::EINTR) => {}
            // A child killed by someone else, a status this wait was not
            // asking for, or `ECHILD` — a PAM host that reaps in its own
            // `SIGCHLD` handler may have collected this child before we
            // looked. Nothing is left running in any of these cases, and an
            // answer that cannot be tied to a status is not used.
            Ok(_) | Err(_) => return Run::unstartable(),
        }
    }
}

/// Stop `child` and collect it, so no process and no zombie outlives the bound.
///
/// `SIGKILL` without a polite stage: the resolver has no state to flush and
/// nothing to clean up, and every millisecond spent here is spent on the login
/// path. The wait afterwards has no bound of its own because the signal cannot
/// be caught or ignored — the child is already on its way out, and giving up on
/// collecting it would leave a zombie behind on every slow login.
fn kill_and_reap(child: Pid) {
    let _signalled = kill(child, Signal::SIGKILL);
    loop {
        match waitpid(child, None) {
            Err(Errno::EINTR) => {}
            _ => return,
        }
    }
}

/// Read everything the ended child wrote, without ever blocking on it.
///
/// The read end is switched to non-blocking first: should a descendant have
/// inherited the write end, a blocking read would park the login path on a pipe
/// nobody is going to close.
fn drain(answer: OwnedFd) -> Vec<u8> {
    let _nonblocking = nix::fcntl::fcntl(
        &answer,
        nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
    );
    let mut source = std::fs::File::from(answer);
    let mut collected = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        match source.read(&mut buffer) {
            Ok(0) => return collected,
            Ok(read) => {
                collected.extend_from_slice(buffer.get(..read).unwrap_or_default());
                if collected.len() > MAX_ANSWER_BYTES {
                    // Past the cap it is not an answer any more, and guessing
                    // at a truncated one on an authentication path is worse
                    // than having none.
                    return Vec::new();
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            // Anything else, `WouldBlock` included, means nothing more is
            // coming: the writer is gone.
            Err(_) => return collected,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::missing_docs_in_private_items)]

    use super::*;

    /// The first of `candidates` that exists, so the tests can run on a
    /// merged-`/usr` Linux and on macOS alike.
    fn first_existing(candidates: &[&str]) -> PathBuf {
        candidates
            .iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
            .expect("one of these programs exists on every supported dev host")
    }

    #[test]
    fn a_resolver_that_outruns_its_bound_is_killed_and_reaped() {
        // The scenario the whole out-of-process design exists for: the
        // resolver does not answer. The bound must end the wait *and* the
        // process — this test returning at all is the proof of the reap,
        // because collecting the child is a wait with no timeout of its own.
        let sleep = first_existing(&["/bin/sleep", "/usr/bin/sleep"]);
        let started = Instant::now();

        let run = run(&sleep, &["30"], Duration::from_millis(50));

        assert_eq!(run.outcome, Outcome::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the bound must end the wait, not the program: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn what_the_resolver_writes_is_collected() {
        let echo = first_existing(&["/bin/echo", "/usr/bin/echo"]);

        let run = run(
            &echo,
            &["serv:x:4000:4000::/home/serv:/bin/sh"],
            Duration::from_secs(30),
        );

        assert_eq!(run.outcome, Outcome::Exited(0));
        assert_eq!(
            String::from_utf8_lossy(&run.stdout).trim(),
            "serv:x:4000:4000::/home/serv:/bin/sh"
        );
    }

    #[test]
    fn a_missing_resolver_is_silence_and_does_not_latch() {
        // A device without `getent`, or with one the path check refuses: the
        // source says nothing, and it is not the kind of nothing that closes
        // the source for the rest of the process — no bound was exhausted.
        let resolution = resolve_with(
            Path::new("/nonexistent/getent"),
            &["serv"],
            Duration::from_secs(30),
        );

        assert!(!resolution.exhausted_its_bound());
        assert_eq!(
            resolution.answer_for("serv"),
            super::super::system_account::PasswdLookup::Unavailable,
            "a resolver that cannot run says nothing about the name"
        );
    }

    #[test]
    fn an_answer_is_parsed_into_a_uid_per_name() {
        // `printf` stands in for `getent`: the format is the same `passwd(5)`
        // line, so the parser and the per-name split are exercised end to end
        // without the name service of the machine running the tests.
        let printf = first_existing(&["/usr/bin/printf", "/bin/printf"]);
        let run = run(
            &printf,
            &["dyn-service:x:61184:61184::/:/usr/sbin/nologin\nserv:x:4000:4000::/home/serv:/bin/sh\n"],
            Duration::from_secs(30),
        );
        assert_eq!(run.outcome, Outcome::Exited(0));

        let dyn_service = lookup_in_passwd_bytes(&run.stdout, "dyn-service", &"getent passwd");
        let serv = lookup_in_passwd_bytes(&run.stdout, "serv", &"getent passwd");
        let absent = lookup_in_passwd_bytes(&run.stdout, "ghost", &"getent passwd");

        assert_eq!(
            dyn_service,
            super::super::system_account::PasswdLookup::Uid(61184)
        );
        assert_eq!(serv, super::super::system_account::PasswdLookup::Uid(4000));
        assert_eq!(absent, super::super::system_account::PasswdLookup::NoEntry);
    }

    #[test]
    fn an_unexpected_status_is_silence() {
        let program = first_existing(&["/usr/bin/false", "/bin/false"]);

        let resolution = resolve_with(&program, &["serv"], Duration::from_secs(30));

        assert!(!resolution.exhausted_its_bound());
        assert_eq!(
            resolution.answer_for("serv"),
            super::super::system_account::PasswdLookup::Unavailable
        );
    }

    #[test]
    fn a_run_stopped_at_its_bound_reports_the_bound_as_exhausted() {
        // What the killed child must turn into: silence about every name, and
        // the one signal that closes the source for the rest of the process.
        let stopped = Run {
            stdout: Vec::new(),
            outcome: Outcome::TimedOut,
        };

        let resolution = interpret(&stopped, &["serv"]);

        assert!(
            resolution.exhausted_its_bound(),
            "an exhausted bound is what closes the source for the rest of the process"
        );
        assert_eq!(
            resolution.answer_for("serv"),
            super::super::system_account::PasswdLookup::Unavailable
        );
    }

    #[test]
    fn a_partial_answer_is_still_an_answer() {
        // Asking about several names at once makes "one or more keys not
        // found" the ordinary status; the lines that are there still count.
        let partial = Run {
            stdout: b"serv:x:4000:4000::/home/serv:/bin/sh\n".to_vec(),
            outcome: Outcome::Exited(KEY_NOT_FOUND),
        };

        let resolution = interpret(&partial, &["serv", "ghost"]);

        assert!(!resolution.exhausted_its_bound());
        assert_eq!(
            resolution.answer_for("serv"),
            super::super::system_account::PasswdLookup::Uid(4000)
        );
        assert_eq!(
            resolution.answer_for("ghost"),
            super::super::system_account::PasswdLookup::NoEntry
        );
    }
}
