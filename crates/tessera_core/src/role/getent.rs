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
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{ForkResult, Pid};

use crate::hooks::child_setup::child_setup;
use crate::hooks::rlimit::default_caps_for_timeout;
use crate::privileged_path::{validate_path, ExecTrust};

use super::schema::RoleId;
use super::store::MAX_ROLES;
use super::system_account::{lookup_in_passwd_bytes, NameResolution};

/// Where `getent` lives on the distributions this product targets.
///
/// `/usr/bin` comes first: on a merged-`/usr` system `/bin` is a symlink, and
/// the path check every executable run at root privilege goes through rejects
/// symlinked components.
const GETENT_CANDIDATES: [&str; 2] = ["/usr/bin/getent", "/bin/getent"];

/// The database `getent` is asked about; the one that answers with uids.
const PASSWD_DATABASE: &str = "passwd";

/// The end-of-options marker every name is passed after.
///
/// `getent` parses its command line with argp, which recognises options
/// wherever they appear — including after the database name and in between
/// keys. The names asked about come from the file stems of a role directory,
/// and a stem like `--service=evil` would otherwise stop being a key and become
/// a request to load a different NSS module into a process running as root.
/// After this marker every remaining word is a key, whatever it looks like.
const END_OF_OPTIONS: &str = "--";

/// `getent`'s status for "one or more of the requested keys was not found".
///
/// Asking about several names at once makes this status ordinary rather than
/// exceptional: any name the directory does not serve produces it while the
/// names it does serve are printed as usual. The lines that *are* there are
/// exactly as trustworthy as under a zero status.
const KEY_NOT_FOUND: i32 = 2;

/// Largest one `passwd` record is taken to be.
///
/// Six of the seven fields are a name, a password placeholder, two ids, a home
/// and a shell, all short; only the gecos field is free text, and a directory
/// that fills it generously still stays orders of magnitude below this.
const MAX_RECORD_BYTES: usize = 16 * 1024;

/// Largest answer that still counts as an answer.
///
/// One record per name asked about, and no more names are asked about than a
/// role base may hold — so the cap is that product, and an answer of the
/// largest shape a real directory could produce still fits inside it whole. It
/// exists only so a resolver that streams without end cannot make the login
/// path allocate without bound.
const MAX_ANSWER_BYTES: usize = MAX_NAMES_PER_RUN * MAX_RECORD_BYTES;

/// Most names one run may be asked about.
///
/// Every name becomes a word on the child's command line, and `execve` refuses
/// an argument list past the kernel's limit — with an errno the child can only
/// turn into silence, indistinguishable from a broken resolver. A directory
/// holding more slices than a role base may contain is a provisioning fault its
/// own diagnostic already names, so the bound here is the same one the base has.
const MAX_NAMES_PER_RUN: usize = MAX_ROLES;

/// How long a killed child is waited for before the login path moves on.
///
/// `SIGKILL` cannot be caught, so this is the scheduling delay between the
/// signal and the process being gone — never a wait on the resolver itself.
/// Past it the login proceeds and the worst that is left behind is one zombie
/// the host reaps when it next waits.
const REAP_GRACE: Duration = Duration::from_secs(1);

/// How often the parent looks at the child once the answer is complete.
///
/// Short enough that the answer is not held back noticeably on a healthy
/// device, long enough that the wait costs no measurable CPU.
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// How long a single wait on the pipe may last when the remaining budget cannot
/// be expressed as a poll timeout.
///
/// The conversion cannot fail for a budget the caller already validated, so this
/// only covers the unforeseen; it is short because the loop re-checks the
/// deadline after every wait, and a fallback that waits *longer* than asked
/// would defeat the bound this whole module exists to keep.
const POLL_RECHECK_MILLIS: u16 = 50;

/// The byte a complete `getent passwd` answer ends on.
///
/// Every record it prints is a whole line, so a final newline is what tells a
/// finished answer from one cut off mid-record — see [`is_complete`].
const RECORD_TERMINATOR: u8 = b'\n';

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
///
/// Only names that could be role ids at all are asked about. The check is
/// cheap and it is the second of the two belts that keep a file stem from
/// steering the resolver: a name outside the grammar can never name a role, so
/// nothing is lost by leaving it out of the command line, and what is not on
/// the command line cannot be read as an option. A name left out is a name the
/// source says nothing about, which is the one answer that never refuses.
fn resolve_with(program: &Path, accounts: &[&str], timeout: Duration) -> NameResolution {
    let Some(askable) = askable(accounts) else {
        return NameResolution::silent();
    };
    let args = command_line(&askable);

    interpret(&run(program, &args, timeout), &askable)
}

/// The names of `accounts` this run will actually ask about, or `None` when
/// there is no run worth making.
fn askable<'a>(accounts: &[&'a str]) -> Option<Vec<&'a str>> {
    let askable: Vec<&str> = accounts
        .iter()
        .copied()
        .filter(|account| RoleId::new(account).is_ok())
        .collect();
    if askable.is_empty() {
        return None;
    }
    if askable.len() > MAX_NAMES_PER_RUN {
        tracing::warn!(
            target: "tessera.role",
            names = askable.len(),
            max = MAX_NAMES_PER_RUN,
            "more names to resolve than a role base may hold; \
             the local account database decides on its own"
        );
        return None;
    }
    Some(askable)
}

/// The words the resolver is run with: the database, the end-of-options
/// marker, then one name per key.
fn command_line<'a>(askable: &[&'a str]) -> Vec<&'a str> {
    let mut args: Vec<&str> = Vec::with_capacity(askable.len() + 2);
    args.push(PASSWD_DATABASE);
    args.push(END_OF_OPTIONS);
    args.extend_from_slice(askable);
    args
}

/// Turn one run of the resolver into what it said about each name.
fn interpret(run: &Run, accounts: &[&str]) -> NameResolution {
    match run.outcome {
        // A name the answer does not mention resolves to "no entry", which is
        // as harmless to the verdict as silence: only a uid outside the
        // regular range can add a refusal.
        //
        // An end without a status is read the same way. The child wrote a whole
        // answer and closed the pipe; that the status could not be collected
        // afterwards says something about the host process, not about the
        // answer.
        Outcome::Exited(0 | KEY_NOT_FOUND) | Outcome::EndedWithoutStatus => {
            NameResolution::answered(
                accounts
                    .iter()
                    .map(|account| {
                        (
                            (*account).to_owned(),
                            lookup_in_passwd_bytes(&run.stdout, account, &"getent passwd"),
                        )
                    })
                    .collect(),
            )
        }
        Outcome::TimedOut => NameResolution::stopped(),
        Outcome::Overlong => {
            tracing::warn!(
                target: "tessera.role",
                max_bytes = MAX_ANSWER_BYTES,
                "name resolution wrote more than an answer can be; \
                 the local account database decides on its own"
            );
            NameResolution::silent()
        }
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
    /// The program ran to its end — it closed the answer pipe — but no status
    /// was left for this code to collect.
    ///
    /// The ordinary cause is a host process that has set `SIGCHLD` to
    /// `SIG_IGN`: the kernel then reaps children by itself, and the wait that
    /// would have read the status returns `ECHILD` instead. The other is a
    /// bound that ran out in the moment between the child's `_exit` and its
    /// status becoming collectable. Neither says anything about the run: the
    /// answer already in hand is the answer.
    EndedWithoutStatus,
    /// The bound ran out; the child was killed and reaped.
    TimedOut,
    /// More was written than an answer can be; the child was killed and reaped.
    Overlong,
    /// The program could not be started, or ended in a way that leaves the
    /// answer untrustworthy.
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
/// Output is read *while* the child runs, never after it. A pipe holds 64 KiB
/// on Linux, and one `passwd` record per name in a full role base is of that
/// order: a parent that waited for the child before reading would deadlock
/// against a child blocked writing into a pipe nobody is emptying, every time,
/// on exactly the devices with the largest role bases. Reading therefore ends at
/// end-of-file on the pipe, the collected bytes themselves say whether the
/// answer is whole, and the child's status only refines that.
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
            supervise(child, &answer_read, timeout)
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

/// Read what `child` writes as it writes it, up to `timeout`, and establish how
/// it ended.
///
/// The pipe is emptied as the child fills it, so a child writing more than the
/// pipe buffer holds keeps making progress instead of stalling against a parent
/// that is not reading yet. The waiting happens in `poll` against what is left
/// of the bound rather than inside `read`, so every idle moment is one the
/// deadline is checked in. End-of-file is what stops the collecting — the child
/// has either `execve`d and exited or died, and in both cases it is the closing
/// of its last descriptor that lets the read return zero. What was collected by
/// then is a whole answer only if it ends on a record boundary; a resolver that
/// closed its output mid-record, or a read that failed mid-answer, leaves bytes
/// that parse as cleanly as a complete answer and silently lack entries, so they
/// are discarded instead.
///
/// Exhausting the bound kills the child and reaps it. That is the whole point
/// of running the lookup elsewhere: the request stops, rather than being left
/// to finish in a library the caller may already have unloaded. Where the bound
/// runs out decides what the run is worth: before the answer is whole there is
/// nothing to keep, while after it only the status is missing.
fn supervise(child: Pid, answer: &OwnedFd, timeout: Duration) -> Run {
    supervise_with(child, answer, timeout, set_nonblocking)
}

/// [`supervise`] against a named way of unblocking the pipe, so the one failure
/// that would leave the read unbounded can be exercised.
fn supervise_with(
    child: Pid,
    answer: &OwnedFd,
    timeout: Duration,
    unblock: fn(&OwnedFd) -> nix::Result<()>,
) -> Run {
    let deadline = Instant::now() + timeout;
    // The whole bound rests on this call. `fill` reports "nothing yet" from
    // `EAGAIN` and from nothing else, and a blocking descriptor never produces
    // one: the parent would sit inside `read` until a writer speaks or every
    // writer closes, and the deadline below would never be looked at. A
    // descendant that inherited the write end could then park the login path
    // for as long as it cared to. So a pipe that could not be unblocked is not
    // read at all.
    if let Err(error) = unblock(answer) {
        tracing::warn!(
            target: "tessera.role",
            error = %error,
            "the answer pipe cannot be given a bound; \
             the local account database decides on its own"
        );
        kill_and_reap(child);
        return Run::unstartable();
    }

    let mut collected: Vec<u8> = Vec::new();
    loop {
        match fill(answer, &mut collected) {
            Filling::Ended => break,
            Filling::Overlong => {
                // Past the cap it is not an answer any more, and guessing at a
                // truncated one on an authentication path is worse than having
                // none.
                kill_and_reap(child);
                return Run {
                    stdout: Vec::new(),
                    outcome: Outcome::Overlong,
                };
            }
            Filling::Waiting => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    kill_and_reap(child);
                    return Run {
                        stdout: Vec::new(),
                        outcome: Outcome::TimedOut,
                    };
                }
                wait_readable(answer, left);
            }
        }
    }

    if !is_complete(&collected) {
        // Collecting stopped in the middle of a record: either the read failed
        // or the resolver closed its output before it had written everything.
        // The bytes in hand cannot be told apart from a whole answer once they
        // are parsed — a name missing from them reads as "no such account",
        // which is exactly the refusal this source was added to find. So the
        // run is treated as a source that did not answer.
        kill_and_reap(child);
        return Run {
            stdout: Vec::new(),
            outcome: Outcome::Unstartable,
        };
    }

    Run {
        outcome: collect_status(child, deadline),
        stdout: collected,
    }
}

/// Whether the collected bytes are a whole answer rather than the front of one.
///
/// `getent passwd` prints whole lines and nothing else, so an answer that ends
/// on a record terminator has no record half-written in it. Nothing collected
/// at all is complete too: that is what "none of these names is known" looks
/// like, and it is the ordinary answer for a role base of names the directory
/// does not serve.
fn is_complete(collected: &[u8]) -> bool {
    match collected.last() {
        None => true,
        Some(last) => *last == RECORD_TERMINATOR,
    }
}

/// Put the read end into non-blocking mode, through an interruption.
///
/// An interrupted `fcntl` has changed nothing, so the only way to know the
/// descriptor is unblocked is to ask again; every other failure is reported,
/// because the caller's bound cannot be enforced without it.
fn set_nonblocking(answer: &OwnedFd) -> nix::Result<()> {
    loop {
        match nix::fcntl::fcntl(
            answer,
            nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
        ) {
            Ok(_) => return Ok(()),
            Err(Errno::EINTR) => {}
            Err(error) => return Err(error),
        }
    }
}

/// What one attempt at emptying the pipe found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Filling {
    /// Nothing more is coming: every writer has closed its end.
    Ended,
    /// The pipe is empty for now and a writer is still holding it open.
    Waiting,
    /// More has arrived than an answer can be.
    Overlong,
}

/// Move whatever is in the pipe right now into `collected`.
fn fill(answer: &OwnedFd, collected: &mut Vec<u8>) -> Filling {
    let mut buffer = [0_u8; 4096];
    loop {
        match nix::unistd::read(answer, &mut buffer) {
            Ok(0) => return Filling::Ended,
            Ok(read) => {
                collected.extend_from_slice(buffer.get(..read).unwrap_or_default());
                if collected.len() > MAX_ANSWER_BYTES {
                    return Filling::Overlong;
                }
            }
            Err(Errno::EINTR) => {}
            Err(Errno::EAGAIN) => return Filling::Waiting,
            // Any other error on the read end is not something a further read
            // would recover from, so collecting stops here. Whether what was
            // collected is a whole answer or the front of one is not this
            // function's to say: the caller decides that from the bytes.
            Err(_) => return Filling::Ended,
        }
    }
}

/// Block until the pipe has something to say, or `budget` runs out.
///
/// An interrupted or failed wait is not distinguished from a timely one: the
/// caller re-reads either way, and the bound is enforced by the deadline it
/// keeps, not by this call.
fn wait_readable(answer: &OwnedFd, budget: Duration) {
    let mut watched = [PollFd::new(answer.as_fd(), PollFlags::POLLIN)];
    let budget = PollTimeout::try_from(budget).unwrap_or_else(|_| POLL_RECHECK_MILLIS.into());
    let _readable = poll(&mut watched, budget);
}

/// Establish how the child that has finished writing ended.
///
/// This runs only once the collected bytes have been found to end on a record
/// boundary, so a whole answer is already in hand and the status can only refine
/// it, never take it away. End-of-file alone would not license that: it says
/// every writer let go, not that the writer was done. What makes the answer
/// complete is the shape of the bytes — see [`is_complete`] — and this function
/// is reached only after that has been established. `ECHILD` is not a failure: a host
/// process with `SIGCHLD` set to `SIG_IGN` has the kernel reap its children, so
/// there is no status left to read and nothing left running either.
///
/// The bound is still enforced — the child is stopped when it runs out — but
/// running out here is not a timeout in the sense the caller acts on: a
/// resolver that streamed a whole answer and closed its pipe has answered, and
/// throwing that away for a status that was a few microseconds late would both
/// discard a complete verdict and quiet the source for its whole cooldown.
fn collect_status(child: Pid, deadline: Instant) -> Outcome {
    loop {
        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => return Outcome::Exited(code),
            Ok(WaitStatus::StillAlive) => {
                // The pipe is closed and the process is not gone yet: normally
                // the last moments between `_exit` and the status being ready.
                if Instant::now() >= deadline {
                    kill_and_reap(child);
                    return Outcome::EndedWithoutStatus;
                }
                std::thread::sleep(CHILD_POLL_INTERVAL);
            }
            Err(Errno::EINTR) => {}
            Err(Errno::ECHILD) => return Outcome::EndedWithoutStatus,
            // A child killed by a signal, or a status this wait was not asking
            // for: the answer cannot be trusted to be whole, so it is not used.
            Ok(_) | Err(_) => return Outcome::Unstartable,
        }
    }
}

/// Stop `child` and collect it, so no process and no zombie outlives the bound.
///
/// `SIGKILL` without a polite stage: the resolver has no state to flush and
/// nothing to clean up, and every millisecond spent here is spent on the login
/// path.
///
/// The wait afterwards polls rather than blocks, and gives up after
/// [`REAP_GRACE`]. A blocking wait would be the shorter code, but on a host
/// that has set `SIGCHLD` to `SIG_IGN` it does not mean "wait for this child":
/// it means "wait until every child of this process has ended", and a greeter
/// with a long-running child of its own would hold the login there for as long
/// as that child lives. A signal that cannot be caught leaves nothing to wait
/// for anyway — the grace is for the moment between the kill and the kernel
/// getting round to it.
fn kill_and_reap(child: Pid) {
    let _signalled = kill(child, Signal::SIGKILL);
    let deadline = Instant::now() + REAP_GRACE;
    loop {
        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                if Instant::now() >= deadline {
                    return;
                }
                std::thread::sleep(CHILD_POLL_INTERVAL);
            }
            Err(Errno::EINTR) => {}
            // Collected — by this wait, or by a kernel reaping for a host that
            // ignores `SIGCHLD` (`ECHILD`). Either way nothing is left behind.
            Ok(_) | Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::missing_docs_in_private_items)]

    use std::fmt::Write as _;

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

    /// A live child and a pipe nothing is ever going to close: the shape in
    /// which a read on a blocking descriptor would never return.
    ///
    /// The write end is handed back so the caller keeps it open; the child is
    /// only there to be waited for and killed.
    #[expect(
        clippy::zombie_processes,
        reason = "the child is collected the way the supervised one is — by \
                  `waitpid` on its pid, which this code under test does"
    )]
    fn unending_pipe_and_child() -> (Pid, OwnedFd, OwnedFd) {
        let sleep = first_existing(&["/bin/sleep", "/usr/bin/sleep"]);
        let child = std::process::Command::new(sleep)
            .arg("30")
            .spawn()
            .expect("a sleep can be started");
        let (read_end, write_end) = cloexec_pipe().expect("a pipe can be made");
        let pid = Pid::from_raw(i32::try_from(child.id()).expect("a pid fits in an i32"));
        (pid, read_end, write_end)
    }

    #[test]
    fn a_pipe_that_cannot_be_bounded_is_never_read() {
        // The bound lives entirely in the non-blocking descriptor: without it
        // the read below would sit there until a writer spoke, and this test
        // would not finish at all. So a refused unblocking must end the run
        // before the first read — as silence, which leaves the local database
        // deciding on its own.
        fn refused(_answer: &OwnedFd) -> nix::Result<()> {
            Err(Errno::EPERM)
        }

        let (child, read_end, _write_end) = unending_pipe_and_child();
        let started = Instant::now();

        let run = supervise_with(child, &read_end, Duration::from_secs(30), refused);

        assert_eq!(run.outcome, Outcome::Unstartable);
        assert!(run.stdout.is_empty(), "nothing was read");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the run must end at the refusal, not on the pipe: {:?}",
            started.elapsed()
        );
        assert_eq!(
            kill(child, None),
            Err(Errno::ESRCH),
            "the child is stopped and collected even though nothing was read"
        );
    }

    #[test]
    fn an_unblocked_pipe_reports_emptiness_instead_of_waiting_on_it() {
        // What the flag buys, stated as the property the deadline depends on:
        // an empty pipe with a writer still holding it open answers at once.
        let (child, read_end, _write_end) = unending_pipe_and_child();

        set_nonblocking(&read_end).expect("a pipe read end can be unblocked");

        let mut collected = Vec::new();
        assert_eq!(fill(&read_end, &mut collected), Filling::Waiting);
        assert!(collected.is_empty());
        kill_and_reap(child);
    }

    #[test]
    fn an_answer_complete_at_the_deadline_is_kept() {
        // The child wrote everything and closed the pipe; only its status was
        // not ready before the bound ran out. The answer is complete, so it
        // stands — and the source is not quieted, because it did answer.
        let (child, _read_end, _write_end) = unending_pipe_and_child();

        let outcome = collect_status(child, Instant::now());

        assert_eq!(
            outcome,
            Outcome::EndedWithoutStatus,
            "a status that came too late is not a lost answer"
        );
        assert_eq!(
            kill(child, None),
            Err(Errno::ESRCH),
            "the bound still ends the process, whatever it does to the answer"
        );

        let resolution = interpret(
            &Run {
                stdout: b"serv:x:4000:4000::/home/serv:/bin/sh\n".to_vec(),
                outcome,
            },
            &["serv"],
        );
        assert!(
            !resolution.exhausted_its_bound(),
            "a source that answered must not be quieted for its cooldown"
        );
        assert_eq!(
            resolution.answer_for("serv"),
            super::super::system_account::PasswdLookup::Uid(4000)
        );
    }

    #[test]
    fn an_answer_cut_off_inside_a_record_is_not_an_answer() {
        // The dangerous truncation: the bytes that did arrive parse perfectly
        // well, and every name missing from them would read as "no such
        // account" — the very refusal this source is consulted for. A record
        // boundary is what tells a finished answer from a severed one, so an
        // answer ending anywhere else is the source saying nothing at all.
        let (child, read_end, write_end) = unending_pipe_and_child();
        let severed = b"dyn-service:x:61184:61184::/:/usr/sbin/nologin\nserv:x:4000:40";
        let written = nix::unistd::write(&write_end, severed).expect("the pipe takes the bytes");
        assert_eq!(written, severed.len());
        drop(write_end);

        let run = supervise_with(child, &read_end, Duration::from_secs(30), set_nonblocking);

        assert_eq!(run.outcome, Outcome::Unstartable);
        assert!(
            run.stdout.is_empty(),
            "a severed answer is not half an answer"
        );

        let resolution = interpret(&run, &["dyn-service", "serv"]);
        assert!(
            !resolution.exhausted_its_bound(),
            "a source that could not be read is silent, not exhausted"
        );
        assert_eq!(
            resolution.answer_for("serv"),
            super::super::system_account::PasswdLookup::Unavailable,
            "a name missing from severed bytes must not read as a name that is not there"
        );
        assert_eq!(
            resolution.answer_for("dyn-service"),
            super::super::system_account::PasswdLookup::Unavailable,
            "the records that did arrive are no more trustworthy than the run"
        );
    }

    #[test]
    fn an_empty_answer_is_the_ordinary_none_of_these_names() {
        // Nothing written at all is what a directory serving none of the names
        // looks like; it must not be mistaken for an answer cut short.
        let (child, read_end, write_end) = unending_pipe_and_child();
        drop(write_end);

        let run = supervise_with(child, &read_end, Duration::from_millis(0), set_nonblocking);

        assert_eq!(run.outcome, Outcome::EndedWithoutStatus);
        assert!(run.stdout.is_empty());

        let resolution = interpret(&run, &["serv"]);
        assert!(!resolution.exhausted_its_bound());
        assert_eq!(
            resolution.answer_for("serv"),
            super::super::system_account::PasswdLookup::NoEntry,
            "an answer that mentions no name says the name is not there"
        );
        assert!(is_complete(b""), "nothing collected is nothing missing");
    }

    #[test]
    fn an_answer_whole_at_the_deadline_is_kept_without_quieting_the_source() {
        // The behaviour the record-boundary check must not undo: the resolver
        // wrote everything and closed the pipe, and only its status was late.
        // The answer stands, and the source is not quieted for its cooldown.
        let (child, read_end, write_end) = unending_pipe_and_child();
        let whole = b"serv:x:4000:4000::/home/serv:/bin/sh\n";
        let written = nix::unistd::write(&write_end, whole).expect("the pipe takes the bytes");
        assert_eq!(written, whole.len());
        drop(write_end);

        let run = supervise_with(child, &read_end, Duration::from_millis(0), set_nonblocking);

        assert_eq!(
            run.outcome,
            Outcome::EndedWithoutStatus,
            "a status that came too late is not a lost answer"
        );
        assert_eq!(run.stdout, whole);

        let resolution = interpret(&run, &["serv"]);
        assert!(
            !resolution.exhausted_its_bound(),
            "a source that answered must not be quieted for its cooldown"
        );
        assert_eq!(
            resolution.answer_for("serv"),
            super::super::system_account::PasswdLookup::Uid(4000)
        );
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
    fn a_missing_resolver_is_silence_and_does_not_quiet_the_source() {
        // A device without `getent`, or with one the path check refuses: the
        // source says nothing, and it is not the kind of nothing that quiets
        // the source for a while — no bound was exhausted.
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
        // the one signal that quiets the source until its cooldown is over.
        let stopped = Run {
            stdout: Vec::new(),
            outcome: Outcome::TimedOut,
        };

        let resolution = interpret(&stopped, &["serv"]);

        assert!(
            resolution.exhausted_its_bound(),
            "an exhausted bound is what quiets the source until the cooldown is over"
        );
        assert_eq!(
            resolution.answer_for("serv"),
            super::super::system_account::PasswdLookup::Unavailable
        );
    }

    #[test]
    fn an_answer_larger_than_the_pipe_is_read_whole() {
        // The pipe holds 64 KiB on Linux. A parent that waited for the child
        // before reading would deadlock against a child blocked writing, and
        // the bound would run out on an answer that was ready all along — on
        // exactly the devices with the largest role bases. Two hundred records
        // of a plausible length put the answer well past the buffer.
        let printf = first_existing(&["/usr/bin/printf", "/bin/printf"]);
        let padding = "x".repeat(300);
        let mut answer = String::new();
        for index in 0..250 {
            let _written = writeln!(
                answer,
                "serv{index:03}:x:{uid}:{uid}:{padding}:/home/serv{index:03}:/bin/sh",
                uid = 4000 + index,
            );
        }
        assert!(
            answer.len() > 80 * 1024,
            "the answer must be past a pipe buffer to prove anything: {}",
            answer.len()
        );

        let run = run(&printf, &[&answer], Duration::from_secs(30));

        assert_eq!(
            run.outcome,
            Outcome::Exited(0),
            "a resolver that fills the pipe still ends normally"
        );
        assert_eq!(run.stdout.len(), answer.len(), "the answer is read whole");
        assert_eq!(
            lookup_in_passwd_bytes(&run.stdout, "serv249", &"getent passwd"),
            super::super::system_account::PasswdLookup::Uid(4249),
            "the last record — the one past the pipe buffer — is there"
        );
    }

    #[test]
    fn a_resolver_that_never_stops_writing_is_cut_off_and_says_nothing() {
        // The cap only became reachable once the pipe is emptied while the
        // child runs. Past it the output is not an answer, and a stream with
        // no end must not be allowed to grow the login path's memory.
        let yes = first_existing(&["/usr/bin/yes", "/bin/yes"]);
        let started = Instant::now();

        let run = run(
            &yes,
            &["serv:x:4000:4000::/home/serv:/bin/sh"],
            Duration::from_secs(30),
        );

        assert_eq!(run.outcome, Outcome::Overlong);
        assert!(
            run.stdout.is_empty(),
            "a capped answer is not half an answer"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the cap must end the run long before the bound: {:?}",
            started.elapsed()
        );
    }

    /// The `SIGCHLD`-ignoring scenario itself; the test below runs it.
    ///
    /// It is `#[ignore]`d because the disposition it changes is the whole
    /// process's, and the rest of this suite spawns children in parallel.
    #[test]
    #[ignore = "changes the process-wide SIGCHLD disposition; run in a process of its own"]
    fn a_reaping_host_keeps_the_answer_inner() {
        use nix::sys::signal::{signal, SigHandler};

        // SAFETY: this process was started by the test below for this scenario
        // alone, so nothing else here depends on how children are collected.
        #[allow(unsafe_code)]
        unsafe { signal(Signal::SIGCHLD, SigHandler::SigIgn) }.expect("SIGCHLD can be ignored");

        let printf = first_existing(&["/usr/bin/printf", "/bin/printf"]);
        let run = run(
            &printf,
            &["serv:x:4000:4000::/home/serv:/bin/sh\n"],
            Duration::from_secs(30),
        );

        assert_ne!(
            run.outcome,
            Outcome::Unstartable,
            "a host that reaps its own children has not broken the resolver"
        );
        assert_eq!(
            lookup_in_passwd_bytes(&run.stdout, "serv", &"getent passwd"),
            super::super::system_account::PasswdLookup::Uid(4000),
            "the answer was written and read; there was simply no status to collect"
        );
    }

    #[test]
    fn a_host_that_reaps_its_own_children_still_gets_the_answer() {
        // `SIGCHLD` set to `SIG_IGN` has the kernel collect children by itself,
        // so the wait returns `ECHILD` for every successful run. Treating that
        // as a failure would throw away a complete answer on every login of
        // every such host, and pay a fork each time for nothing.
        let binary = std::env::current_exe().expect("the test binary knows its own path");
        let inner = std::process::Command::new(binary)
            .args([
                "--exact",
                "role::getent::tests::a_reaping_host_keeps_the_answer_inner",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .output()
            .expect("the test binary can run itself");

        assert!(
            inner.status.success(),
            "{}{}",
            String::from_utf8_lossy(&inner.stdout),
            String::from_utf8_lossy(&inner.stderr)
        );
    }

    #[test]
    fn an_end_without_a_status_is_still_an_answer() {
        // What the scenario above amounts to, stated directly: the child wrote
        // its answer and closed the pipe, and that the status could not be
        // collected says something about the host, not about the answer.
        let reaped = Run {
            stdout: b"dyn-service:x:61184:61184::/:/usr/sbin/nologin\n".to_vec(),
            outcome: Outcome::EndedWithoutStatus,
        };

        let resolution = interpret(&reaped, &["dyn-service"]);

        assert!(!resolution.exhausted_its_bound());
        assert_eq!(
            resolution.answer_for("dyn-service"),
            super::super::system_account::PasswdLookup::Uid(61184)
        );
    }

    #[test]
    fn only_names_that_could_be_roles_are_asked_about() {
        // A name is a file stem, and nothing has checked it against the
        // role-id grammar by the time it gets here. One outside the grammar
        // can never be a role, so leaving it out costs nothing — and what is
        // not on the command line cannot be read as an option.
        let asked = askable(&[
            "serv",
            "--service=evil",
            "-s",
            "--help",
            "ROOT",
            "with space",
            "toolongtobearoleid",
        ])
        .expect("one askable name remains");

        assert_eq!(asked, vec!["serv"]);
        assert!(
            askable(&["--service=evil"]).is_none(),
            "a run with nothing askable left is not worth a process"
        );
    }

    #[test]
    fn every_name_is_passed_after_the_end_of_options_marker() {
        // `getent` parses options wherever they appear, so the marker is what
        // makes a key a key.
        assert_eq!(
            command_line(&["serv", "oper"]),
            vec!["passwd", "--", "serv", "oper"]
        );
    }

    #[test]
    fn a_hostile_name_reaches_the_resolver_as_nothing_at_all() {
        // End to end: the run happens for the name that could be a role, and
        // the one that could not is a name the source says nothing about.
        let echo = first_existing(&["/bin/echo", "/usr/bin/echo"]);

        let resolution = resolve_with(&echo, &["--service=evil", "serv"], Duration::from_secs(30));

        assert!(!resolution.exhausted_its_bound());
        assert_eq!(
            resolution.answer_for("--service=evil"),
            super::super::system_account::PasswdLookup::Unavailable
        );
    }

    #[test]
    fn a_base_past_the_cap_is_not_asked_about_at_all() {
        // Every name is a word on a command line, and an argument list past
        // the kernel's limit fails inside the child, where the only thing it
        // can turn into is silence indistinguishable from a broken resolver.
        let names: Vec<String> = (0..=MAX_NAMES_PER_RUN)
            .map(|index| format!("role{index:04}"))
            .collect();
        let borrowed: Vec<&str> = names.iter().map(String::as_str).collect();

        assert!(askable(&borrowed).is_none());
        assert!(
            askable(
                borrowed
                    .get(..MAX_NAMES_PER_RUN)
                    .expect("the list is longer than the cap")
            )
            .is_some(),
            "a base at the cap is still asked about"
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
