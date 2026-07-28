//! The boundary between system accounts and accounts that may act as roles.
//!
//! A role name is a login account name (`ssh serv@device`), so the role
//! namespace and the Unix account namespace are the same namespace. `root`,
//! `daemon`, `bin`, `sys`, `mail` and `nobody` all satisfy the role-id grammar
//! `^[a-z][a-z0-9-]{0,15}$`, which makes a stray `root.toml` in the role store
//! — a provisioning typo, or a copied sample — enough to turn `ssh root@device`
//! into an ordinary role login.
//!
//! The rejection is keyed on the **uid the account has on this device**, not on
//! a list of reserved names: the danger is not the name but the fact that an
//! account with somebody else's privileges already exists under it. A name list
//! would encode a guess about which names those are, drift from the
//! distribution, and reject legitimate roles (`mail` is a system account on
//! Debian and a sensible role name at the same time).
//!
//! The uid range a role may occupy is bounded at **both** ends
//! ([`FIRST_REGULAR_UID`]`..=`[`LAST_REGULAR_UID`]). Distributions reserve the
//! top of the uid space as thoroughly as the bottom — `nobody` and systemd's
//! `DynamicUser=` accounts live there — and a session under one of those would
//! hand the role's groups and sudo rights to an identity daemons already share.
//!
//! Two call sites share this module: the PAM login path (refuse the login) and
//! the role-store loader (refuse the slice, so the operator sees the
//! provisioning mistake before an engineer trips over it).
//!
//! Two sources answer the question, and they fail by **different** rules:
//!
//! - the local account database ([`LOCAL_PASSWD_PATH`]), read and parsed here,
//!   is **mandatory**. Not being able to read it is a refusal: there is nothing
//!   left to prove the account is not the system's own;
//! - name resolution through NSS is **additive**. When it answers with a uid
//!   outside the regular range the login is refused; when it does not answer,
//!   is unreachable or does not know the name, the verdict is whatever the
//!   local file made it. Refusing because of NSS silence is forbidden.
//!
//! The asymmetry is the point. This check runs before any credential is
//! presented, so a source allowed to close a login by being unreachable would
//! let an LDAP outage lock every session on the device, including the emergency
//! console one — in a product sold on authenticating without a network. Yet the
//! local file alone is not enough either: systemd synthesises `DynamicUser=`
//! accounts through `nss-systemd` and writes nothing to `/etc/passwd`, so the
//! file answers "no such account" for exactly the uids from 61184 upwards the
//! upper boundary exists to refuse, while the session the system would open
//! runs under that system uid.
//!
//! Silence being harmless to the verdict does not make it free: the additive
//! source is asked on every login attempt, before any credential is presented,
//! and an unanswering directory would otherwise hold the attempt for as long as
//! the resolver's own timeouts run. So the additive source is bounded in time
//! ([`SystemAccounts::device`] takes the bound, `[roles].account_lookup_timeout_seconds`
//! sets it), and exhausting the bound is silence, not a refusal — the emergency
//! console login must stay as fast as it is on a healthy device.
//!
//! The bound is enforceable only because the question is put to a separate
//! process ([`super::getent`]): a lookup running inside this library could be
//! stopped waiting for, but not stopped, and unfinished work in a PAM module
//! outlives the unloading of that module. Exhausting the bound therefore ends
//! the child rather than abandoning it.
//!
//! An exhausted bound also quiets the additive source for a while
//! ([`NAME_RESOLUTION_COOLDOWN`]), so a directory that has stopped answering is
//! waited out once rather than once per attempt. The quiet expires on its own:
//! in a resident greeter the process outlives many logins, and a source shut
//! for good there would turn one transient failure into a device that never
//! sees a `DynamicUser=` account again.
//!
//! Both sources are asked **once per set of names** ([`SystemAccounts::snapshot`]).
//! The role-store loader runs on every login and holds up to a few hundred
//! slices; reading the local file — let alone spawning a resolver — per slice
//! would multiply the cost of a login by the size of the base.

use std::path::Path;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Lowest uid a regular account can have; anything below it belongs to the
/// system.
///
/// 1000 is `UID_MIN` from `/etc/login.defs` on Debian, Ubuntu and Astra Linux,
/// the distributions this product targets: accounts a distribution or a package
/// creates for its own use land below it, accounts created for people or for
/// Tessera roles land at or above it. Census provisions role accounts from a
/// declared `uid_range` inside the regular range, so the boundary does not cut
/// off correctly provisioned roles.
///
/// The value is compiled in rather than parsed from `/etc/login.defs` at
/// authentication time: a login-time dependency on that file would let a local
/// edit of `UID_MIN` widen the gate, and would put a file parser on the
/// authentication path for a number that has not moved on any supported
/// distribution.
pub const FIRST_REGULAR_UID: u32 = 1000;

/// Highest uid a regular account can have; everything above it is reserved for
/// the system.
///
/// The whole block from 61184 (`0xEF00`) upwards is handed to services, never
/// to people:
///
/// - 61184–65519 is the range systemd allocates for `DynamicUser=`, so any
///   unit with that setting may be running under one of these uids right now;
/// - 65520–65533 systemd documents as reserved and leaves unallocated;
/// - 65534 is `nobody` — the identity unprivileged, unmapped and sandboxed work
///   is dropped into, shared by many daemons and by NFS id-squashing;
/// - 65535 is `nogroup` and the value libc APIs return for "no such / invalid
///   uid"; together with 65534 it is −1 and −2 in the 16-bit representation uids
///   grew out of, which is why they are reserved everywhere.
///
/// The range is closed at the top because `nobody` and a `DynamicUser` service
/// account are system accounts by every meaning this module uses, yet they sit
/// far above `UID_MIN`. A session opened under one of them would carry the
/// role's groups and sudo rights into an identity that daemons already share.
///
/// One boundary is drawn instead of listing the individual reserved uids: an
/// enumeration would have to be kept in step with systemd, and there is nothing
/// above 61184 a role account should ever be given. `/etc/login.defs` has a
/// `UID_MAX` too (60000 on Debian), but it only bounds what `useradd` allocates
/// by itself — a role provisioned above it must still be able to log in, so it
/// is not the boundary used here.
pub const LAST_REGULAR_UID: u32 = 61183;

/// The local account database every supported distribution keeps.
///
/// A constant rather than configuration: the file's location is fixed by the
/// C library on every system this product runs on, and a setting would only add
/// a way to point the check at a file an attacker controls.
pub const LOCAL_PASSWD_PATH: &str = "/etc/passwd";

/// Largest local account database this module will read.
///
/// A plausible `/etc/passwd` runs to tens of kilobytes; 8 MiB is beyond a
/// hundred thousand accounts. The cap exists so that a truncated disk, a
/// mangled file or a mount pointing somewhere unexpected cannot make the login
/// path allocate without bound. A file over the cap is not parsed at all — it
/// is not a plausible account database, and guessing at its contents on an
/// authentication path is worse than refusing to answer.
const MAX_PASSWD_BYTES: u64 = 8 * 1024 * 1024;

/// How long the additive source may take before it counts as silent.
///
/// Ten seconds is longer than a healthy directory ever needs and short enough
/// that an operator at an unresponsive console does not read the delay as a
/// dead device. The value is a default rather than a constant because the
/// directory a fleet runs against is not this product's to predict.
pub const DEFAULT_ACCOUNT_LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Longest bound configuration may set for the additive source.
///
/// The bound sits on the login path, ahead of the credential, so waiting past a
/// minute buys an answer nobody is still there to receive. Rejecting larger
/// values at load keeps a mistyped setting from turning into a login that looks
/// hung.
pub const MAX_ACCOUNT_LOOKUP_TIMEOUT: Duration = Duration::from_mins(1);

/// How long the additive source is left alone after it failed to answer inside
/// its bound.
///
/// A directory that did not answer in the time it was given will not answer any
/// faster to the next question, and that time is paid on every login attempt,
/// before any credential is presented. A run of attempts during an outage would
/// otherwise pay the full bound each time.
///
/// The suppression expires rather than lasting, because the process asking is
/// not always short-lived. `sshd`, `login` and `su` are gone by the next login,
/// but a graphical greeter is resident for as long as the device is on: a
/// permanent switch there would let one transient failure — a directory not yet
/// up after a reboot — close the additive source until the daemon is
/// restarted, and with it the only source that sees a `DynamicUser=` account.
///
/// Five minutes is the trade: long enough that a burst of attempts against a
/// dead directory costs one wait rather than one per attempt, short enough that
/// a directory coming back is consulted again while the same operator is still
/// standing at the device.
const NAME_RESOLUTION_COOLDOWN: Duration = Duration::from_mins(5);

/// When the additive source may be consulted again after an exhausted bound.
///
/// A [`Mutex`] rather than an atomic: what has to be stored is a point in time,
/// and there is no contention worth avoiding — the cell is touched once per
/// snapshot, on a path that has just spent milliseconds reading a file or
/// seconds waiting for a directory.
static NAME_RESOLUTION_SUPPRESSED: Suppression = Suppression::new();

/// What one account source says about a login name.
///
/// The same three answers describe both sources; what differs is what
/// [`AccountSnapshot::check`] does with [`Self::Unavailable`], which is a
/// refusal from the local database and mere silence from the name service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswdLookup {
    /// The account exists and carries this uid.
    Uid(u32),
    /// The source has no entry for the name.
    NoEntry,
    /// The source could not be consulted, or the entry it holds for the name is
    /// unusable (missing, non-numeric or out-of-range uid). The account's class
    /// stays unknown to this source.
    Unavailable,
}

/// Why an account name cannot be used as a role.
///
/// The message never mentions the role store: whether a slice with this name
/// exists is exactly the fact the login path must not leak (an early
/// store-existence check was rejected for being such an oracle). The account
/// name and its uid are public through `getent passwd`, so naming them tells an
/// attacker nothing they could not read themselves.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SystemAccountError {
    /// The account exists on this device with a uid outside
    /// [`FIRST_REGULAR_UID`]`..=`[`LAST_REGULAR_UID`] — below the boundary the
    /// distribution reserves for its own accounts, or inside the block reserved
    /// at the top of the uid space.
    #[error(
        "account `{account}` is a system account on this device \
         (uid {uid}, outside the regular uid range {first_regular}..={last_regular}) \
         and cannot be a role"
    )]
    SystemAccount {
        /// The login account name.
        account: String,
        /// The uid the account carries on this device.
        uid: u32,
        /// Lower end of the applied range ([`FIRST_REGULAR_UID`]).
        first_regular: u32,
        /// Upper end of the applied range ([`LAST_REGULAR_UID`]).
        last_regular: u32,
    },

    /// The local account database could not be read, or holds an entry for
    /// this name that has no usable uid, so the account could not be cleared.
    /// Fail-closed: an unknown class is refused, not assumed regular.
    #[error("cannot establish whether `{account}` is a system account: account lookup failed")]
    LookupFailed {
        /// The login account name.
        account: String,
    },
}

/// Where the mandatory source's answers come from.
///
/// The production variant hands over the *whole* database, because that is how
/// it is consulted: read once per snapshot, then looked into per name. A
/// per-name function could not express that, which is why the two shapes are
/// separate variants rather than one signature. Both stay [`Copy`] and
/// const-constructible, so [`SystemAccounts`] keeps both properties too.
#[derive(Debug, Clone, Copy)]
enum LocalSource {
    /// The whole account database in `passwd(5)` format, or `None` when it
    /// could not be read.
    Database(fn() -> Option<Vec<u8>>),
    /// A per-name answer supplied by the caller, for callers with no device
    /// database to consult.
    Answers(fn(&str) -> PasswdLookup),
}

/// Where the additive source's answers come from.
#[derive(Debug, Clone, Copy)]
enum NameSource {
    /// Resolution through NSS, run outside this process and bounded in time.
    Resolver,
    /// A per-name answer supplied by the caller.
    Answers(fn(&str, Duration) -> PasswdLookup),
}

/// This device's account view, used to tell system accounts from accounts that
/// may act as roles.
///
/// The type stays [`Copy`] and free of lifetimes so it can be threaded through
/// the store loader and the flow without a wrapper in any public signature.
/// [`SystemAccounts::device`] is the production view; the other constructors
/// exist for callers that have no device account database to consult (offline
/// linting) and for tests, which must not depend on the passwd file or the name
/// service of the machine running them.
///
/// The bound on the additive source travels in the same struct, as a
/// [`Duration`], so configuration reaches the lookup without the type growing a
/// generic parameter or a borrow.
#[derive(Debug, Clone, Copy)]
pub struct SystemAccounts {
    /// The mandatory source: the local account database.
    local: LocalSource,
    /// The additive source: name resolution through NSS.
    names: NameSource,
    /// How long the additive source may take before it counts as silent.
    nss_timeout: Duration,
}

impl Default for SystemAccounts {
    fn default() -> Self {
        Self::device(DEFAULT_ACCOUNT_LOOKUP_TIMEOUT)
    }
}

impl SystemAccounts {
    /// The device's own accounts: the local database ([`LOCAL_PASSWD_PATH`])
    /// plus name resolution through NSS, bounded by `nss_timeout`.
    ///
    /// Exhausting `nss_timeout` leaves the verdict where the local database put
    /// it — the bound shortens the login, it never closes one.
    #[must_use]
    pub const fn device(nss_timeout: Duration) -> Self {
        Self {
            local: LocalSource::Database(read_local_database),
            names: NameSource::Resolver,
            nss_timeout,
        }
    }

    /// A view whose local database is whatever `database` returns, read once
    /// per snapshot, and whose name service stays silent.
    ///
    /// For callers that hold a `passwd(5)` database elsewhere than the device's
    /// own file, and for tests that have to show the database is read once for
    /// a whole set of names rather than once per name.
    #[must_use]
    pub const fn with_database(database: fn() -> Option<Vec<u8>>) -> Self {
        Self {
            local: LocalSource::Database(database),
            names: NameSource::Answers(no_such_account_resolved),
            nss_timeout: DEFAULT_ACCOUNT_LOOKUP_TIMEOUT,
        }
    }

    /// A view in which no account exists, so every name is cleared.
    ///
    /// For callers whose machine says nothing about the device the base is
    /// meant for — `role lint` / `role list` run anywhere but on that device,
    /// and tests, whose verdicts must not depend on the machine running them.
    /// Clearing every name is the honest answer there: an unrelated account
    /// database can neither convict a slice nor acquit it, and the on-device
    /// load path checks again with the device's own view.
    ///
    /// Both sources are off, the name service included: leaving it on would
    /// make the answer depend on the directory the running machine is joined
    /// to, which is the very thing this constructor exists to avoid.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            local: LocalSource::Answers(no_such_account),
            names: NameSource::Answers(no_such_account_resolved),
            nss_timeout: DEFAULT_ACCOUNT_LOOKUP_TIMEOUT,
        }
    }

    /// A view whose local database is `lookup` and whose name service stays
    /// silent.
    ///
    /// The silent name service is what makes this constructor usable in tests:
    /// the fixture decides the whole verdict, on a machine whose own directory
    /// would otherwise resolve `root` and every other name it serves.
    #[must_use]
    pub const fn with_lookup(lookup: fn(&str) -> PasswdLookup) -> Self {
        Self {
            local: LocalSource::Answers(lookup),
            names: NameSource::Answers(no_such_account_resolved),
            nss_timeout: DEFAULT_ACCOUNT_LOOKUP_TIMEOUT,
        }
    }

    /// A view backed by both sources explicitly, for exercising the rules that
    /// differ between them.
    ///
    /// The additive source is handed the bound as its second argument, the
    /// same way the real one receives it.
    #[must_use]
    pub const fn with_sources(
        passwd: fn(&str) -> PasswdLookup,
        nss: fn(&str, Duration) -> PasswdLookup,
    ) -> Self {
        Self {
            local: LocalSource::Answers(passwd),
            names: NameSource::Answers(nss),
            nss_timeout: DEFAULT_ACCOUNT_LOOKUP_TIMEOUT,
        }
    }

    /// The same view with a different bound on the additive source.
    #[must_use]
    pub const fn with_nss_timeout(self, nss_timeout: Duration) -> Self {
        Self {
            local: self.local,
            names: self.names,
            nss_timeout,
        }
    }

    /// The bound this view puts on the additive source.
    ///
    /// Exposed so a caller that has to answer the same question as the login
    /// path can show it is doing so under the same bound: only an answer that
    /// arrives inside the bound can add a refusal, so two runs with different
    /// bounds may reach different verdicts about one name.
    #[must_use]
    pub const fn name_lookup_bound(&self) -> Duration {
        self.nss_timeout
    }

    /// Ask both sources about `accounts`, once, and keep what they said.
    ///
    /// This is the entry point for a caller with several names to judge — the
    /// role-store loader, `role lint`. The local database is read a single
    /// time and the name service is run a single time, so the cost of the
    /// check does not grow with the size of the role base.
    ///
    /// The additive source is only asked about the names the local database
    /// left open: a name it already refuses is settled, and a database it
    /// could not read refuses every name on its own.
    #[must_use]
    pub fn snapshot(&self, accounts: &[&str]) -> AccountSnapshot {
        let local = match self.local {
            LocalSource::Database(database) => LocalAccounts::Database(database()),
            LocalSource::Answers(answers) => LocalAccounts::Answers(answers),
        };

        let unsettled: Vec<&str> = accounts
            .iter()
            .copied()
            .filter(|account| local_leaves_open(local.lookup(account)))
            .collect();

        let resolved = if unsettled.is_empty() {
            NameResolution::silent()
        } else {
            match self.names {
                NameSource::Resolver => bounded_resolution(
                    &unsettled,
                    self.nss_timeout,
                    super::getent::resolve,
                    &NAME_RESOLUTION_SUPPRESSED,
                    NAME_RESOLUTION_COOLDOWN,
                ),
                NameSource::Answers(answers) => NameResolution::answered(
                    unsettled
                        .iter()
                        .map(|account| ((*account).to_owned(), answers(account, self.nss_timeout)))
                        .collect(),
                ),
            }
        };

        AccountSnapshot {
            local,
            resolved,
            asked: accounts
                .iter()
                .map(|account| (*account).to_owned())
                .collect(),
        }
    }

    /// Decide whether `account` may be used as a role name on this device.
    ///
    /// A single-name [`Self::snapshot`]; see [`AccountSnapshot::check`] for the
    /// rules the verdict follows.
    ///
    /// # Errors
    ///
    /// [`SystemAccountError::SystemAccount`] when either source places the
    /// account outside [`FIRST_REGULAR_UID`]`..=`[`LAST_REGULAR_UID`],
    /// [`SystemAccountError::LookupFailed`] when the local database could not
    /// be consulted.
    pub fn check(&self, account: &str) -> Result<(), SystemAccountError> {
        self.snapshot(&[account]).check(account)
    }
}

/// What both sources said about a set of names at one moment.
///
/// Held by the caller for as long as it judges that set: the answers were paid
/// for once and are not asked for again per name.
#[derive(Debug, Clone)]
pub struct AccountSnapshot {
    /// The local database as it was when the snapshot was taken.
    local: LocalAccounts,
    /// What name resolution answered about the names still open then.
    resolved: NameResolution,
    /// The names this snapshot was taken for.
    asked: Vec<String>,
}

impl AccountSnapshot {
    /// Whether this snapshot was taken for `account`.
    ///
    /// A caller that has to judge a name has a complete verdict for it only if
    /// the name was in the set: for any other name the mandatory source still
    /// answers in full, but the additive one was never asked, and reusing such
    /// a verdict would silently drop the only source that sees an account no
    /// local file holds.
    #[must_use]
    pub fn covers(&self, account: &str) -> bool {
        self.asked.iter().any(|name| name == account)
    }
    /// Decide whether `account` may be used as a role name on this device.
    ///
    /// An account neither source knows is *not* a system account: it is simply
    /// absent, and the caller's own path (role resolution, login) rejects it
    /// on its own terms. Turning absence into a refusal here would change
    /// observable behaviour where nothing was promised.
    ///
    /// The local database settles the question on its own — both by refusing
    /// and by failing. The name service can then only add a refusal: an
    /// unreachable directory — or one that outran its bound — leaves the
    /// verdict exactly as the file left it, because this runs before any
    /// credential is presented and a login must neither hang nor fail on a
    /// network the product promises not to need.
    ///
    /// A name this snapshot was not taken for is treated as one the name
    /// service said nothing about: the local database still answers in full,
    /// and silence from the additive source can never refuse.
    ///
    /// # Errors
    ///
    /// [`SystemAccountError::SystemAccount`] when either source places the
    /// account outside [`FIRST_REGULAR_UID`]`..=`[`LAST_REGULAR_UID`],
    /// [`SystemAccountError::LookupFailed`] when the local database could not
    /// be consulted.
    pub fn check(&self, account: &str) -> Result<(), SystemAccountError> {
        let local_uid = match self.local.lookup(account) {
            PasswdLookup::Unavailable => {
                return Err(SystemAccountError::LookupFailed {
                    account: account.to_owned(),
                })
            }
            PasswdLookup::Uid(uid) if !is_regular(uid) => return Err(system_account(account, uid)),
            PasswdLookup::Uid(uid) => Some(uid),
            PasswdLookup::NoEntry => None,
        };

        match self.resolved.answer_for(account) {
            PasswdLookup::Uid(uid) if !is_regular(uid) => {
                if let Some(local_uid) = local_uid {
                    // Two databases describe one name differently, and which
                    // of them the rest of the system will use comes down to
                    // the order in `nsswitch.conf`. Guessing that order on the
                    // login path would decide the session's identity by
                    // configuration this code never reads, so the disagreement
                    // itself is the refusal.
                    tracing::warn!(
                        target: "tessera.role",
                        account,
                        local_uid,
                        resolved_uid = uid,
                        "the local account database and name resolution disagree about this \
                         account; refusing because one of them makes it a system account"
                    );
                }
                Err(system_account(account, uid))
            }
            // A uid inside the range adds nothing the file did not already
            // allow, and silence — no entry, no answer, no reachable
            // directory — may never turn into a refusal.
            PasswdLookup::Uid(_) | PasswdLookup::NoEntry | PasswdLookup::Unavailable => Ok(()),
        }
    }
}

/// A device's account view together with the verdicts already reached *under
/// that view*, for a caller that has to judge one name.
///
/// The pairing is the whole point of the type. An [`AccountSnapshot`] carries
/// no trace of the view it was taken with, and a snapshot taken under a view
/// that knows no accounts clears every name — including `root`. Handing such a
/// snapshot to a login that means to judge against the device's real accounts
/// would let the login into an account the system owns, so there is no way to
/// build that pair here: a check either has no snapshot at all
/// ([`Self::from_view`]) or takes both halves from the one place they were
/// paired, the store's own load ([`Self::from_store`]).
///
/// It stays [`Copy`] and borrows the snapshot rather than owning it, so passing
/// it costs no more than passing the view did.
#[derive(Debug, Clone, Copy)]
pub struct AccountCheck<'a> {
    /// The view every name is judged against.
    view: SystemAccounts,
    /// Verdicts this very view already reached, if any.
    settled: Option<&'a AccountSnapshot>,
}

impl<'a> AccountCheck<'a> {
    /// A check that asks `view` about every name afresh.
    ///
    /// For a caller with no load of its own to draw on, and for one whose load
    /// ran against a different view than the one it now means to judge by: the
    /// answers cost a lookup each, and cost nothing in trust.
    #[must_use]
    pub const fn from_view(view: SystemAccounts) -> Self {
        Self {
            view,
            settled: None,
        }
    }

    /// A check that reuses what loading `store` established, under the view
    /// that load ran against.
    ///
    /// Loading a base asks both sources about every slice name — the additive
    /// one by running a process, and on an unanswering directory by waiting out
    /// the whole configured bound. A login into one of those names would
    /// otherwise pay that a second time, and the bound the configuration states
    /// would not be the bound one login costs.
    ///
    /// Both halves come from the store, so they cannot be mismatched: the view
    /// is the one the snapshot was taken with, by construction.
    #[must_use]
    pub fn from_store(store: &'a super::store::RoleStore) -> Self {
        Self {
            view: store.account_view(),
            settled: store.account_snapshot(),
        }
    }

    /// Decide whether `account` may be used as a role name on this device.
    ///
    /// A name the snapshot was taken for is answered from it; any other name is
    /// asked about afresh, because the snapshot's mandatory source would answer
    /// about it but its additive one was never asked — and that is the only
    /// source that sees an account no local file holds.
    ///
    /// # Errors
    ///
    /// The errors of [`AccountSnapshot::check`], which the verdict comes from
    /// either way.
    pub fn check(&self, account: &str) -> Result<(), SystemAccountError> {
        match self.settled {
            Some(snapshot) if snapshot.covers(account) => snapshot.check(account),
            Some(_) | None => self.view.check(account),
        }
    }
}

/// The mandatory source as it stood when a snapshot was taken.
#[derive(Debug, Clone)]
enum LocalAccounts {
    /// The account database read in one go; `None` when it could not be read,
    /// which refuses every name.
    Database(Option<Vec<u8>>),
    /// A per-name answer standing in for a device database.
    Answers(fn(&str) -> PasswdLookup),
}

impl LocalAccounts {
    /// What this source says about one name.
    fn lookup(&self, account: &str) -> PasswdLookup {
        match self {
            Self::Database(Some(contents)) => {
                lookup_in_passwd_bytes(contents, account, &LOCAL_PASSWD_PATH)
            }
            Self::Database(None) => PasswdLookup::Unavailable,
            Self::Answers(answers) => answers(account),
        }
    }
}

/// Read the device's own account database, in full, for one snapshot.
///
/// A failure is `None` rather than an error: the caller turns it into the
/// refusal every name gets when the mandatory source cannot be consulted, and
/// the reason belongs in the log next to the path, not in a per-name verdict.
fn read_local_database() -> Option<Vec<u8>> {
    match read_capped(Path::new(LOCAL_PASSWD_PATH), MAX_PASSWD_BYTES) {
        Ok(contents) => Some(contents),
        Err(error) => {
            tracing::warn!(
                target: "tessera.role",
                path = LOCAL_PASSWD_PATH,
                error = %error,
                "local account database could not be read; \
                 no account can be cleared as non-system"
            );
            None
        }
    }
}

/// Whether the local database's answer still leaves something for the additive
/// source to add.
///
/// A refusal and a failure are both final, and asking a name service about a
/// name that is already settled would put a network round trip — or a process —
/// on the login path for an answer nobody would look at.
const fn local_leaves_open(lookup: PasswdLookup) -> bool {
    match lookup {
        PasswdLookup::Unavailable => false,
        PasswdLookup::Uid(uid) => is_regular(uid),
        PasswdLookup::NoEntry => true,
    }
}

/// What the additive source answered about a set of names, in one pass.
#[derive(Debug, Clone, Default)]
pub(super) struct NameResolution {
    /// One answer per name the source was asked about.
    answers: Vec<(String, PasswdLookup)>,
    /// The source ran out of its bound and was stopped.
    timed_out: bool,
}

impl NameResolution {
    /// The source said nothing at all.
    pub(super) const fn silent() -> Self {
        Self {
            answers: Vec::new(),
            timed_out: false,
        }
    }

    /// The source ran out of its bound and was stopped.
    pub(super) const fn stopped() -> Self {
        Self {
            answers: Vec::new(),
            timed_out: true,
        }
    }

    /// The source answered about these names.
    pub(super) const fn answered(answers: Vec<(String, PasswdLookup)>) -> Self {
        Self {
            answers,
            timed_out: false,
        }
    }

    /// Whether the bound ran out on this run.
    pub(super) const fn exhausted_its_bound(&self) -> bool {
        self.timed_out
    }

    /// What the source said about one name; silence for a name it was never
    /// asked about.
    pub(super) fn answer_for(&self, account: &str) -> PasswdLookup {
        self.answers
            .iter()
            .find(|(name, _)| name == account)
            .map_or(PasswdLookup::Unavailable, |(_, lookup)| *lookup)
    }
}

/// Whether the additive source is currently being left alone, and until when.
///
/// `None` means it is consulted as usual.
#[derive(Debug)]
struct Suppression(Mutex<Option<Instant>>);

impl Suppression {
    /// A source that is being consulted.
    const fn new() -> Self {
        Self(Mutex::new(None))
    }

    /// Whether the source should be skipped at `now`.
    ///
    /// A poisoned lock is read through: the only thing behind it is a
    /// timestamp, a panic cannot have left it half-written, and refusing to
    /// look would either wait out the bound on every login or skip the source
    /// forever — the two failures this cell exists to avoid.
    fn suppressed(&self, now: Instant) -> bool {
        let until = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        until.is_some_and(|until| now < until)
    }

    /// Leave the source alone until `until`.
    fn suppress(&self, until: Instant) {
        let mut cell = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        *cell = Some(until);
    }
}

/// Run `resolve` unless an exhausted bound is still being waited out, and start
/// waiting one out when the bound runs out here.
///
/// `resolve`, the cell and the cooldown are all parameters so every half of
/// that rule can be exercised without a directory and without waiting.
fn bounded_resolution(
    accounts: &[&str],
    timeout: Duration,
    resolve: fn(&[&str], Duration) -> NameResolution,
    suppressed: &Suppression,
    cooldown: Duration,
) -> NameResolution {
    if suppressed.suppressed(Instant::now()) {
        return NameResolution::silent();
    }
    let resolution = resolve(accounts, timeout);
    if resolution.exhausted_its_bound() {
        suppressed.suppress(Instant::now() + cooldown);
        tracing::warn!(
            target: "tessera.role",
            timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
            cooldown_ms = u64::try_from(cooldown.as_millis()).unwrap_or(u64::MAX),
            "name resolution did not answer within its limit and was stopped; the local account \
             database decides on its own, and the source is left alone for the cooldown before \
             it is consulted again"
        );
    }
    resolution
}

/// Whether `uid` belongs to the band a role account may occupy.
const fn is_regular(uid: u32) -> bool {
    FIRST_REGULAR_UID <= uid && uid <= LAST_REGULAR_UID
}

/// The refusal raised for an account that exists outside the regular band.
fn system_account(account: &str, uid: u32) -> SystemAccountError {
    SystemAccountError::SystemAccount {
        account: account.to_owned(),
        uid,
        first_regular: FIRST_REGULAR_UID,
        last_regular: LAST_REGULAR_UID,
    }
}

/// Look `account` up in a `passwd(5)`-format file.
///
/// The path is a parameter so tests can point at a fixture instead of the
/// machine's own database.
#[must_use]
pub fn lookup_in_passwd_file(path: &Path, account: &str) -> PasswdLookup {
    match read_capped(path, MAX_PASSWD_BYTES) {
        Ok(contents) => lookup_in_passwd_bytes(&contents, account, &path.display()),
        Err(error) => {
            tracing::warn!(
                target: "tessera.role",
                path = %path.display(),
                error = %error,
                "local account database could not be read; no account can be cleared as non-system"
            );
            PasswdLookup::Unavailable
        }
    }
}

/// Look `account` up in `passwd(5)`-format text.
///
/// The text is parsed here instead of being resolved through the C library so
/// that the local answer depends on nothing but a local file — see the module
/// docs. The same parser reads the output of the out-of-process resolver, which
/// prints records in exactly this format: two parsers would be two chances for
/// the two sources to disagree about what a record says.
///
/// Parsing follows `passwd(5)`: one record per line, fields separated by `:`,
/// the login name first and the uid third. Lines that cannot be a record are
/// ignored — empty ones, `#` comments, the `+`/`-` NIS compatibility entries,
/// and anything with fewer than the five fields a record has before the
/// optional ones. One line being unusable must not cost the reader the rest of
/// the text, which is why they are skipped rather than fatal.
///
/// A line that *does* name `account` but whose uid is missing, non-numeric or
/// too large is **not** skipped: skipping it would answer "no such account" for
/// an account that plainly exists, which is the one answer that lets the
/// caller through. It ends the search as [`PasswdLookup::Unavailable`], so the
/// caller fails closed.
///
/// The first matching record wins, as it does in the C library: additional
/// records for the same name are shadowed there too, and a check that consulted
/// a later duplicate would judge a login the rest of the system resolves
/// differently.
///
/// `source` names where the text came from, for the one diagnostic this parser
/// emits.
#[must_use]
pub(super) fn lookup_in_passwd_bytes(
    contents: &[u8],
    account: &str,
    source: &dyn std::fmt::Display,
) -> PasswdLookup {
    for line in contents.split(|byte| *byte == b'\n') {
        // Tolerate CRLF: only the trailing carriage return would be part of
        // the last field anyway.
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty()
            || line.starts_with(b"#")
            || line.starts_with(b"+")
            || line.starts_with(b"-")
        {
            continue;
        }
        let mut fields = line.split(|byte| *byte == b':');
        let (Some(name), Some(_password), Some(uid), Some(_gid), Some(_gecos)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        if name != account.as_bytes() {
            continue;
        }
        let Some(uid) = std::str::from_utf8(uid).ok().and_then(|u| u.parse().ok()) else {
            tracing::warn!(
                target: "tessera.role",
                source = %source,
                account,
                "account database has an entry for this account with an unusable uid"
            );
            return PasswdLookup::Unavailable;
        };
        return PasswdLookup::Uid(uid);
    }

    PasswdLookup::NoEntry
}

/// Read at most `max_bytes` from `path`, refusing anything larger.
///
/// The cap is a parameter so the refusal can be exercised without writing a
/// file the size of the production cap.
fn read_capped(path: &Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;

    let file = std::fs::File::open(path)?;
    let mut contents = Vec::new();
    // One byte over the cap is enough to tell "at the cap" from "over it".
    file.take(max_bytes + 1).read_to_end(&mut contents)?;
    if contents.len() as u64 > max_bytes {
        return Err(std::io::Error::other(format!(
            "account database at {} exceeds {max_bytes} bytes",
            path.display()
        )));
    }
    Ok(contents)
}

/// Lookup used by [`SystemAccounts::empty`].
fn no_such_account(_account: &str) -> PasswdLookup {
    PasswdLookup::NoEntry
}

/// The same answer in the shape the additive source is called with.
fn no_such_account_resolved(_account: &str, _timeout: Duration) -> PasswdLookup {
    PasswdLookup::NoEntry
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::missing_docs_in_private_items)]

    use std::sync::atomic::Ordering;

    use super::*;

    /// A passwd view with the accounts a Debian-family device would have:
    /// `root` at 0, a packaged system account, a provisioned role account, and
    /// one account on each side of both boundaries.
    fn fixture() -> SystemAccounts {
        SystemAccounts::with_lookup(|account| match account {
            "root" => PasswdLookup::Uid(0),
            "mail" => PasswdLookup::Uid(8),
            "low-edge" => PasswdLookup::Uid(FIRST_REGULAR_UID - 1),
            "low-first" => PasswdLookup::Uid(FIRST_REGULAR_UID),
            "serv" => PasswdLookup::Uid(4000),
            "high-last" => PasswdLookup::Uid(LAST_REGULAR_UID),
            "dyn-service" => PasswdLookup::Uid(LAST_REGULAR_UID + 1),
            "nobody" => PasswdLookup::Uid(65534),
            "nogroup" => PasswdLookup::Uid(65535),
            "broken" => PasswdLookup::Unavailable,
            _ => PasswdLookup::NoEntry,
        })
    }

    #[test]
    fn root_is_a_system_account() {
        let err = fixture().check("root").expect_err("root must be refused");
        assert!(matches!(
            err,
            SystemAccountError::SystemAccount { uid: 0, .. }
        ));
    }

    #[test]
    fn packaged_system_account_is_refused_even_with_a_role_like_name() {
        // `mail` is a valid role id and a Debian system account at once — the
        // case a static name list would get wrong in both directions.
        assert!(fixture().check("mail").is_err());
    }

    #[test]
    fn the_lower_boundary_is_exact() {
        // 999 belongs to the distribution, 1000 is the first account a person
        // or a role can hold.
        assert!(fixture().check("low-edge").is_err());
        fixture()
            .check("low-first")
            .expect("the first regular uid must pass");
    }

    #[test]
    fn the_upper_boundary_is_exact() {
        // The reserved block starts right above the last regular uid: systemd
        // hands 61184 and up to `DynamicUser=` services.
        fixture()
            .check("high-last")
            .expect("the last regular uid must pass");
        assert!(fixture().check("dyn-service").is_err());
    }

    #[test]
    fn nobody_is_a_system_account_despite_its_high_uid() {
        // 65534 sits far above `UID_MIN`, is shared by daemons and NFS
        // id-squashing, and would otherwise have passed a one-sided check.
        let err = fixture()
            .check("nobody")
            .expect_err("nobody must be refused");
        assert!(matches!(
            err,
            SystemAccountError::SystemAccount { uid: 65534, .. }
        ));
        assert!(fixture().check("nogroup").is_err());
    }

    #[test]
    fn provisioned_role_account_passes() {
        fixture().check("serv").expect("a role account must pass");
    }

    #[test]
    fn absent_account_is_not_a_system_account() {
        // Absence is not a refusal reason: the caller's own path rejects an
        // unknown account, and inventing a new refusal here would change
        // observable behaviour.
        fixture()
            .check("ghost")
            .expect("an absent account must not be refused here");
    }

    #[test]
    fn unavailable_passwd_fails_closed() {
        let err = fixture()
            .check("broken")
            .expect_err("an unusable passwd database must fail closed");
        assert!(matches!(err, SystemAccountError::LookupFailed { .. }));
    }

    #[test]
    fn empty_view_clears_every_name() {
        // `root` resolves on every machine this suite can run on, through the
        // file and through the name service alike — so it passing here is the
        // proof that the empty view really consults neither.
        SystemAccounts::empty()
            .check("root")
            .expect("an empty account view knows no accounts");
    }

    #[test]
    fn a_fixture_view_does_not_consult_the_running_machine() {
        // Same proof for the fixture constructor: the name service of the
        // machine running the tests knows `root`, and its verdict must not
        // reach a view whose fixture says the account is absent.
        SystemAccounts::with_lookup(|_| PasswdLookup::NoEntry)
            .check("root")
            .expect("only the fixture may decide");
    }

    // ---- the two sources ---------------------------------------------------

    #[test]
    fn a_dynamic_user_account_absent_from_the_file_is_refused_through_name_resolution() {
        // The case the file alone gets wrong: systemd allocated the uid, wrote
        // nothing to `/etc/passwd`, and a session under that name would run as
        // the service identity.
        let accounts = SystemAccounts::with_sources(
            |_| PasswdLookup::NoEntry,
            |account, _| match account {
                "dyn-service" => PasswdLookup::Uid(61184),
                _ => PasswdLookup::NoEntry,
            },
        );

        let err = accounts
            .check("dyn-service")
            .expect_err("a DynamicUser account must be refused");
        assert!(matches!(
            err,
            SystemAccountError::SystemAccount { uid: 61184, .. }
        ));
    }

    #[test]
    fn an_unreachable_name_service_does_not_change_the_verdict() {
        // The LDAP-outage case: the check runs before any credential is
        // presented, so a source allowed to refuse by silence would close every
        // login on the device while the outage lasts.
        let unreachable = SystemAccounts::with_sources(
            |account| match account {
                "serv" => PasswdLookup::Uid(4000),
                _ => PasswdLookup::NoEntry,
            },
            |_, _| PasswdLookup::Unavailable,
        );

        unreachable
            .check("serv")
            .expect("a role account the file clears must still pass");
        unreachable
            .check("ghost")
            .expect("a name neither source resolves is not a system account");
    }

    #[test]
    fn a_name_service_that_answers_within_the_range_adds_nothing() {
        let directory_user = SystemAccounts::with_sources(
            |_| PasswdLookup::NoEntry,
            |_, _| PasswdLookup::Uid(20_000),
        );
        directory_user
            .check("ldap-user")
            .expect("a directory account inside the regular range is not a system account");
    }

    #[test]
    fn an_unreadable_file_refuses_even_when_name_resolution_answers() {
        // The file is the mandatory source: with it gone there is nothing left
        // to prove the account is not the system's own, and a name service
        // cannot stand in for it.
        let accounts = SystemAccounts::with_sources(
            |_| PasswdLookup::Unavailable,
            |_, _| PasswdLookup::Uid(4000),
        );

        let err = accounts
            .check("serv")
            .expect_err("an unreadable local database must fail closed");
        assert!(matches!(err, SystemAccountError::LookupFailed { .. }));
    }

    #[test]
    fn sources_that_disagree_about_one_name_refuse() {
        // The file would clear the account and name resolution makes it a
        // system one. Which answer the rest of the system uses depends on the
        // order in `nsswitch.conf`, and a login is not the place to guess it.
        let accounts =
            SystemAccounts::with_sources(|_| PasswdLookup::Uid(4000), |_, _| PasswdLookup::Uid(0));

        let err = accounts
            .check("serv")
            .expect_err("a disagreement about one name must not open a login");
        assert!(matches!(
            err,
            SystemAccountError::SystemAccount { uid: 0, .. }
        ));
    }

    /// How many times [`counted_nss`] was asked, so a test can show that the
    /// name service is not consulted once the local file has decided.
    static NSS_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    /// A name-service source that records every call.
    fn counted_nss(_account: &str, _timeout: Duration) -> PasswdLookup {
        NSS_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        PasswdLookup::NoEntry
    }

    #[test]
    fn the_file_settles_the_question_without_asking_the_name_service() {
        use std::sync::atomic::Ordering::Relaxed;

        let accounts = SystemAccounts::with_sources(
            |account| match account {
                "root" => PasswdLookup::Uid(0),
                "broken" => PasswdLookup::Unavailable,
                _ => PasswdLookup::Uid(4000),
            },
            counted_nss,
        );

        NSS_CALLS.store(0, Relaxed);
        assert!(accounts.check("root").is_err());
        assert!(accounts.check("broken").is_err());
        assert_eq!(
            NSS_CALLS.load(Relaxed),
            0,
            "a refusal the file already reached must not wait on a name service"
        );

        accounts.check("serv").expect("a role account passes");
        assert_eq!(
            NSS_CALLS.load(Relaxed),
            1,
            "an account the file clears still has to be checked for a second identity"
        );
    }

    // ---- one snapshot per set of names --------------------------------------

    /// How many answers the source in [`a_snapshot_asks_each_source_once_for_the_whole_set`]
    /// was asked for. A counter of its own: the suite runs its tests in
    /// parallel, and a shared one would count another test's questions.
    static SET_NSS_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    /// A name-service source for that test alone.
    fn set_counted_nss(_account: &str, _timeout: Duration) -> PasswdLookup {
        SET_NSS_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        PasswdLookup::NoEntry
    }

    #[test]
    fn a_snapshot_asks_each_source_once_for_the_whole_set() {
        use std::sync::atomic::Ordering::Relaxed;

        // A production snapshot reads the file once and looks names up inside
        // the bytes it read; the fixture cannot do that, so what is asserted
        // here is the other half of the same property — that the name service,
        // whose cost is a process, is run once for the set rather than once
        // per name.
        let accounts = SystemAccounts::with_sources(|_| PasswdLookup::NoEntry, set_counted_nss);

        let snapshot = accounts.snapshot(&["oper", "serv", "admin"]);
        for account in ["oper", "serv", "admin"] {
            snapshot
                .check(account)
                .expect("none of these is a system account");
        }

        assert_eq!(
            SET_NSS_CALLS.load(Relaxed),
            3,
            "one answer per name, all of them from a single pass"
        );
    }

    /// The counters for [`a_snapshot_does_not_ask_the_name_service_about_settled_names`].
    static SETTLED_NSS_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    /// How many times that test's local source was consulted.
    static SETTLED_LOCAL_LOOKUPS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    /// A name-service source for that test alone.
    fn settled_counted_nss(_account: &str, _timeout: Duration) -> PasswdLookup {
        SETTLED_NSS_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        PasswdLookup::NoEntry
    }

    /// A local source for that test alone: `root` is the system's, everything
    /// else is a role account.
    fn settled_counted_local(account: &str) -> PasswdLookup {
        SETTLED_LOCAL_LOOKUPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match account {
            "root" => PasswdLookup::Uid(0),
            _ => PasswdLookup::Uid(4000),
        }
    }

    #[test]
    fn a_snapshot_does_not_ask_the_name_service_about_settled_names() {
        use std::sync::atomic::Ordering::Relaxed;

        let accounts = SystemAccounts::with_sources(settled_counted_local, settled_counted_nss);

        let snapshot = accounts.snapshot(&["root", "serv"]);
        assert!(snapshot.check("root").is_err());
        snapshot.check("serv").expect("a role account passes");

        assert_eq!(
            SETTLED_NSS_CALLS.load(Relaxed),
            1,
            "only the name the file left open is worth a resolver run"
        );
        assert!(
            SETTLED_LOCAL_LOOKUPS.load(Relaxed) > 0,
            "the local source is what settles the other name"
        );
    }

    /// How many times the local database was read.
    static DATABASE_READS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    /// A local database in the production shape: handed over whole, once.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "the shape is the account source's: `None` is a database that could not be read"
    )]
    fn counted_database() -> Option<Vec<u8>> {
        DATABASE_READS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(
            b"root:x:0:0:root:/root:/bin/bash\n\
              serv:x:4000:4000::/home/serv:/bin/sh\n\
              oper:x:4001:4001::/home/oper:/bin/sh\n"
                .to_vec(),
        )
    }

    #[test]
    fn the_local_database_is_read_once_for_the_whole_set() {
        use std::sync::atomic::Ordering::Relaxed;

        DATABASE_READS.store(0, Relaxed);
        let accounts = SystemAccounts::with_database(counted_database);

        let snapshot = accounts.snapshot(&["root", "serv", "oper", "ghost"]);
        assert!(snapshot.check("root").is_err());
        snapshot.check("serv").expect("a role account passes");
        snapshot.check("oper").expect("a role account passes");
        snapshot
            .check("ghost")
            .expect("an absent name is not a system account");

        assert_eq!(
            DATABASE_READS.load(Relaxed),
            1,
            "the database is read for the snapshot, not for each name in it"
        );
    }

    #[test]
    fn a_name_outside_the_snapshot_is_still_judged_by_the_local_database() {
        // Silence from the additive source can never refuse, so a name the
        // snapshot was not taken for stays as safe as an unreachable directory
        // makes it — and the local database still answers about it in full.
        let accounts = SystemAccounts::with_sources(
            |account| match account {
                "root" => PasswdLookup::Uid(0),
                _ => PasswdLookup::Uid(4000),
            },
            |_, _| PasswdLookup::Uid(0),
        );

        let snapshot = accounts.snapshot(&["serv"]);

        assert!(
            snapshot.check("root").is_err(),
            "the local database judges every name, asked for or not"
        );
        snapshot
            .check("oper")
            .expect("a name resolution was never asked about cannot be refused by it");
    }

    // ---- the bound on the additive source ----------------------------------

    #[test]
    fn an_answer_inside_the_limit_is_the_one_that_counts() {
        static SUPPRESSED: Suppression = Suppression::new();

        fn prompt_resolver(accounts: &[&str], _timeout: Duration) -> NameResolution {
            NameResolution::answered(
                accounts
                    .iter()
                    .map(|account| ((*account).to_owned(), PasswdLookup::Uid(61184)))
                    .collect(),
            )
        }

        let resolution = bounded_resolution(
            &["dyn-service"],
            Duration::from_secs(10),
            prompt_resolver,
            &SUPPRESSED,
            NAME_RESOLUTION_COOLDOWN,
        );

        assert_eq!(
            resolution.answer_for("dyn-service"),
            PasswdLookup::Uid(61184)
        );
        assert!(
            !SUPPRESSED.suppressed(Instant::now()),
            "an answer in time must not quiet the source"
        );
    }

    /// How many times [`stopped_resolver`] was run.
    static STOPPED_RESOLVER_RUNS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    /// A resolver that reports its bound exhausted — the shape the real one
    /// takes when the child had to be killed.
    fn stopped_resolver(_accounts: &[&str], _timeout: Duration) -> NameResolution {
        STOPPED_RESOLVER_RUNS.fetch_add(1, Ordering::Relaxed);
        NameResolution::stopped()
    }

    /// The cooldown, proven on a resolver whose bound always runs out.
    ///
    /// The exhausted bound must end in silence rather than a refusal, and the
    /// attempts that follow it inside the cooldown must not pay the wait again.
    #[test]
    fn a_name_service_past_the_limit_falls_silent_and_is_left_alone_for_a_while() {
        static SUPPRESSED: Suppression = Suppression::new();

        let first = bounded_resolution(
            &["serv"],
            Duration::from_millis(20),
            stopped_resolver,
            &SUPPRESSED,
            Duration::from_mins(5),
        );
        assert_eq!(
            first.answer_for("serv"),
            PasswdLookup::Unavailable,
            "an exhausted bound says nothing about the name"
        );
        assert!(
            SUPPRESSED.suppressed(Instant::now()),
            "the exhausted limit must quiet the source"
        );
        assert_eq!(STOPPED_RESOLVER_RUNS.load(Ordering::Relaxed), 1);

        let second = bounded_resolution(
            &["serv"],
            Duration::from_millis(20),
            stopped_resolver,
            &SUPPRESSED,
            Duration::from_mins(5),
        );
        assert_eq!(second.answer_for("serv"), PasswdLookup::Unavailable);
        assert_eq!(
            STOPPED_RESOLVER_RUNS.load(Ordering::Relaxed),
            1,
            "inside the cooldown the resolver must not be run again: the directory that did not \
             answer in time will not answer faster to the next login"
        );
    }

    /// How many times [`recovering_resolver`] was run.
    static RECOVERING_RESOLVER_RUNS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    /// A resolver whose bound runs out once and answers afterwards — a
    /// directory that was not up yet when the first login was attempted.
    fn recovering_resolver(accounts: &[&str], _timeout: Duration) -> NameResolution {
        if RECOVERING_RESOLVER_RUNS.fetch_add(1, Ordering::Relaxed) == 0 {
            return NameResolution::stopped();
        }
        NameResolution::answered(
            accounts
                .iter()
                .map(|account| ((*account).to_owned(), PasswdLookup::Uid(61184)))
                .collect(),
        )
    }

    #[test]
    fn the_source_is_consulted_again_once_the_cooldown_is_over() {
        // The half that a permanent switch got wrong. A resident greeter keeps
        // one process across every login of the day: an outage during the first
        // one must not blind the device to `DynamicUser=` accounts until the
        // daemon is restarted. A zero cooldown stands in for one that has run
        // out, so the test does not have to wait for it.
        static SUPPRESSED: Suppression = Suppression::new();

        let first = bounded_resolution(
            &["dyn-service"],
            Duration::from_millis(20),
            recovering_resolver,
            &SUPPRESSED,
            Duration::ZERO,
        );
        assert_eq!(first.answer_for("dyn-service"), PasswdLookup::Unavailable);

        let second = bounded_resolution(
            &["dyn-service"],
            Duration::from_millis(20),
            recovering_resolver,
            &SUPPRESSED,
            Duration::ZERO,
        );
        assert_eq!(
            second.answer_for("dyn-service"),
            PasswdLookup::Uid(61184),
            "a directory that came back must be seen again"
        );
        assert_eq!(RECOVERING_RESOLVER_RUNS.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_quieted_source_leaves_the_local_verdict_alone() {
        // What the cooldown must never do is change the answer: with the source
        // quiet, the file decides — a role account still passes and a system
        // account is still refused.
        static SUPPRESSED: Suppression = Suppression::new();

        fn never_run(_accounts: &[&str], _timeout: Duration) -> NameResolution {
            unreachable!("a quieted source must not be run");
        }

        SUPPRESSED.suppress(Instant::now() + Duration::from_mins(5));
        let resolution = bounded_resolution(
            &["serv"],
            Duration::from_millis(20),
            never_run,
            &SUPPRESSED,
            Duration::from_mins(5),
        );
        assert_eq!(resolution.answer_for("serv"), PasswdLookup::Unavailable);

        let snapshot = AccountSnapshot {
            local: LocalAccounts::Answers(|account| match account {
                "root" => PasswdLookup::Uid(0),
                _ => PasswdLookup::Uid(4000),
            }),
            resolved: resolution,
            asked: vec!["serv".to_owned(), "root".to_owned()],
        };
        snapshot
            .check("serv")
            .expect("a limit that ran out is silence: the local file's verdict stands");
        assert!(snapshot.check("root").is_err());
    }

    // ---- the pairing of a view with its own verdicts ------------------------

    /// A one-slice base on disk, loaded through `view`.
    fn store_loaded_through(view: SystemAccounts) -> (tempfile::TempDir, super::super::RoleStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("serv.toml"),
            b"role = \"serv\"\nversion = 4\nos = \"linux\"\nname = \"serv\"\nlevel = 1\n"
                .as_slice(),
        )
        .expect("write slice");
        let store = super::super::RoleStore::load(
            dir.path(),
            super::super::RoleOs::Linux,
            super::super::TrustMode::Standalone,
            view,
        )
        .expect("the base loads");
        (dir, store)
    }

    #[test]
    fn a_check_judges_by_the_view_its_verdicts_were_reached_under() {
        // The verdicts of a load and the view that load ran against are one
        // thing, and this is why: a base loaded through a view that knows no
        // accounts clears every name, `root` among them. Pairing those verdicts
        // with a device view that refuses `root` would be a login into the
        // system's own account, so both halves come from the same place — the
        // store — and the pair cannot be assembled by hand.
        let (_lenient_dir, lenient) = store_loaded_through(SystemAccounts::empty());
        let (_device_dir, device) = store_loaded_through(fixture());

        AccountCheck::from_store(&lenient)
            .check("root")
            .expect("a view that knows no accounts clears every name, and says so about itself");
        assert!(
            AccountCheck::from_store(&device).check("root").is_err(),
            "a load through the device's own view carries that view's refusal"
        );
        assert!(
            AccountCheck::from_view(fixture()).check("root").is_err(),
            "a view asked afresh refuses it too, whatever any load concluded"
        );
    }

    /// How many times [`counted_names`] was asked.
    static PAIRED_NAME_LOOKUPS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    /// The additive source of the view below, counting its questions.
    fn counted_names(_account: &str, _timeout: Duration) -> PasswdLookup {
        PAIRED_NAME_LOOKUPS.fetch_add(1, Ordering::Relaxed);
        PasswdLookup::NoEntry
    }

    /// Its mandatory half: every name is a regular account, so the additive
    /// source is always worth asking.
    fn open_local(_account: &str) -> PasswdLookup {
        PasswdLookup::NoEntry
    }

    #[test]
    fn a_name_the_load_asked_about_is_not_asked_about_twice() {
        // The other half of the pairing: verdicts travel with the check so a
        // login into a slice name does not pay the additive source's cost — a
        // process, and on an unanswering directory the whole bound — again. A
        // name that load never saw is still asked about in full.
        let view = SystemAccounts::with_sources(open_local, counted_names);
        PAIRED_NAME_LOOKUPS.store(0, Ordering::Relaxed);
        let (_dir, store) = store_loaded_through(view);
        assert_eq!(
            PAIRED_NAME_LOOKUPS.load(Ordering::Relaxed),
            1,
            "the load asks about the one slice name"
        );

        let check = AccountCheck::from_store(&store);
        check.check("serv").expect("a role account passes");
        assert_eq!(
            PAIRED_NAME_LOOKUPS.load(Ordering::Relaxed),
            1,
            "the verdict the load reached is the verdict the check uses"
        );

        check
            .check("oper")
            .expect("an absent account is not refused");
        assert_eq!(
            PAIRED_NAME_LOOKUPS.load(Ordering::Relaxed),
            2,
            "a name the load never saw has to be asked about"
        );
    }

    #[test]
    fn message_says_nothing_about_the_role_store() {
        let message = fixture()
            .check("root")
            .expect_err("root must be refused")
            .to_string();
        assert!(!message.contains("slice"), "{message}");
        assert!(!message.contains("store"), "{message}");
    }

    // ---- the local account database ----------------------------------------

    /// Write a `passwd(5)` fixture and return its path (kept alive by `dir`).
    fn passwd_file(dir: &tempfile::TempDir, contents: &str) -> std::path::PathBuf {
        let path = dir.path().join("passwd");
        std::fs::write(&path, contents.as_bytes()).expect("write passwd fixture");
        path
    }

    #[test]
    fn a_system_account_is_read_out_of_the_local_database_and_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = passwd_file(
            &dir,
            "root:x:0:0:root:/root:/bin/bash\n\
             serv:x:4000:4000:role account:/home/serv:/bin/bash\n",
        );

        assert_eq!(
            lookup_in_passwd_file(&path, "root"),
            PasswdLookup::Uid(0),
            "the uid must come from the file, not from name resolution"
        );
        // ...and uid 0 is what the boundary check refuses.
        assert!(SystemAccounts::with_lookup(|_| PasswdLookup::Uid(0))
            .check("root")
            .is_err());
    }

    #[test]
    fn a_provisioned_role_account_is_found_with_its_uid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = passwd_file(
            &dir,
            "root:x:0:0:root:/root:/bin/bash\n\
             serv:x:4000:4000:role account:/home/serv:/bin/bash\n",
        );

        assert_eq!(
            lookup_in_passwd_file(&path, "serv"),
            PasswdLookup::Uid(4000)
        );
        SystemAccounts::with_lookup(|_| PasswdLookup::Uid(4000))
            .check("serv")
            .expect("a role account must pass");
    }

    #[test]
    fn a_name_absent_from_the_local_database_is_not_an_entry() {
        // Absence is the LDAP case too: an account the directory serves is
        // simply not a system account, and the login proceeds to the checks
        // that do concern it.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = passwd_file(&dir, "root:x:0:0:root:/root:/bin/bash\n");

        assert_eq!(
            lookup_in_passwd_file(&path, "ldap-user"),
            PasswdLookup::NoEntry
        );
        SystemAccounts::with_lookup(|_| PasswdLookup::NoEntry)
            .check("ldap-user")
            .expect("an absent name must not be refused here");
    }

    #[test]
    fn an_unreadable_database_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("no-such-passwd");

        assert_eq!(
            lookup_in_passwd_file(&missing, "serv"),
            PasswdLookup::Unavailable
        );
    }

    #[test]
    fn a_database_over_the_size_cap_is_refused_rather_than_parsed() {
        // A file too large to be an account database is not guessed at on an
        // authentication path; the caller fails closed instead. The cap is
        // exercised at a size a test can write, not at the production one.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = passwd_file(&dir, "serv:x:4000:4000::/home/serv:/bin/bash\n");

        assert!(
            read_capped(&path, 8).is_err(),
            "a file past the cap must not be read"
        );
        read_capped(&path, MAX_PASSWD_BYTES).expect("a plausible database must be read");
    }

    #[test]
    fn unusable_lines_do_not_hide_the_record_that_follows_them() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = passwd_file(
            &dir,
            "\n\
             # a comment, as some distributions ship\n\
             +@admins\n\
             +::::::\n\
             -baduser\n\
             truncated:x:7\n\
             \n\
             root:x:0:0:root:/root:/bin/bash\r\n\
             serv:x:4000:4000::/home/serv:/bin/bash\n",
        );

        assert_eq!(
            lookup_in_passwd_file(&path, "serv"),
            PasswdLookup::Uid(4000)
        );
        // The CRLF line parses too: the stray carriage return only ever lands
        // in the last field.
        assert_eq!(lookup_in_passwd_file(&path, "root"), PasswdLookup::Uid(0));
    }

    #[test]
    fn a_broken_record_for_the_searched_name_fails_closed() {
        // Skipping it would answer "no such account" for an account that
        // plainly exists — the one answer that lets the caller through.
        let dir = tempfile::tempdir().expect("tempdir");
        let non_numeric = passwd_file(&dir, "serv:x:notauid:4000::/home/serv:/bin/sh\n");
        assert_eq!(
            lookup_in_passwd_file(&non_numeric, "serv"),
            PasswdLookup::Unavailable
        );

        let dir2 = tempfile::tempdir().expect("tempdir");
        let too_large = passwd_file(&dir2, "serv:x:4294967296:4000::/home/serv:/bin/sh\n");
        assert_eq!(
            lookup_in_passwd_file(&too_large, "serv"),
            PasswdLookup::Unavailable
        );

        let dir3 = tempfile::tempdir().expect("tempdir");
        let empty_uid = passwd_file(&dir3, "serv:x::4000::/home/serv:/bin/sh\n");
        assert_eq!(
            lookup_in_passwd_file(&empty_uid, "serv"),
            PasswdLookup::Unavailable
        );
    }

    #[test]
    fn the_first_record_for_a_name_is_the_one_that_counts() {
        // The C library resolves a duplicated name to the first record, and a
        // check that used a later one would judge a login by an identity the
        // rest of the system does not give it.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = passwd_file(
            &dir,
            "serv:x:0:0:shadowing entry:/root:/bin/bash\n\
             serv:x:4000:4000::/home/serv:/bin/bash\n",
        );

        assert_eq!(lookup_in_passwd_file(&path, "serv"), PasswdLookup::Uid(0));
    }

    #[test]
    fn a_name_is_matched_whole() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = passwd_file(&dir, "service:x:4000:4000::/home/service:/bin/sh\n");

        assert_eq!(lookup_in_passwd_file(&path, "serv"), PasswdLookup::NoEntry);
        assert_eq!(
            lookup_in_passwd_file(&path, "service"),
            PasswdLookup::Uid(4000)
        );
    }
}
