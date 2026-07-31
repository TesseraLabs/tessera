//! DACL-based trust walk for privileged reads on Windows.
//!
//! The Unix walk asks "who owns this component and which mode bits does it
//! carry". Windows answers the same question through a different object model:
//! an owner SID plus a discretionary ACL of per-SID access masks. Translating
//! the POSIX rules component-by-component would produce a check that looks
//! plausible and enforces nothing, so this module states the policy in Windows
//! terms directly:
//!
//! * Every component of the canonical path — from the volume root to the leaf
//!   inclusive — must be owned by `LocalSystem`, the built-in administrators
//!   group, or `TrustedInstaller`. The last is required rather than tolerated:
//!   on a stock install it owns the volume root.
//! * No *effective* DACL entry may grant the right to *substitute* a component
//!   to anyone other than those same three. An allowing entry for `Users`,
//!   `Authenticated Users`, `Everyone` or a named engineer account is a refusal,
//!   not a warning. Entries flagged `INHERIT_ONLY` are not effective on the
//!   object that carries them and are skipped — see [`check_dacl`].
//! * The path must live on a fixed local volume. A network share or a removable
//!   volume cannot be reasoned about at all: its permissions are asserted by
//!   something outside this machine's control.
//!
//! What counts as substitution depends on the object type, because the same
//! access bits mean different things on a directory and on a file. Deleting or
//! renaming the component, deleting what is inside it, rewriting its DACL or
//! taking its ownership are substitution everywhere; changing or extending
//! content is substitution on a file. Creating a *new* entry in an ancestor
//! directory is not: it neither removes nor alters any component of the path.
//! That distinction is load-bearing rather than pedantic — stock Windows ACLs
//! let `Users` create objects in the volume root and in `%ProgramData%`, so
//! reading the create bits as substitution would refuse every path on every
//! standard system. See [`ObjectKind::substitution_mask`].
//!
//! Everything that prevents the check from reaching a verdict — an unreadable
//! security descriptor, an owner that does not resolve, a NULL DACL (which
//! grants everyone full access), an ACE type whose layout this code cannot
//! parse, a path that will not canonicalize — is a refusal. There is no path
//! through this module that reads a file whose trust was not established.
//!
//! # Known gap
//!
//! Unlike the Unix walk, this one does not close the window between the check
//! and the read: it neither holds an open handle across the verdict nor
//! compares the file id afterwards. Exploiting that window requires the ability
//! to write into a directory whose DACL grants write only to SYSTEM and
//! administrators, i.e. an attacker who is already above the threat model this
//! check defends. Closing it is tracked separately.
//!
//! # FFI
//!
//! All raw Win32 calls live here so the rest of the crate stays under
//! `unsafe_code = "deny"`. Every `unsafe` block wraps exactly one operation and
//! carries the reasoning that makes it sound.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr;

use windows_sys::Win32::Foundation::{
    LocalFree, ERROR_SUCCESS, GENERIC_ALL, GENERIC_WRITE, HLOCAL,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    EqualSid, GetAce, IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetDriveTypeW, GetVolumePathNameW, DELETE, FILE_APPEND_DATA, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DELETE_CHILD, FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
};

use super::PrivilegedPathError;

/// `SDDL_REVISION_1`, the only security-descriptor string revision defined.
#[cfg(test)]
const SDDL_REVISION_1: u32 = 1;

/// `GetDriveTypeW` verdict for a non-removable local volume. Every other
/// verdict — removable, remote, CD-ROM, RAM disk, unknown — is a refusal, so
/// only this one needs a name.
const DRIVE_FIXED: u32 = 3;

/// `MAXIMUM_ALLOWED`: an ACE carrying this bit grants whatever the object
/// allows, which includes write. `windows-sys` does not export it.
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// Access bits that mean substitution regardless of the object's type:
/// deleting or renaming the component itself, rewriting its DACL, or taking its
/// ownership (which confers the first two).
///
/// `GENERIC_ALL` maps to `FILE_ALL_ACCESS`, which carries `DELETE`,
/// `FILE_DELETE_CHILD`, `WRITE_DAC` and `WRITE_OWNER`, so it belongs here for
/// every object type. `MAXIMUM_ALLOWED` asks for whatever the object permits
/// and therefore cannot be bounded from the ACE alone.
const SUBSTITUTION_ANY_KIND: u32 = DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | MAXIMUM_ALLOWED;

/// Additional substitution bits on a directory.
///
/// `FILE_DELETE_CHILD` lets the holder delete or rename the entries inside,
/// which is exactly how a path component below it gets swapped. The create bits
/// (`FILE_ADD_FILE`, `FILE_ADD_SUBDIRECTORY` — the same values as
/// `FILE_WRITE_DATA` and `FILE_APPEND_DATA`) are deliberately absent: a new
/// sibling next to `config.toml` is not `config.toml`.
///
/// `GENERIC_WRITE` is absent for the same reason, and by expansion rather than
/// by analogy with the file case: on a file object it maps to
/// `FILE_GENERIC_WRITE`, i.e. the create/append bits plus `FILE_WRITE_EA` and
/// `FILE_WRITE_ATTRIBUTES`. On a directory that is "may add entries and touch
/// metadata" — it carries neither `DELETE` nor `FILE_DELETE_CHILD`, so it
/// cannot remove or rename an existing component.
const SUBSTITUTION_DIRECTORY: u32 = SUBSTITUTION_ANY_KIND | FILE_DELETE_CHILD;

/// Additional substitution bits on a file.
///
/// Here the same values mean content: `FILE_WRITE_DATA` overwrites it,
/// `FILE_APPEND_DATA` extends it, and `FILE_WRITE_EA` alters data attached to
/// it. `GENERIC_WRITE` expands to all three on a file object and so is
/// substitution, unlike on a directory.
///
/// `FILE_WRITE_ATTRIBUTES` is deliberately absent: changing timestamps does not
/// let anyone swap what a privileged read sees. `FILE_DELETE_CHILD` is also
/// absent — that bit value is meaningless on a file, and treating it as a grant
/// would be reading a directory right into a file's mask.
const SUBSTITUTION_FILE: u32 =
    SUBSTITUTION_ANY_KIND | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | GENERIC_WRITE;

/// The kind of filesystem object a path component is, which decides how its
/// access mask is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObjectKind {
    /// A directory: an ancestor of the target, or a directory target such as
    /// the role-store base.
    Directory,
    /// A file, and the fallback for anything that is not a directory — the file
    /// mask is the stricter of the two.
    File,
}

impl ObjectKind {
    /// Access bits that let their holder substitute an object of this kind.
    const fn substitution_mask(self) -> u32 {
        match self {
            Self::Directory => SUBSTITUTION_DIRECTORY,
            Self::File => SUBSTITUTION_FILE,
        }
    }
}

/// `ACCESS_ALLOWED_ACE_TYPE` — the only allowing ACE whose layout this code
/// parses. Object and callback variants place the SID at a different offset.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
/// `ACCESS_DENIED_ACE_TYPE`.
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
/// `ACCESS_DENIED_OBJECT_ACE_TYPE`.
const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 6;
/// `ACCESS_DENIED_CALLBACK_ACE_TYPE`.
const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 10;
/// `ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE`.
const ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: u8 = 12;

/// Well-known SID string for `NT SERVICE\TrustedInstaller`. It has no
/// `WELL_KNOWN_SID_TYPE`, so it is compared by value.
const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

/// The outcome of a successful walk: the canonical path plus the leaf's kind,
/// which the caller turns into a [`super::ValidatedPath`].
#[derive(Debug)]
pub(super) struct Validated {
    /// Canonical, reparse-point-free path that passed the walk.
    pub(super) canonical: PathBuf,
    /// Whether the validated leaf is a regular file.
    pub(super) is_file: bool,
    /// Whether the validated leaf is a directory.
    pub(super) is_dir: bool,
}

/// Owner of a `LocalAlloc`-ed block returned by a Win32 call.
///
/// `GetNamedSecurityInfoW` and the SID/string converters all allocate through
/// `LocalAlloc` and require `LocalFree`. Wrapping the pointer means an early
/// return from a failed check cannot leak it.
struct LocalBlock(*mut c_void);

impl Drop for LocalBlock {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a Win32 call documented to return
            // `LocalAlloc`-ed memory, is freed exactly once here, and is not
            // used afterwards because `self` is being dropped.
            let _ = unsafe { LocalFree(self.0.cast::<c_void>() as HLOCAL) };
        }
    }
}

/// SIDs the policy trusts, resolved once per walk rather than per ACE.
struct TrustedSids {
    /// Backing allocation for [`Self::trusted_installer`].
    _storage: LocalBlock,
    /// `NT SERVICE\TrustedInstaller`.
    trusted_installer: PSID,
}

impl TrustedSids {
    /// Resolve the SIDs that are not covered by `IsWellKnownSid`.
    fn resolve(path: &Path) -> Result<Self, PrivilegedPathError> {
        let text = encode_wide(TRUSTED_INSTALLER_SID);
        let mut sid: PSID = ptr::null_mut();
        // SAFETY: `text` is a NUL-terminated UTF-16 buffer that outlives the
        // call, and `sid` is a valid out-parameter for a single `PSID`.
        let ok = unsafe { ConvertStringSidToSidW(text.as_ptr(), &raw mut sid) };
        if ok == 0 || sid.is_null() {
            return Err(PrivilegedPathError::SecurityDescriptorUnavailable {
                path: path.to_path_buf(),
                code: last_error(),
            });
        }
        Ok(Self {
            _storage: LocalBlock(sid),
            trusted_installer: sid,
        })
    }
}

/// Owner SID and DACL of one filesystem component, valid while the descriptor
/// allocation is alive.
struct ComponentSecurity {
    /// Backing allocation the owner and DACL pointers point into.
    _descriptor: LocalBlock,
    /// The component's owner; NULL when the descriptor carries none.
    owner: PSID,
    /// The component's discretionary ACL; NULL when the descriptor has none,
    /// which grants every account full access.
    dacl: *const ACL,
}

impl ComponentSecurity {
    /// Read the owner and DACL of `path`.
    ///
    /// Either pointer may come back NULL — a descriptor without an owner or
    /// without a DACL is a legal Windows object, and both are refusals. That
    /// verdict is [`check_security`]'s, so that it can be exercised against a
    /// descriptor built in a test as well as one read from disk.
    fn read(path: &Path) -> Result<Self, PrivilegedPathError> {
        let wide = encode_path(path)?;
        let mut owner: PSID = ptr::null_mut();
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `wide` is a NUL-terminated UTF-16 path that outlives the
        // call; the four out-parameters are valid, distinct locations of the
        // right types; the group and SACL out-parameters are optional and
        // passed as NULL, which the API documents as "do not retrieve".
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &raw mut owner,
                ptr::null_mut(),
                &raw mut dacl,
                ptr::null_mut(),
                &raw mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(PrivilegedPathError::SecurityDescriptorUnavailable {
                path: path.to_path_buf(),
                code: status,
            });
        }
        Ok(Self {
            _descriptor: LocalBlock(descriptor),
            owner,
            dacl: dacl.cast_const(),
        })
    }
}

/// Validate `path` against the Windows privileged-path policy.
///
/// The volume is classified before anything is opened, so a network or
/// removable path is refused without the process ever touching it. The caller's
/// own component chain is then walked and any reparse point in it is refused,
/// which leaves the canonical form differing from it only by normalisation; the
/// owner and DACL walk finally runs over the canonical chain.
pub(super) fn validate(path: &Path) -> Result<Validated, PrivilegedPathError> {
    if !path.is_absolute() {
        return Err(PrivilegedPathError::NotAbsolute {
            path: path.to_path_buf(),
        });
    }
    require_fixed_local_volume(path)?;
    reject_reparse_points(path)?;

    let canonical =
        std::fs::canonicalize(path).map_err(|source| PrivilegedPathError::Unresolvable {
            path: path.to_path_buf(),
            source,
        })?;
    // Canonicalisation can cross a mount point, so the volume is classified
    // again against the path that will actually be read.
    require_fixed_local_volume(&canonical)?;

    let leaf =
        std::fs::symlink_metadata(&canonical).map_err(|source| PrivilegedPathError::Stat {
            path: canonical.clone(),
            source,
        })?;

    let trusted = TrustedSids::resolve(&canonical)?;
    // Only the leaf can be something other than a directory; every ancestor is
    // one by construction, so the kind is narrowed once and then fixed.
    let mut kind = if leaf.is_dir() {
        ObjectKind::Directory
    } else {
        ObjectKind::File
    };
    let mut cursor = Some(canonical.as_path());
    while let Some(component) = cursor {
        check_component(component, kind, &trusted)?;
        cursor = component.parent();
        kind = ObjectKind::Directory;
    }

    Ok(Validated {
        is_file: leaf.is_file(),
        is_dir: leaf.is_dir(),
        canonical,
    })
}

/// Open the validated leaf for reading and refuse a leaf that turned into a
/// reparse point after the walk.
///
/// This does not close the check/use window (see the module docs); it only
/// makes the cheap half of it — a swap to a symlink or junction — observable.
pub(super) fn open_readonly(canonical: &Path) -> Result<std::fs::File, PrivilegedPathError> {
    let file =
        std::fs::File::open(canonical).map_err(|source| PrivilegedPathError::Unresolvable {
            path: canonical.to_path_buf(),
            source,
        })?;
    let meta = file
        .metadata()
        .map_err(|source| PrivilegedPathError::Stat {
            path: canonical.to_path_buf(),
            source,
        })?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(PrivilegedPathError::SymlinkNotAllowed {
            path: canonical.to_path_buf(),
        });
    }
    Ok(file)
}

/// Refuse `..` and any reparse point in the caller's component chain.
///
/// A junction or symlink anywhere on the way to the target lets whoever owns
/// it choose which file the privileged read consumes, even when the link's
/// current target is itself trusted.
fn reject_reparse_points(path: &Path) -> Result<(), PrivilegedPathError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                return Err(PrivilegedPathError::NotNormalized {
                    path: path.to_path_buf(),
                });
            }
            Component::CurDir => continue,
            Component::Prefix(_) | Component::RootDir => {
                current.push(component.as_os_str());
                continue;
            }
            Component::Normal(name) => current.push(name),
        }
        let meta =
            std::fs::symlink_metadata(&current).map_err(|source| PrivilegedPathError::Stat {
                path: current.clone(),
                source,
            })?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(PrivilegedPathError::SymlinkNotAllowed { path: current });
        }
    }
    Ok(())
}

/// Refuse a path that is not on a fixed local volume.
///
/// A UNC path's permissions are asserted by a remote server, and a removable
/// volume can be replaced wholesale; neither can carry the trust a privileged
/// read needs, so neither is walked at all.
fn require_fixed_local_volume(canonical: &Path) -> Result<(), PrivilegedPathError> {
    match canonical.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(_) | Prefix::VerbatimDisk(_) => {}
            Prefix::UNC(_, _) | Prefix::VerbatimUNC(_, _) => {
                return Err(PrivilegedPathError::NetworkPath {
                    path: canonical.to_path_buf(),
                });
            }
            Prefix::Verbatim(_) | Prefix::DeviceNS(_) => {
                return Err(PrivilegedPathError::UntrustedVolume {
                    path: canonical.to_path_buf(),
                    drive_type: 0,
                });
            }
        },
        _ => {
            return Err(PrivilegedPathError::NotAbsolute {
                path: canonical.to_path_buf(),
            });
        }
    }

    let wide = encode_path(canonical)?;
    // A volume mount point fits in `MAX_PATH` for drive letters and stays well
    // under this bound for mounted-folder paths.
    let mut root = vec![0_u16; 4096];
    let capacity = u32::try_from(root.len()).unwrap_or(u32::MAX);
    // SAFETY: `wide` is a NUL-terminated UTF-16 path; `root` is a writable
    // buffer of exactly `capacity` `u16`s that outlives the call.
    let ok = unsafe { GetVolumePathNameW(wide.as_ptr(), root.as_mut_ptr(), capacity) };
    if ok == 0 {
        return Err(PrivilegedPathError::SecurityDescriptorUnavailable {
            path: canonical.to_path_buf(),
            code: last_error(),
        });
    }
    // SAFETY: `GetVolumePathNameW` succeeded, so `root` holds a NUL-terminated
    // UTF-16 string within its own allocation.
    let drive_type = unsafe { GetDriveTypeW(root.as_ptr()) };
    if drive_type != DRIVE_FIXED {
        return Err(PrivilegedPathError::UntrustedVolume {
            path: canonical.to_path_buf(),
            drive_type,
        });
    }
    Ok(())
}

/// Enforce the owner and DACL policy against one path component.
fn check_component(
    path: &Path,
    kind: ObjectKind,
    trusted: &TrustedSids,
) -> Result<(), PrivilegedPathError> {
    let security = ComponentSecurity::read(path)?;
    check_security(
        path,
        kind,
        security.owner,
        security.dacl,
        trusted.trusted_installer,
    )
}

/// The whole verdict for one component, expressed over an owner SID and a DACL.
///
/// A NULL owner leaves the implicit `WRITE_DAC` that ownership confers
/// unattributable; a NULL DACL grants every account full access. Neither is an
/// absence of restrictions — both are refusals.
fn check_security(
    path: &Path,
    kind: ObjectKind,
    owner: PSID,
    dacl: *const ACL,
    trusted_installer: PSID,
) -> Result<(), PrivilegedPathError> {
    if owner.is_null() {
        return Err(PrivilegedPathError::OwnerUnavailable {
            path: path.to_path_buf(),
        });
    }
    if dacl.is_null() {
        return Err(PrivilegedPathError::NullDacl {
            path: path.to_path_buf(),
        });
    }
    check_owner(path, owner, trusted_installer)?;
    check_dacl(path, kind, dacl, trusted_installer)
}

/// The owner may only be `LocalSystem`, the built-in administrators group, or
/// `TrustedInstaller`.
///
/// An owner implicitly holds `WRITE_DAC`, so an untrusted owner can grant
/// itself substitution rights regardless of what the DACL says today.
///
/// `TrustedInstaller` is not a concession: on a stock Windows install it owns
/// the volume root itself, so a policy without it refuses every path on every
/// machine. It is the identity the servicing stack runs as, which is above the
/// privilege this check defends.
fn check_owner(
    path: &Path,
    owner: PSID,
    trusted_installer: PSID,
) -> Result<(), PrivilegedPathError> {
    if is_local_system(owner)
        || is_builtin_administrators(owner)
        || equals(owner, trusted_installer)
    {
        return Ok(());
    }
    Err(PrivilegedPathError::UntrustedOwnerSid {
        path: path.to_path_buf(),
        sid: sid_to_string(owner),
    })
}

/// Refuse a DACL that grants the right to substitute an object of `kind` to
/// anyone outside the trusted set, or that this code cannot fully parse.
fn check_dacl(
    path: &Path,
    kind: ObjectKind,
    dacl: *const ACL,
    trusted_installer: PSID,
) -> Result<(), PrivilegedPathError> {
    let substitution = kind.substitution_mask();
    // SAFETY: `dacl` points at an `ACL` inside a live security descriptor, so
    // its header is initialised and readable.
    let count = unsafe { (*dacl).AceCount };
    for index in 0..u32::from(count) {
        let mut ace: *mut c_void = ptr::null_mut();
        // SAFETY: `dacl` is a live ACL and `index` is below its `AceCount`;
        // `ace` is a valid out-parameter for a single pointer.
        let ok = unsafe { GetAce(dacl, index, &raw mut ace) };
        if ok == 0 || ace.is_null() {
            return Err(PrivilegedPathError::SecurityDescriptorUnavailable {
                path: path.to_path_buf(),
                code: last_error(),
            });
        }
        let header = ace.cast::<ACE_HEADER>();
        // SAFETY: `GetAce` yielded a pointer to an ACE, every variant of which
        // begins with an `ACE_HEADER`.
        let ace_flags = u32::from(unsafe { (*header).AceFlags });
        // An `INHERIT_ONLY` entry grants nothing on this object: it is the
        // template Windows stamps onto objects created inside it. Stock installs
        // carry several — `CREATOR OWNER: GENERIC_ALL (OI)(CI)(IO)` on
        // `%ProgramData%`, `Authenticated Users` on the volume root — and
        // reading them as effective refuses paths that are in fact protected.
        // The rights they hand down are not lost: they materialise as effective
        // entries on the descendants themselves, and are checked there when
        // those descendants are components of a path.
        //
        // `INHERITED_ACE` (a different flag) is deliberately not skipped: an
        // entry that arrived by inheritance is fully effective here.
        if ace_flags & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        // SAFETY: same pointer, same layout guarantee as the flags read above.
        let ace_type = unsafe { (*header).AceType };
        match ace_type {
            // A denying entry never widens access, so it cannot hand an
            // untrusted party the right to substitute a component.
            ACCESS_DENIED_ACE_TYPE
            | ACCESS_DENIED_OBJECT_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => continue,
            ACCESS_ALLOWED_ACE_TYPE => {}
            // Object and callback allow-ACEs put the SID at an offset this
            // code does not compute, and an unknown type cannot be reasoned
            // about at all. Both are refusals rather than guesses.
            other => {
                return Err(PrivilegedPathError::UnanalyzableAce {
                    path: path.to_path_buf(),
                    ace_type: other,
                });
            }
        }
        let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
        // SAFETY: the header identified this ACE as `ACCESS_ALLOWED_ACE_TYPE`,
        // so it has the `ACCESS_ALLOWED_ACE` layout.
        let mask = unsafe { (*allowed).Mask };
        if mask & substitution == 0 {
            continue;
        }
        // SAFETY: same layout guarantee; `SidStart` is the first word of the
        // variable-length SID stored inline after the mask, which is what the
        // SID-consuming APIs expect as a `PSID`.
        let sid: PSID = unsafe { &raw const (*allowed).SidStart }
            .cast::<c_void>()
            .cast_mut();
        if is_local_system(sid) || is_builtin_administrators(sid) || equals(sid, trusted_installer)
        {
            continue;
        }
        return Err(PrivilegedPathError::UntrustedSubstitution {
            path: path.to_path_buf(),
            sid: sid_to_string(sid),
            mask,
        });
    }
    Ok(())
}

/// Whether `sid` is `NT AUTHORITY\SYSTEM`.
fn is_local_system(sid: PSID) -> bool {
    // SAFETY: `sid` points at a SID inside a live security descriptor or a
    // live `LocalAlloc` block; `IsWellKnownSid` only reads it.
    unsafe { IsWellKnownSid(sid, WinLocalSystemSid) != 0 }
}

/// Whether `sid` is `BUILTIN\Administrators`.
fn is_builtin_administrators(sid: PSID) -> bool {
    // SAFETY: as above — a live SID, read-only use.
    unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0 }
}

/// Whether two live SIDs are equal.
fn equals(left: PSID, right: PSID) -> bool {
    // SAFETY: both pointers refer to live SIDs; `EqualSid` only reads them.
    unsafe { EqualSid(left, right) != 0 }
}

/// Render a SID for diagnostics, falling back to a placeholder when it cannot
/// be converted. A failure to print must never turn a refusal into anything
/// else, so it is not propagated.
fn sid_to_string(sid: PSID) -> String {
    let mut text: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` is a live SID and `text` is a valid out-parameter for a
    // single string pointer.
    let ok = unsafe { ConvertSidToStringSidW(sid, &raw mut text) };
    if ok == 0 || text.is_null() {
        return "<unprintable SID>".to_owned();
    }
    let _guard = LocalBlock(text.cast::<c_void>());
    let mut len = 0_usize;
    loop {
        // SAFETY: `ConvertSidToStringSidW` succeeded, so `text` is a
        // NUL-terminated UTF-16 string; `len` has not yet passed the
        // terminator, so the offset stays inside the allocation.
        let cell = unsafe { text.add(len) };
        // SAFETY: `cell` points at an initialised unit of that string.
        let unit = unsafe { *cell };
        if unit == 0 {
            break;
        }
        len += 1;
    }
    // SAFETY: `len` counts the units before the terminator, so the slice lies
    // entirely within the string's allocation.
    let units = unsafe { std::slice::from_raw_parts(text, len) };
    String::from_utf16_lossy(units)
}

/// The calling thread's last Win32 error code.
fn last_error() -> u32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
        .unwrap_or(u32::MAX)
}

/// Encode a `&str` as a NUL-terminated UTF-16 buffer.
fn encode_wide(text: &str) -> Vec<u16> {
    let mut buf: Vec<u16> = text.encode_utf16().collect();
    buf.push(0);
    buf
}

/// Encode a path as a NUL-terminated UTF-16 buffer, refusing an embedded NUL.
///
/// A NUL inside the path would silently truncate what the Win32 call sees, so
/// the check would be performed against a different object than the read.
fn encode_path(path: &Path) -> Result<Vec<u16>, PrivilegedPathError> {
    let mut buf: Vec<u16> = path.as_os_str().encode_wide().collect();
    if buf.contains(&0) {
        return Err(PrivilegedPathError::Unresolvable {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path contains an interior NUL",
            ),
        });
    }
    buf.push(0);
    Ok(buf)
}

// The policy verdict is exercised against security descriptors built from SDDL
// rather than against a real directory tree: producing a component owned by
// SYSTEM with a SYSTEM-only DACL requires privileges a test run does not have,
// while the verdict itself is exactly what these scenarios are about.
#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::{GetSecurityDescriptorDacl, GetSecurityDescriptorOwner};

    /// A security descriptor parsed from SDDL, kept alive for the assertions.
    struct Descriptor {
        _storage: LocalBlock,
        owner: PSID,
        dacl: *const ACL,
    }

    impl Descriptor {
        fn parse(sddl: &str) -> Self {
            let text = encode_wide(sddl);
            let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
            // SAFETY: `text` is a NUL-terminated UTF-16 SDDL string and `sd`
            // is a valid out-parameter; the size out-parameter is optional.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    SDDL_REVISION_1,
                    &raw mut sd,
                    ptr::null_mut(),
                )
            };
            assert!(ok != 0, "SDDL {sddl} must parse");
            let storage = LocalBlock(sd);

            let mut owner: PSID = ptr::null_mut();
            let mut defaulted = 0;
            // SAFETY: `sd` is a live security descriptor and both
            // out-parameters are valid.
            let ok = unsafe { GetSecurityDescriptorOwner(sd, &raw mut owner, &raw mut defaulted) };
            assert!(ok != 0, "owner must be readable");

            let mut present = 0;
            let mut dacl: *mut ACL = ptr::null_mut();
            // SAFETY: `sd` is a live security descriptor and all three
            // out-parameters are valid.
            let ok = unsafe {
                GetSecurityDescriptorDacl(sd, &raw mut present, &raw mut dacl, &raw mut defaulted)
            };
            assert!(ok != 0, "DACL must be readable");

            Self {
                _storage: storage,
                owner,
                dacl: dacl.cast_const(),
            }
        }
    }

    fn trusted_installer_sid() -> TrustedSids {
        TrustedSids::resolve(Path::new(r"C:\")).expect("TrustedInstaller SID must resolve")
    }

    /// Run the component verdict against an SDDL-built descriptor.
    fn probe_kind(sddl: &str, kind: ObjectKind) -> Result<(), PrivilegedPathError> {
        let descriptor = Descriptor::parse(sddl);
        let trusted = trusted_installer_sid();
        let path = match kind {
            ObjectKind::Directory => Path::new(r"C:\ProgramData"),
            ObjectKind::File => Path::new(r"C:\ProgramData\Tessera\config.toml"),
        };
        check_security(
            path,
            kind,
            descriptor.owner,
            descriptor.dacl,
            trusted.trusted_installer,
        )
    }

    /// Verdicts that must hold regardless of object type are asserted against
    /// the stricter of the two masks.
    fn probe(sddl: &str) -> Result<(), PrivilegedPathError> {
        probe_kind(sddl, ObjectKind::File)
    }

    /// The shape `prepare` creates: owned by SYSTEM, write reserved to SYSTEM,
    /// administrators and `TrustedInstaller`.
    #[test]
    fn system_owned_system_only_dacl_is_trusted() {
        probe("O:SYG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)")
            .expect("a SYSTEM-owned, SYSTEM-writable component must be trusted");
    }

    /// Read access for ordinary users is not what the policy is about; only the
    /// ability to substitute a component disqualifies it.
    #[test]
    fn read_only_grant_to_users_is_trusted() {
        probe("O:SYG:BAD:P(A;;FA;;;SY)(A;;FR;;;BU)")
            .expect("read-only access for Users must not disqualify a component");
    }

    /// The stock shape of the volume root and `%ProgramData%`: `Users` may
    /// create files and subdirectories, but may not delete or alter what is
    /// already there. Reading those bits as substitution would refuse every
    /// path on every standard system.
    ///
    /// `0x00100004` is `SYNCHRONIZE | FILE_ADD_SUBDIRECTORY`, `0x00000002` is
    /// `FILE_ADD_FILE`.
    #[test]
    fn stock_create_rights_on_ancestor_directory_are_trusted() {
        probe_kind(
            "O:SYG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x00100004;;;BU)(A;;0x00000002;;;BU)",
            ObjectKind::Directory,
        )
        .expect("stock create rights for Users on an ancestor directory must be trusted");
    }

    /// `GENERIC_WRITE` on a directory expands to the create and metadata bits
    /// and carries neither `DELETE` nor `FILE_DELETE_CHILD`, so it cannot
    /// remove or rename an existing component.
    #[test]
    fn generic_write_on_ancestor_directory_is_trusted() {
        probe_kind("O:SYG:BAD:P(A;;FA;;;SY)(A;;GW;;;BU)", ObjectKind::Directory)
            .expect("GENERIC_WRITE for Users on a directory must not disqualify it");
    }

    /// `FILE_DELETE_CHILD` (`0x00000040`) is exactly how a component below an
    /// ancestor gets swapped, so it disqualifies the directory.
    #[test]
    fn delete_child_on_ancestor_directory_is_rejected() {
        let err = probe_kind(
            "O:SYG:BAD:P(A;;FA;;;SY)(A;;0x00000040;;;BU)",
            ObjectKind::Directory,
        )
        .expect_err("a directory whose children Users may delete must be rejected");
        assert!(
            matches!(err, PrivilegedPathError::UntrustedSubstitution { .. }),
            "{err:?}"
        );
    }

    /// The same bit values that mean "create an entry" on a directory mean
    /// "rewrite the content" on a file, and there they are substitution.
    #[test]
    fn write_data_on_target_file_is_rejected() {
        let err = probe_kind(
            "O:SYG:BAD:P(A;;FA;;;SY)(A;;0x00000002;;;BU)",
            ObjectKind::File,
        )
        .expect_err("a target file Users may write must be rejected");
        assert!(
            matches!(err, PrivilegedPathError::UntrustedSubstitution { .. }),
            "{err:?}"
        );
    }

    /// `GENERIC_WRITE` on a file expands to the content-write bits, so unlike
    /// on a directory it is substitution.
    #[test]
    fn generic_write_on_target_file_is_rejected() {
        let err = probe_kind("O:SYG:BAD:P(A;;FA;;;SY)(A;;GW;;;BU)", ObjectKind::File)
            .expect_err("GENERIC_WRITE for Users on a target file must be rejected");
        assert!(
            matches!(err, PrivilegedPathError::UntrustedSubstitution { .. }),
            "{err:?}"
        );
    }

    /// Deletion is substitution on every object type, directories included.
    #[test]
    fn delete_right_is_rejected_on_both_kinds() {
        for kind in [ObjectKind::Directory, ObjectKind::File] {
            let err = probe_kind("O:SYG:BAD:P(A;;FA;;;SY)(A;;SD;;;BU)", kind)
                .expect_err("a component Users may delete must be rejected");
            assert!(
                matches!(err, PrivilegedPathError::UntrustedSubstitution { .. }),
                "{kind:?}: {err:?}"
            );
        }
    }

    /// Rewriting the DACL or taking ownership hands over everything else, so
    /// both disqualify a directory as much as a file.
    #[test]
    fn write_dac_and_write_owner_are_rejected_on_both_kinds() {
        for sddl in [
            "O:SYG:BAD:P(A;;FA;;;SY)(A;;WD;;;BU)",
            "O:SYG:BAD:P(A;;FA;;;SY)(A;;WO;;;BU)",
        ] {
            for kind in [ObjectKind::Directory, ObjectKind::File] {
                let err = probe_kind(sddl, kind)
                    .expect_err("a component whose rights Users may rewrite must be rejected");
                assert!(
                    matches!(err, PrivilegedPathError::UntrustedSubstitution { .. }),
                    "{sddl} / {kind:?}: {err:?}"
                );
            }
        }
    }

    #[test]
    fn full_access_granted_to_users_is_rejected() {
        for kind in [ObjectKind::Directory, ObjectKind::File] {
            let err = probe_kind("O:SYG:BAD:P(A;;FA;;;SY)(A;;FA;;;BU)", kind)
                .expect_err("a component Users fully control must be rejected");
            assert!(
                matches!(err, PrivilegedPathError::UntrustedSubstitution { .. }),
                "{kind:?}: {err:?}"
            );
        }
    }

    /// `0x00000116` is `FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
    /// FILE_WRITE_ATTRIBUTES` — the content-write shape on a file.
    #[test]
    fn write_granted_to_everyone_is_rejected() {
        let err = probe("O:SYG:BAD:P(A;;FA;;;SY)(A;;0x00000116;;;WD)")
            .expect_err("a target file writable by Everyone must be rejected");
        assert!(
            matches!(err, PrivilegedPathError::UntrustedSubstitution { .. }),
            "{err:?}"
        );
    }

    /// The descriptor a stock Windows 11 install carries on `C:\`, transcribed
    /// from `Get-Acl` on a clean VM: owned by `TrustedInstaller`, with
    /// `Authenticated Users` holding `FILE_APPEND_DATA` outright and a wide
    /// `INHERIT_ONLY` template for its descendants.
    ///
    /// Both properties refused this component before, and both refusals were
    /// wrong: the owner is the servicing identity, and the wide grant applies to
    /// objects created inside, not to the root itself.
    #[test]
    fn stock_volume_root_descriptor_is_trusted() {
        probe_kind(
            concat!(
                "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
                "G:BAD:P",
                "(A;;0x00000004;;;AU)",
                "(A;OICIIO;0xE0010000;;;AU)",
                "(A;OICI;FA;;;SY)",
                "(A;OICI;FA;;;BA)",
                "(A;OICI;0x001200A9;;;BU)"
            ),
            ObjectKind::Directory,
        )
        .expect("the stock descriptor of C:\\ must be trusted");
    }

    /// The descriptor a stock install carries on `%ProgramData%`: owned by
    /// SYSTEM, with `CREATOR OWNER: GENERIC_ALL` marked `INHERIT_ONLY` and
    /// `Users` holding container-inherited write.
    #[test]
    fn stock_program_data_descriptor_is_trusted() {
        probe_kind(
            concat!(
                "O:SYG:BAD:P",
                "(A;OICIIO;GA;;;CO)",
                "(A;;FA;;;SY)",
                "(A;;FA;;;BA)",
                "(A;;0x001200A9;;;BU)",
                "(A;CI;0x00000116;;;BU)"
            ),
            ObjectKind::Directory,
        )
        .expect("the stock descriptor of %ProgramData% must be trusted");
    }

    /// `TrustedInstaller` is a trusted owner in its own right, not only as part
    /// of the stock volume-root descriptor.
    #[test]
    fn trusted_installer_owned_component_is_trusted() {
        probe(concat!(
            "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
            "G:BAD:P(A;;FA;;;SY)"
        ))
        .expect("a component owned by TrustedInstaller must be trusted");
    }

    /// The `INHERIT_ONLY` skip is about effectiveness, not about the rights
    /// themselves: the same grant to the same principal, without the flag, acts
    /// on the component and must be refused.
    #[test]
    fn same_grant_without_inherit_only_is_rejected() {
        let inherit_only = "O:SYG:BAD:P(A;OICIIO;GA;;;CO)(A;;FA;;;SY)";
        let effective = "O:SYG:BAD:P(A;OICI;GA;;;CO)(A;;FA;;;SY)";

        probe_kind(inherit_only, ObjectKind::Directory)
            .expect("an INHERIT_ONLY template must not disqualify the component");

        let err = probe_kind(effective, ObjectKind::Directory)
            .expect_err("the same grant acting on the component must be rejected");
        assert!(
            matches!(err, PrivilegedPathError::UntrustedSubstitution { .. }),
            "{err:?}"
        );
    }

    /// An entry that arrived by inheritance is fully effective on the object
    /// that carries it, so `INHERITED_ACE` must not be confused with
    /// `INHERIT_ONLY_ACE` and skipped.
    #[test]
    fn inherited_but_effective_entry_is_still_checked() {
        let err = probe_kind(
            "O:SYG:BAD:P(A;ID;FA;;;BU)(A;;FA;;;SY)",
            ObjectKind::Directory,
        )
        .expect_err("an inherited effective grant to Users must be rejected");
        assert!(
            matches!(err, PrivilegedPathError::UntrustedSubstitution { .. }),
            "{err:?}"
        );
    }

    /// An intermediate directory owned by an engineer account disqualifies the
    /// whole path: its owner can rewrite the DACL at will.
    #[test]
    fn engineer_owned_component_is_rejected() {
        let err = probe("O:S-1-5-21-1111111111-2222222222-3333333333-1001G:BAD:P(A;;FA;;;SY)")
            .expect_err("a component owned by an engineer account must be rejected");
        assert!(
            matches!(err, PrivilegedPathError::UntrustedOwnerSid { .. }),
            "{err:?}"
        );
    }

    /// A denying entry cannot widen access, so it must not be mistaken for one.
    #[test]
    fn denying_entry_for_users_does_not_disqualify() {
        probe("O:SYG:BAD:P(D;;FA;;;BU)(A;;FA;;;SY)")
            .expect("a deny entry must not be read as a grant");
    }

    /// A NULL DACL grants everyone full access, so a descriptor without one is
    /// a refusal rather than an absence of restrictions.
    #[test]
    fn absent_dacl_is_rejected() {
        let err = probe("O:SYG:BA").expect_err("a component with no DACL must be rejected");
        assert!(
            matches!(err, PrivilegedPathError::NullDacl { .. }),
            "{err:?}"
        );
    }

    /// A security descriptor that cannot be read must be distinguishable from
    /// a missing file, so that an operator does not chase the wrong fault.
    #[test]
    fn unreadable_descriptor_reads_differently_from_missing_file() {
        let unreadable = PrivilegedPathError::SecurityDescriptorUnavailable {
            path: PathBuf::from(r"C:\ProgramData\Tessera\config.toml"),
            code: 5,
        };
        let missing = PrivilegedPathError::Unresolvable {
            path: PathBuf::from(r"C:\ProgramData\Tessera\config.toml"),
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        };
        assert_ne!(unreadable.to_string(), missing.to_string());
        assert!(unreadable.to_string().contains("security descriptor"));
    }

    #[test]
    fn missing_path_is_unresolvable_not_trusted() {
        let err = validate(Path::new(
            r"C:\Windows\Temp\tessera-does-not-exist\config.toml",
        ))
        .expect_err("a missing path must never validate");
        assert!(
            matches!(
                err,
                PrivilegedPathError::Unresolvable { .. } | PrivilegedPathError::Stat { .. }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn relative_path_is_rejected() {
        let err = validate(Path::new(r"Tessera\config.toml"))
            .expect_err("a relative path must be rejected");
        assert!(
            matches!(err, PrivilegedPathError::NotAbsolute { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn parent_component_is_rejected() {
        let err = validate(Path::new(
            r"C:\ProgramData\..\ProgramData\Tessera\config.toml",
        ))
        .expect_err("a path with `..` must be rejected");
        assert!(
            matches!(err, PrivilegedPathError::NotNormalized { .. }),
            "{err:?}"
        );
    }

    /// A UNC path is refused before any descriptor is read: its permissions
    /// are asserted by a machine outside this one's control.
    #[test]
    fn network_prefix_is_rejected() {
        let err = require_fixed_local_volume(Path::new(r"\\server\share\tessera\config.toml"))
            .expect_err("a UNC path must be rejected");
        assert!(
            matches!(err, PrivilegedPathError::NetworkPath { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn verbatim_unc_prefix_is_rejected() {
        let err = require_fixed_local_volume(Path::new(r"\\?\UNC\server\share\tessera"))
            .expect_err("a verbatim UNC path must be rejected");
        assert!(
            matches!(err, PrivilegedPathError::NetworkPath { .. }),
            "{err:?}"
        );
    }
}
