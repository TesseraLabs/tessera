//! Private filesystem boundary for locally owned enrollment state.
use crate::privileged_path::{validate_directory, ExecTrust};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};

pub(super) fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) fn directory(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid("owned state needs an absolute normalized path"));
    }
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component);
        if fs::symlink_metadata(&current)?.file_type().is_symlink() {
            return Err(invalid("owned state cannot traverse symlinks"));
        }
    }
    validate_directory(
        path,
        ExecTrust::User {
            uid: rustix::process::geteuid().as_raw(),
            gid: rustix::process::getegid().as_raw(),
        },
    )
    .map_err(|_| invalid("owned state directory is not trusted"))?;
    Ok(())
}

pub(super) fn private_directory(path: &Path) -> io::Result<()> {
    directory(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(invalid(
            "private directory must belong to the current account and have mode 0700",
        ));
    }
    Ok(())
}

pub(super) fn make_directory(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| invalid("missing parent"))?;
    directory(parent)?;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    crate::fs_mode::sync_dir(parent)
}

pub(super) fn read(path: &Path, cap: usize, private: bool) -> io::Result<Vec<u8>> {
    directory(path.parent().ok_or_else(|| invalid("missing parent"))?)?;
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.permissions().mode() & 0o022 != 0
        || private && meta.permissions().mode() & 0o7777 != 0o600
    {
        return Err(invalid("owned file has unsafe type, owner or permissions"));
    }
    match crate::fs_mode::read_capped_regular(path, cap)? {
        crate::fs_mode::CappedRead::Whole(bytes) => Ok(bytes),
        crate::fs_mode::CappedRead::TooLarge => Err(invalid("owned file exceeds bound")),
    }
}

pub(super) fn write_new(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    directory(path.parent().ok_or_else(|| invalid("missing parent"))?)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.write_all(bytes)?;
    file.sync_all()
}

pub(super) fn replace(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| invalid("missing parent"))?;
    directory(parent)?;
    match fs::symlink_metadata(path) {
        Ok(meta)
            if !meta.is_file()
                || meta.uid() != rustix::process::geteuid().as_raw()
                || meta.permissions().mode() & 0o022 != 0 =>
        {
            return Err(invalid("unsafe destination"))
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let tmp = parent.join(format!(".enrollment-{}", uuid::Uuid::new_v4()));
    write_new(&tmp, bytes, mode)?;
    let result = fs::rename(&tmp, path).and_then(|()| crate::fs_mode::sync_dir(parent));
    if result.is_err() {
        drop(fs::remove_file(tmp));
    }
    result
}

pub(super) fn lock(root: &Path) -> io::Result<tessera_hashchain::file_lock::FileLock> {
    private_directory(root)?;
    let path = root.join("enrollment.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("lock is not a regular file"));
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    tessera_hashchain::file_lock::lock_exclusive(
        file,
        std::time::Duration::from_secs(10),
        std::time::Duration::from_millis(20),
    )
}

pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}
