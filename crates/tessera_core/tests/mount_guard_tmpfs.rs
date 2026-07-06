#![allow(missing_docs)]
#![cfg(target_os = "linux")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::items_after_statements,
    clippy::manual_let_else
)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tessera_core::error::MountGuardError;
use tessera_core::mount_guard::{MountFlags, MountGuard, MountOps};

#[derive(Default)]
struct CountingMockOps {
    mounted: AtomicUsize,
    umounted: AtomicUsize,
    rmdir_called: AtomicUsize,
}

impl MountOps for CountingMockOps {
    fn mount(
        &self,
        _source: &Path,
        _target: &Path,
        _fs_type: &str,
        _flags: MountFlags,
        _data: Option<&str>,
    ) -> Result<(), MountGuardError> {
        self.mounted.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn umount(&self, _target: &Path) -> Result<(), MountGuardError> {
        self.umounted.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn mkdir_mode_0700(&self, _path: &Path) -> Result<(), MountGuardError> {
        Ok(())
    }
    fn rmdir(&self, _path: &Path) -> Result<(), MountGuardError> {
        self.rmdir_called.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn mount_guard_drop_calls_umount_then_rmdir() {
    // P0-3 regression: umount MUST be invoked before rmdir on Drop.
    let ops = Arc::new(CountingMockOps::default());
    {
        let _guard = MountGuard::new_tmpfs(Arc::clone(&ops), &PathBuf::from("/tmp"), "p0-3-test")
            .unwrap_or_else(|err| panic!("guard: {err}"));
    }
    assert_eq!(ops.mounted.load(Ordering::SeqCst), 1, "mount called once");
    assert_eq!(
        ops.umounted.load(Ordering::SeqCst),
        1,
        "umount must be called on Drop (P0-3)"
    );
    assert_eq!(
        ops.rmdir_called.load(Ordering::SeqCst),
        1,
        "rmdir must be called on Drop"
    );
}

#[test]
fn mount_guard_real_ops_placeholder_lifecycle() {
    let tmp = tempfile::tempdir().unwrap_or_else(|err| panic!("tempdir: {err}"));
    {
        let ops = std::sync::Arc::new(tessera_core::mount_guard::RealMountOps);
        let _guard = tessera_core::mount_guard::MountGuard::new_tmpfs(ops, tmp.path(), "abc-test")
            .unwrap_or_else(|err| panic!("guard: {err}"));
    }
    assert!(!tmp.path().join("abc-test").exists());
}
