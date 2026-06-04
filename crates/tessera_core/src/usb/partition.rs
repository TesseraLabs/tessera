//! Pure partition-selection helper for the partition-table fallback.
//!
//! Some USB sticks carry a partition table (`DEVTYPE=disk`) where the
//! filesystem lives on a child partition (`DEVTYPE=partition`).  In that
//! case udev reports `ID_FS_TYPE` only on the partition node, not the
//! whole device, so the existing whole-device path fails with
//! `UnsupportedFs("(unknown)")`.
//!
//! [`select_partitions`] picks every child whose `ID_FS_TYPE` belongs to
//! the [`ALLOWED_FS`](crate::mount::usb::ALLOWED_FS) allowlist.  It is
//! deliberately pure — no udev calls — so it can be unit-tested on any
//! platform.
//!
//! When the parent whole-device already has a filesystem the function
//! returns an empty `Vec` (the caller stays on the whole-device path).
//! Otherwise it returns every viable partition in the input order so the
//! caller can iterate them and try each one until a `.p12` shows up.
//! The real trust boundary is `.p12` decryption + chain validation —
//! filtering by label adds no security, only UX friction.
//!
//! Note: the [`PartitionCandidate::fs_label`] field is retained because
//! it is useful in logs, but the selection logic ignores it.

use crate::mount::usb::ALLOWED_FS;
use std::path::PathBuf;

/// A child-partition record observed under a whole-device USB block.
///
/// Built by the udev backend from `ID_FS_TYPE` / `ID_FS_LABEL` properties
/// of a `DEVTYPE=partition` child node.  Kept minimal so the pure
/// selection logic stays trivially testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionCandidate {
    /// Partition devnode (e.g. `/dev/sdb1`).
    pub devnode: PathBuf,
    /// `ID_FS_TYPE` reported by udev/blkid on the partition itself.
    pub fs_type: Option<String>,
    /// `ID_FS_LABEL` reported by udev/blkid on the partition itself.
    ///
    /// Retained for diagnostic logging only — the selection logic ignores
    /// it.
    pub fs_label: Option<String>,
}

/// Pick every child partition with an allow-listed filesystem.
///
/// - `parent_fs_type` — `ID_FS_TYPE` reported on the whole-device.  When
///   `Some`, the whole-device already has a filesystem and the caller
///   stays on the whole-device path (returns an empty vector — no
///   partition-table fallback is needed).
/// - `partitions` — children of the whole-device with `DEVTYPE=partition`.
///
/// The returned vector preserves the input order so the caller can iterate
/// partitions deterministically (typically sysfs natural sort: `sda1`,
/// `sda2`, …, `sda10`).
#[must_use]
pub fn select_partitions<'a>(
    parent_fs_type: Option<&str>,
    partitions: &'a [PartitionCandidate],
) -> Vec<&'a PartitionCandidate> {
    // Whole-device already has a filesystem — caller stays on existing path.
    if parent_fs_type.is_some() {
        return Vec::new();
    }

    partitions
        .iter()
        .filter(|p| {
            p.fs_type
                .as_deref()
                .is_some_and(|fs| ALLOWED_FS.contains(&fs))
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn part(devnode: &str, fs: Option<&str>, label: Option<&str>) -> PartitionCandidate {
        PartitionCandidate {
            devnode: PathBuf::from(devnode),
            fs_type: fs.map(str::to_string),
            fs_label: label.map(str::to_string),
        }
    }

    #[test]
    fn parent_has_fs_returns_empty_even_with_matching_partitions() {
        let parts = vec![part("/dev/sdb1", Some("vfat"), Some("PAMCERT"))];
        let res = select_partitions(Some("ext4"), &parts);
        assert!(res.is_empty());
    }

    #[test]
    fn parent_no_fs_no_partitions_returns_empty() {
        let parts: Vec<PartitionCandidate> = vec![];
        let res = select_partitions(None, &parts);
        assert!(res.is_empty());
    }

    #[test]
    fn one_partition_with_allowed_fs_is_picked_regardless_of_label() {
        let parts = vec![part("/dev/sdb1", Some("ext4"), Some("any-old-label"))];
        let res = select_partitions(None, &parts);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].devnode, PathBuf::from("/dev/sdb1"));
    }

    #[test]
    fn two_allowed_partitions_both_picked_in_input_order() {
        let parts = vec![
            part("/dev/sdb1", Some("ext4"), Some("A")),
            part("/dev/sdb2", Some("vfat"), Some("B")),
        ];
        let res = select_partitions(None, &parts);
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].devnode, PathBuf::from("/dev/sdb1"));
        assert_eq!(res[1].devnode, PathBuf::from("/dev/sdb2"));
    }

    #[test]
    fn mixed_only_allowed_picked_order_preserved() {
        let parts = vec![
            part("/dev/sdb1", Some("ext4"), Some("A")),
            part("/dev/sdb2", Some("btrfs"), Some("X")),
            part("/dev/sdb3", Some("vfat"), Some("B")),
        ];
        let res = select_partitions(None, &parts);
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].devnode, PathBuf::from("/dev/sdb1"));
        assert_eq!(res[1].devnode, PathBuf::from("/dev/sdb3"));
    }

    #[test]
    fn all_unsupported_fs_returns_empty() {
        let parts = vec![
            part("/dev/sdb1", Some("btrfs"), None),
            part("/dev/sdb2", Some("xfs"), None),
        ];
        let res = select_partitions(None, &parts);
        assert!(res.is_empty());
    }

    #[test]
    fn pamcert_label_is_ignored_both_partitions_picked() {
        // Historically only the partition with label=PAMCERT was selected;
        // now label is irrelevant — both allow-listed partitions show up.
        let parts = vec![
            part("/dev/sdb1", Some("ext4"), Some("PAMCERT")),
            part("/dev/sdb2", Some("vfat"), Some("OTHER")),
        ];
        let res = select_partitions(None, &parts);
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].devnode, PathBuf::from("/dev/sdb1"));
        assert_eq!(res[1].devnode, PathBuf::from("/dev/sdb2"));
    }

    #[test]
    fn partition_without_fs_type_is_skipped() {
        let parts = vec![
            part("/dev/sdb1", None, Some("PAMCERT")),
            part("/dev/sdb2", Some("vfat"), None),
        ];
        let res = select_partitions(None, &parts);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].devnode, PathBuf::from("/dev/sdb2"));
    }
}
