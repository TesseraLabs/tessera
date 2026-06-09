//! Linux-only udev backend for [`super::wait_for_usb_devices`] and
//! [`super::UdevEnumerator`].
//!
//! Only compiled on `cfg(target_os = "linux")`.  Splitting it out keeps
//! `mod.rs` readable on non-Linux hosts (such as the maintainers' macOS dev
//! boxes) and avoids leaking udev types into the public surface.

use super::partition::{select_partitions, PartitionCandidate};
use super::{UsbDevice, UsbError};
use std::ffi::OsStr;
use std::os::fd::AsFd;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Default `max_usb_partitions` cap used by [`enumerate_once`] / the
/// `UdevEnumerator` trait impl, which has no access to a validated
/// config.  Production callers go through [`super::wait_for_usb_devices`]
/// with the configured limit; the trait path is only used by callers
/// that don't carry a config (CLI smoke tests, mock-style helpers), so
/// the upstream hard cap (64) is the right safety net here.
const DEFAULT_MAX_USB_PARTITIONS: usize = 64;

/// One-shot enumeration of attached USB block devices.
///
/// Each whole-device with a filesystem produces a single [`UsbDevice`];
/// whole-devices with a partition table produce one entry per viable
/// child partition (FS in the allow-list), capped at
/// [`DEFAULT_MAX_USB_PARTITIONS`].
pub(super) fn enumerate_once(
    vid_pid_filter: &[(u16, u16)],
) -> Result<Vec<UsbDevice>, UsbError> {
    enumerate_once_with_limit(vid_pid_filter, DEFAULT_MAX_USB_PARTITIONS)
}

/// Variant of [`enumerate_once`] that takes an explicit cap on the
/// number of partitions accepted per whole-disk.
pub(super) fn enumerate_once_with_limit(
    vid_pid_filter: &[(u16, u16)],
    max_usb_partitions: usize,
) -> Result<Vec<UsbDevice>, UsbError> {
    let mut e = udev::Enumerator::new().map_err(|e| UsbError::Udev(e.to_string()))?;
    e.match_subsystem("block")
        .map_err(|e| UsbError::Udev(e.to_string()))?;
    e.match_property("ID_BUS", "usb")
        .map_err(|e| UsbError::Udev(e.to_string()))?;

    let mut out = Vec::new();
    let scanned = e
        .scan_devices()
        .map_err(|e| UsbError::Udev(e.to_string()))?;
    for d in scanned {
        out.extend(devices_from(&d, vid_pid_filter, max_usb_partitions)?);
    }
    Ok(out)
}

/// Two-phase wait: enumerate, then monitor "add" events.
pub(super) fn wait_for_usb_real(
    timeout: Duration,
    vid_pid_filter: &[(u16, u16)],
    max_usb_partitions: usize,
) -> Result<Vec<UsbDevice>, UsbError> {
    // Phase 1 — already attached?
    let already = enumerate_once_with_limit(vid_pid_filter, max_usb_partitions)?;
    if !already.is_empty() {
        return Ok(already);
    }

    // Phase 2 — block on udev monitor for "add" events.
    let socket = udev::MonitorBuilder::new()
        .map_err(|e| UsbError::Udev(e.to_string()))?
        .match_subsystem("block")
        .map_err(|e| UsbError::Udev(e.to_string()))?
        .listen()
        .map_err(|e| UsbError::Udev(e.to_string()))?;

    let deadline = Instant::now() + timeout;

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(UsbError::Timeout);
        }
        let remaining = deadline.saturating_duration_since(now);
        let remaining_ms = u16::try_from(remaining.as_millis()).unwrap_or(u16::MAX);

        // Drain whatever is already queued without blocking.
        for event in socket.iter() {
            if event.event_type() == udev::EventType::Add {
                let dev_ref = event.device();
                if dev_ref
                    .property_value("ID_BUS")
                    .is_some_and(|v| v == OsStr::new("usb"))
                {
                    let devs = devices_from(&dev_ref, vid_pid_filter, max_usb_partitions)?;
                    if !devs.is_empty() {
                        return Ok(devs);
                    }
                }
            }
        }

        // Block on the monitor FD.
        let socket_fd = socket.as_fd();
        let mut pollfds = [nix::poll::PollFd::new(
            socket_fd,
            nix::poll::PollFlags::POLLIN,
        )];
        match nix::poll::poll(&mut pollfds, nix::poll::PollTimeout::from(remaining_ms)) {
            Ok(0) => return Err(UsbError::Timeout),
            Ok(_) | Err(nix::errno::Errno::EINTR) => {
                // loop back, drain queue / restart on EINTR
            }
            Err(e) => {
                return Err(UsbError::Io(std::io::Error::from_raw_os_error(e as i32)));
            }
        }
    }
}

/// Convert one udev device into zero or more [`UsbDevice`] records.
///
/// - A whole-device with `ID_FS_TYPE` set produces exactly one entry
///   (the existing whole-device path).
/// - A `DEVTYPE=disk` node with no FS triggers child enumeration; each
///   child partition whose FS is in [`super::super::mount::usb::ALLOWED_FS`]
///   becomes its own [`UsbDevice`].  Partitions are returned in stable
///   sysfs natural order (`sda1`, `sda2`, …, `sda10`).
/// - Any other device (loose partition node observed independently,
///   wrong subsystem, etc.) yields an empty vector.
///
/// If a whole-disk has more candidate partitions than `max_usb_partitions`
/// the function returns [`UsbError::TooManyPartitions`] (fail-closed).
fn devices_from(
    d: &udev::Device,
    filter: &[(u16, u16)],
    max_usb_partitions: usize,
) -> Result<Vec<UsbDevice>, UsbError> {
    let Some(devnode) = d.devnode() else {
        return Ok(Vec::new());
    };
    let devnode: PathBuf = devnode.to_path_buf();

    let vid = parse_hex16(d.property_value("ID_VENDOR_ID"))?;
    let pid = parse_hex16(d.property_value("ID_MODEL_ID"))?;

    if !filter.is_empty() && !filter.contains(&(vid, pid)) {
        return Ok(Vec::new());
    }

    let serial = d
        .property_value("ID_SERIAL_SHORT")
        .or_else(|| d.property_value("ID_SERIAL"))
        .map(|s| s.to_string_lossy().into_owned());

    let fs_type = d
        .property_value("ID_FS_TYPE")
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty());

    // Whole-device already carries a filesystem — single UsbDevice, no
    // partition fallback.
    if fs_type.is_some() {
        return Ok(vec![UsbDevice {
            devnode,
            serial,
            vid,
            pid,
            fs_type,
        }]);
    }

    // No FS on the parent — try the partition-table fallback.  We only
    // do this for `DEVTYPE=disk` so that incidentally enumerated
    // partition nodes are skipped (they get attributed via their parent).
    if !is_whole_disk(d) {
        return Ok(Vec::new());
    }

    tracing::info!(
        target: "tessera.usb",
        parent_devnode = %devnode.display(),
        "whole-device has no FS, scanning partitions",
    );
    let candidates = match collect_partition_candidates(d) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                target: "tessera.usb",
                parent_devnode = %devnode.display(),
                error = %e,
                "failed to enumerate child partitions",
            );
            return Ok(Vec::new());
        }
    };

    if candidates.len() > max_usb_partitions {
        tracing::warn!(
            target: "tessera.usb",
            parent_devnode = %devnode.display(),
            count = candidates.len(),
            limit = max_usb_partitions,
            "too many USB partitions; refusing to enumerate",
        );
        return Err(UsbError::TooManyPartitions {
            devnode,
            count: candidates.len(),
            limit: max_usb_partitions,
        });
    }

    let picked = select_partitions(None, &candidates);
    let mut out = Vec::with_capacity(picked.len());
    for p in picked {
        tracing::info!(
            target: "tessera.usb",
            partition_devnode = %p.devnode.display(),
            fs_type = p.fs_type.as_deref().unwrap_or("(unknown)"),
            fs_label = p.fs_label.as_deref().unwrap_or(""),
            "viable USB partition",
        );
        out.push(UsbDevice {
            devnode: p.devnode.clone(),
            serial: serial.clone(),
            vid,
            pid,
            fs_type: p.fs_type.clone(),
        });
    }
    Ok(out)
}

/// `true` when the udev device is a whole-disk node (`DEVTYPE=disk`),
/// suitable for the partition-table fallback.
fn is_whole_disk(d: &udev::Device) -> bool {
    d.property_value("DEVTYPE")
        .is_some_and(|v| v == OsStr::new("disk"))
}

/// Enumerate child partition nodes of `parent` and convert them to pure
/// [`PartitionCandidate`] records suitable for [`select_partitions`].
///
/// Partitions are returned in sysfs natural-sort order, sorted by their
/// kernel name (so `sda1`, `sda2`, …, `sda10`).
fn collect_partition_candidates(
    parent: &udev::Device,
) -> Result<Vec<PartitionCandidate>, UsbError> {
    let mut e = udev::Enumerator::new().map_err(|e| UsbError::Udev(e.to_string()))?;
    e.match_subsystem("block")
        .map_err(|e| UsbError::Udev(e.to_string()))?;
    e.match_parent(parent)
        .map_err(|e| UsbError::Udev(e.to_string()))?;

    // Collect (kernel_name, candidate) pairs so we can sort deterministically.
    let mut tagged: Vec<(String, PartitionCandidate)> = Vec::new();
    for child in e
        .scan_devices()
        .map_err(|e| UsbError::Udev(e.to_string()))?
    {
        // Skip the parent itself; we only want partitions.
        let is_partition = child
            .property_value("DEVTYPE")
            .is_some_and(|v| v == OsStr::new("partition"));
        if !is_partition {
            continue;
        }
        let Some(devnode) = child.devnode() else {
            continue;
        };
        let kernel = child.sysname().to_string_lossy().into_owned();
        let fs_type = child
            .property_value("ID_FS_TYPE")
            .map(|s| s.to_string_lossy().into_owned())
            .filter(|s| !s.is_empty());
        let fs_label = child
            .property_value("ID_FS_LABEL")
            .map(|s| s.to_string_lossy().into_owned())
            .filter(|s| !s.is_empty());
        tagged.push((
            kernel,
            PartitionCandidate {
                devnode: devnode.to_path_buf(),
                fs_type,
                fs_label,
            },
        ));
    }
    // Sysfs natural sort: split trailing digits so `sda2` < `sda10`.
    tagged.sort_by(|a, b| natural_cmp(&a.0, &b.0));
    Ok(tagged.into_iter().map(|(_, c)| c).collect())
}

/// Simple natural-sort comparator: splits the trailing decimal suffix off
/// the kernel name and compares the prefix lexicographically + suffix
/// numerically.  Good enough for `sd[a-z]+\d+` and `nvme0n1p\d+`.
fn natural_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    fn split_suffix(s: &str) -> (&str, u64) {
        let mut idx = s.len();
        for (i, c) in s.char_indices().rev() {
            if c.is_ascii_digit() {
                idx = i;
            } else {
                break;
            }
        }
        let (prefix, suffix) = s.split_at(idx);
        let n = suffix.parse::<u64>().unwrap_or(0);
        (prefix, n)
    }
    let (pa, na) = split_suffix(a);
    let (pb, nb) = split_suffix(b);
    match pa.cmp(pb) {
        std::cmp::Ordering::Equal => na.cmp(&nb),
        other => other,
    }
}

fn parse_hex16(v: Option<&OsStr>) -> Result<u16, UsbError> {
    let s = v
        .and_then(|s| s.to_str())
        .ok_or_else(|| UsbError::MissingProperty("ID_VENDOR_ID/ID_MODEL_ID".to_string()))?;
    u16::from_str_radix(s, 16)
        .map_err(|_| UsbError::MissingProperty(format!("malformed hex VID/PID: {s}")))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn natural_cmp_orders_partitions_correctly() {
        let mut v = vec!["sda10", "sda2", "sda1", "sdb1"];
        v.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(v, vec!["sda1", "sda2", "sda10", "sdb1"]);
    }
}
