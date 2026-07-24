//! Udev presence query — used to detect SessionOpen-vs-Remove races.

/// USB block-device identity captured by PAM at authentication time.
///
/// The descriptor serial is necessary to find candidates, while VID/PID and
/// the block-device node bind the check to the same topology PAM observed.
/// Optional fields are left unconstrained for legacy clients that did not
/// capture them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdevDeviceIdentity<'a> {
    /// `ID_SERIAL_SHORT`, falling back to `ID_SERIAL`.
    pub serial: &'a str,
    /// Lowercase hexadecimal `vvvv:pppp`, when captured.
    pub vid_pid: Option<&'a str>,
    /// Block-device node, e.g. `/dev/sdb1`, when captured.
    pub devnode: Option<&'a str>,
}

/// Trait abstraction so that tests can inject a fake.
pub trait UdevQuery: Send + Sync {
    /// Returns true if a USB block device matches every captured identity
    /// component.
    fn is_device_present(&self, identity: UdevDeviceIdentity<'_>) -> bool;
}

/// Always returns false. Used by tests + macOS dev builds.
#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysAbsent;

impl UdevQuery for AlwaysAbsent {
    fn is_device_present(&self, _identity: UdevDeviceIdentity<'_>) -> bool {
        false
    }
}

/// Always returns true. Used by integration tests where the device
/// presence check must not interfere.
#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysPresent;

impl UdevQuery for AlwaysPresent {
    fn is_device_present(&self, _identity: UdevDeviceIdentity<'_>) -> bool {
        true
    }
}

/// Static-set fake driver for tests.
#[derive(Debug, Default, Clone)]
pub struct FakeUdevQuery {
    devices: Vec<FakeDevice>,
}

#[derive(Debug, Clone)]
struct FakeDevice {
    serial: String,
    vid_pid: Option<String>,
    devnode: Option<String>,
}

impl FakeUdevQuery {
    /// Construct serial-only legacy devices from an iterator.
    pub fn with<I, S>(serials: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            devices: serials
                .into_iter()
                .map(|serial| FakeDevice {
                    serial: serial.into(),
                    vid_pid: None,
                    devnode: None,
                })
                .collect(),
        }
    }

    /// Construct one device with a complete captured topology.
    #[must_use]
    pub fn with_device(serial: &str, vid_pid: Option<&str>, devnode: Option<&str>) -> Self {
        Self {
            devices: vec![FakeDevice {
                serial: serial.to_owned(),
                vid_pid: vid_pid.map(str::to_owned),
                devnode: devnode.map(str::to_owned),
            }],
        }
    }
}

impl UdevQuery for FakeUdevQuery {
    fn is_device_present(&self, identity: UdevDeviceIdentity<'_>) -> bool {
        self.devices.iter().any(|device| {
            device.serial == identity.serial
                && identity
                    .vid_pid
                    .is_none_or(|expected| device.vid_pid.as_deref() == Some(expected))
                && identity
                    .devnode
                    .is_none_or(|expected| device.devnode.as_deref() == Some(expected))
        })
    }
}

#[cfg(target_os = "linux")]
mod real {
    use super::{UdevDeviceIdentity, UdevQuery};

    /// Real udev-backed query.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct RealUdevQuery;

    impl UdevQuery for RealUdevQuery {
        fn is_device_present(&self, identity: UdevDeviceIdentity<'_>) -> bool {
            let mut e = match udev::Enumerator::new() {
                Ok(e) => e,
                Err(_) => return false,
            };
            if e.match_subsystem("block").is_err() {
                return false;
            }
            match e.scan_devices() {
                Ok(iter) => iter
                    .into_iter()
                    .any(|device| matches_identity(&device, identity)),
                Err(_) => false,
            }
        }
    }

    fn matches_identity(device: &udev::Device, identity: UdevDeviceIdentity<'_>) -> bool {
        if device
            .property_value("ID_BUS")
            .and_then(|value| value.to_str())
            != Some("usb")
        {
            return false;
        }

        let serial_matches = ["ID_SERIAL_SHORT", "ID_SERIAL"].into_iter().any(|key| {
            device.property_value(key).and_then(|value| value.to_str()) == Some(identity.serial)
        });
        if !serial_matches {
            return false;
        }

        let vid_pid_matches = identity.vid_pid.is_none_or(|expected| {
            let vid = device
                .property_value("ID_VENDOR_ID")
                .and_then(|value| value.to_str());
            let pid = device
                .property_value("ID_MODEL_ID")
                .and_then(|value| value.to_str());
            matches!((vid, pid), (Some(vid), Some(pid)) if format!("{vid}:{pid}").eq_ignore_ascii_case(expected))
        });
        let devnode_matches = identity.devnode.is_none_or(|expected| {
            device.devnode().and_then(|value| value.to_str()) == Some(expected)
        });

        vid_pid_matches && devnode_matches
    }
}

#[cfg(target_os = "linux")]
pub use real::RealUdevQuery;

#[cfg(not(target_os = "linux"))]
/// Stub for non-Linux dev/test hosts.
pub type RealUdevQuery = AlwaysAbsent;
