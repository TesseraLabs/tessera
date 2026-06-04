//! Udev presence query — used to detect SessionOpen-vs-Remove races.

/// Trait abstraction so that tests can inject a fake.
pub trait UdevQuery: Send + Sync {
    /// Returns true if any block-subsystem udev device currently exposes
    /// `serial` as either `ID_SERIAL_SHORT` or `ID_SERIAL`.
    fn is_serial_present(&self, serial: &str) -> bool;
}

/// Always returns false. Used by tests + macOS dev builds.
#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysAbsent;

impl UdevQuery for AlwaysAbsent {
    fn is_serial_present(&self, _serial: &str) -> bool {
        false
    }
}

/// Always returns true. Used by integration tests where the device
/// presence check must not interfere.
#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysPresent;

impl UdevQuery for AlwaysPresent {
    fn is_serial_present(&self, _serial: &str) -> bool {
        true
    }
}

/// Static-set fake driver for tests.
#[derive(Debug, Default, Clone)]
pub struct FakeUdevQuery {
    serials: std::collections::HashSet<String>,
}

impl FakeUdevQuery {
    /// Construct from an iterator of serials.
    pub fn with<I, S>(serials: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            serials: serials.into_iter().map(Into::into).collect(),
        }
    }
}

impl UdevQuery for FakeUdevQuery {
    fn is_serial_present(&self, serial: &str) -> bool {
        self.serials.contains(serial)
    }
}

#[cfg(target_os = "linux")]
mod real {
    use super::UdevQuery;

    /// Real udev-backed query.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct RealUdevQuery;

    impl UdevQuery for RealUdevQuery {
        fn is_serial_present(&self, serial: &str) -> bool {
            let mut e = match udev::Enumerator::new() {
                Ok(e) => e,
                Err(_) => return false,
            };
            if e.match_subsystem("block").is_err() {
                return false;
            }
            match e.scan_devices() {
                Ok(iter) => iter.into_iter().any(|d| matches_serial(&d, serial)),
                Err(_) => false,
            }
        }
    }

    fn matches_serial(d: &udev::Device, serial: &str) -> bool {
        for key in ["ID_SERIAL_SHORT", "ID_SERIAL"] {
            if let Some(v) = d.property_value(key).and_then(|v| v.to_str()) {
                if v == serial {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(target_os = "linux")]
pub use real::RealUdevQuery;

#[cfg(not(target_os = "linux"))]
/// Stub for non-Linux dev/test hosts.
pub type RealUdevQuery = AlwaysAbsent;
