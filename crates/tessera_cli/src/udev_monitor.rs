//! Blocking udev monitor running on a dedicated thread.
//!
//! Linux-only. The thread polls `udev::MonitorBuilder::new().match_subsystem("block")`
//! and forwards every interesting event into a tokio mpsc.

use std::collections::HashMap;

use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;

/// Action carried in [`UdevEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdevAction {
    /// Device added.
    Add,
    /// Device removed.
    Remove,
    /// Other actions (`change`, `bind`, `unbind`, ...).
    Change,
}

/// One udev event distilled into the fields monitord cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdevEvent {
    /// What happened.
    pub action: UdevAction,
    /// Block-device node path, e.g. `/dev/sdb1`.
    pub devnode: Option<String>,
    /// `ID_SERIAL_SHORT` (preferred) falling back to `ID_SERIAL`.
    pub serial: Option<String>,
    /// `ID_VENDOR_ID:ID_MODEL_ID` decoded as hex.
    pub vid_pid: Option<(u16, u16)>,
    /// Whether `ID_BUS == "usb"`.
    pub is_usb: bool,
}

/// Parse a HashMap of udev properties into a [`UdevEvent`].
#[must_use]
pub fn parse_udev_fields(props: &HashMap<String, String>) -> Option<UdevEvent> {
    let action = match props.get("ACTION").map(String::as_str) {
        Some("add") => UdevAction::Add,
        Some("remove") => UdevAction::Remove,
        _ => UdevAction::Change,
    };
    let serial = props
        .get("ID_SERIAL_SHORT")
        .or_else(|| props.get("ID_SERIAL"))
        .cloned();
    let vid = props
        .get("ID_VENDOR_ID")
        .and_then(|s| u16::from_str_radix(s, 16).ok());
    let pid = props
        .get("ID_MODEL_ID")
        .and_then(|s| u16::from_str_radix(s, 16).ok());
    let vid_pid = vid.zip(pid);
    let is_usb = props.get("ID_BUS").map(String::as_str) == Some("usb");
    Some(UdevEvent {
        action,
        devnode: props.get("DEVNAME").cloned(),
        serial,
        vid_pid,
        is_usb,
    })
}

/// Spawn the blocking udev thread.
///
/// On non-Linux platforms returns a no-op thread that exits immediately —
/// integration tests inject events directly into the state manager channel.
#[cfg(target_os = "linux")]
pub fn spawn_udev_thread(
    tx: UnboundedSender<UdevEvent>,
    shutdown: CancellationToken,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("udev-monitor".into())
        .spawn(move || {
            while !shutdown.is_cancelled() {
                if let Err(e) = run_monitor(&tx, &shutdown) {
                    tracing::warn!(target: "tessera.monitord", error = %e, "udev monitor failed, retrying in 1s");
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
        })
        .unwrap_or_else(|e| {
            tracing::error!(target: "tessera.monitord", error = %e, "failed to spawn udev thread");
            std::thread::spawn(|| {})
        })
}

/// Stub spawn for non-Linux dev hosts.
#[cfg(not(target_os = "linux"))]
pub fn spawn_udev_thread(
    _tx: UnboundedSender<UdevEvent>,
    _shutdown: CancellationToken,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(|| {})
}

#[cfg(target_os = "linux")]
fn run_monitor(
    tx: &UnboundedSender<UdevEvent>,
    shutdown: &CancellationToken,
) -> anyhow::Result<()> {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use std::os::fd::{AsFd, AsRawFd};

    let socket = udev::MonitorBuilder::new()?
        .match_subsystem("block")?
        .listen()?;
    // Best effort: udev sockets default to non-blocking on the kernel side,
    // but we still poll with a short timeout so the shutdown token is
    // honoured promptly.
    let iter = socket;
    let _ = iter.as_raw_fd(); // sanity check that the fd is valid
    loop {
        if shutdown.is_cancelled() {
            return Ok(());
        }
        let mut fds = [PollFd::new(iter.as_fd(), PollFlags::POLLIN)];
        let n = poll(&mut fds, PollTimeout::from(250u16))?;
        if n == 0 {
            continue;
        }
        for event in iter.iter() {
            let mut props = HashMap::new();
            for prop in event.properties() {
                if let (Some(k), Some(v)) = (prop.name().to_str(), prop.value().to_str()) {
                    props.insert(k.to_string(), v.to_string());
                }
            }
            if let Some(udev_event) = parse_udev_fields(&props) {
                if !udev_event.is_usb
                    && matches!(udev_event.action, UdevAction::Add | UdevAction::Remove)
                {
                    // Drop non-USB block events early.
                    continue;
                }
                if tx.send(udev_event).is_err() {
                    return Ok(());
                }
            }
        }
    }
}
