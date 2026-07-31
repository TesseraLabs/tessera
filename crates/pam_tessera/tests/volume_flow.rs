//! Candidate selection across several already-mounted volumes.
//!
//! The Windows media path differs from the Linux one only in where candidates
//! come from, so the behaviour worth testing — the order they are tried in,
//! which one binds the attempt, and how the three ways an attempt can fail on
//! the media are told apart — lives in `VolumeFlowIo` and is platform-neutral.
//! These tests drive the real flow over staged directories standing in for
//! volumes, and therefore run everywhere the suite runs.
//!
//! What they deliberately do not cover is Win32 enumeration itself: that has
//! no counterpart off Windows and is exercised on the bench.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::duration_suboptimal_units,
    clippy::pedantic
)]

mod common;

use std::path::Path;
use std::time::Duration;

use common::*;
use pam_tessera::flow::{authenticate, Deps, FlowError, FlowOutcome};
use pam_tessera::volume_flow::VolumeFlowIo;
use secrecy::SecretString;
use tessera_core::host_identity::HostIdSourceKind;
use tessera_core::ipc::StubClient;
use tessera_core::mount_guard::SystemMountedOps;
use tessera_core::usb::{MockEnumerator, UsbDevice, UsbError};

/// A volume record pointing at `path`, shaped the way the Windows enumerator
/// fills one in: no USB descriptor, the volume's own identifier as serial.
fn volume(path: &Path, id: &str) -> UsbDevice {
    UsbDevice {
        devnode: path.to_path_buf(),
        serial: Some(id.to_string()),
        vid: 0,
        pid: 0,
        fs_type: Some("exfat".to_string()),
    }
}

/// Drive the full flow over `volumes`, in the order given.
fn run_over(
    volumes: Vec<UsbDevice>,
    pin: &str,
) -> Result<FlowOutcome<SystemMountedOps>, FlowError> {
    let verifier = build_verifier(vec![]);
    let cfg = minimal_cfg();
    let monitor = StubClient;
    let exec = tessera_core::hooks::NoopExecutor::new();
    let roles = RoleFixture::serv();
    let deps = Deps {
        cfg: &cfg,
        trust: &verifier,
        monitor: &monitor,
        hook_executor: &exec,
        host_id_hash: "host-T-hash",
        host_id_source: HostIdSourceKind::Override,
        pam_target: tessera_proto::SessionTarget::Unknown,
        role_stage: roles.stage(),
        device_tags: pam_tessera::flow::empty_device_tags(),
    };
    let io = VolumeFlowIo::new(
        MockEnumerator {
            devices: volumes,
            error: None,
        },
        Duration::from_millis(100),
    )
    .with_poll_interval(Duration::from_millis(10));
    let pin = pin.to_string();
    authenticate(
        deps,
        &io,
        RoleFixture::ACCOUNT,
        "tessera-verify",
        "sess-volume".to_string(),
        |_prompt| Ok(SecretString::from(pin.clone())),
    )
}

/// A directory standing in for a volume with no credential on it.
fn empty_volume() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn no_volume_at_all_is_a_wait_timeout() {
    let err = run_over(vec![], "correct-pin").unwrap_err();
    assert!(
        matches!(err, FlowError::Usb(UsbError::Timeout)),
        "expected a media-wait timeout, got {err:?}"
    );
    assert_eq!(err.pam_code(), 9, "PAM_AUTHINFO_UNAVAIL");
}

#[test]
fn volumes_without_a_credential_are_reported_as_a_missing_credential() {
    let first = empty_volume();
    let second = empty_volume();
    let err = run_over(
        vec![
            volume(first.path(), "VOL-1"),
            volume(second.path(), "VOL-2"),
        ],
        "correct-pin",
    )
    .unwrap_err();
    // Distinct from the timeout above: media was present and readable, the
    // credential was not on it.
    assert!(
        matches!(
            err,
            FlowError::Discovery(tessera_core::discovery::DiscoveryError::P12NotFound { .. })
        ),
        "expected a missing credential, got {err:?}"
    );
}

#[test]
fn the_attempt_uses_the_first_volume_that_carries_a_credential() {
    let first = empty_volume();
    let second = stage_mount("leaf_rsa.p12", false);
    let outcome = run_over(
        vec![
            volume(first.path(), "VOL-1"),
            volume(second.path(), "VOL-2"),
        ],
        "correct-pin",
    )
    .expect("the credential on the second volume must be used");
    assert_eq!(outcome.auth_ctx.usb_serial.as_deref(), Some("VOL-2"));
}

#[test]
fn a_rejected_credential_ends_the_attempt_instead_of_trying_the_next_volume() {
    // Both volumes carry the same valid credential; only the PIN is wrong.
    // Continuing past the first one would spend a fresh PIN budget on every
    // volume attached to the machine, which is a guessing oracle dressed up
    // as a retry.
    let first = stage_mount("leaf_rsa.p12", false);
    let second = stage_mount("leaf_rsa.p12", false);
    let err = run_over(
        vec![
            volume(first.path(), "VOL-1"),
            volume(second.path(), "VOL-2"),
        ],
        "wrong-pin",
    )
    .unwrap_err();
    assert!(
        matches!(err, FlowError::MaxTries),
        "expected the bound volume's own verdict, got {err:?}"
    );
    assert_eq!(err.pam_code(), 11, "PAM_MAXTRIES");
}

#[test]
fn a_single_volume_authenticates_and_leaves_the_media_untouched() {
    let only = stage_mount("leaf_rsa.p12", false);
    let p12 = only.path().join("certs").join("user.p12");
    let outcome = run_over(vec![volume(only.path(), "VOL-1")], "correct-pin")
        .expect("a valid credential on the only volume must be admitted");
    assert_eq!(outcome.auth_ctx.usb_serial.as_deref(), Some("VOL-1"));
    assert_eq!(
        outcome.auth_ctx.usb_vid_pid.as_deref(),
        Some("0000:0000"),
        "a volume carries no USB descriptor in this wave"
    );
    drop(outcome);
    assert!(
        p12.is_file(),
        "the volume must survive the attempt unchanged"
    );
}

#[test]
fn a_volume_that_vanished_between_enumeration_and_use_is_a_mount_failure() {
    let gone = empty_volume();
    let path = gone.path().to_path_buf();
    drop(gone);
    let err = run_over(vec![volume(&path, "VOL-1")], "correct-pin").unwrap_err();
    assert!(
        matches!(
            err,
            FlowError::Mount(tessera_core::mount::usb::MountError::MountpointInvalid(_))
        ),
        "expected a mount failure, got {err:?}"
    );
}
