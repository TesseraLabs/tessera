#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]

use tessera_cli::udev_monitor::{parse_udev_fields, UdevAction};
use std::collections::HashMap;

#[test]
fn parses_add_with_serial() {
    let mut props = HashMap::new();
    props.insert("ACTION".to_string(), "add".to_string());
    props.insert("DEVNAME".to_string(), "/dev/sdb".to_string());
    props.insert("ID_SERIAL_SHORT".to_string(), "AB12".to_string());
    props.insert("ID_VENDOR_ID".to_string(), "1234".to_string());
    props.insert("ID_MODEL_ID".to_string(), "abcd".to_string());
    props.insert("ID_BUS".to_string(), "usb".to_string());
    let ev = parse_udev_fields(&props).expect("parse");
    assert_eq!(ev.action, UdevAction::Add);
    assert_eq!(ev.devnode.as_deref(), Some("/dev/sdb"));
    assert_eq!(ev.serial.as_deref(), Some("AB12"));
    assert_eq!(ev.vid_pid, Some((0x1234, 0xabcd)));
    assert!(ev.is_usb);
}

#[test]
fn parses_remove_without_serial() {
    let mut p = HashMap::new();
    p.insert("ACTION".into(), "remove".into());
    p.insert("DEVNAME".into(), "/dev/sdc".into());
    let ev = parse_udev_fields(&p).expect("parse");
    assert_eq!(ev.action, UdevAction::Remove);
    assert!(ev.serial.is_none());
}

#[test]
fn unknown_action_is_change() {
    let mut p = HashMap::new();
    p.insert("ACTION".into(), "change".into());
    let ev = parse_udev_fields(&p).expect("parse");
    assert_eq!(ev.action, UdevAction::Change);
}

#[test]
fn falls_back_to_id_serial_when_short_missing() {
    let mut p = HashMap::new();
    p.insert("ACTION".into(), "add".into());
    p.insert("ID_SERIAL".into(), "long_serial_name".into());
    let ev = parse_udev_fields(&p).expect("parse");
    assert_eq!(ev.serial.as_deref(), Some("long_serial_name"));
}

#[test]
fn non_usb_block_is_marked_not_usb() {
    let mut p = HashMap::new();
    p.insert("ACTION".into(), "add".into());
    p.insert("ID_BUS".into(), "scsi".into());
    let ev = parse_udev_fields(&p).expect("parse");
    assert!(!ev.is_usb);
}
