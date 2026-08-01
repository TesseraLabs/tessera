//! Timing bounds two sides of the protocol have to agree on.
//!
//! A bound lives here when getting it wrong on one side breaks the other. The
//! wait for removable media is the one such bound today: the side that waits
//! and the side that waits *for* the waiter are different processes, built from
//! different crates, and a deadline shorter than the wait turns a slow
//! engineer into a failed logon with no diagnosis to give.

/// Longest an authentication may spend waiting for the engineer's medium to
/// appear, in seconds.
///
/// This is the ceiling the configured `usb_wait_seconds` is validated against,
/// which makes it also the floor for any client-side deadline on a verdict: a
/// client that gives up sooner reports a stuck service while the service is
/// doing exactly what it was configured to do. Beyond five minutes the wait
/// would hold the logon screen hostage for a medium that is not coming.
pub const MEDIA_WAIT_SECONDS_MAX: u64 = 300;
