//! Serde helper that encodes [`std::time::SystemTime`] as a non-negative
//! `i64` count of seconds since the Unix epoch.
//!
//! Negative values are rejected on deserialization. Times before 1970 are
//! disallowed because `monitord` stamps these from `SystemTime::now()` and
//! ought to fail loudly if anything weird is on the wire.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Serialize [`SystemTime`] as Unix seconds.
///
/// # Errors
///
/// Returns the serializer's native error when the destination cannot accept
/// an `i64` or when the time is before the epoch.
pub fn serialize<S: Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map_err(|e| serde::ser::Error::custom(format!("time before epoch: {e}")))?
        .as_secs();
    let signed: i64 = secs
        .try_into()
        .map_err(|_| serde::ser::Error::custom("seconds overflow i64"))?;
    signed.serialize(s)
}

/// Deserialize [`SystemTime`] from Unix seconds.
///
/// # Errors
///
/// Returns the deserializer's native error for non-numeric input or values
/// less than zero.
pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SystemTime, D::Error> {
    let secs = i64::deserialize(d)?;
    if secs < 0 {
        return Err(serde::de::Error::custom("negative unix seconds"));
    }
    let unsigned = u64::try_from(secs).map_err(|_| serde::de::Error::custom("seconds overflow"))?;
    UNIX_EPOCH
        .checked_add(Duration::from_secs(unsigned))
        .ok_or_else(|| serde::de::Error::custom("time overflow"))
}
