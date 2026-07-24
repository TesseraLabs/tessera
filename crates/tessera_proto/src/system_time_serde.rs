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
    secs_to_system_time(secs).map_err(serde::de::Error::custom)
}

/// Convert non-negative Unix seconds into a [`SystemTime`], rejecting negative
/// or unrepresentable values. Shared by the scalar and [`option`] codecs.
fn secs_to_system_time(secs: i64) -> Result<SystemTime, &'static str> {
    if secs < 0 {
        return Err("negative unix seconds");
    }
    let unsigned = u64::try_from(secs).map_err(|_| "seconds overflow")?;
    UNIX_EPOCH
        .checked_add(Duration::from_secs(unsigned))
        .ok_or("time overflow")
}

/// Serde codec for `Option<SystemTime>`, encoding `Some` as the same
/// non-negative Unix-seconds `i64` used by the scalar codec and `None` as a
/// JSON null. Pair it with `#[serde(default, skip_serializing_if =
/// "Option::is_none")]` so an absent field round-trips as `None`.
pub mod option {
    use super::{secs_to_system_time, serialize as serialize_scalar};
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::SystemTime;

    /// Serialize `Option<SystemTime>` as an optional Unix-seconds `i64`.
    ///
    /// # Errors
    ///
    /// Propagates the scalar serializer's error when the inner time is before
    /// the epoch or overflows `i64`.
    pub fn serialize<S: Serializer>(t: &Option<SystemTime>, s: S) -> Result<S::Ok, S::Error> {
        match t {
            Some(inner) => serialize_scalar(inner, s),
            None => s.serialize_none(),
        }
    }

    /// Deserialize `Option<SystemTime>` from an optional Unix-seconds `i64`.
    ///
    /// # Errors
    ///
    /// Returns the deserializer's native error for non-numeric input or a
    /// negative / unrepresentable second count.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<SystemTime>, D::Error> {
        match Option::<i64>::deserialize(d)? {
            Some(secs) => secs_to_system_time(secs)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}
