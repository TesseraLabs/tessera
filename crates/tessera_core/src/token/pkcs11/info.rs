//! Token-info helpers (Task T10).
//!
//! [`read_token_serial`] returns the trimmed `CK_TOKEN_INFO.serialNumber`
//! string for `slot`.  In `mode = "pkcs11"` flows this value populates
//! [`crate::pam_data::AuthContext::usb_serial`] — the existing per-session
//! field used by monitord and the host ACL pipeline.  We deliberately
//! **don't** invent a separate `token_serial` field at this stage:
//! semantically the token serial replaces the USB serial in mode B.

use cryptoki::slot::Slot;

use super::backend::Pkcs11Backend;
use super::error::Pkcs11Error;
use super::locking::with_global_lock;

/// Read the trimmed token serial number reported by `C_GetTokenInfo`.
///
/// Most PKCS#11 providers right-pad the field with ASCII spaces; we trim
/// only the trailing whitespace so well-formed serials with embedded
/// spaces (rare but legal) are preserved as-is.
///
/// # Errors
///
/// - [`Pkcs11Error::Cryptoki`] when `C_GetTokenInfo` itself fails.
/// - [`Pkcs11Error::TokenSerialMissing`] when the provider returns an
///   empty serial number string.
pub fn read_token_serial(backend: &Pkcs11Backend, slot: Slot) -> Result<String, Pkcs11Error> {
    let info = with_global_lock(backend.locking_mode(), || {
        backend.ctx().get_token_info(slot)
    })?;
    let raw = info.serial_number().trim_end();
    if raw.is_empty() {
        return Err(Pkcs11Error::TokenSerialMissing);
    }
    Ok(raw.to_owned())
}
