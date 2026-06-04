//! Secret redaction wrapper.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

/// Redacts display/debug and zeroizes on drop.
pub struct Secret<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> Secret<T> {
    /// Create a new secret.
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Expose the wrapped secret.
    pub fn expose_secret(&self) -> &T {
        &self.inner
    }

    /// Return the inner value wrapped in [`Zeroizing`].
    pub fn into_inner_zeroize_on_drop(mut self) -> Zeroizing<T>
    where
        T: Default,
    {
        let inner = std::mem::take(&mut self.inner);
        Zeroizing::new(inner)
    }
}

impl Secret<Vec<u8>> {
    /// Constant-time equality for byte secrets.
    pub fn ct_eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(self.inner.ct_eq(&other.inner))
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_redacted_for_string() {
        let s: Secret<String> = Secret::new("topsecret".to_string());
        assert_eq!(format!("{s}"), "<redacted>");
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
    }

    #[test]
    fn constant_time_eq_for_bytes() {
        let a = Secret::new(vec![1_u8, 2, 3]);
        let b = Secret::new(vec![1_u8, 2, 3]);
        let c = Secret::new(vec![1_u8, 2, 4]);
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }
}
