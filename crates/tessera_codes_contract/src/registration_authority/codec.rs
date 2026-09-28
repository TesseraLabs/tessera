use super::AuthorityError;
use crate::signature::Signature;
use crate::wire;
use unicode_normalization::UnicodeNormalization as _;

pub(crate) fn text(value: &str) -> Result<(), AuthorityError> {
    if value.len() > 128 || value.trim() != value || !value.nfc().eq(value.chars()) {
        return Err(AuthorityError::Malformed("noncanonical or oversized text"));
    }
    wire::check_free_text("identifier", value)?;
    Ok(())
}
pub(crate) fn uuid(value: &str) -> Result<(), AuthorityError> {
    if value.len() != 36
        || value == "00000000-0000-0000-0000-000000000000"
        || !value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
    {
        return Err(AuthorityError::Malformed("noncanonical UUID"));
    }
    Ok(())
}
pub(crate) fn signature(bytes: &[u8]) -> Result<(), AuthorityError> {
    // Strict positive, minimally encoded ASN.1 INTEGERs. Scalar range and
    // actual P-256 arithmetic are mandatory obligations of the backend.
    if !(8..=72).contains(&bytes.len())
        || bytes.first() != Some(&0x30)
        || bytes.get(1).copied().map(usize::from) != Some(bytes.len() - 2)
    {
        return Err(AuthorityError::Malformed(
            "signature is not bounded canonical DER",
        ));
    }
    let mut rest = bytes
        .get(2..)
        .ok_or(AuthorityError::Malformed("signature"))?;
    for _ in 0..2 {
        if rest.first() != Some(&2) {
            return Err(AuthorityError::Malformed("signature integer"));
        }
        let len = rest
            .get(1)
            .copied()
            .map(usize::from)
            .ok_or(AuthorityError::Malformed("signature integer"))?;
        let value = rest
            .get(2..2 + len)
            .ok_or(AuthorityError::Malformed("signature integer"))?;
        if !(1..=33).contains(&len)
            || value.first().is_none_or(|b| b & 0x80 != 0)
            || value.iter().all(|b| *b == 0)
            || value.first() == Some(&0) && (len == 1 || value.get(1).is_none_or(|b| b & 0x80 == 0))
        {
            return Err(AuthorityError::Malformed("noncanonical signature integer"));
        }
        rest = rest
            .get(2 + len..)
            .ok_or(AuthorityError::Malformed("signature"))?;
    }
    if !rest.is_empty() {
        return Err(AuthorityError::Malformed("signature trailing bytes"));
    }
    Ok(())
}
pub(crate) fn hex_bytes(value: &str, max: usize) -> Result<Vec<u8>, AuthorityError> {
    if value.len() > max.saturating_mul(2)
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(AuthorityError::Malformed("noncanonical hex"));
    }
    hex::decode(value).map_err(|_| AuthorityError::Malformed("hex"))
}
pub(crate) fn parse_signature(value: &str) -> Result<Signature, AuthorityError> {
    let bytes = hex_bytes(value, 72)?;
    signature(&bytes)?;
    Ok(Signature::new(bytes)?)
}
pub(crate) fn decimal(value: &str) -> Result<u64, AuthorityError> {
    let n = value
        .parse::<u64>()
        .map_err(|_| AuthorityError::Malformed("integer"))?;
    if n.to_string() != value {
        return Err(AuthorityError::Malformed("noncanonical integer"));
    }
    Ok(n)
}
pub(crate) fn hash(value: &str) -> Result<[u8; 32], AuthorityError> {
    hex_bytes(value, 32)?
        .try_into()
        .map_err(|_| AuthorityError::Malformed("digest width"))
}
pub(super) struct Reader<'a> {
    rest: &'a [u8],
}
impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }
    pub(super) fn field(&mut self, max: usize) -> Result<&'a [u8], AuthorityError> {
        let raw: [u8; 4] = self
            .rest
            .get(..4)
            .ok_or(AuthorityError::Malformed("truncated length"))?
            .try_into()
            .map_err(|_| AuthorityError::Malformed("length"))?;
        let len = usize::try_from(u32::from_be_bytes(raw))
            .map_err(|_| AuthorityError::Malformed("length"))?;
        if len > max {
            return Err(AuthorityError::Malformed("field bound"));
        }
        let value = self
            .rest
            .get(4..4 + len)
            .ok_or(AuthorityError::Malformed("truncated field"))?;
        self.rest = self
            .rest
            .get(4 + len..)
            .ok_or(AuthorityError::Malformed("field"))?;
        Ok(value)
    }
    pub(super) fn string(&mut self, max: usize) -> Result<String, AuthorityError> {
        Ok(std::str::from_utf8(self.field(max)?)
            .map_err(|_| AuthorityError::Malformed("UTF8"))?
            .to_owned())
    }
    pub(super) fn u64(&mut self) -> Result<u64, AuthorityError> {
        Ok(u64::from_be_bytes(
            self.field(8)?
                .try_into()
                .map_err(|_| AuthorityError::Malformed("u64 width"))?,
        ))
    }
    pub(super) fn u32(&mut self) -> Result<u32, AuthorityError> {
        Ok(u32::from_be_bytes(
            self.field(4)?
                .try_into()
                .map_err(|_| AuthorityError::Malformed("u32 width"))?,
        ))
    }
    pub(super) fn digest(&mut self) -> Result<[u8; 32], AuthorityError> {
        self.field(32)?
            .try_into()
            .map_err(|_| AuthorityError::Malformed("digest width"))
    }
    pub(super) fn finish(self) -> Result<(), AuthorityError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(AuthorityError::Malformed("trailing bytes"))
        }
    }
}
