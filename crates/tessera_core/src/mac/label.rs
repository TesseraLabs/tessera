//! `IntegrityLabel` — Astra МКЦ integrity coordinate (linear level + categories).

/// Errors produced by DER (de)serialization of `IntegrityLabel`.
#[derive(Debug, thiserror::Error)]
pub enum LabelDerError {
    /// `level` не помещается в `i8`.
    #[error("level out of int8 range")]
    LevelOutOfRange,
    /// Malformed DER.
    #[error("malformed DER: {0}")]
    Malformed(&'static str),
    /// `openssl` backend error.
    #[error(transparent)]
    Openssl(#[from] openssl::error::ErrorStack),
}

/// Bound on Astra integrity.  Поля соответствуют официальной модели Astra:
/// линейный уровень целостности `linear_ilev` (int8, -128..=127) и
/// 64-битная маска категорий целостности (`PDP_CAT_T = uint64_t`,
/// `pdp_common.h`, fetch 2026-05-14).  Сериализуется в DER (§2.2 spec) и в
/// text-формат `libpdp` `"conf:integ:cat_hex:flags:linear"` (§C.4/C.10 spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntegrityLabel {
    /// Линейный уровень целостности (`PDP_ILINEAR_T` = int8).
    /// Отрицательные — untrusted (sandbox); 0 — default.
    pub level: i8,
    /// Битовая маска категорий целостности (до 64 бит).
    pub categories: u64,
}

impl IntegrityLabel {
    /// Maximum allowed level (int8 upper bound).
    pub const MAX_LEVEL: i8 = i8::MAX;
    /// Minimum allowed level (int8 lower bound, untrusted/sandbox).
    pub const MIN_LEVEL: i8 = i8::MIN;

    /// Plain set-intersection (treats empty categories literally as "no cats").
    #[must_use]
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            level: self.level.min(other.level),
            categories: self.categories & other.categories,
        }
    }

    /// Intersection where `self` is the cert bound and `other` is the user
    /// МНКЦ.  `self.categories == 0` is interpreted as "cert imposes no
    /// category restriction" so `other.categories` survives unchanged.  This
    /// is the cert-vs-user-МНКЦ axis, not symmetric — do not call with
    /// arguments swapped.
    #[must_use]
    pub fn intersect_cert_with_user(&self, other: &Self) -> Self {
        let cats = if self.categories == 0 {
            other.categories
        } else {
            self.categories & other.categories
        };
        Self {
            level: self.level.min(other.level),
            categories: cats,
        }
    }

    /// Strict componentwise less-than (level lower OR fewer categories).
    #[must_use]
    pub fn strictly_below(&self, other: &Self) -> bool {
        let cats_subset = (self.categories & other.categories) == self.categories;
        (self.level < other.level && cats_subset)
            || (self.level <= other.level && self.categories != other.categories && cats_subset)
    }

    /// Encode as DER `SEQUENCE { level INTEGER, categories BIT STRING }`.
    ///
    /// `level` всегда помещается в один байт (диапазон int8); кодируется
    /// как DER INTEGER длины 1 (signed two's complement byte).  Поле
    /// `categories` сериализуется как `BIT STRING` минимальной длины;
    /// нулевая маска даёт пустой `BIT STRING`.
    ///
    /// # Errors
    /// `Malformed` если длина превышает short-form DER.
    pub fn to_der(&self) -> Result<Vec<u8>, LabelDerError> {
        let mut inner = Vec::with_capacity(16);
        // INTEGER (level — signed int8, one byte two's-complement)
        inner.push(0x02);
        inner.push(0x01);
        inner.push(self.level.cast_unsigned());
        // BIT STRING (categories, до 64 бит). Empty if zero.
        if self.categories == 0 {
            inner.push(0x03);
            inner.push(0x01);
            inner.push(0x00); // 0 unused bits, no payload
        } else {
            // 8 bytes big-endian; strip leading zero bytes (min-length
            // encoding) but keep at least one byte.
            let bytes = self.categories.to_be_bytes();
            let start = bytes.iter().position(|b| *b != 0).unwrap_or(7);
            // `start` гарантированно < 8 (position в массиве из 8 байт либо
            // unwrap_or(7)), поэтому срез всегда в границах.
            #[allow(clippy::indexing_slicing)]
            let payload = &bytes[start..];
            inner.push(0x03);
            inner.push(
                u8::try_from(payload.len() + 1).map_err(|_| LabelDerError::Malformed("len"))?,
            );
            inner.push(0x00); // unused bits
            inner.extend_from_slice(payload);
        }
        let mut out = Vec::with_capacity(inner.len() + 2);
        out.push(0x30);
        out.push(u8::try_from(inner.len()).map_err(|_| LabelDerError::Malformed("seq len"))?);
        out.extend_from_slice(&inner);
        Ok(out)
    }

    /// Decode a DER `SEQUENCE { level INTEGER, categories BIT STRING DEFAULT ''B }`.
    ///
    /// # Errors
    /// `Malformed` on bad tags/lengths, `LevelOutOfRange` if INTEGER не
    /// помещается в `i8`.
    pub fn from_der(der: &[u8]) -> Result<Self, LabelDerError> {
        let [0x30, len_byte, ..] = *der else {
            return Err(LabelDerError::Malformed("not a SEQUENCE"));
        };
        let seq_len = usize::from(len_byte);
        if 2 + seq_len > der.len() || len_byte & 0x80 != 0 {
            return Err(LabelDerError::Malformed("bad seq length"));
        }
        if 2 + seq_len != der.len() {
            return Err(LabelDerError::Malformed("trailing bytes after SEQUENCE"));
        }
        let body = der
            .get(2..2 + seq_len)
            .ok_or(LabelDerError::Malformed("bad seq length"))?;
        // INTEGER
        let [0x02, int_len_byte, ..] = *body else {
            return Err(LabelDerError::Malformed("missing INTEGER tag"));
        };
        if body.len() < 3 {
            return Err(LabelDerError::Malformed("missing INTEGER tag"));
        }
        let int_len = usize::from(int_len_byte);
        if int_len == 0 || 2 + int_len > body.len() {
            return Err(LabelDerError::Malformed("bad INTEGER length"));
        }
        let int_bytes = body
            .get(2..2 + int_len)
            .ok_or(LabelDerError::Malformed("bad INTEGER length"))?;
        let level = match int_bytes {
            [b] => b.cast_signed(),
            // INTEGER не помещается в один байт → не помещается в i8.
            _ => return Err(LabelDerError::LevelOutOfRange),
        };
        // BIT STRING (optional, default empty)
        let after_int = 2 + int_len;
        let categories = if after_int == body.len() {
            0u64
        } else {
            let bs = body
                .get(after_int..)
                .ok_or(LabelDerError::Malformed("bad INTEGER length"))?;
            let [0x03, bs_len_byte, ..] = *bs else {
                return Err(LabelDerError::Malformed("missing BIT STRING tag"));
            };
            let bs_len = usize::from(bs_len_byte);
            if bs_len == 0 || 2 + bs_len > bs.len() {
                return Err(LabelDerError::Malformed("bad BIT STRING length"));
            }
            if 2 + bs_len != bs.len() {
                return Err(LabelDerError::Malformed("trailing bytes after BIT STRING"));
            }
            let payload = bs
                .get(2..2 + bs_len)
                .ok_or(LabelDerError::Malformed("bad BIT STRING length"))?;
            let (&unused, bits) = payload
                .split_first()
                .ok_or(LabelDerError::Malformed("BIT STRING missing unused-bits byte"))?;
            if unused > 7 {
                return Err(LabelDerError::Malformed("BIT STRING unused-bits > 7"));
            }
            if bits.len() > 8 {
                return Err(LabelDerError::Malformed("categories > 64 bits"));
            }
            let mut buf = [0u8; 8];
            buf.get_mut(8 - bits.len()..)
                .ok_or(LabelDerError::Malformed("categories > 64 bits"))?
                .copy_from_slice(bits);
            u64::from_be_bytes(buf)
        };
        // N3: emit Notice for >32-bit categories (see audit::emit_categories_above_32bit).
        if categories >> 32 != 0 {
            crate::mac::audit::emit_categories_above_32bit(categories);
        }
        Ok(Self { level, categories })
    }
}
