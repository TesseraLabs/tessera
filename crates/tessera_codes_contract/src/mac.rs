//! HMAC-SHA256 and HKDF-SHA256, written on top of `sha2` alone.
//!
//! Both constructions are pinned to their specification vectors in the tests
//! (RFC 4231 for HMAC, RFC 5869 for HKDF), because the whole contract rests on
//! two sides computing the same bytes from the same inputs.

use sha2::{Digest, Sha256};

/// SHA-256 block size, the width HMAC pads its key to.
const BLOCK_LEN: usize = 64;

/// SHA-256 output size.
pub(crate) const DIGEST_LEN: usize = 32;

/// Returns the SHA-256 digest of `data`.
pub(crate) fn sha256(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    into_array(&hasher.finalize())
}

/// Returns `HMAC-SHA256(key, message)` as defined by RFC 2104.
pub(crate) fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; DIGEST_LEN] {
    let mut block = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        let digest = sha256(key);
        copy_into(&mut block, &digest);
    } else {
        copy_into(&mut block, key);
    }

    let mut ipad = [0x36u8; BLOCK_LEN];
    let mut opad = [0x5cu8; BLOCK_LEN];
    for ((i, o), k) in ipad.iter_mut().zip(opad.iter_mut()).zip(block.iter()) {
        *i ^= *k;
        *o ^= *k;
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    into_array(&outer.finalize())
}

/// Returns 32 bytes of HKDF-SHA256 output (RFC 5869) for the given inputs.
///
/// Only one output block is produced: every consumer of this crate needs a
/// 256-bit key and nothing longer, and a single block keeps the counter out of
/// the frozen derivation.
pub(crate) fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; DIGEST_LEN] {
    let prk = hmac_sha256(salt, ikm);

    let mut block = Vec::with_capacity(info.len() + 1);
    block.extend_from_slice(info);
    block.push(0x01);
    hmac_sha256(&prk, &block)
}

/// Copies `src` into the front of `dst`, leaving the rest untouched.
///
/// `src` is never longer than `dst` at any call site, and a shorter `src` is
/// exactly the zero-padded key HMAC asks for.
fn copy_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = *s;
    }
}

/// Converts a digest output into a plain array without indexing.
fn into_array(digest: &[u8]) -> [u8; DIGEST_LEN] {
    let mut out = [0u8; DIGEST_LEN];
    copy_into(&mut out, digest);
    out
}

#[cfg(test)]
mod tests {
    use super::{hkdf_sha256, hmac_sha256};

    fn unhex(text: &str) -> Vec<u8> {
        hex::decode(text).unwrap_or_default()
    }

    #[test]
    fn hmac_matches_rfc_4231_case_1() {
        let mac = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            mac.to_vec(),
            unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
    }

    #[test]
    fn hmac_matches_rfc_4231_case_2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            mac.to_vec(),
            unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }

    #[test]
    fn hmac_hashes_a_key_longer_than_the_block() {
        let mac = hmac_sha256(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            mac.to_vec(),
            unhex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
    }

    #[test]
    fn hkdf_matches_rfc_5869_case_1() {
        let okm = hkdf_sha256(
            &unhex("000102030405060708090a0b0c"),
            &[0x0b; 22],
            &unhex("f0f1f2f3f4f5f6f7f8f9"),
        );
        // The first output block of the 42-byte OKM of test case 1.
        assert_eq!(
            okm.to_vec(),
            unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
        );
    }
}
