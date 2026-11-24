//! Bit-packing and unpacking utilities for SHA-256 word conversion (Issue #457).
//!
//! SHA-256 operates entirely on 32-bit words (`u32`). Before hashing a BN254
//! scalar field element, callers must *pack* its canonical big-endian byte
//! representation into a contiguous `[u32; 8]` word array (one word per 4
//! bytes, big-endian). After hashing they must be able to *unpack* a `[u32; 8]`
//! digest back into the 32-byte form understood by the rest of the library.
//!
//! ## Layout contract
//!
//! A 256-bit field element is always treated as a **32-byte big-endian** buffer:
//!
//! ```text
//! bytes[0..4]   → words[0]   (most-significant word)
//! bytes[4..8]   → words[1]
//! ...
//! bytes[28..32] → words[7]   (least-significant word)
//! ```
//!
//! This matches the byte order used by [`ethnum::u256::to_be_bytes`] and by the
//! `sha256` compression function in `soroban-zk-std::gadgets::hash::sha256`.
//!
//! ## Wasm / no_std compatibility
//!
//! All code in this module is `#[no_std]`.  No heap allocation is performed;
//! every intermediate value lives on the stack.  All loops are over fixed-size
//! arrays, and the compiler inlines them into a flat sequence of register moves
//! for a near-zero Wasm instruction overhead.
//!
//! ## Constant-time note
//!
//! The packing and unpacking routines visit every byte/word unconditionally, so
//! their execution time is independent of the field-element value — no
//! early-exit path exists.  This is appropriate for cryptographic use.

use crate::ZkError;
use ethnum::u256;

// ── Core word conversion ─────────────────────────────────────────────────────

/// Pack a 32-byte big-endian buffer into eight 32-bit words.
///
/// Word `i` receives bytes `[4i, 4i+1, 4i+2, 4i+3]` in big-endian order:
/// `words[i] = (bytes[4i] << 24) | (bytes[4i+1] << 16) | …`.
///
/// This is exactly the byte-to-word mapping that the SHA-256 message schedule
/// uses for the first 16 words of each 64-byte block, and it is the canonical
/// form needed before passing a field element as SHA-256 input.
///
/// # Arguments
/// * `bytes` — 32-byte big-endian encoding of a field element.
///
/// # Returns
/// `[u32; 8]` where `words[0]` is the most-significant 32 bits.
#[inline(always)]
pub fn pack_bytes_to_words(bytes: &[u8; 32]) -> [u32; 8] {
    let mut words = [0u32; 8];
    let mut i = 0usize;
    while i < 8 {
        words[i] = u32::from_be_bytes([
            bytes[4 * i],
            bytes[4 * i + 1],
            bytes[4 * i + 2],
            bytes[4 * i + 3],
        ]);
        i += 1;
    }
    words
}

/// Unpack eight 32-bit words into a 32-byte big-endian buffer.
///
/// Inverse of [`pack_bytes_to_words`]:
/// `bytes[4i..4i+4] = words[i].to_be_bytes()`.
///
/// # Arguments
/// * `words` — eight 32-bit SHA-256 words.
///
/// # Returns
/// 32-byte big-endian buffer suitable for converting back to a field element.
#[inline(always)]
pub fn unpack_words_to_bytes(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let mut i = 0usize;
    while i < 8 {
        let w = words[i].to_be_bytes();
        bytes[4 * i] = w[0];
        bytes[4 * i + 1] = w[1];
        bytes[4 * i + 2] = w[2];
        bytes[4 * i + 3] = w[3];
        i += 1;
    }
    bytes
}

// ── Field-element ↔ word-array bridges ──────────────────────────────────────

/// Convert a BN254 field element (`u256`) to its SHA-256 word representation.
///
/// The value is first serialised as a 32-byte big-endian buffer (the canonical
/// form used throughout the library), then packed into eight 32-bit words with
/// [`pack_bytes_to_words`].
///
/// # Errors
/// Returns [`ZkError::InvalidFieldElement`] if `field` is ≥ the BN254 scalar
/// field modulus.  The caller should treat any `Err` as a constraint violation;
/// attempting to hash an out-of-range value is always a programming error.
///
/// # Example
/// ```ignore
/// let words = field_to_words(fr_val).unwrap();
/// // words[0] holds the most-significant 32 bits of the field element.
/// ```
#[inline]
pub fn field_to_words(field: u256) -> Result<[u32; 8], ZkError> {
    if field >= crate::Bn254::FR_MODULUS {
        return Err(ZkError::InvalidFieldElement);
    }
    Ok(pack_bytes_to_words(&field.to_be_bytes()))
}

/// Convert a SHA-256 word array back into a BN254 field element.
///
/// The words are unpacked into a 32-byte big-endian buffer with
/// [`unpack_words_to_bytes`], then interpreted as a `u256`.
///
/// # Errors
/// Returns [`ZkError::InvalidFieldElement`] if the resulting 256-bit value
/// is ≥ the BN254 scalar field modulus.  SHA-256 digests can fall anywhere in
/// `[0, 2^256)`, so callers must handle this case (in practice, wrap-back into
/// the field with a modular reduction if needed).
///
/// # Example
/// ```ignore
/// let fr_val = words_to_field(&digest_words).unwrap();
/// ```
#[inline]
pub fn words_to_field(words: &[u32; 8]) -> Result<u256, ZkError> {
    let bytes = unpack_words_to_bytes(words);
    let val = u256::from_be_bytes(bytes);
    if val >= crate::Bn254::FR_MODULUS {
        return Err(ZkError::InvalidFieldElement);
    }
    Ok(val)
}

/// Convert a SHA-256 word array back into a `u256` raw value (no range check).
///
/// This is appropriate when the caller needs the raw 256-bit digest (e.g. to
/// store it in a 32-byte hash output) rather than a scalar field element.
/// Use [`words_to_field`] when you need a validated `Fr` value.
#[inline(always)]
pub fn words_to_u256(words: &[u32; 8]) -> u256 {
    u256::from_be_bytes(unpack_words_to_bytes(words))
}

// ── Multi-field packing ──────────────────────────────────────────────────────

/// Pack `N` field elements into a contiguous `[u32; N * 8]` word buffer.
///
/// Each field element contributes exactly 8 words (32 bytes), laid out
/// sequentially from the first element to the last.  This is the format
/// expected when pre-processing multiple BN254 scalars before a multi-block
/// SHA-256 hash.
///
/// The function is generic over `N` to keep the buffer on the stack; `N` must
/// be chosen at compile time.  For runtime-sized inputs use
/// [`pack_field_slice_into`].
///
/// # Errors
/// Returns [`ZkError::InvalidFieldElement`] on the first element that falls
/// outside `[0, r)`.
///
/// # Example
/// ```ignore
/// let words: [u32; 16] = pack_fields::<2>(&[a, b]).unwrap();
/// ```
#[inline]
pub fn pack_fields<const N: usize>(fields: &[u256; N]) -> Result<[u32; N], ZkError>
where
    [u32; N]: Sized,
{
    // We need N to be a multiple of 8 since each field element packs to 8 words.
    // Because const generics cannot yet express arithmetic constraints in stable
    // Rust, we assert at runtime (only affects debug builds / tests).
    debug_assert!(
        N % 8 == 0,
        "pack_fields: N must be a multiple of 8 (8 words per field element)"
    );

    let n_fields = N / 8;
    debug_assert_eq!(
        n_fields,
        fields.len(),
        "pack_fields: N/8 must equal fields.len()"
    );

    let mut out = [0u32; N];
    let mut i = 0usize;
    while i < n_fields {
        let words = field_to_words(fields[i])?;
        let base = i * 8;
        let mut j = 0usize;
        while j < 8 {
            out[base + j] = words[j];
            j += 1;
        }
        i += 1;
    }
    Ok(out)
}

/// Pack a runtime-length slice of field elements into a caller-supplied word
/// buffer.
///
/// Writes `fields.len() * 8` words into `out` starting at offset 0.
///
/// # Errors
/// - [`ZkError::InvalidInput`] if `out.len() < fields.len() * 8`.
/// - [`ZkError::InvalidFieldElement`] on any out-of-range field element.
///
/// # Example
/// ```ignore
/// let mut buf = [0u32; 24];
/// pack_field_slice_into(&[a, b, c], &mut buf).unwrap();
/// ```
#[inline]
pub fn pack_field_slice_into(fields: &[u256], out: &mut [u32]) -> Result<(), ZkError> {
    let needed = fields.len().wrapping_mul(8);
    if out.len() < needed {
        return Err(ZkError::InvalidInput);
    }
    let mut i = 0usize;
    while i < fields.len() {
        let words = field_to_words(fields[i])?;
        let base = i * 8;
        let mut j = 0usize;
        while j < 8 {
            out[base + j] = words[j];
            j += 1;
        }
        i += 1;
    }
    Ok(())
}

/// Unpack a word buffer into individual field elements.
///
/// Each group of 8 consecutive words is converted to one `u256` via
/// [`words_to_field`].  The output slice must have exactly `words.len() / 8`
/// elements.
///
/// # Errors
/// - [`ZkError::InvalidInput`] if `words.len()` is not a multiple of 8, or if
///   `out.len() != words.len() / 8`.
/// - [`ZkError::InvalidFieldElement`] on any word group whose value is ≥ `r`.
#[inline]
pub fn unpack_words_to_fields(words: &[u32], out: &mut [u256]) -> Result<(), ZkError> {
    if words.len() % 8 != 0 {
        return Err(ZkError::InvalidInput);
    }
    let n_fields = words.len() / 8;
    if out.len() != n_fields {
        return Err(ZkError::InvalidInput);
    }
    let mut i = 0usize;
    while i < n_fields {
        let base = i * 8;
        let group: [u32; 8] = [
            words[base],
            words[base + 1],
            words[base + 2],
            words[base + 3],
            words[base + 4],
            words[base + 5],
            words[base + 6],
            words[base + 7],
        ];
        out[i] = words_to_field(&group)?;
        i += 1;
    }
    Ok(())
}

// ── Digest helpers ───────────────────────────────────────────────────────────

/// Interpret a SHA-256 digest (`[u8; 32]`) as an eight-word array.
///
/// Convenience wrapper around [`pack_bytes_to_words`] for callers that already
/// hold a raw byte digest (e.g. from `sha2::Sha256::finalize()`).
#[inline(always)]
pub fn digest_bytes_to_words(digest: &[u8; 32]) -> [u32; 8] {
    pack_bytes_to_words(digest)
}

/// Reconstruct a SHA-256 digest byte array from an eight-word state.
///
/// Convenience wrapper around [`unpack_words_to_bytes`] for callers that hold
/// the state words of the SHA-256 compressor (e.g. `H[0..8]` after
/// compression).
#[inline(always)]
pub fn digest_words_to_bytes(words: &[u32; 8]) -> [u8; 32] {
    unpack_words_to_bytes(words)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Bn254;

    // ── pack_bytes_to_words ──────────────────────────────────────────────────

    #[test]
    fn pack_zero_bytes() {
        let bytes = [0u8; 32];
        let words = pack_bytes_to_words(&bytes);
        assert_eq!(words, [0u32; 8]);
    }

    #[test]
    fn pack_known_pattern() {
        // bytes[0..4] = [0x01, 0x02, 0x03, 0x04] → word 0 = 0x01020304
        let mut bytes = [0u8; 32];
        bytes[0] = 0x01;
        bytes[1] = 0x02;
        bytes[2] = 0x03;
        bytes[3] = 0x04;
        bytes[4] = 0xDE;
        bytes[5] = 0xAD;
        bytes[6] = 0xBE;
        bytes[7] = 0xEF;
        let words = pack_bytes_to_words(&bytes);
        assert_eq!(words[0], 0x01020304_u32);
        assert_eq!(words[1], 0xDEADBEEF_u32);
        assert_eq!(words[2], 0x00000000_u32);
    }

    #[test]
    fn pack_max_bytes() {
        let bytes = [0xFF_u8; 32];
        let words = pack_bytes_to_words(&bytes);
        assert_eq!(words, [u32::MAX; 8]);
    }

    // ── unpack_words_to_bytes ────────────────────────────────────────────────

    #[test]
    fn unpack_zero_words() {
        let words = [0u32; 8];
        let bytes = unpack_words_to_bytes(&words);
        assert_eq!(bytes, [0u8; 32]);
    }

    #[test]
    fn unpack_max_words() {
        let words = [u32::MAX; 8];
        let bytes = unpack_words_to_bytes(&words);
        assert_eq!(bytes, [0xFF_u8; 32]);
    }

    #[test]
    fn unpack_known_pattern() {
        let words = [0x01020304_u32, 0xDEADBEEF_u32, 0, 0, 0, 0, 0, 0];
        let bytes = unpack_words_to_bytes(&words);
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[1], 0x02);
        assert_eq!(bytes[2], 0x03);
        assert_eq!(bytes[3], 0x04);
        assert_eq!(bytes[4], 0xDE);
        assert_eq!(bytes[5], 0xAD);
        assert_eq!(bytes[6], 0xBE);
        assert_eq!(bytes[7], 0xEF);
    }

    // ── round-trip: pack → unpack ─────────────────────────────────────────────

    #[test]
    fn pack_unpack_round_trip_zeros() {
        let bytes = [0u8; 32];
        let recovered = unpack_words_to_bytes(&pack_bytes_to_words(&bytes));
        assert_eq!(recovered, bytes);
    }

    #[test]
    fn pack_unpack_round_trip_max() {
        let bytes = [0xFF_u8; 32];
        let recovered = unpack_words_to_bytes(&pack_bytes_to_words(&bytes));
        assert_eq!(recovered, bytes);
    }

    #[test]
    fn pack_unpack_round_trip_arbitrary() {
        let bytes: [u8; 32] = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
            0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93,
            0xf0, 0x00, 0x00, 0x00,
        ];
        let recovered = unpack_words_to_bytes(&pack_bytes_to_words(&bytes));
        assert_eq!(recovered, bytes);
    }

    // ── field_to_words ───────────────────────────────────────────────────────

    #[test]
    fn field_to_words_zero() {
        let words = field_to_words(u256::from(0u8)).unwrap();
        assert_eq!(words, [0u32; 8]);
    }

    #[test]
    fn field_to_words_one() {
        let words = field_to_words(u256::from(1u8)).unwrap();
        // 1 in big-endian 32 bytes: only the last byte is 0x01
        assert_eq!(words[7], 0x00000001_u32);
        assert_eq!(words[0], 0x00000000_u32);
    }

    #[test]
    fn field_to_words_known_value() {
        // 0xDEADBEEFCAFEBABE = decimal 16045690984833335998
        let v = u256::from(0xDEAD_BEEF_CAFE_BABE_u64);
        let words = field_to_words(v).unwrap();
        // The value fits in 8 bytes; the most-significant 6 words are 0.
        assert_eq!(words[6], 0xDEADBEEF_u32);
        assert_eq!(words[7], 0xCAFEBABE_u32);
        for &w in &words[0..6] {
            assert_eq!(w, 0u32);
        }
    }

    #[test]
    fn field_to_words_fr_modulus_minus_one() {
        // FR_MODULUS - 1 is the largest valid field element.
        let max_fr = Bn254::FR_MODULUS - u256::from(1u8);
        let words = field_to_words(max_fr).unwrap();
        // Reconstructing should give back the same value.
        let recovered = words_to_u256(&words);
        assert_eq!(recovered, max_fr);
    }

    #[test]
    fn field_to_words_rejects_fr_modulus() {
        assert_eq!(
            field_to_words(Bn254::FR_MODULUS),
            Err(ZkError::InvalidFieldElement)
        );
    }

    #[test]
    fn field_to_words_rejects_above_modulus() {
        assert_eq!(
            field_to_words(Bn254::FR_MODULUS + u256::from(1u8)),
            Err(ZkError::InvalidFieldElement)
        );
    }

    #[test]
    fn field_to_words_rejects_u256_max() {
        assert_eq!(field_to_words(u256::MAX), Err(ZkError::InvalidFieldElement));
    }

    // ── words_to_field ───────────────────────────────────────────────────────

    #[test]
    fn words_to_field_zero() {
        let result = words_to_field(&[0u32; 8]).unwrap();
        assert_eq!(result, u256::from(0u8));
    }

    #[test]
    fn words_to_field_one() {
        let mut words = [0u32; 8];
        words[7] = 1;
        let result = words_to_field(&words).unwrap();
        assert_eq!(result, u256::from(1u8));
    }

    #[test]
    fn words_to_field_rejects_above_modulus() {
        // All 0xFF bytes → u256::MAX >> fails range check.
        assert_eq!(
            words_to_field(&[u32::MAX; 8]),
            Err(ZkError::InvalidFieldElement)
        );
    }

    // ── round-trip: field → words → field ────────────────────────────────────

    #[test]
    fn field_round_trip_zero() {
        let v = u256::from(0u8);
        let words = field_to_words(v).unwrap();
        assert_eq!(words_to_u256(&words), v);
    }

    #[test]
    fn field_round_trip_one() {
        let v = u256::from(1u8);
        let words = field_to_words(v).unwrap();
        assert_eq!(words_to_u256(&words), v);
    }

    #[test]
    fn field_round_trip_large() {
        let v = u256::from_words(0x1234567890abcdef_u128, 0xdeadbeef00000000_u128);
        // Ensure it is in field range (it is: << FR_MODULUS hi limb).
        if v < Bn254::FR_MODULUS {
            let words = field_to_words(v).unwrap();
            assert_eq!(words_to_u256(&words), v);
        }
    }

    #[test]
    fn field_round_trip_fr_modulus_minus_one() {
        let v = Bn254::FR_MODULUS - u256::from(1u8);
        let words = field_to_words(v).unwrap();
        assert_eq!(words_to_u256(&words), v);
    }

    // ── pack_field_slice_into ─────────────────────────────────────────────────

    #[test]
    fn pack_field_slice_single() {
        let v = u256::from(42u8);
        let mut out = [0u32; 8];
        pack_field_slice_into(&[v], &mut out).unwrap();
        assert_eq!(words_to_u256(&out), v);
    }

    #[test]
    fn pack_field_slice_two() {
        let a = u256::from(1u8);
        let b = u256::from(2u8);
        let mut out = [0u32; 16];
        pack_field_slice_into(&[a, b], &mut out).unwrap();
        assert_eq!(words_to_u256(&out[0..8].try_into().unwrap()), a);
        assert_eq!(words_to_u256(&out[8..16].try_into().unwrap()), b);
    }

    #[test]
    fn pack_field_slice_buffer_too_small() {
        let v = u256::from(1u8);
        let mut out = [0u32; 7]; // needs 8 words but only 7 available
        assert_eq!(
            pack_field_slice_into(&[v], &mut out),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn pack_field_slice_rejects_out_of_range() {
        let bad = Bn254::FR_MODULUS;
        let mut out = [0u32; 8];
        assert_eq!(
            pack_field_slice_into(&[bad], &mut out),
            Err(ZkError::InvalidFieldElement)
        );
    }

    // ── unpack_words_to_fields ────────────────────────────────────────────────

    #[test]
    fn unpack_fields_round_trip() {
        let a = u256::from(10u8);
        let b = u256::from(20u8);
        let mut packed = [0u32; 16];
        pack_field_slice_into(&[a, b], &mut packed).unwrap();

        let mut fields = [u256::ZERO; 2];
        unpack_words_to_fields(&packed, &mut fields).unwrap();
        assert_eq!(fields[0], a);
        assert_eq!(fields[1], b);
    }

    #[test]
    fn unpack_fields_non_multiple_of_8() {
        let words = [0u32; 9]; // 9 is not a multiple of 8
        let mut out = [u256::ZERO; 1];
        assert_eq!(
            unpack_words_to_fields(&words, &mut out),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn unpack_fields_output_length_mismatch() {
        let words = [0u32; 16]; // 2 fields worth
        let mut out = [u256::ZERO; 3]; // but we only provide space for 3 (mismatch)
        assert_eq!(
            unpack_words_to_fields(&words, &mut out),
            Err(ZkError::InvalidInput)
        );
    }

    // ── digest helpers ────────────────────────────────────────────────────────

    #[test]
    fn digest_bytes_to_words_known_sha256_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let digest: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        let words = digest_bytes_to_words(&digest);
        // First 4 bytes of the digest: 0xe3, 0xb0, 0xc4, 0x42 → 0xe3b0c442
        assert_eq!(words[0], 0xe3b0c442_u32);
        assert_eq!(words[1], 0x98fc1c14_u32);
        // Reconstruct and verify.
        assert_eq!(digest_words_to_bytes(&words), digest);
    }

    #[test]
    fn digest_words_round_trip() {
        let digest: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        let words = digest_bytes_to_words(&digest);
        assert_eq!(digest_words_to_bytes(&words), digest);
    }

    // ── words_to_u256 (no range check) ───────────────────────────────────────

    #[test]
    fn words_to_u256_max_value() {
        // u256::MAX should be representable without error (no range check here).
        let words = [u32::MAX; 8];
        let val = words_to_u256(&words);
        assert_eq!(val, u256::MAX);
    }

    #[test]
    fn words_to_u256_zero() {
        let val = words_to_u256(&[0u32; 8]);
        assert_eq!(val, u256::from(0u8));
    }
}
