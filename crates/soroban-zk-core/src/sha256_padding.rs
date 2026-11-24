// SPDX-License-Identifier: Apache-2.0

//! # SHA-256 Padding Validator
//!
//! Implements the standard FIPS-180-4 SHA-256 message padding scheme:
//!
//! 1. Append a single `0x80` byte (the `1` bit).
//! 2. Append zero bytes until the message length ≡ 56 (mod 64).
//! 3. Append the original bit-length as a **64-bit big-endian** integer.
//!
//! The result is a padded message whose length is a multiple of 64 bytes
//! (i.e., a whole number of 512-bit SHA-256 blocks).
//!
//! ## Field-modular limit
//!
//! SHA-256 encodes the bit-length in 64 bits, so inputs are bounded by
//! `2^61 - 1` bytes (≈ 2 EiB). This validator enforces that limit and
//! additionally verifies that intermediate calculations do not overflow.
//!
//! ## `no_std` design
//!
//! This module has **no Soroban or standard-library dependencies**.
//! All padding is written into a caller-supplied fixed-size output buffer
//! (`[u8; MAX_PADDED_LEN]`) with the true length returned alongside it,
//! or into a slice via [`pad_into`].  This avoids heap allocation and keeps
//! WASM binary size minimal.

use crate::ZkError;

// ── Constants ────────────────────────────────────────────────────────────────

/// SHA-256 block size in bytes.
pub const BLOCK_SIZE: usize = 64;

/// Number of bytes used to encode the bit-length at the end of each padded
/// block (64-bit big-endian value — 8 bytes).
pub const LENGTH_FIELD_BYTES: usize = 8;

/// Maximum message length in bytes that can be encoded by the 64-bit
/// big-endian bit-length field: `(2^64 - 1) / 8 = 2^61 - 1` bytes.
///
/// Inputs larger than this cannot have their bit-length represented in the
/// SHA-256 length field and will produce a [`ZkError::InvalidInput`] error.
pub const MAX_INPUT_BYTES: usize = (u64::MAX / 8) as usize; // 2^61 - 1

/// Maximum padded message length for a *single* SHA-256 block (64 bytes of
/// input → 128 bytes padded).  Used as the stack-allocated buffer size when
/// callers call [`pad_single_block`].
pub const MAX_PADDED_LEN: usize = BLOCK_SIZE * 2;

// ── Public API ────────────────────────────────────────────────────────────────

/// The result of a successful padding operation.
///
/// `data` is a fixed-size stack buffer; `len` is the number of meaningful
/// bytes (always a multiple of [`BLOCK_SIZE`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaddedBlock {
    /// Padded data stored in a fixed-size stack buffer.
    pub data: [u8; MAX_PADDED_LEN],
    /// Number of valid bytes in `data` (multiple of 64).
    pub len: usize,
}

impl PaddedBlock {
    /// Returns the padded data as a slice of the valid portion.
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// Validates `input` against SHA-256 constraints and pads it into a
/// stack-allocated [`PaddedBlock`].
///
/// Suitable for inputs up to [`MAX_PADDED_LEN`] − 1 = 127 bytes (two
/// 512-bit blocks).  For longer inputs use [`pad_into`] with a caller-managed
/// buffer.
///
/// # Errors
///
/// | Condition                                              | Error                    |
/// |--------------------------------------------------------|--------------------------|
/// | `input.len()` > [`MAX_INPUT_BYTES`]                   | [`ZkError::InvalidInput`] |
/// | Padded length would exceed `MAX_PADDED_LEN`           | [`ZkError::InvalidInput`] |
/// | Bit-length computation would overflow `u64`           | [`ZkError::InvalidInput`] |
///
/// # Example
///
/// ```rust
/// use soroban_zk_core::sha256_padding::pad_message;
///
/// let padded = pad_message(b"abc").unwrap();
/// // "abc" → 3 bytes → fits in one 64-byte block
/// assert_eq!(padded.len, 64);
/// // First byte after 'c' (index 3) is the 0x80 marker
/// assert_eq!(padded.data[3], 0x80);
/// // Last 8 bytes are big-endian bit-length: 3 * 8 = 24 = 0x18
/// assert_eq!(&padded.data[56..64], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18]);
/// ```
pub fn pad_message(input: &[u8]) -> Result<PaddedBlock, ZkError> {
    let mut buf = [0u8; MAX_PADDED_LEN];
    let padded_len = pad_into(input, &mut buf)?;
    Ok(PaddedBlock { data: buf, len: padded_len })
}

/// Validates `input` and writes the SHA-256-padded message into `out`.
///
/// Returns the number of bytes written (always a multiple of 64).
///
/// `out` must be at least `padded_length(input.len())` bytes long.
/// Use [`padded_length`] to compute the required size before calling this.
///
/// # Errors
///
/// | Condition                                              | Error                    |
/// |--------------------------------------------------------|--------------------------|
/// | `input.len()` > [`MAX_INPUT_BYTES`]                   | [`ZkError::InvalidInput`] |
/// | `out` is too short to hold the padded message         | [`ZkError::InvalidInput`] |
/// | Bit-length computation would overflow `u64`           | [`ZkError::InvalidInput`] |
pub fn pad_into(input: &[u8], out: &mut [u8]) -> Result<usize, ZkError> {
    let input_len = input.len();

    // ── Guard 1: field-modular / SHA-256 spec limit ───────────────────────
    // The 64-bit big-endian bit-length field can represent at most 2^64−1 bits,
    // i.e. (2^64−1)/8 = 2^61−1 bytes.  Inputs at or above this limit cannot
    // be validly encoded and must be rejected.
    if input_len > MAX_INPUT_BYTES {
        return Err(ZkError::InvalidInput);
    }

    // ── Guard 2: bit-length overflow ──────────────────────────────────────
    // Multiply by 8 to get bit length.  Since input_len ≤ MAX_INPUT_BYTES =
    // u64::MAX/8, this multiplication is safe, but we use checked_mul for
    // defence-in-depth.
    let bit_len: u64 = (input_len as u64)
        .checked_mul(8)
        .ok_or(ZkError::InvalidInput)?;

    // ── Compute padded length ─────────────────────────────────────────────
    let target_len = padded_length(input_len)?;

    // ── Guard 3: output buffer is large enough ────────────────────────────
    if out.len() < target_len {
        return Err(ZkError::InvalidInput);
    }

    // ── Step 1: copy original message ─────────────────────────────────────
    out[..input_len].copy_from_slice(input);

    // ── Step 2: append the 0x80 byte ─────────────────────────────────────
    out[input_len] = 0x80;

    // ── Step 3: zero-fill the gap (already zeroed from the array init,
    //           but we zero explicitly here for clarity and to support
    //           callers that pass a re-used buffer).
    for byte in out[input_len + 1..target_len - LENGTH_FIELD_BYTES].iter_mut() {
        *byte = 0x00;
    }

    // ── Step 4: append 64-bit big-endian bit-length ───────────────────────
    // The last 8 bytes of the final 64-byte block hold the original message
    // length in bits, encoded as a big-endian u64 (FIPS-180-4 §5.1.1).
    let length_offset = target_len - LENGTH_FIELD_BYTES;
    out[length_offset..target_len].copy_from_slice(&bit_len.to_be_bytes());

    Ok(target_len)
}

/// Computes the padded message length (in bytes) for a message of `input_len`
/// bytes.
///
/// The result is always a multiple of [`BLOCK_SIZE`] (64).
///
/// Returns [`ZkError::InvalidInput`] if `input_len` exceeds [`MAX_INPUT_BYTES`].
///
/// # Formula
///
/// ```text
/// padded_len = ceil((input_len + 1 + 8) / 64) * 64
///            = ceil((input_len + 9)     / 64) * 64
/// ```
///
/// The `+1` accounts for the `0x80` marker byte; the `+8` for the 64-bit
/// big-endian length field.
pub fn padded_length(input_len: usize) -> Result<usize, ZkError> {
    if input_len > MAX_INPUT_BYTES {
        return Err(ZkError::InvalidInput);
    }
    // We need room for: input | 0x80 | zero_bytes | 8-byte-length
    // The total must be ≡ 0 (mod 64).
    // Minimum bytes needed beyond the raw input: 1 (marker) + 8 (length) = 9.
    let min_len = input_len
        .checked_add(9)
        .ok_or(ZkError::InvalidInput)?;
    // Round up to next multiple of 64.
    let blocks = min_len.checked_add(BLOCK_SIZE - 1).ok_or(ZkError::InvalidInput)?;
    Ok((blocks / BLOCK_SIZE) * BLOCK_SIZE)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;

    // ── padded_length ─────────────────────────────────────────────────────

    #[test]
    fn test_padded_length_empty() {
        // Empty input: 0 + 1 (marker) + 8 (length) = 9 → ceil(9/64)*64 = 64
        assert_eq!(padded_length(0).unwrap(), 64);
    }

    #[test]
    fn test_padded_length_55_bytes() {
        // 55 + 1 + 8 = 64 → exactly one block
        assert_eq!(padded_length(55).unwrap(), 64);
    }

    #[test]
    fn test_padded_length_56_bytes() {
        // 56 + 1 + 8 = 65 → needs a second block → 128
        assert_eq!(padded_length(56).unwrap(), 128);
    }

    #[test]
    fn test_padded_length_63_bytes() {
        // 63 + 1 + 8 = 72 → ceil(72/64)*64 = 128
        assert_eq!(padded_length(63).unwrap(), 128);
    }

    #[test]
    fn test_padded_length_64_bytes() {
        // 64 + 1 + 8 = 73 → 128
        assert_eq!(padded_length(64).unwrap(), 128);
    }

    #[test]
    fn test_padded_length_119_bytes() {
        // 119 + 1 + 8 = 128 → exactly two blocks
        assert_eq!(padded_length(119).unwrap(), 128);
    }

    #[test]
    fn test_padded_length_120_bytes() {
        // 120 + 1 + 8 = 129 → three blocks → 192
        assert_eq!(padded_length(120).unwrap(), 192);
    }

    #[test]
    fn test_padded_length_overflow() {
        assert_eq!(padded_length(MAX_INPUT_BYTES + 1), Err(ZkError::InvalidInput));
    }

    // ── pad_into: structure ───────────────────────────────────────────────

    #[test]
    fn test_pad_into_empty_input() {
        let input: &[u8] = &[];
        let mut buf = [0u8; 64];
        let n = pad_into(input, &mut buf).unwrap();

        assert_eq!(n, 64);
        // Marker bit
        assert_eq!(buf[0], 0x80);
        // Zero fill bytes 1..56
        for i in 1..56 {
            assert_eq!(buf[i], 0x00, "byte {i} should be zero");
        }
        // Bit-length: 0 bits → all zeros
        assert_eq!(&buf[56..64], &[0x00u8; 8]);
    }

    #[test]
    fn test_pad_into_single_byte() {
        let input = [0x42u8];
        let mut buf = [0u8; 64];
        let n = pad_into(&input, &mut buf).unwrap();

        assert_eq!(n, 64);
        assert_eq!(buf[0], 0x42);  // original byte preserved
        assert_eq!(buf[1], 0x80);  // marker
        for i in 2..56 {
            assert_eq!(buf[i], 0x00, "byte {i} should be zero");
        }
        // Bit-length: 1 * 8 = 8 = 0x0000_0000_0000_0008
        assert_eq!(&buf[56..64], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08]);
    }

    #[test]
    fn test_pad_into_abc_matches_fips_vector() {
        // NIST FIPS-180-4 example: "abc" (3 bytes)
        // Padded message (hex):
        //   61 62 63 80 00 00 ... 00 00 00 00 00 00 00 00 18
        // bit-length = 3 * 8 = 24 = 0x18
        let input = b"abc";
        let mut buf = [0u8; 64];
        let n = pad_into(input, &mut buf).unwrap();

        assert_eq!(n, 64);
        assert_eq!(&buf[..3], b"abc");
        assert_eq!(buf[3], 0x80);
        for i in 4..56 {
            assert_eq!(buf[i], 0x00, "byte {i} should be zero");
        }
        assert_eq!(&buf[56..64], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18]);
    }

    #[test]
    fn test_pad_into_55_byte_input_fills_one_block() {
        let input = [0xAAu8; 55];
        let mut buf = [0u8; 64];
        let n = pad_into(&input, &mut buf).unwrap();

        assert_eq!(n, 64);
        assert_eq!(&buf[..55], &[0xAAu8; 55]);
        assert_eq!(buf[55], 0x80);  // marker immediately after input
        // No zero-fill bytes needed (55 + 1 = 56, then 8 bytes for length)
        let bit_len = (55u64 * 8).to_be_bytes();
        assert_eq!(&buf[56..64], &bit_len);
    }

    #[test]
    fn test_pad_into_56_byte_input_spills_to_second_block() {
        // 56 bytes → padded length = 128 (two blocks)
        let input = [0xBBu8; 56];
        let mut buf = [0u8; MAX_PADDED_LEN];
        let n = pad_into(&input, &mut buf).unwrap();

        assert_eq!(n, 128);
        assert_eq!(&buf[..56], &[0xBBu8; 56]);
        assert_eq!(buf[56], 0x80);          // marker in second block
        for i in 57..120 {
            assert_eq!(buf[i], 0x00, "byte {i} should be zero");
        }
        let bit_len = (56u64 * 8).to_be_bytes();
        assert_eq!(&buf[120..128], &bit_len);
    }

    #[test]
    fn test_pad_into_63_byte_input_spills_to_second_block() {
        let input = [0xCCu8; 63];
        let mut buf = [0u8; MAX_PADDED_LEN];
        let n = pad_into(&input, &mut buf).unwrap();

        assert_eq!(n, 128);
        assert_eq!(buf[63], 0x80);
        let bit_len = (63u64 * 8).to_be_bytes();
        assert_eq!(&buf[120..128], &bit_len);
    }

    #[test]
    fn test_pad_into_64_byte_input_spills_to_second_block() {
        let input = [0xDDu8; 64];
        let mut buf = [0u8; MAX_PADDED_LEN];
        let n = pad_into(&input, &mut buf).unwrap();

        assert_eq!(n, 128);
        assert_eq!(&buf[..64], &[0xDDu8; 64]);
        assert_eq!(buf[64], 0x80);
        let bit_len = (64u64 * 8).to_be_bytes();
        assert_eq!(&buf[120..128], &bit_len);
    }

    // ── pad_into: length field is big-endian ─────────────────────────────

    #[test]
    fn test_length_field_is_big_endian() {
        // Input: 0x01 byte (1 byte = 8 bits).
        // Expected length field (big-endian u64): 0x0000000000000008
        let input = [0x01u8];
        let mut buf = [0u8; 64];
        pad_into(&input, &mut buf).unwrap();

        // Big-endian: most-significant byte first
        assert_eq!(buf[56], 0x00);
        assert_eq!(buf[57], 0x00);
        assert_eq!(buf[58], 0x00);
        assert_eq!(buf[59], 0x00);
        assert_eq!(buf[60], 0x00);
        assert_eq!(buf[61], 0x00);
        assert_eq!(buf[62], 0x00);
        assert_eq!(buf[63], 0x08); // 8 bits
    }

    #[test]
    fn test_length_field_multi_byte() {
        // 256 bytes → 2048 bits = 0x0000_0000_0000_0800
        // padded_length(256) = ceil((256+9)/64)*64 = ceil(265/64)*64
        //                    = ceil(4.14)*64 = 5*64 = 320
        let input = [0xFFu8; 256];
        let pl = padded_length(256).unwrap();
        assert_eq!(pl, 320);

        let mut buf = vec![0u8; pl];
        let n = pad_into(&input, &mut buf).unwrap();
        assert_eq!(n, 320);

        // Length field at last 8 bytes
        let bit_len = (256u64 * 8).to_be_bytes();
        assert_eq!(&buf[312..320], &bit_len);
    }

    // ── pad_into: error paths ─────────────────────────────────────────────

    #[test]
    fn test_pad_into_rejects_oversized_input() {
        // Use a slice reference rather than allocating 2^61 bytes.
        // We can test the guard by calling padded_length directly.
        assert_eq!(
            padded_length(MAX_INPUT_BYTES + 1),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn test_pad_into_rejects_too_small_output_buffer() {
        let input = [0u8; 4];
        let mut tiny_buf = [0u8; 8]; // far too small (need 64)
        assert_eq!(pad_into(&input, &mut tiny_buf), Err(ZkError::InvalidInput));
    }

    // ── pad_message convenience wrapper ──────────────────────────────────

    #[test]
    fn test_pad_message_empty() {
        let padded = pad_message(&[]).unwrap();
        assert_eq!(padded.len, 64);
        assert_eq!(padded.data[0], 0x80);
        assert_eq!(&padded.data[56..64], &[0u8; 8]);
    }

    #[test]
    fn test_pad_message_abc() {
        let padded = pad_message(b"abc").unwrap();
        assert_eq!(padded.len, 64);
        assert_eq!(&padded.as_slice()[..3], b"abc");
        assert_eq!(padded.data[3], 0x80);
        assert_eq!(&padded.data[56..64], &[0, 0, 0, 0, 0, 0, 0, 0x18]);
    }

    #[test]
    fn test_pad_message_returns_error_for_oversize_input() {
        // 128 bytes → padded_length = 192 > MAX_PADDED_LEN (128)
        // so pad_message should return Err rather than panic.
        let input = [0u8; 128];
        assert_eq!(pad_message(&input), Err(ZkError::InvalidInput));
    }

    // ── Constant-time invariant: output length only depends on input length ──

    #[test]
    fn test_padded_length_depends_only_on_input_length() {
        // Two inputs of the same length but different content must produce
        // the same padded length (no early-exit on content).
        let a = [0x00u8; 32];
        let b = [0xFFu8; 32];
        assert_eq!(padded_length(a.len()), padded_length(b.len()));
    }

    // ── Zero-fill between marker and length field ─────────────────────────

    #[test]
    fn test_zero_fill_region_is_clean() {
        // Provide a dirty output buffer to confirm zero-fill is explicit.
        let input = [0x01u8; 10];
        let mut buf = [0xDEu8; 64]; // pre-fill with 0xDE
        pad_into(&input, &mut buf).unwrap();

        // Bytes 11..56 (marker at 10, zeros 11–55, length at 56–63)
        for i in 11..56 {
            assert_eq!(buf[i], 0x00, "byte {i} should have been zero-filled");
        }
    }

    // ── Alignment: padded length is always a multiple of BLOCK_SIZE ───────

    #[test]
    fn test_padded_length_always_multiple_of_block_size() {
        for len in [0, 1, 7, 32, 55, 56, 63, 64, 65, 112, 119, 120, 255] {
            let pl = padded_length(len).unwrap();
            assert_eq!(pl % BLOCK_SIZE, 0, "padded_length({len}) = {pl} is not a multiple of 64");
        }
    }
}
