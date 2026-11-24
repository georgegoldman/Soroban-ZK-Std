// SPDX-License-Identifier: Apache-2.0

//! Integration tests for SHA-256 padding conformance (Issue #456).
//!
//! These tests validate the padding implementation against FIPS-180-4 known-
//! answer vectors and boundary conditions.  No Soroban host or std dependencies.

#![allow(clippy::needless_range_loop)]

use soroban_zk_core::sha256_padding::{
    pad_into, pad_message, padded_length, BLOCK_SIZE, MAX_PADDED_LEN,
};
use soroban_zk_core::ZkError;

// ── FIPS-180-4 known-answer tests ─────────────────────────────────────────────

/// NIST FIPS-180-4, §B.1: message = "abc" (3 bytes = 24 bits).
///
/// Expected padded block (hex, 64 bytes):
/// ```text
/// 61 62 63 80 00 00 00 00  00 00 00 00 00 00 00 00
/// 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
/// 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
/// 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 18
/// ```
#[test]
fn fips_b1_abc() {
    let mut buf = [0u8; 64];
    let n = pad_into(b"abc", &mut buf).expect("padding must succeed");

    assert_eq!(n, 64, "padded length for 3-byte input");
    assert_eq!(&buf[..3], b"abc", "message bytes preserved");
    assert_eq!(buf[3], 0x80, "marker byte");
    for i in 4..56 {
        assert_eq!(buf[i], 0x00, "zero fill at byte {i}");
    }
    // bit-length = 3 * 8 = 24 = 0x0000_0000_0000_0018
    assert_eq!(
        &buf[56..64],
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18],
        "big-endian bit-length"
    );
}

/// NIST FIPS-180-4, §B.2: 56-byte message that spills into a second block.
///
/// "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
#[test]
fn fips_b2_56_byte_message_spills_to_second_block() {
    let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    assert_eq!(msg.len(), 56);

    let pl = padded_length(56).expect("padded_length");
    assert_eq!(pl, 128, "56-byte input needs 2 blocks");

    let mut buf = [0u8; 128];
    let n = pad_into(msg, &mut buf).expect("padding must succeed");

    assert_eq!(n, 128);
    assert_eq!(&buf[..56], msg.as_ref(), "message bytes preserved");
    assert_eq!(buf[56], 0x80, "marker byte at index 56");
    for i in 57..120 {
        assert_eq!(buf[i], 0x00, "zero fill at byte {i}");
    }
    // bit-length = 56 * 8 = 448 = 0x0000_0000_0000_01C0
    assert_eq!(
        &buf[120..128],
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xC0],
        "big-endian bit-length"
    );
}

// ── Boundary conditions ───────────────────────────────────────────────────────

#[test]
fn boundary_empty_input() {
    let padded = pad_message(&[]).expect("empty input is valid");
    assert_eq!(padded.len, 64);
    assert_eq!(padded.data[0], 0x80, "marker byte at index 0");
    for i in 1..56 {
        assert_eq!(padded.data[i], 0x00, "zero fill at {i}");
    }
    assert_eq!(&padded.data[56..64], &[0u8; 8], "zero bit-length");
}

#[test]
fn boundary_one_byte_input() {
    let mut buf = [0u8; 64];
    let n = pad_into(&[0x42], &mut buf).expect("1-byte input is valid");
    assert_eq!(n, 64);
    assert_eq!(buf[0], 0x42, "original byte preserved");
    assert_eq!(buf[1], 0x80, "marker byte");
    for i in 2..56 {
        assert_eq!(buf[i], 0x00, "zero fill at {i}");
    }
    // bit-length = 1 * 8 = 8 = 0x0000_0000_0000_0008
    assert_eq!(
        &buf[56..64],
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08]
    );
}

/// 55 bytes: the tightest single-block fit (55 + 1 + 8 = 64).
#[test]
fn boundary_55_bytes_fits_exactly_in_one_block() {
    let input = [0xAAu8; 55];
    let mut buf = [0u8; 64];
    let n = pad_into(&input, &mut buf).expect("55-byte input is valid");

    assert_eq!(n, 64, "55-byte input fits in exactly one block");
    assert_eq!(&buf[..55], &[0xAAu8; 55]);
    assert_eq!(buf[55], 0x80, "marker immediately after last byte");
    // No zero-fill bytes — length field starts right after marker
    let expected_len = (55u64 * 8).to_be_bytes();
    assert_eq!(&buf[56..64], &expected_len);
}

/// 56 bytes: the smallest input that requires a second block.
#[test]
fn boundary_56_bytes_spills_to_second_block() {
    let input = [0xBBu8; 56];
    let mut buf = [0u8; MAX_PADDED_LEN];
    let n = pad_into(&input, &mut buf).expect("56-byte input is valid");

    assert_eq!(n, 128, "56-byte input requires two blocks");
    assert_eq!(&buf[..56], &[0xBBu8; 56]);
    assert_eq!(buf[56], 0x80, "marker at first byte of second block");
    for i in 57..120 {
        assert_eq!(buf[i], 0x00, "zero fill at {i}");
    }
    let expected_len = (56u64 * 8).to_be_bytes();
    assert_eq!(&buf[120..128], &expected_len);
}

#[test]
fn boundary_63_bytes_spills_to_second_block() {
    let input = [0xCCu8; 63];
    let mut buf = [0u8; MAX_PADDED_LEN];
    let n = pad_into(&input, &mut buf).expect("63-byte input is valid");

    assert_eq!(n, 128);
    assert_eq!(&buf[..63], &[0xCCu8; 63]);
    assert_eq!(buf[63], 0x80, "marker");
    for i in 64..120 {
        assert_eq!(buf[i], 0x00, "zero fill at {i}");
    }
    let expected_len = (63u64 * 8).to_be_bytes();
    assert_eq!(&buf[120..128], &expected_len);
}

#[test]
fn boundary_64_bytes_spills_to_second_block() {
    let input = [0xDDu8; 64];
    let mut buf = [0u8; MAX_PADDED_LEN];
    let n = pad_into(&input, &mut buf).expect("64-byte input is valid");

    assert_eq!(n, 128, "64-byte input requires two blocks");
    assert_eq!(&buf[..64], &[0xDDu8; 64]);
    assert_eq!(buf[64], 0x80, "marker at start of second block");
    for i in 65..120 {
        assert_eq!(buf[i], 0x00, "zero fill at {i}");
    }
    let expected_len = (64u64 * 8).to_be_bytes();
    assert_eq!(&buf[120..128], &expected_len);
}

// ── Error paths ───────────────────────────────────────────────────────────────

/// Inputs beyond the SHA-256 bit-length capacity must be rejected cleanly.
#[test]
fn error_input_exceeds_sha256_limit() {
    use soroban_zk_core::sha256_padding::MAX_INPUT_BYTES;
    assert_eq!(
        padded_length(MAX_INPUT_BYTES + 1),
        Err(ZkError::InvalidInput),
        "inputs beyond 2^61-1 bytes must produce InvalidInput"
    );
}

/// A buffer too small for the padded output must return `Err`, never panic.
#[test]
fn error_output_buffer_too_small() {
    let input = [0u8; 4];
    let mut tiny = [0u8; 8]; // need at least 64 bytes
    assert_eq!(
        pad_into(&input, &mut tiny),
        Err(ZkError::InvalidInput),
        "under-sized buffer must return Err"
    );
}

/// `pad_message` must return `Err` when the padded result won't fit its
/// internal fixed-size buffer (inputs ≥ 120 bytes need > 128 bytes padded).
#[test]
fn error_pad_message_oversized_input() {
    // padded_length(128) = 192 > MAX_PADDED_LEN (128)
    let input = [0u8; 128];
    assert_eq!(
        pad_message(&input),
        Err(ZkError::InvalidInput),
        "pad_message must Err for inputs whose padding won't fit MAX_PADDED_LEN"
    );
}

// ── Structural invariants ─────────────────────────────────────────────────────

/// Padded length is always a multiple of the SHA-256 block size (64 bytes).
#[test]
fn invariant_padded_length_always_multiple_of_block_size() {
    let test_lengths = [
        0usize, 1, 7, 32, 55, 56, 63, 64, 65, 100, 112, 119, 120, 127, 200, 255,
    ];
    for &len in &test_lengths {
        let pl = padded_length(len).expect("padded_length");
        assert_eq!(
            pl % BLOCK_SIZE,
            0,
            "padded_length({len}) = {pl} is not a multiple of {BLOCK_SIZE}"
        );
    }
}

/// The zero-fill region must be explicitly zeroed, even when the caller
/// provides a pre-dirtied output buffer.
#[test]
fn invariant_zero_fill_overwrites_dirty_buffer() {
    let input = [0x01u8; 10];
    let mut buf = [0xDEu8; 64]; // pre-fill with 0xDE garbage
    pad_into(&input, &mut buf).expect("padding must succeed");

    // bytes 11..56 are the zero-fill region for a 10-byte input
    for i in 11..56 {
        assert_eq!(
            buf[i], 0x00,
            "byte {i} must be zeroed even in a dirty buffer"
        );
    }
}

/// Length field encoding is big-endian (FIPS-180-4 §5.1.1).
/// 64 bytes of input = 512 bits = 0x0000_0000_0000_0200 big-endian.
#[test]
fn invariant_length_field_is_big_endian() {
    let input = [0u8; 64];
    let mut buf = [0u8; MAX_PADDED_LEN];
    pad_into(&input, &mut buf).expect("padding must succeed");

    let length_field = &buf[120..128];
    assert_eq!(
        length_field,
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00],
        "512 bits must be encoded as big-endian 0x0000000000000200"
    );
}

/// Constant-time property: padded length depends only on input *length*, not
/// on input *content*.
#[test]
fn invariant_padded_length_depends_only_on_length_not_content() {
    let zeros = [0x00u8; 32];
    let ones = [0xFFu8; 32];
    assert_eq!(
        padded_length(zeros.len()),
        padded_length(ones.len()),
        "padded_length must be identical for equal-length inputs regardless of content"
    );
}
