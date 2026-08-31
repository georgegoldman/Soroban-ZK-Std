//! SHA-256 hashing gadget (Issue #367, Phase 4).
//!
//! Converts one or more BN254 scalar field elements into their canonical
//! big-endian byte streams and evaluates the standard SHA-256 compression
//! function over them, returning the 256-bit digest as a field element. Because
//! the evaluation is pure (no host crypto call), a prover can commit to it in
//! circuit and a verifier can re-check the digest exactly.
//!
//! The byte-parsing step is the critical safety boundary: a field element is
//! *always* interpreted as a fixed 32-byte big-endian buffer, so two different
//! field values can never collapse to the same bit stream and a malicious
//! prover cannot reinterpret a witness.
//!
//! Implemented entirely on the stack (no heap allocation) so it is safe to run
//! inside a `no_std` Soroban contract guest.

use soroban_sdk::{Bytes, Env, U256};
use soroban_zk_core::ZkError;

// ── SHA-256 core (pure, no_std, stack-only) ─────────────────────────────────────

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Maximum message length (in bytes) accepted by the field hashing gadgets.
/// Keeps the padded-message buffer on the stack. Messages larger than this are
/// out of scope for a single on-chain hash call (and are better served by a
/// LUT-based Merkle tree).
pub const MAX_MSG_BYTES: usize = 2048;

/// Standard SHA-256 over a byte slice. The slice must be `<= [`MAX_MSG_BYTES`]`
/// after padding is applied; larger inputs panic (callers should pre-chunk).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = H0;
    let bit_len = (data.len() as u64).wrapping_mul(8);

    // Padded length (with 0x80, zero pad, 8-byte length), in 64-byte blocks.
    let pad_len = (64 - ((data.len() + 1 + 8) % 64)) % 64;
    let total = data.len() + 1 + pad_len + 8;
    debug_assert!(total.is_multiple_of(64));

    let mut block = [0u8; 64];
    let mut g = 0usize; // global byte index within the padded message
    while g < total {
        for (p, slot) in block.iter_mut().enumerate() {
            *slot = padded_byte(data, bit_len, total, g + p);
        }
        compress(&mut h, &block);
        g += 64;
    }

    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

/// Return the byte at a given global index of the SHA-256 padded message.
#[inline(always)]
fn padded_byte(data: &[u8], bit_len: u64, total: usize, g: usize) -> u8 {
    if g < data.len() {
        return data[g];
    }
    let pad_start = data.len();
    let len_start = total - 8;
    if g == pad_start {
        return 0x80;
    }
    if g >= len_start {
        // Last 8 bytes encode the bit length, big-endian.
        let idx = g - len_start; // 0..8
        return (bit_len >> (56 - 8 * idx)) as u8;
    }
    0x00
}

/// One SHA-256 compression of a 64-byte block.
fn compress(h: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[4 * i],
            block[4 * i + 1],
            block[4 * i + 2],
            block[4 * i + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut hh = h[7];

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);

        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

// ── Field-element wrappers ─────────────────────────────────────────────────────

/// Convert a field element into its canonical 32-byte big-endian buffer.
pub fn field_to_bytes(env: &Env, x: &U256) -> [u8; 32] {
    let mut b = [0u8; 32];
    x.to_be_bytes().copy_into_slice(&mut b);
    let _ = env;
    b
}

/// SHA-256 of a single field element, returned as a digest field element.
pub fn sha256_field(env: &Env, x: U256) -> U256 {
    let bytes = field_to_bytes(env, &x);
    digest_to_field(env, &sha256(&bytes))
}

/// SHA-256 over a concatenation of field elements (each 32 big-endian bytes),
/// returned as a digest field element. The message is assembled on the stack,
/// so the total length must be `<= [`MAX_MSG_BYTES`]`.
pub fn sha256_fields(env: &Env, fields: &[U256]) -> Result<U256, ZkError> {
    let total = fields.len().wrapping_mul(32);
    if total > MAX_MSG_BYTES {
        return Err(ZkError::InvalidInput);
    }
    let mut msg = [0u8; MAX_MSG_BYTES];
    for (i, f) in fields.iter().enumerate() {
        let bytes = field_to_bytes(env, f);
        msg[i * 32..i * 32 + 32].copy_from_slice(&bytes);
    }
    Ok(digest_to_field(env, &sha256(&msg[..total])))
}

/// Verify that `claimed` equals the SHA-256 digest of `fields`; a forged digest
/// is rejected by the verifier.
pub fn assert_sha256_fields(env: &Env, fields: &[U256], claimed: &U256) -> Result<(), ZkError> {
    if &sha256_fields(env, fields)? == claimed {
        Ok(())
    } else {
        Err(ZkError::ConstraintUnsatisfied)
    }
}

fn digest_to_field(env: &Env, digest: &[u8; 32]) -> U256 {
    U256::from_be_bytes(env, &Bytes::from_array(env, digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use soroban_sdk::Env;

    fn env() -> Env {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e
    }

    #[test]
    fn sha256_matches_reference_on_known_vector() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let expected =
            hex_to_bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(sha256(b"abc"), expected);
    }

    #[test]
    fn sha256_empty_matches_reference() {
        let expected =
            hex_to_bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(sha256(b""), expected);
    }

    #[test]
    fn sha256_field_matches_sha2_reference() {
        let env = env();
        let x = U256::from_u128(&env, 0xDEAD_BEEF_1234_5678);
        let bytes = field_to_bytes(&env, &x);
        let expected = Sha256::digest(bytes);
        let got = sha256_field(&env, x);
        let got_bytes = field_to_bytes(&env, &got);
        assert_eq!(&got_bytes[..], &expected[..]);
    }

    #[test]
    fn sha256_fields_matches_concat_reference() {
        let env = env();
        let a = U256::from_u128(&env, 1);
        let b = U256::from_u128(&env, 2);
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&field_to_bytes(&env, &a));
        bytes[32..].copy_from_slice(&field_to_bytes(&env, &b));
        let expected = Sha256::digest(&bytes[..]);
        let got = sha256_fields(&env, &[a, b]).unwrap();
        assert_eq!(&field_to_bytes(&env, &got)[..], &expected[..]);
    }

    #[test]
    fn assert_sha256_rejects_forged_digest() {
        let env = env();
        let a = U256::from_u128(&env, 42);
        let real = sha256_field(&env, a.clone());
        assert!(assert_sha256_fields(&env, core::slice::from_ref(&a), &real).is_ok());
        assert_eq!(
            assert_sha256_fields(&env, &[a], &U256::from_u128(&env, 0)),
            Err(ZkError::ConstraintUnsatisfied)
        );
    }

    fn hex_to_bytes(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        let b = s.as_bytes();
        for i in 0..32 {
            let hi = (b[2 * i] as char).to_digit(16).unwrap();
            let lo = (b[2 * i + 1] as char).to_digit(16).unwrap();
            out[i] = (hi * 16 + lo) as u8;
        }
        out
    }
}
