//! Hash-to-Curve for BN254 G1 (try-and-increment).
//!
//! Many ZK protocols need to map arbitrary data to a curve point `H(m) → G1`,
//! for example to derive a deterministic commitment base from an asset id, a
//! vote option, or a Fiat-Shamir transcript hash.
//!
//! This module implements the *try-and-increment* construction:
//!
//! 1. Compute `x = Poseidon2(DST || message || counter)` for `counter = 0, 1, …`.
//! 2. Compute `rhs = x³ + 3 (mod p)`, the right-hand side of the BN254 curve
//!    equation `y² = x³ + 3` over the base field `Fq`.
//! 3. If `rhs` is a quadratic residue, set `y = sqrt(rhs)` and return `(x, y)`.
//! 4. Otherwise increment `counter` and retry.
//!
//! # Security model
//!
//! Try-and-increment is **not constant-time**: the number of iterations depends
//! on the input, which leaks information through timing. It is therefore only
//! safe for **public** data (the `message` is not secret) — anonymous-voting
//! options, asset identifiers, transcript hashes, and similar. For secret
//! inputs, a constant-time map such as SWU (Simplified Shallue–van de
//! Woestijne–Ulas) must be used instead.
//!
//! Each `x` candidate is a quadratic residue with probability ≈ 1/2, so the
//! iteration count is geometrically distributed with mean 2. The counter is
//! capped at [`MAX_COUNTER`] iterations; the probability of exceeding it is
//! ≈ `2^-256`, at which point [`hash_to_g1`] returns `None` rather than
//! panicking.
//!
//! # Domain separation
//!
//! The hash input is prefixed with the domain separation tag [`DST`]. Domain
//! separation ensures that points produced by this hash-to-curve routine can
//! never collide with field elements produced by a bare Poseidon2 hash of the
//! same bytes, nor with points produced by a future, differently-tagged
//! construction (e.g. a SWU map, or a `v2` revision of this one). Protocols that
//! rely on `H(m)` being an independent, unpredictable generator depend on this
//! separation for their security proofs.

use ethnum::u256 as eth_u256;
use soroban_sdk::{Bytes, Env, Vec, U256};
use zk_core::{Bn254, G1Affine};

use crate::poseidon2::Poseidon2Sponge;

/// Domain separation tag prefixed to every hash-to-curve input.
///
/// Versioned (`-v1`) so a future construction can adopt a distinct tag without
/// colliding with points produced here. See the module-level documentation for
/// the rationale.
pub const DST: &[u8] = b"soroban-zk-std-hash-to-g1-v1";

/// Maximum number of `try-and-increment` iterations before giving up.
///
/// Each iteration succeeds with probability ≈ 1/2, so the chance of all
/// [`MAX_COUNTER`] iterations failing is ≈ `2^-256` — negligible.
pub const MAX_COUNTER: u32 = 256;

/// Hashes arbitrary bytes to a BN254 G1 point using try-and-increment.
///
/// Returns `Some(point)` where `point` is guaranteed to satisfy the curve
/// equation `y² = x³ + 3`. Returns `None` only if all [`MAX_COUNTER`]
/// candidate `x` values were non-residues (probability ≈ `2^-256`).
///
/// The output is deterministic: the same `message` always maps to the same
/// point. The construction is **not** constant-time and must only be used with
/// public (non-secret) `message` data — see the module-level security model.
pub fn hash_to_g1(message: &[u8], env: &Env) -> Option<G1Affine> {
    hash_to_g1_capped(message, env, MAX_COUNTER)
}

/// [`hash_to_g1`] with an explicit iteration cap, used internally and by tests
/// to exercise the counter-overflow path.
fn hash_to_g1_capped(message: &[u8], env: &Env, max_counter: u32) -> Option<G1Affine> {
    let field_elements = message_to_field_elements(env, message);

    for counter in 0..max_counter {
        let x = candidate_x(env, &field_elements, counter);
        if let Some(point) = point_from_x(x) {
            return Some(point);
        }
    }
    None
}

/// Derives the next candidate `x` coordinate as `Poseidon2(field_elements || counter)`.
///
/// The Poseidon2 output lies in `[0, r)` where `r < p`, so it is always a valid
/// `Fq` base-field element.
fn candidate_x(env: &Env, field_elements: &Vec<U256>, counter: u32) -> eth_u256 {
    let mut sponge = Poseidon2Sponge::new(env);
    for fe in field_elements.iter() {
        sponge.absorb(core::slice::from_ref(&fe));
    }
    let counter_fe = U256::from_u128(env, counter as u128);
    sponge.absorb(core::slice::from_ref(&counter_fe));
    to_eth_u256(&sponge.squeeze())
}

/// Attempts to lift an `x` coordinate to a curve point.
///
/// Returns `Some((x, y))` with the canonical (smaller) square root of
/// `x³ + 3` when that value is a quadratic residue, otherwise `None`.
fn point_from_x(x: eth_u256) -> Option<G1Affine> {
    let x_sq = Bn254::mul_fq(x, x);
    let x_cb = Bn254::mul_fq(x_sq, x);
    let rhs = Bn254::add_fq(x_cb, Bn254::G1_B);

    if !is_quadratic_residue(rhs) {
        return None;
    }

    let y = sqrt_fq(rhs);
    // Pick the canonical root deterministically: the numerically smaller of
    // `y` and `p - y`.
    let neg_y = Bn254::sub_fq(eth_u256::from(0u8), y);
    let y = if y <= neg_y { y } else { neg_y };

    Some(G1Affine { x, y })
}

/// Tests whether `a` is a quadratic residue in `Fq` via the Legendre symbol
/// `a^((p-1)/2) == 1`.
fn is_quadratic_residue(a: eth_u256) -> bool {
    pow_fq(a, Bn254::LEGENDRE_EXP_FQ) == eth_u256::from(1u8)
}

/// Computes a square root in `Fq`.
///
/// BN254's base-field modulus satisfies `p ≡ 3 (mod 4)`, so for any quadratic
/// residue `a` the value `a^((p+1)/4)` is a square root of `a`. The caller must
/// have established that `a` is a residue (see [`is_quadratic_residue`]).
fn sqrt_fq(a: eth_u256) -> eth_u256 {
    // (p + 1) / 4. `p ≡ 3 (mod 4)` guarantees the division is exact.
    let exp = (Bn254::FQ_MODULUS + eth_u256::from(1u8)) >> 2;
    pow_fq(a, exp)
}

/// Modular exponentiation in `Fq` (square-and-multiply).
fn pow_fq(mut base: eth_u256, mut exp: eth_u256) -> eth_u256 {
    let mut result = eth_u256::from(1u8);
    while exp > 0 {
        if exp & eth_u256::from(1u8) != eth_u256::from(0u8) {
            result = Bn254::mul_fq(result, base);
        }
        base = Bn254::mul_fq(base, base);
        exp >>= 1;
    }
    result
}

/// Packs `DST || message` into BN254 field elements, 31 bytes per element
/// (big-endian), so every chunk is strictly below the field modulus.
///
/// `DST` is non-empty, so the returned vector always holds at least one element.
fn message_to_field_elements(env: &Env, message: &[u8]) -> Vec<U256> {
    let total = DST.len() + message.len();
    let byte_at = |k: usize| -> u8 {
        if k < DST.len() {
            DST[k]
        } else {
            message[k - DST.len()]
        }
    };

    let mut out = Vec::new(env);
    let mut i = 0usize;
    while i < total {
        let chunk_len = core::cmp::min(31, total - i);
        let mut block = [0u8; 32];
        for j in 0..chunk_len {
            block[32 - chunk_len + j] = byte_at(i + j);
        }
        out.push_back(U256::from_be_bytes(env, &Bytes::from_array(env, &block)));
        i += chunk_len;
    }
    out
}

/// Converts a Soroban host [`U256`] into an `ethnum` `u256` via big-endian bytes.
fn to_eth_u256(value: &U256) -> eth_u256 {
    let mut bytes = [0u8; 32];
    value.to_be_bytes().copy_into_slice(&mut bytes);
    eth_u256::from_be_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Env {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e
    }

    #[test]
    fn is_deterministic() {
        let env = env();
        let a = hash_to_g1(b"asset-001", &env).unwrap();
        let b = hash_to_g1(b"asset-001", &env).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_inputs_give_distinct_points() {
        let env = env();
        let a = hash_to_g1(b"vote-yes", &env).unwrap();
        let b = hash_to_g1(b"vote-no", &env).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn output_is_always_on_curve() {
        let env = env();
        for msg in [
            b"".as_slice(),
            b"a".as_slice(),
            b"asset-001".as_slice(),
            b"a slightly longer message that spans multiple field-element chunks!!".as_slice(),
        ] {
            let p = hash_to_g1(msg, &env).unwrap();
            assert!(
                Bn254::is_valid_g1(p.x, p.y),
                "hash_to_g1 produced an off-curve point for {msg:?}"
            );
        }
    }

    #[test]
    fn empty_input_succeeds() {
        let env = env();
        let p = hash_to_g1(b"", &env).unwrap();
        assert!(Bn254::is_valid_g1(p.x, p.y));
    }

    #[test]
    fn canonical_root_is_the_smaller_one() {
        let env = env();
        let p = hash_to_g1(b"asset-001", &env).unwrap();
        let neg_y = Bn254::sub_fq(eth_u256::from(0u8), p.y);
        assert!(p.y <= neg_y, "expected the numerically smaller root");
    }

    #[test]
    fn counter_overflow_returns_none_without_panicking() {
        // A cap of zero performs no iterations, so the function must return
        // `None` rather than panicking.
        let env = env();
        assert!(hash_to_g1_capped(b"asset-001", &env, 0).is_none());
    }
}
