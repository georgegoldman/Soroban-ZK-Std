//! Base boolean & bitwise circuit building blocks (Issue #367, Phase 1).
//!
//! Every gadget here is a *constraint gadget*: it both computes the expected
//! output and verifies that the supplied witness values satisfy the algebraic
//! relation a verifier would enforce. A malicious prover cannot forge a bit
//! representation, overflow a limb, or produce a witness that fails any of the
//! [`ZkError::ConstraintUnsatisfied`] checks below.
//!
//! All values are BN254 scalar field elements carried in a Soroban [`U256`].
//! Bit-level work is performed on [`ethnum::u256`] which is a dependency of the
//! crate; the gadget layer converts at the boundary so callers only see [`U256`].

use ethnum::u256 as eth_u256;
use soroban_sdk::{Bytes, Env, Vec, U256};
use soroban_zk_core::ZkError;

/// Abstraction over a sequence of boolean field elements, implemented for both
/// `soroban_sdk::Vec<U256>` and fixed `[U256; N]` arrays so the gate helpers
/// accept either representation.
pub trait Bits {
    /// Number of bits.
    fn bits_len(&self) -> u32;
    /// The `i`-th bit.
    fn bits_get(&self, i: u32) -> U256;
}

impl Bits for Vec<U256> {
    fn bits_len(&self) -> u32 {
        self.len()
    }
    fn bits_get(&self, i: u32) -> U256 {
        self.get(i).unwrap()
    }
}

impl<const N: usize> Bits for [U256; N] {
    fn bits_len(&self) -> u32 {
        N as u32
    }
    fn bits_get(&self, i: u32) -> U256 {
        self[i as usize].clone()
    }
}

// ── Boundary conversions ───────────────────────────────────────────────────────

/// Convert a Soroban [`U256`] into an [`ethnum::u256`] for bit/arithmetic work.
#[inline(always)]
pub(crate) fn to_eth(v: &U256) -> eth_u256 {
    let mut b = [0u8; 32];
    v.to_be_bytes().copy_into_slice(&mut b);
    eth_u256::from_be_bytes(b)
}

/// Convert an [`ethnum::u256`] back into a Soroban [`U256`].
#[inline(always)]
pub(crate) fn from_eth(env: &Env, v: eth_u256) -> U256 {
    U256::from_be_bytes(env, &Bytes::from_array(env, &v.to_be_bytes()))
}

/// Build the [`U256`] value `0`.
#[inline(always)]
pub(crate) fn u256_zero(env: &Env) -> U256 {
    U256::from_u128(env, 0)
}

/// Build the [`U256`] value `1`.
#[inline(always)]
pub(crate) fn u256_one(env: &Env) -> U256 {
    U256::from_u128(env, 1)
}

// ── Boolean safety ─────────────────────────────────────────────────────────────

/// Constrain `bit` to be exactly `0` or `1`.
///
/// Any gadget that interprets a field element as a wire carrying a single bit
/// MUST call this first. Without it a prover could supply `2` (or any other
/// value) and silently violate the boolean premise of downstream gates.
pub fn assert_bool(bit: &U256) -> Result<(), ZkError> {
    let v = to_eth(bit);
    if v == eth_u256::ZERO || v == eth_u256::ONE {
        Ok(())
    } else {
        Err(ZkError::ConstraintUnsatisfied)
    }
}

/// Constrain every element of `bits` to be a single bit (`0` or `1`).
pub fn assert_bits<B: Bits>(bits: &B) -> Result<(), ZkError> {
    for i in 0..bits.bits_len() {
        assert_bool(&bits.bits_get(i))?;
    }
    Ok(())
}

/// Constrain a whole [`Vec`] of bits (used by lookup/witness helpers).
pub fn assert_bits_vec(bits: &Vec<U256>) -> Result<(), ZkError> {
    assert_bits(bits)
}

// ── Bit decomposition ──────────────────────────────────────────────────────────

/// Decompose `value` into `n_bits` little-endian boolean limbs and verify the
/// recomposition equals `value` exactly (`value < 2^n_bits`).
///
/// Returns the bits `b_0 .. b_{n_bits-1}` such that
/// `value == Σ b_i · 2^i`. Fails if `value` overflows `n_bits`.
pub fn bit_decompose(env: &Env, value: &U256, n_bits: u32) -> Result<Vec<U256>, ZkError> {
    if n_bits > 256 {
        return Err(ZkError::InvalidInput);
    }
    let v = to_eth(value);
    let mut bits = Vec::new(env);
    let mut recomp = eth_u256::ZERO;
    for i in 0..n_bits {
        let bit = (v >> i) & eth_u256::ONE;
        recomp |= bit << i;
        bits.push_back(from_eth(env, bit));
    }
    if recomp != v {
        return Err(ZkError::ConstraintUnsatisfied);
    }
    Ok(bits)
}

/// Verify a *prover-supplied* decomposition: each `bits[i]` is boolean and
/// `value == Σ bits[i] · 2^i` (over exactly `n_bits` bits).
pub fn assert_bit_decomposition<B: Bits>(
    value: &U256,
    bits: &B,
    n_bits: u32,
) -> Result<(), ZkError> {
    if n_bits != bits.bits_len() {
        return Err(ZkError::InvalidInput);
    }
    assert_bits(bits)?;
    let v = to_eth(value);
    let mut recomp = eth_u256::ZERO;
    for i in 0..bits.bits_len() {
        recomp |= to_eth(&bits.bits_get(i)) << i;
    }
    if recomp != v {
        return Err(ZkError::ConstraintUnsatisfied);
    }
    Ok(())
}

/// Range check: constrain `value < 2^n_bits` by decomposing it into `n_bits`
/// bits and dropping the result. Sound because [`bit_decompose`] fails unless
/// the high bits (above `n_bits`) are all zero.
pub fn range_check(env: &Env, value: &U256, n_bits: u32) -> Result<(), ZkError> {
    let _ = bit_decompose(env, value, n_bits)?;
    Ok(())
}

// ── Bitwise gates (per-bit, on boolean vectors) ─────────────────────────────────

/// AND of two equal-length boolean vectors: `out[i] = a[i] · b[i]`.
/// Both inputs are constrained boolean; the output is computed and returned.
pub fn and_bits<A: Bits, B: Bits>(env: &Env, a: &A, b: &B) -> Result<Vec<U256>, ZkError> {
    if a.bits_len() != b.bits_len() {
        return Err(ZkError::InvalidInput);
    }
    assert_bits(a)?;
    assert_bits(b)?;
    let mut out = Vec::new(env);
    for i in 0..a.bits_len() {
        let ai = to_eth(&a.bits_get(i));
        let bi = to_eth(&b.bits_get(i));
        out.push_back(from_eth(env, ai & bi));
    }
    Ok(out)
}

/// OR of two equal-length boolean vectors: `out[i] = a[i] + b[i] − a[i]·b[i]`.
pub fn or_bits<A: Bits, B: Bits>(env: &Env, a: &A, b: &B) -> Result<Vec<U256>, ZkError> {
    if a.bits_len() != b.bits_len() {
        return Err(ZkError::InvalidInput);
    }
    assert_bits(a)?;
    assert_bits(b)?;
    let mut out = Vec::new(env);
    for i in 0..a.bits_len() {
        let ai = to_eth(&a.bits_get(i));
        let bi = to_eth(&b.bits_get(i));
        out.push_back(from_eth(env, ai + bi - ai * bi));
    }
    Ok(out)
}

/// XOR of two equal-length boolean vectors: `out[i] = a[i] + b[i] − 2·a[i]·b[i]`.
pub fn xor_bits<A: Bits, B: Bits>(env: &Env, a: &A, b: &B) -> Result<Vec<U256>, ZkError> {
    if a.bits_len() != b.bits_len() {
        return Err(ZkError::InvalidInput);
    }
    assert_bits(a)?;
    assert_bits(b)?;
    let mut out = Vec::new(env);
    for i in 0..a.bits_len() {
        let ai = to_eth(&a.bits_get(i));
        let bi = to_eth(&b.bits_get(i));
        out.push_back(from_eth(env, ai + bi - (ai * bi) * eth_u256::from(2u8)));
    }
    Ok(out)
}

/// NOT of a boolean vector: `out[i] = 1 − a[i]`.
pub fn not_bits<B: Bits>(env: &Env, a: &B) -> Result<Vec<U256>, ZkError> {
    assert_bits(a)?;
    let one = eth_u256::ONE;
    let mut out = Vec::new(env);
    for i in 0..a.bits_len() {
        out.push_back(from_eth(env, one - to_eth(&a.bits_get(i))));
    }
    Ok(out)
}

/// Recompose a little-endian boolean vector back into a single field element and
/// verify the recomposition, returning the value.
pub fn recompose<B: Bits>(env: &Env, bits: &B) -> Result<U256, ZkError> {
    assert_bits(bits)?;
    let mut v = eth_u256::ZERO;
    for i in 0..bits.bits_len() {
        v |= to_eth(&bits.bits_get(i)) << i;
    }
    Ok(from_eth(env, v))
}

// ── Whole-element bitwise (via decomposition) ───────────────────────────────────

/// Bitwise AND of two field elements over `n_bits` low bits.
pub fn bitwise_and(env: &Env, a: &U256, b: &U256, n_bits: u32) -> Result<U256, ZkError> {
    let ba = bit_decompose(env, a, n_bits)?;
    let bb = bit_decompose(env, b, n_bits)?;
    recompose(env, &and_bits(env, &ba, &bb)?)
}

/// Bitwise OR of two field elements over `n_bits` low bits.
pub fn bitwise_or(env: &Env, a: &U256, b: &U256, n_bits: u32) -> Result<U256, ZkError> {
    let ba = bit_decompose(env, a, n_bits)?;
    let bb = bit_decompose(env, b, n_bits)?;
    recompose(env, &or_bits(env, &ba, &bb)?)
}

/// Bitwise XOR of two field elements over `n_bits` low bits.
pub fn bitwise_xor(env: &Env, a: &U256, b: &U256, n_bits: u32) -> Result<U256, ZkError> {
    let ba = bit_decompose(env, a, n_bits)?;
    let bb = bit_decompose(env, b, n_bits)?;
    recompose(env, &xor_bits(env, &ba, &bb)?)
}

// ── Equality & multiplexer ──────────────────────────────────────────────────────

/// Return `1` if `a == b`, else `0`, and constrain the result to be boolean.
///
/// This is a verifier-side equality test: the verifier recomputes the selector
/// directly rather than trusting a prover-supplied bit, so it is sound.
pub fn is_equal(env: &Env, a: &U256, b: &U256) -> U256 {
    if *a == *b {
        u256_one(env)
    } else {
        u256_zero(env)
    }
}

/// Constrain `a == b`. Returns [`ZkError::ConstraintUnsatisfied`] on mismatch.
pub fn assert_equal(a: &U256, b: &U256) -> Result<(), ZkError> {
    if *a == *b {
        Ok(())
    } else {
        Err(ZkError::ConstraintUnsatisfied)
    }
}

/// Boolean multiplexer (selector `sel`).
///
/// Returns `out = (1 − sel)·a + sel·b`. The selector is constrained boolean; the
/// output is computed and returned. A prover cannot influence `out` except
/// through `a`/`b` because `sel` is range-checked.
pub fn mux(env: &Env, sel: &U256, a: &U256, b: &U256) -> Result<U256, ZkError> {
    assert_bool(sel)?;
    let s = to_eth(sel); // 0 or 1
    let av = to_eth(a);
    let bv = to_eth(b);
    // out = a + s*(b - a)
    let out = av + s * (bv - av);
    Ok(from_eth(env, out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    fn env() -> Env {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e
    }

    #[test]
    fn assert_bool_accepts_0_and_1() {
        let env = env();
        assert!(assert_bool(&u256_zero(&env)).is_ok());
        assert!(assert_bool(&u256_one(&env)).is_ok());
    }

    #[test]
    fn assert_bool_rejects_other_values() {
        let env = env();
        assert_eq!(
            assert_bool(&U256::from_u128(&env, 2)),
            Err(ZkError::ConstraintUnsatisfied)
        );
        assert_eq!(
            assert_bool(&U256::from_u128(&env, 255)),
            Err(ZkError::ConstraintUnsatisfied)
        );
    }

    #[test]
    fn bit_decompose_recomposes() {
        let env = env();
        let val = U256::from_u128(&env, 0b1011_0110);
        let bits = bit_decompose(&env, &val, 8).unwrap();
        assert_eq!(bits.len(), 8);
        assert!(assert_bits(&bits).is_ok());
        let recomp = recompose(&env, &bits).unwrap();
        assert_eq!(recomp, val);
    }

    #[test]
    fn bit_decompose_rejects_overflow() {
        let env = env();
        let val = U256::from_u128(&env, 0b1000_0000); // bit 7 set
        assert_eq!(
            bit_decompose(&env, &val, 4),
            Err(ZkError::ConstraintUnsatisfied)
        );
    }

    #[test]
    fn assert_bit_decomposition_rejects_wrong_bits() {
        let env = env();
        let val = U256::from_u128(&env, 5);
        let mut bits = bit_decompose(&env, &val, 8).unwrap();
        // Flip bit 1 (0 -> 1) to forge a different value (5 -> 7).
        bits.set(1, u256_one(&env));
        assert_eq!(
            assert_bit_decomposition(&val, &bits, 8),
            Err(ZkError::ConstraintUnsatisfied)
        );
    }

    #[test]
    fn and_or_xor_bits_match_reference() {
        let env = env();
        let a = [
            u256_one(&env),
            u256_zero(&env),
            u256_one(&env),
            u256_one(&env),
        ];
        let b = [
            u256_one(&env),
            u256_one(&env),
            u256_zero(&env),
            u256_one(&env),
        ];
        let and = and_bits(&env, &a, &b).unwrap();
        let or = or_bits(&env, &a, &b).unwrap();
        let xor = xor_bits(&env, &a, &b).unwrap();
        // a = 0b1101, b = 0b1011
        assert_eq!(
            recompose(&env, &and).unwrap(),
            U256::from_u128(&env, 0b1001)
        );
        assert_eq!(recompose(&env, &or).unwrap(), U256::from_u128(&env, 0b1111));
        assert_eq!(
            recompose(&env, &xor).unwrap(),
            U256::from_u128(&env, 0b0110)
        );
        assert!(assert_bits(&a).is_ok());
        assert!(assert_bits(&b).is_ok());
    }

    #[test]
    fn bitwise_xor_over_field_elements() {
        let env = env();
        let a = U256::from_u128(&env, 0b1101);
        let b = U256::from_u128(&env, 0b1011);
        assert_eq!(
            bitwise_xor(&env, &a, &b, 4).unwrap(),
            U256::from_u128(&env, 0b0110)
        );
    }

    #[test]
    fn is_equal_and_mux() {
        let env = env();
        assert_eq!(
            is_equal(&env, &U256::from_u128(&env, 7), &U256::from_u128(&env, 7)),
            u256_one(&env)
        );
        assert_eq!(
            is_equal(&env, &U256::from_u128(&env, 7), &U256::from_u128(&env, 8)),
            u256_zero(&env)
        );

        let sel = u256_one(&env);
        let out = mux(
            &env,
            &sel,
            &U256::from_u128(&env, 11),
            &U256::from_u128(&env, 22),
        )
        .unwrap();
        assert_eq!(out, U256::from_u128(&env, 22));

        let out0 = mux(
            &env,
            &u256_zero(&env),
            &U256::from_u128(&env, 11),
            &U256::from_u128(&env, 22),
        )
        .unwrap();
        assert_eq!(out0, U256::from_u128(&env, 11));
    }

    #[test]
    fn mux_rejects_nonboolean_selector() {
        let env = env();
        assert_eq!(
            mux(
                &env,
                &U256::from_u128(&env, 2),
                &u256_zero(&env),
                &u256_one(&env)
            ),
            Err(ZkError::ConstraintUnsatisfied)
        );
    }

    #[test]
    fn range_check_accepts_and_rejects() {
        let env = env();
        assert!(range_check(&env, &U256::from_u128(&env, 15), 4).is_ok());
        assert_eq!(
            range_check(&env, &U256::from_u128(&env, 16), 4),
            Err(ZkError::ConstraintUnsatisfied)
        );
    }

    #[test]
    fn bit_decompose_u256_full() {
        let env = env();
        let val = U256::from_u128(&env, u128::MAX);
        let bits = bit_decompose(&env, &val, 128).unwrap();
        assert_eq!(bits.len(), 128);
        assert_eq!(recompose(&env, &bits).unwrap(), val);
    }
}
