//! Bounded, allocation-free multilinear Sumcheck verification over BN254 Fr.
//!
//! This module implements the verifier side of the multilinear Sumcheck
//! protocol that Barretenberg's UltraHonk prover/verifier uses for its
//! "sumcheck" rounds (Noir / Aztec BN254 flavour).
//!
//! ## Protocol recap
//!
//! A multilinear polynomial `f: {0,1}^v -> Fr` is given by its `2^v`
//! hypercube evaluations. The prover claims
//!
//! ```text
//!     H = sum_{b in {0,1}^v} f(b)
//! ```
//!
//! and proves it in `v` rounds. In round `i` it sends a univariate
//! `g_i(X) = sum_{b in {0,1}^{v-i}} f(r_1, ..., r_{i-1}, X, b)`, and the
//! verifier checks
//!
//! ```text
//!     g_i(0) + g_i(1) = g_{i-1}(r_{i-1})        (with g_0(r_0) := H)
//!     g_v(r_v)        = f(r_1, ..., r_v)         (final oracle check)
//! ```
//!
//! ## Bounds and failure model
//!
//! * `MAX_MULTILINEAR_VARS` bounds the hypercube at 4096 evaluations and the
//!   number of rounds at 12, so every buffer lives on the stack and the cost is
//!   predictable in a Soroban instruction budget.
//! * Every entry point validates its scalars against the BN254 scalar field
//!   modulus and returns [`ZkError`] instead of panicking. The module contains
//!   no `unwrap`, `expect`, `panic!`, heap allocation, or floats.
//! * All `u256` values are treated as canonical residues in `[0, r)`; the
//!   caller-supplied round polynomials are constructed through
//!   [`RoundPoly`] so their coefficients are range-checked once at the boundary.

use ethnum::u256;

use crate::{Bn254, ZkError};

/// Maximum number of variables (and therefore sumcheck rounds) supported by the
/// bounded evaluator. `2^12 = 4096` hypercube evaluations.
pub const MAX_MULTILINEAR_VARS: usize = 12;

/// Maximum number of coefficients in a round polynomial.
///
/// UltraHonk uses degree-2 round polynomials (`3` coefficients: evaluations at
/// `0`, `1`, `2`); four coefficients leave room for a cubic round without
/// changing the type.
pub const MAX_ROUND_COEFFS: usize = 4;

#[inline(always)]
fn zero() -> u256 {
    u256::from(0u8)
}

#[inline(always)]
fn one() -> u256 {
    u256::from(1u8)
}

/// `2^-1 mod r`, used to interpolate degree-2 round polynomials from the
/// evaluations at `0`, `1` and `2`. `r` is odd, so `(r + 1) / 2` is the inverse
/// of two and never overflows 256 bits.
#[inline(always)]
fn inv_two() -> u256 {
    (Bn254::FR_MODULUS + one()) >> 1
}

/// Returns `Err(ZkError::InvalidFieldElement)` unless `value < r`.
#[inline(always)]
fn check_fr(value: u256) -> Result<(), ZkError> {
    if value >= Bn254::FR_MODULUS {
        Err(ZkError::InvalidFieldElement)
    } else {
        Ok(())
    }
}

/// Evaluates the multilinear extension of a hypercube evaluation table at
/// `point`, without allocating.
///
/// `evals` must hold exactly `2^point.len()` canonical Fr elements, in
/// little-endian bit order over the variables (index `b` has variable `j` in bit
/// `j`). The evaluation is the explicit Lagrange sum
///
/// ```text
///     f(r) = sum_b evals[b] * prod_j (b_j ? r_j : 1 - r_j)
/// ```
///
/// which is `O(2^v · v)` field multiplications with a single stack accumulator.
///
/// # Errors
///
/// * [`ZkError::InvalidInput`] — empty table, table length not a power of two,
///   table length inconsistent with `point.len()`, or more than
///   [`MAX_MULTILINEAR_VARS`] variables.
/// * [`ZkError::InvalidFieldElement`] — any evaluation or challenge point is
///   `>= r`.
pub fn multilinear_eval(evals: &[u256], point: &[u256]) -> Result<u256, ZkError> {
    let vars = point.len();
    if vars == 0 || vars > MAX_MULTILINEAR_VARS {
        return Err(ZkError::InvalidInput);
    }
    if !evals.len().is_power_of_two() || evals.len() != 1usize << vars {
        return Err(ZkError::InvalidInput);
    }
    for &r in point {
        check_fr(r)?;
    }

    let mut acc = zero();
    for (index, &eval) in evals.iter().enumerate() {
        check_fr(eval)?;
        let mut weight = one();
        for (j, &r) in point.iter().enumerate() {
            let factor = if (index >> j) & 1 == 1 {
                r
            } else {
                // chi_j(0) = 1 - r
                Bn254::sub(one(), r)
            };
            weight = Bn254::mul(weight, factor);
        }
        acc = Bn254::add(acc, Bn254::mul(weight, eval));
    }
    Ok(acc)
}

/// A univariate round polynomial with a bounded number of coefficients.
///
/// Coefficients are stored little-endian (`coeffs[0]` is the constant term) and
/// canonicalised: trailing zero coefficients are dropped, so `len` is the
/// canonical length. Instances can only be built through the checked
/// constructors below, which keeps every coefficient in `[0, r)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoundPoly<const N: usize> {
    coeffs: [u256; N],
    len: usize,
}

impl<const N: usize> Default for RoundPoly<N> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<const N: usize> RoundPoly<N> {
    /// The zero polynomial.
    pub const fn zero() -> Self {
        Self {
            coeffs: [u256::from_words(0, 0); N],
            len: 0,
        }
    }

    /// Builds a round polynomial from a little-endian coefficient slice.
    ///
    /// # Errors
    ///
    /// * [`ZkError::InvalidInput`] if the slice is longer than `N`.
    /// * [`ZkError::InvalidFieldElement`] if any coefficient is `>= r`.
    pub fn from_coefficients_slice(coeffs: &[u256]) -> Result<Self, ZkError> {
        if coeffs.len() > N {
            return Err(ZkError::InvalidInput);
        }
        let mut out = [zero(); N];
        for (slot, &c) in out.iter_mut().zip(coeffs.iter()) {
            check_fr(c)?;
            *slot = c;
        }
        Ok(Self {
            coeffs: out,
            len: canonical_len(coeffs),
        })
    }

    /// Interpolates the degree-≤2 round polynomial passing through
    /// `g(0) = g0`, `g(1) = g1`, `g(2) = g2` — the wire format Barretenberg
    /// uses for UltraHonk sumcheck univariates.
    ///
    /// # Errors
    ///
    /// * [`ZkError::InvalidInput`] if `N < 3`.
    /// * [`ZkError::InvalidFieldElement`] if any evaluation is `>= r`.
    pub fn from_evaluations_zero_one_two(g0: u256, g1: u256, g2: u256) -> Result<Self, ZkError> {
        if N < 3 {
            return Err(ZkError::InvalidInput);
        }
        check_fr(g0)?;
        check_fr(g1)?;
        check_fr(g2)?;

        // g(X) = c0 + c1 X + c2 X^2 with
        //   c0 = g(0)
        //   c1 = (-3 g(0) + 4 g(1) - g(2)) / 2
        //   c2 = ( g(0) - 2 g(1) + g(2)) / 2
        let four_g1 = Bn254::mul(g1, u256::from(4u8));
        let three_g0 = Bn254::mul(g0, u256::from(3u8));
        let neg_three_g0 = Bn254::sub(zero(), three_g0);
        let c1_num = Bn254::sub(Bn254::add(four_g1, neg_three_g0), g2);
        let c1 = Bn254::mul(c1_num, inv_two());

        let two_g1 = Bn254::add(g1, g1);
        let c2_num = Bn254::add(Bn254::sub(g0, two_g1), g2);
        let c2 = Bn254::mul(c2_num, inv_two());

        let provisional = [g0, c1, c2];
        let mut out = [zero(); N];
        for (slot, &c) in out.iter_mut().zip(provisional.iter()) {
            *slot = c;
        }
        Ok(Self {
            coeffs: out,
            len: canonical_len(&provisional),
        })
    }

    /// Canonical coefficient slice (trailing zeroes removed).
    #[inline(always)]
    pub fn coeffs(&self) -> &[u256] {
        &self.coeffs[..self.len]
    }

    /// Number of canonical coefficients; `0` for the zero polynomial.
    #[inline(always)]
    pub fn num_coeffs(&self) -> usize {
        self.len
    }

    /// Returns `true` for the zero polynomial.
    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.len == 0
    }

    /// Degree of the polynomial (`0` for the zero polynomial).
    #[inline(always)]
    pub fn degree(&self) -> usize {
        self.len.saturating_sub(1)
    }

    /// Evaluates the polynomial at `x` with Horner's rule.
    ///
    /// `x` must already be a canonical Fr element (all entry points that accept
    /// arbitrary input validate it).
    pub fn evaluate(&self, x: u256) -> u256 {
        let mut acc = zero();
        for &c in self.coeffs().iter().rev() {
            acc = Bn254::add(Bn254::mul(acc, x), c);
        }
        acc
    }

    /// `g(0) + g(1)`, the round-consistency quantity of the protocol.
    pub fn endpoint_sum(&self) -> u256 {
        Bn254::add(self.evaluate(zero()), self.evaluate(one()))
    }
}

fn canonical_len(coeffs: &[u256]) -> usize {
    let mut len = coeffs.len();
    while len > 0 && coeffs[len - 1] == zero() {
        len -= 1;
    }
    len
}

/// Verifies the round-consistency chain of a multilinear Sumcheck proof.
///
/// Starting from `claimed_sum`, for every round `i` this checks
///
/// ```text
///     g_i(0) + g_i(1) == g_{i-1}(r_{i-1})
/// ```
///
/// and, when `final_evaluation` is supplied, the final oracle identity
/// `g_last(r_last) == final_evaluation`.
///
/// # Errors
///
/// * [`ZkError::InvalidInput`] — no rounds, or a round/challenge count mismatch,
///   or more rounds than [`MAX_MULTILINEAR_VARS`].
/// * [`ZkError::InvalidFieldElement`] — a non-canonical claimed sum, challenge
///   or coefficient.
/// * [`ZkError::ConstraintUnsatisfied`] — the chain or the final check fails.
pub fn verify_sumcheck<const N: usize>(
    claimed_sum: u256,
    round_polys: &[RoundPoly<N>],
    challenges: &[u256],
    final_evaluation: Option<u256>,
) -> Result<(), ZkError> {
    if round_polys.is_empty()
        || round_polys.len() != challenges.len()
        || round_polys.len() > MAX_MULTILINEAR_VARS
    {
        return Err(ZkError::InvalidInput);
    }
    check_fr(claimed_sum)?;
    for &r in challenges {
        check_fr(r)?;
    }
    for poly in round_polys {
        for &c in poly.coeffs() {
            check_fr(c)?;
        }
    }
    if let Some(final_value) = final_evaluation {
        check_fr(final_value)?;
    }

    // Round 1 must sum to the claimed total.
    if round_polys[0].endpoint_sum() != claimed_sum {
        return Err(ZkError::ConstraintUnsatisfied);
    }

    // Every later round must land on the previous round polynomial's value at
    // the previous verifier challenge.
    for i in 1..round_polys.len() {
        let expected = round_polys[i - 1].evaluate(challenges[i - 1]);
        if round_polys[i].endpoint_sum() != expected {
            return Err(ZkError::ConstraintUnsatisfied);
        }
    }

    // Final oracle check, when the caller has the evaluated oracle available.
    if let Some(final_value) = final_evaluation {
        let last = round_polys.len() - 1;
        if round_polys[last].evaluate(challenges[last]) != final_value {
            return Err(ZkError::ConstraintUnsatisfied);
        }
    }

    Ok(())
}

/// Verifies a complete Sumcheck proof against the multilinear polynomial's
/// hypercube evaluations.
///
/// This is [`verify_sumcheck`] plus the final oracle check
/// `g_last(r_last) == f(r_1, ..., r_v)`, computed with [`multilinear_eval`].
///
/// # Errors
///
/// Propagates [`verify_sumcheck`] errors and [`multilinear_eval`] errors; a
/// mismatch between the last round polynomial and the true multilinear
/// evaluation is reported as [`ZkError::ConstraintUnsatisfied`].
pub fn verify_sumcheck_with_oracle<const N: usize>(
    evals: &[u256],
    claimed_sum: u256,
    round_polys: &[RoundPoly<N>],
    challenges: &[u256],
) -> Result<(), ZkError> {
    verify_sumcheck(claimed_sum, round_polys, challenges, None)?;

    let oracle_value = multilinear_eval(evals, challenges)?;
    let last = round_polys.len() - 1;
    if round_polys[last].evaluate(challenges[last]) != oracle_value {
        return Err(ZkError::ConstraintUnsatisfied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(v: u8) -> u256 {
        u256::from(v)
    }

    /// `f(x1, x2) = 3 + 2 x1 + 5 x2 + 7 x1 x2` on `{0,1}^2`.
    fn bilinear_table() -> [u256; 4] {
        // Index bit 0 = x1, bit 1 = x2.
        [f(3), f(5), f(8), f(17)]
    }

    #[test]
    fn multilinear_eval_matches_closed_form() {
        let table = bilinear_table();
        // f(2, 5) = 3 + 4 + 25 + 70 = 102
        assert_eq!(
            multilinear_eval(&table, &[f(2), f(5)]).unwrap(),
            f(102),
            "multilinear extension must reproduce the closed form"
        );
        // Evaluations at the hypercube points must recover the table.
        assert_eq!(multilinear_eval(&table, &[f(0), f(0)]).unwrap(), f(3));
        assert_eq!(multilinear_eval(&table, &[f(1), f(0)]).unwrap(), f(5));
        assert_eq!(multilinear_eval(&table, &[f(0), f(1)]).unwrap(), f(8));
        assert_eq!(multilinear_eval(&table, &[f(1), f(1)]).unwrap(), f(17));
    }

    #[test]
    fn multilinear_eval_rejects_malformed_shapes() {
        let table = bilinear_table();
        // Empty point, non-power-of-two table, mismatched arity.
        assert_eq!(multilinear_eval(&table, &[]), Err(ZkError::InvalidInput));
        assert_eq!(
            multilinear_eval(&[f(1), f(2), f(3)], &[f(1), f(2)]),
            Err(ZkError::InvalidInput)
        );
        assert_eq!(
            multilinear_eval(&table, &[f(1)]),
            Err(ZkError::InvalidInput)
        );
        // Too many variables (rejected before the table size is examined).
        let point = [f(1); MAX_MULTILINEAR_VARS + 1];
        assert_eq!(multilinear_eval(&table, &point), Err(ZkError::InvalidInput));
        // Non-canonical challenge and evaluation.
        assert_eq!(
            multilinear_eval(&table, &[Bn254::FR_MODULUS, f(0)]),
            Err(ZkError::InvalidFieldElement)
        );
        let mut evals = bilinear_table();
        evals[0] = Bn254::FR_MODULUS;
        assert_eq!(
            multilinear_eval(&evals, &[f(0), f(0)]),
            Err(ZkError::InvalidFieldElement)
        );
    }

    #[test]
    fn round_poly_interpolation_recovers_control_points() {
        let g = RoundPoly::<3>::from_evaluations_zero_one_two(f(8), f(17), f(26)).unwrap();
        assert_eq!(g.evaluate(f(0)), f(8));
        assert_eq!(g.evaluate(f(1)), f(17));
        assert_eq!(g.evaluate(f(2)), f(26));
        // g(X) = 8 + 9X (constant second difference is zero).
        assert_eq!(g.num_coeffs(), 2);
        assert_eq!(g.degree(), 1);
        assert_eq!(g.endpoint_sum(), f(25));
    }

    #[test]
    fn round_poly_constructors_reject_bad_input() {
        assert_eq!(
            RoundPoly::<3>::from_coefficients_slice(&[f(1), f(2), f(3), f(4)]),
            Err(ZkError::InvalidInput)
        );
        assert_eq!(
            RoundPoly::<3>::from_coefficients_slice(&[f(1), Bn254::FR_MODULUS]),
            Err(ZkError::InvalidFieldElement)
        );
        assert_eq!(
            RoundPoly::<2>::from_evaluations_zero_one_two(f(1), f(2), f(3)),
            Err(ZkError::InvalidInput)
        );
        assert_eq!(
            RoundPoly::<3>::from_evaluations_zero_one_two(Bn254::FR_MODULUS, f(2), f(3)),
            Err(ZkError::InvalidFieldElement)
        );
        let zero = RoundPoly::<3>::zero();
        assert!(zero.is_zero());
        assert_eq!(zero.num_coeffs(), 0);
        assert_eq!(zero.evaluate(f(7)), f(0));
        assert_eq!(zero.endpoint_sum(), f(0));
    }

    /// The two-round chain for `f(x1, x2) = 3 + 2x1 + 5x2 + 7x1x2`:
    /// `g_1(X) = 11 + 11X`, `g_2(X) = 7 + 19X`.
    fn bilinear_round_polys() -> [RoundPoly<3>; 2] {
        [
            RoundPoly::from_evaluations_zero_one_two(f(11), f(22), f(33)).unwrap(),
            RoundPoly::from_evaluations_zero_one_two(f(7), f(26), f(45)).unwrap(),
        ]
    }

    #[test]
    fn verify_sumcheck_accepts_genuine_bilinear_instance() {
        let rounds = bilinear_round_polys();
        let challenges = [f(2), f(5)];
        // g_1(0) + g_1(1) = 11 + 22 = 33 = sum over the hypercube.
        verify_sumcheck(f(33), &rounds, &challenges, Some(f(102))).unwrap();
    }

    #[test]
    fn verify_sumcheck_with_oracle_accepts_genuine_instance() {
        let rounds = bilinear_round_polys();
        let challenges = [f(2), f(5)];
        verify_sumcheck_with_oracle(&bilinear_table(), f(33), &rounds, &challenges).unwrap();
    }

    #[test]
    fn verify_sumcheck_rejects_wrong_claimed_sum() {
        let rounds = bilinear_round_polys();
        assert_eq!(
            verify_sumcheck(f(34), &rounds, &[f(2), f(5)], None),
            Err(ZkError::ConstraintUnsatisfied)
        );
    }

    #[test]
    fn verify_sumcheck_rejects_broken_round_chain() {
        let rounds = bilinear_round_polys();
        // g_2(0) + g_2(1) = 33 != g_1(3) = 44, so the chain must fail.
        assert_eq!(
            verify_sumcheck(f(33), &rounds, &[f(3), f(5)], None),
            Err(ZkError::ConstraintUnsatisfied)
        );
    }

    #[test]
    fn verify_sumcheck_rejects_wrong_final_evaluation() {
        let rounds = bilinear_round_polys();
        assert_eq!(
            verify_sumcheck(f(33), &rounds, &[f(2), f(5)], Some(f(101))),
            Err(ZkError::ConstraintUnsatisfied)
        );
    }

    #[test]
    fn verify_sumcheck_rejects_oracle_mismatch() {
        let rounds = bilinear_round_polys();
        // Temporarily claim the oracle is a different (still well-formed) table.
        let mut table = bilinear_table();
        table[3] = f(18);
        assert_eq!(
            verify_sumcheck_with_oracle(&table, f(33), &rounds, &[f(2), f(5)]),
            Err(ZkError::ConstraintUnsatisfied)
        );
    }

    #[test]
    fn verify_sumcheck_rejects_malformed_inputs() {
        let rounds = bilinear_round_polys();
        // No rounds / mismatched counts.
        assert_eq!(
            verify_sumcheck::<3>(f(33), &[], &[], None),
            Err(ZkError::InvalidInput)
        );
        assert_eq!(
            verify_sumcheck(f(33), &rounds, &[f(2)], None),
            Err(ZkError::InvalidInput)
        );
        // Non-canonical scalars.
        assert_eq!(
            verify_sumcheck(Bn254::FR_MODULUS, &rounds, &[f(2), f(5)], None),
            Err(ZkError::InvalidFieldElement)
        );
        assert_eq!(
            verify_sumcheck(f(33), &rounds, &[f(2), Bn254::FR_MODULUS], None),
            Err(ZkError::InvalidFieldElement)
        );
        assert_eq!(
            verify_sumcheck(f(33), &rounds, &[f(2), f(5)], Some(Bn254::FR_MODULUS)),
            Err(ZkError::InvalidFieldElement)
        );
    }

    #[test]
    fn verify_sumcheck_supports_max_rounds_without_allocation() {
        // A constant summand `f ≡ 1` over 12 variables: round `i` is the
        // constant `2^(11-i)`, every challenge is irrelevant (the evaluation of
        // a constant is itself) and the final oracle check is `1`.
        let mut rounds = [RoundPoly::<3>::zero(); MAX_MULTILINEAR_VARS];
        for (i, round) in rounds.iter_mut().enumerate() {
            let value = 1u32 << (MAX_MULTILINEAR_VARS - 1 - i);
            *round = RoundPoly::from_coefficients_slice(&[u256::from(value)]).unwrap();
        }
        let mut challenges = [f(0); MAX_MULTILINEAR_VARS];
        for (i, c) in challenges.iter_mut().enumerate() {
            *c = f(i as u8 + 1);
        }
        verify_sumcheck(u256::from(4096u32), &rounds, &challenges, Some(f(1))).unwrap();
        // A wrong claim is rejected even at the maximum depth.
        assert_eq!(
            verify_sumcheck(f(2), &rounds, &challenges, Some(f(1))),
            Err(ZkError::ConstraintUnsatisfied)
        );
    }
}
