//! Bounded, allocation-free multilinear Sumcheck over BN254 Fr.
//!
//! This module implements the two halves of the Sumcheck protocol that an
//! on-chain verifier needs, with no heap allocation, no panics and a
//! compile-time bound on every buffer:
//!
//! * [`MultilinearPolynomial`] stores the evaluations of an `n`-variable
//!   multilinear polynomial on the boolean hypercube `{0,1}^n` and evaluates
//!   its multilinear extension (MLE) at an arbitrary point by in-place folding
//!   on a fixed-size stack table.
//! * [`RoundPolynomial`] is a bounded univariate polynomial (the prover's
//!   message for one Sumcheck round).
//! * [`verify_sumcheck`] checks the round-by-round consistency relation
//!   `g_i(0) + g_i(1) = g_{i-1}(r_{i-1})`.
//! * [`verify_multilinear_sumcheck`] additionally checks the final oracle
//!   evaluation `g_{n-1}(r_{n-1}) = p(r_0, …, r_{n-1})` against the committed
//!   polynomial, which is the check that makes the reduction sound.
//!
//! # Variable ordering
//!
//! The evaluation table is indexed by `i ∈ [0, 2^n)`, and variable `k` is bit
//! `n - 1 - k` of `i`: variable 0 is the most significant bit. Round `k` folds
//! each entry of the first half against the matching entry of the second half
//! (`j` with `j + 2^(n-1-k)`), which is the ordering Barretenberg's Sumcheck
//! uses and makes round 0 the first univariate in an UltraHonk proof.
//!
//! # Field discipline
//!
//! Every scalar is a canonical BN254 Fr element in `[0, r)`; out-of-range
//! inputs produce [`ZkError::InvalidFieldElement`] before any arithmetic. A
//! failed protocol check produces [`ZkError::ConstraintUnsatisfied`], so
//! callers can distinguish malformed data from a rejected proof.

use ethnum::u256;

use crate::{Bn254, ZkError};

/// Largest supported number of Sumcheck variables.
///
/// A 2¹⁶-entry hypercube table is 2 MiB of stack, far beyond what a Soroban
/// contract can afford; real UltraHonk circuits are verified one relation at a
/// time and pass a much smaller table. The constant exists so the verifier's
/// memory use is statically bounded, not because 2¹⁶ is a practical target.
pub const MAX_VARIABLES: usize = 16;

/// Maximum number of coefficients a round polynomial may carry.
///
/// UltraHonk's arithmetic relation is at most quadratic in each variable, so
/// three coefficients (degree ≤ 2) cover it; the generic verifier accepts any
/// degree up to this bound.
pub const MAX_ROUND_TERMS: usize = 4;

#[inline(always)]
fn zero() -> u256 {
    u256::from(0u8)
}

#[inline(always)]
fn one() -> u256 {
    u256::from(1u8)
}

#[inline(always)]
fn is_field_element(value: u256) -> bool {
    Bn254::is_valid_scalar(value)
}

/// A multilinear polynomial given by its `2^n` evaluations on `{0,1}^n`.
///
/// `MAX_EVALS` is the compile-time capacity of the evaluation table; the
/// constructor rejects slices that exceed it. The representation is padded with
/// zeros past `len`, so the type never needs allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultilinearPolynomial<const MAX_EVALS: usize> {
    evaluations: [u256; MAX_EVALS],
    len: usize,
}

impl<const MAX_EVALS: usize> MultilinearPolynomial<MAX_EVALS> {
    /// Builds a polynomial from its hypercube evaluations.
    ///
    /// # Errors
    ///
    /// - [`ZkError::InvalidInput`] if the slice is empty, its length is not a
    ///   power of two, or it exceeds `MAX_EVALS`.
    /// - [`ZkError::InvalidFieldElement`] if any evaluation is ≥ the BN254
    ///   scalar field modulus.
    pub fn from_evaluations(evaluations: &[u256]) -> Result<Self, ZkError> {
        let len = evaluations.len();
        if len == 0 || !len.is_power_of_two() || len > MAX_EVALS {
            return Err(ZkError::InvalidInput);
        }
        // `len.trailing_zeros()` is the number of variables; keep it inside the
        // documented bound so the MLE fold table always fits.
        if len.trailing_zeros() as usize > MAX_VARIABLES {
            return Err(ZkError::InvalidInput);
        }
        for &evaluation in evaluations {
            if !is_field_element(evaluation) {
                return Err(ZkError::InvalidFieldElement);
            }
        }

        let mut table = [zero(); MAX_EVALS];
        table[..len].copy_from_slice(evaluations);
        Ok(Self {
            evaluations: table,
            len,
        })
    }

    /// Number of variables `n` (the hypercube has `2^n` points).
    pub fn num_variables(&self) -> usize {
        self.len.trailing_zeros() as usize
    }

    /// Number of stored hypercube evaluations (`2^n`).
    pub fn len(&self) -> usize {
        self.len
    }

    /// Always `false`: construction rejects empty tables.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The hypercube evaluations in canonical index order.
    pub fn evaluations(&self) -> &[u256] {
        &self.evaluations[..self.len]
    }

    /// Sum of all hypercube evaluations — the initial Sumcheck claim.
    pub fn hypercube_sum(&self) -> u256 {
        let mut acc = zero();
        for &evaluation in self.evaluations() {
            acc = Bn254::add(acc, evaluation);
        }
        acc
    }

    /// Evaluates the multilinear extension at `point` (`len == n`).
    ///
    /// Folding is done in place on a stack copy of the table: for the current
    /// variable `x`, entries `j` and `j + half` become
    /// `p(x, rest) = p(0, rest) + x·(p(1, rest) - p(0, rest))`.
    /// Each fold halves the active table, so the whole evaluation performs
    /// exactly `2^n - 1` field combines and allocates nothing. The fold buffer
    /// is `MAX_EVALS · 32` bytes of stack, so a caller choosing a large
    /// `MAX_EVALS` must provide a stack at least that big; a Soroban verifier
    /// should keep `n` small enough for the contract's own stack.
    ///
    /// # Errors
    ///
    /// - [`ZkError::InvalidInput`] if `point.len() != num_variables()`.
    /// - [`ZkError::InvalidFieldElement`] if any coordinate is ≥ the BN254
    ///   scalar field modulus.
    pub fn evaluate(&self, point: &[u256]) -> Result<u256, ZkError> {
        if point.len() != self.num_variables() {
            return Err(ZkError::InvalidInput);
        }

        let mut table = [zero(); MAX_EVALS];
        table[..self.len].copy_from_slice(self.evaluations());
        let mut active = self.len;

        for &coordinate in point {
            if !is_field_element(coordinate) {
                return Err(ZkError::InvalidFieldElement);
            }
            let half = active / 2;
            for j in 0..half {
                let lo = table[j];
                let hi = table[j + half];
                table[j] = Bn254::add(lo, Bn254::mul(coordinate, Bn254::sub(hi, lo)));
            }
            active = half;
        }

        Ok(if active == 0 { zero() } else { table[0] })
    }
}

/// A bounded univariate round polynomial in coefficient order (constant first).
///
/// Trailing zero coefficients are stripped on construction, so two polynomials
/// that differ only in zero padding compare equal and produce the same
/// Fiat-Shamir transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoundPolynomial<const MAX_TERMS: usize> {
    coefficients: [u256; MAX_TERMS],
    len: usize,
}

impl<const MAX_TERMS: usize> RoundPolynomial<MAX_TERMS> {
    /// The zero polynomial.
    pub fn zero() -> Self {
        Self {
            coefficients: [zero(); MAX_TERMS],
            len: 0,
        }
    }

    /// Builds a round polynomial from `coefficients` (constant term first).
    ///
    /// # Errors
    ///
    /// - [`ZkError::InvalidInput`] if there are more than `MAX_TERMS`
    ///   coefficients.
    /// - [`ZkError::InvalidFieldElement`] if any coefficient is out of range.
    pub fn from_coefficients(coefficients: &[u256]) -> Result<Self, ZkError> {
        if coefficients.len() > MAX_TERMS {
            return Err(ZkError::InvalidInput);
        }
        for &coefficient in coefficients {
            if !is_field_element(coefficient) {
                return Err(ZkError::InvalidFieldElement);
            }
        }

        let mut stored = [zero(); MAX_TERMS];
        stored[..coefficients.len()].copy_from_slice(coefficients);
        let mut len = coefficients.len();
        while len > 0 && stored[len - 1] == zero() {
            len -= 1;
        }
        Ok(Self {
            coefficients: stored,
            len,
        })
    }

    /// Canonical coefficients (constant first, no trailing zeros).
    pub fn coefficients(&self) -> &[u256] {
        &self.coefficients[..self.len]
    }

    /// Degree of the polynomial (0 for the zero polynomial).
    pub fn degree(&self) -> usize {
        self.len.saturating_sub(1)
    }

    /// `true` for the zero polynomial.
    pub fn is_zero(&self) -> bool {
        self.len == 0
    }

    /// Evaluates the polynomial at `x` with Horner's rule.
    ///
    /// # Errors
    ///
    /// [`ZkError::InvalidFieldElement`] if `x` is ≥ the BN254 scalar modulus.
    pub fn evaluate(&self, x: u256) -> Result<u256, ZkError> {
        if !is_field_element(x) {
            return Err(ZkError::InvalidFieldElement);
        }
        let mut acc = zero();
        for &coefficient in self.coefficients().iter().rev() {
            acc = Bn254::add(Bn254::mul(acc, x), coefficient);
        }
        Ok(acc)
    }

    /// `g(0) + g(1)`, the sum a Sumcheck round must match.
    ///
    /// For a multilinear polynomial's round polynomial this equals the sum over
    /// the remaining hypercube; the verifier compares it against the previous
    /// round's claimed value.
    pub fn sum_over_hypercube(&self) -> Result<u256, ZkError> {
        let at_zero = self.evaluate(zero())?;
        let at_one = self.evaluate(one())?;
        Ok(Bn254::add(at_zero, at_one))
    }
}

/// The outcome of a verified Sumcheck reduction.
///
/// `challenges` is fixed-size so the value is `Copy` and lives on the stack;
/// only the first `num_rounds` entries are meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SumcheckReduction<const MAX_ROUNDS: usize> {
    /// Verifier challenges `r_0, …, r_{n-1}` (zero-padded past `num_rounds`).
    pub challenges: [u256; MAX_ROUNDS],
    /// Number of variables / rounds that were verified.
    pub num_rounds: usize,
    /// Final claimed evaluation `g_{n-1}(r_{n-1})`.
    pub final_evaluation: u256,
}

impl<const MAX_ROUNDS: usize> SumcheckReduction<MAX_ROUNDS> {
    /// The meaningful challenge prefix `r_0, …, r_{n-1}`.
    pub fn challenge_slice(&self) -> &[u256] {
        &self.challenges[..self.num_rounds]
    }
}

/// Verifies the Sumcheck round-consistency chain.
///
/// For each round `i` with polynomial `g_i` and challenge `r_i` this checks
///
/// ```text
/// g_0(0) + g_0(1) == claimed_sum
/// g_i(0) + g_i(1) == g_{i-1}(r_{i-1})      for i > 0
/// ```
///
/// and returns the final claim `g_{n-1}(r_{n-1})`. It does **not** know the
/// committed polynomial, so soundness requires the caller to finish with
/// [`verify_multilinear_sumcheck`] (or to check the final evaluation against the
/// relation itself).
///
/// # Errors
///
/// - [`ZkError::InvalidInput`] for an empty chain, mismatched
///   `round_polynomials`/`challenges` lengths, or more rounds than
///   `MAX_ROUNDS`.
/// - [`ZkError::InvalidFieldElement`] if `claimed_sum` or a challenge is out of
///   range.
/// - [`ZkError::ConstraintUnsatisfied`] if a round's `g(0) + g(1)` does not
///   match the running claim.
pub fn verify_sumcheck<const MAX_ROUNDS: usize, const MAX_TERMS: usize>(
    claimed_sum: u256,
    round_polynomials: &[RoundPolynomial<MAX_TERMS>],
    challenges: &[u256],
) -> Result<SumcheckReduction<MAX_ROUNDS>, ZkError> {
    let num_rounds = round_polynomials.len();
    if num_rounds == 0 || num_rounds != challenges.len() || num_rounds > MAX_ROUNDS {
        return Err(ZkError::InvalidInput);
    }
    if !is_field_element(claimed_sum) {
        return Err(ZkError::InvalidFieldElement);
    }

    let mut verifier_challenges = [zero(); MAX_ROUNDS];
    let mut expected = claimed_sum;

    for (round, polynomial) in round_polynomials.iter().enumerate() {
        let challenge = challenges[round];
        if !is_field_element(challenge) {
            return Err(ZkError::InvalidFieldElement);
        }
        if polynomial.sum_over_hypercube()? != expected {
            return Err(ZkError::ConstraintUnsatisfied);
        }
        expected = polynomial.evaluate(challenge)?;
        verifier_challenges[round] = challenge;
    }

    Ok(SumcheckReduction {
        challenges: verifier_challenges,
        num_rounds,
        final_evaluation: expected,
    })
}

/// Verifies a full multilinear Sumcheck reduction against the committed
/// polynomial's evaluation oracle.
///
/// Runs [`verify_sumcheck`] and then checks
/// `p(r_0, …, r_{n-1}) == g_{n-1}(r_{n-1})`. This is the check that binds the
/// univariate chain to the actual polynomial, and it is the reason the verifier
/// never has to trust the prover's final claim.
///
/// # Errors
///
/// In addition to the errors of [`verify_sumcheck`]:
///
/// - [`ZkError::InvalidInput`] if the number of rounds does not equal
///   `polynomial.num_variables()`.
/// - [`ZkError::ConstraintUnsatisfied`] if the final round evaluation differs
///   from the multilinear extension at the challenge point.
pub fn verify_multilinear_sumcheck<
    const MAX_EVALS: usize,
    const MAX_ROUNDS: usize,
    const MAX_TERMS: usize,
>(
    polynomial: &MultilinearPolynomial<MAX_EVALS>,
    claimed_sum: u256,
    round_polynomials: &[RoundPolynomial<MAX_TERMS>],
    challenges: &[u256],
) -> Result<SumcheckReduction<MAX_ROUNDS>, ZkError> {
    if polynomial.num_variables() != round_polynomials.len() {
        return Err(ZkError::InvalidInput);
    }

    let reduction = verify_sumcheck(claimed_sum, round_polynomials, challenges)?;
    let oracle = polynomial.evaluate(reduction.challenge_slice())?;
    if oracle != reduction.final_evaluation {
        return Err(ZkError::ConstraintUnsatisfied);
    }
    Ok(reduction)
}
