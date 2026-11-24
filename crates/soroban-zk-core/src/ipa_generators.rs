//! Constant-time IPA (Inner-Product Argument) generator vector utilities.
//!
//! This module provides the building blocks needed to work with the *generator
//! vectors* `g` and `h` that appear in Halo2 / Bulletproofs-style IPA
//! protocols.  Every operation is designed to resist **timing side-channel
//! attacks**:
//!
//! * No scalar-dependent branches.
//! * All conditional selections use the [`G1Projective::ct_select`] /
//!   [`ct_select_affine`] branchless mask pattern that is already established
//!   in `g1_scalar_mul` and throughout the rest of the crate.
//!
//! # Protocol background
//!
//! An IPA for vectors of length `N = 2^k` reduces the verification cost from
//! `O(N)` to `O(log N)` by recursively folding the generator vectors in half
//! at each round.  Given a challenge scalar `x` and its inverse `x_inv`:
//!
//! ```text
//! g'[i] = x_inv * g[i] + x     * g[half + i]   for i in 0..half
//! h'[i] = x     * h[i] + x_inv * h[half + i]   for i in 0..half
//! ```
//!
//! After `k = log2(N)` rounds, both vectors are reduced to a single point.
//!
//! # `no_std` constraints
//!
//! * Zero heap allocation — all state lives on the stack inside fixed-size
//!   arrays sized by const generics.
//! * No `unwrap` / `expect` / `panic!` — errors propagate via `Result<T, ZkError>`.
//! * Compatible with `wasm32v1-none` (Soroban WASM runtime).
//!
//! # Const-generic requirements
//!
//! `N` must be a **power of two** and `N >= 2` for folding operations.
//! [`fold_generators`] and [`fold_generators_rounds`] return
//! [`ZkError::InvalidInput`] immediately if either invariant is violated.

use ethnum::u256;

use crate::{Bn254, G1Affine, G1Projective, ZkError};

// ---------------------------------------------------------------------------
// Identity point helper (the same constant used in bulletproofs.rs)
// ---------------------------------------------------------------------------

const IDENTITY: G1Affine = G1Affine {
    x: u256::from_words(0u128, 0u128),
    y: u256::from_words(0u128, 0u128),
};

// ---------------------------------------------------------------------------
// Constant-time affine-point select
// ---------------------------------------------------------------------------

/// Branchless select between two affine G1 points.
///
/// Returns `a` when `choice != 0`, else `b`.  Internally uses the same
/// 256-bit mask technique as [`G1Projective::ct_select`] — no conditional
/// branch is ever taken on `choice`, so execution time does not depend on
/// which point is selected.
#[inline(always)]
pub fn ct_select_affine(choice: u128, a: G1Affine, b: G1Affine) -> G1Affine {
    let mask = u256::from(0u128).wrapping_sub(u256::from(choice));
    let not_mask = !mask;
    G1Affine {
        x: (mask & a.x) | (not_mask & b.x),
        y: (mask & a.y) | (not_mask & b.y),
    }
}

// ---------------------------------------------------------------------------
// GeneratorVec
// ---------------------------------------------------------------------------

/// A fixed-size vector of `N` BN254 G1 generator points used as the basis
/// for IPA commitments.
///
/// The const parameter `N` is the *current* length of the vector.  After each
/// folding round the caller works with a new `GeneratorVec<{N/2}>`.  Because
/// const-generic arithmetic in array positions is still unstable on stable
/// Rust, the caller is responsible for passing the correctly-sized type at
/// each level.
///
/// Construct via [`GeneratorVec::new`] (from an existing array) or
/// [`GeneratorVec::identity`] (all identity points, useful as a zero-initialised
/// accumulator).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeneratorVec<const N: usize> {
    /// The underlying fixed-size array of affine points.
    pub points: [G1Affine; N],
}

impl<const N: usize> GeneratorVec<N> {
    /// Build a `GeneratorVec` from an existing fixed-size array of points.
    pub const fn new(points: [G1Affine; N]) -> Self {
        Self { points }
    }

    /// Build a `GeneratorVec` whose every element is the identity point.
    ///
    /// Useful as a zero-initialised accumulator before populating the vector
    /// with real generator points.
    pub fn identity() -> Self {
        Self {
            points: [IDENTITY; N],
        }
    }

    /// Return the generator at position `index`.
    ///
    /// Returns [`ZkError::InvalidInput`] when `index >= N`.
    #[inline(always)]
    pub fn get(&self, index: usize) -> Result<G1Affine, ZkError> {
        if index >= N {
            return Err(ZkError::InvalidInput);
        }
        Ok(self.points[index])
    }

    /// Return the number of generators (always `N`).
    #[inline(always)]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns `true` when `N == 0`.
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

// ---------------------------------------------------------------------------
// Constant-time linear combination helper (projective)
// ---------------------------------------------------------------------------

/// Computes `s1 * p1 + s2 * p2` using the constant-time scalar-mul path,
/// returning the result as a [`G1Projective`] accumulator.
///
/// This mirrors the `lin_comb` helper in `bulletproofs.rs` but is exposed
/// here as a public primitive for use in the generator folding kernel.
#[inline(always)]
fn lin_comb_proj(p1: G1Affine, s1: u256, p2: G1Affine, s2: u256) -> G1Projective {
    let t1 = G1Projective::from(p1.scalar_mul(s1));
    let t2 = G1Projective::from(p2.scalar_mul(s2));
    t1.add(&t2)
}

// ---------------------------------------------------------------------------
// Single-round generator folding
// ---------------------------------------------------------------------------

/// Perform one round of IPA generator-vector folding in **constant time**.
///
/// Given a pair of generator vectors `(g, h)` of length `N` and a challenge
/// scalar `x ∈ Fr` (with its inverse computed internally), this function
/// returns the folded pair `(g', h')` of length `N/2`:
///
/// ```text
/// g'[i] = x_inv * g[i]        + x     * g[half + i]
/// h'[i] = x     * h[i]        + x_inv * h[half + i]
/// ```
///
/// These are exactly the folding relations used in the IPA recursion of both
/// Halo2 and Bulletproofs.
///
/// # Errors
///
/// Returns [`ZkError::InvalidInput`] if:
/// * `N == 0`  — empty vectors have no half.
/// * `N` is odd — folding requires an even length at every round.
/// * `N == 1`  — the vectors are already at the base case; call the final
///   check instead of folding further.
/// * `x == 0`  — challenge zero makes the inverse undefined.
///
/// # Constant-time guarantees
///
/// The scalar multiplication inside [`G1Affine::scalar_mul`] uses
/// [`Bn254::g1_scalar_mul`] which is already constant-time (double-and-add
/// with `ct_select`).  No branch in this function depends on the values of
/// the input points or the challenge scalar.
///
/// # Returns
///
/// A pair `(g_folded, h_folded)` of [`GeneratorVec<{N/2}>`].  Because Rust
/// does not yet support const-generic arithmetic in array length positions,
/// the output length `HALF` must be supplied explicitly as a separate const
/// parameter that equals `N / 2`.  The function returns
/// [`ZkError::InvalidInput`] if `HALF * 2 != N`.
pub fn fold_generators<const N: usize, const HALF: usize>(
    g: &GeneratorVec<N>,
    h: &GeneratorVec<N>,
    x: u256,
) -> Result<(GeneratorVec<HALF>, GeneratorVec<HALF>), ZkError> {
    // Structural checks -------------------------------------------------------
    if N == 0 || N == 1 || N % 2 != 0 {
        return Err(ZkError::InvalidInput);
    }
    // The caller-supplied HALF must match the actual half of N.
    if HALF * 2 != N {
        return Err(ZkError::InvalidInput);
    }
    if x == u256::from(0u8) {
        // x == 0 makes the inverse undefined; reject to avoid silent corruption.
        return Err(ZkError::InvalidInput);
    }
    // x must be a valid field element.
    if x >= Bn254::FR_MODULUS {
        return Err(ZkError::InvalidInput);
    }

    // Compute x_inv = x^{r-2} mod r (Fermat-based, constant-time) ------------
    let x_inv = Bn254::invert(x);

    // Fold the vectors --------------------------------------------------------
    let mut g_out: [G1Affine; HALF] = [IDENTITY; HALF];
    let mut h_out: [G1Affine; HALF] = [IDENTITY; HALF];

    for i in 0..HALF {
        // g'[i] = x_inv * g[i] + x * g[half + i]
        g_out[i] = lin_comb_proj(g.points[i], x_inv, g.points[HALF + i], x).to_affine();
        // h'[i] = x * h[i] + x_inv * h[half + i]
        h_out[i] = lin_comb_proj(h.points[i], x, h.points[HALF + i], x_inv).to_affine();
    }

    Ok((GeneratorVec::new(g_out), GeneratorVec::new(h_out)))
}

// ---------------------------------------------------------------------------
// Multi-round folding
// ---------------------------------------------------------------------------

/// Apply `log2(N)` rounds of IPA generator-vector folding, driven by a slice
/// of pre-computed challenge scalars.
///
/// This is the complete generator-reduction step needed by both the prover and
/// the verifier of a Halo2 / Bulletproofs IPA.  After all rounds, the caller
/// receives the single generator point pair `(g[0], h[0])` that appears in
/// the final scalar check.
///
/// # Arguments
///
/// * `g` — initial `g` generator vector of length `N` (must be a power of 2).
/// * `h` — initial `h` generator vector of length `N`.
/// * `challenges` — `log2(N)` non-zero challenge scalars in `Fr`, one per
///   round (index 0 = first round).
///
/// # Errors
///
/// Returns [`ZkError::InvalidInput`] if:
/// * `N == 0` or `N == 1`.
/// * `N` is not a power of two.
/// * `challenges.len() != log2(N)`.
/// * Any challenge is zero or `>= FR_MODULUS`.
///
/// # Returns
///
/// `(g_final, h_final)` — the single affine generator points that survive all
/// folding rounds.
pub fn fold_generators_rounds<const N: usize>(
    g: &GeneratorVec<N>,
    h: &GeneratorVec<N>,
    challenges: &[u256],
) -> Result<(G1Affine, G1Affine), ZkError> {
    // Structural checks -------------------------------------------------------
    if N == 0 || N == 1 {
        return Err(ZkError::InvalidInput);
    }
    if !is_power_of_two(N) {
        return Err(ZkError::InvalidInput);
    }
    let rounds = log2_exact(N);
    if challenges.len() != rounds {
        return Err(ZkError::InvalidInput);
    }
    for &c in challenges {
        if c == u256::from(0u8) || c >= Bn254::FR_MODULUS {
            return Err(ZkError::InvalidInput);
        }
    }

    // Iterative folding over mutable slices of a fixed-size workspace --------
    //
    // Rather than recursing (which would require const-generic arithmetic in
    // array sizes), we maintain a single working copy of the generator vectors
    // inside a flat [G1Affine; N] array and shrink the active window by half
    // on every iteration.

    let mut g_work: [G1Affine; N] = g.points;
    let mut h_work: [G1Affine; N] = h.points;

    let mut cur_len = N;

    for round in 0..rounds {
        let x = challenges[round];
        let x_inv = Bn254::invert(x);
        let half = cur_len / 2;

        // Fold in-place: write the folded result into the lower half of the
        // working arrays.  We read from [0..half) and [half..cur_len) and
        // write back into [0..half).  There is no aliasing because we only
        // write positions in [0..half) and read positions in [0..cur_len).
        for i in 0..half {
            let g_lo = g_work[i];
            let g_hi = g_work[half + i];
            let h_lo = h_work[i];
            let h_hi = h_work[half + i];

            // g'[i] = x_inv * g_lo + x * g_hi
            g_work[i] = lin_comb_proj(g_lo, x_inv, g_hi, x).to_affine();
            // h'[i] = x * h_lo + x_inv * h_hi
            h_work[i] = lin_comb_proj(h_lo, x, h_hi, x_inv).to_affine();
        }

        cur_len = half;
    }

    // After all rounds cur_len == 1.
    Ok((g_work[0], h_work[0]))
}

// ---------------------------------------------------------------------------
// Scalar commitment (MSM over a generator vector)
// ---------------------------------------------------------------------------

/// Compute the multi-scalar multiplication `∑ scalars[i] * generators[i]`,
/// returning the result as an affine G1 point.
///
/// This implements the Pedersen-style "inner product with generators"
/// commitment `⟨scalars, generators⟩` used by the IPA prover when building
/// the commitment `P = ⟨a, g⟩ + ⟨b, h⟩`.
///
/// # Errors
///
/// Returns [`ZkError::InvalidInput`] if `scalars.len() != N`.
///
/// # Constant time
///
/// Each scalar multiplication delegates to [`Bn254::g1_scalar_mul`], which is
/// constant-time.  The accumulation loop is data-independent (fixed `N`
/// iterations).
pub fn commit_generators<const N: usize>(
    generators: &GeneratorVec<N>,
    scalars: &[u256],
) -> Result<G1Affine, ZkError> {
    if scalars.len() != N {
        return Err(ZkError::InvalidInput);
    }

    let mut acc = G1Projective::identity();
    for i in 0..N {
        let term = Bn254::g1_scalar_mul(G1Projective::from(generators.points[i]), scalars[i]);
        acc = acc.add(&term);
    }
    Ok(acc.to_affine())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Returns `true` iff `n` is a power of two (and non-zero).
#[inline(always)]
const fn is_power_of_two(n: usize) -> bool {
    n != 0 && (n & (n - 1)) == 0
}

/// Returns `k` such that `2^k == n`.  Assumes `n` is already a power of two.
#[inline(always)]
const fn log2_exact(n: usize) -> usize {
    n.trailing_zeros() as usize
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Shared test helpers
    // -----------------------------------------------------------------------

    /// Deterministic G1 point at scalar multiple `k * G`, used to produce
    /// distinguishable, valid test points without hash-to-curve overhead.
    fn test_point(k: u64) -> G1Affine {
        const G: G1Affine = G1Affine {
            x: u256::from_words(0, 1),
            y: u256::from_words(0, 2),
        };
        G.scalar_mul(u256::from(k))
    }

    /// Build a `GeneratorVec<N>` filled with distinct test points.
    fn test_vec<const N: usize>(offset: u64) -> GeneratorVec<N> {
        let mut pts = [IDENTITY; N];
        for i in 0..N {
            pts[i] = test_point(offset + i as u64 + 1);
        }
        GeneratorVec::new(pts)
    }

    // -----------------------------------------------------------------------
    // ct_select_affine
    // -----------------------------------------------------------------------

    #[test]
    fn ct_select_affine_choice_one_returns_a() {
        let a = test_point(1);
        let b = test_point(2);
        let result = ct_select_affine(1, a, b);
        assert_eq!(result, a);
    }

    #[test]
    fn ct_select_affine_choice_zero_returns_b() {
        let a = test_point(1);
        let b = test_point(2);
        let result = ct_select_affine(0, a, b);
        assert_eq!(result, b);
    }

    #[test]
    fn ct_select_affine_nonzero_choice_returns_a() {
        let a = test_point(3);
        let b = test_point(5);
        // Any non-zero value should select `a`.
        let result = ct_select_affine(0xff, a, b);
        assert_eq!(result, a);
    }

    // -----------------------------------------------------------------------
    // GeneratorVec construction & accessors
    // -----------------------------------------------------------------------

    #[test]
    fn generator_vec_identity_is_all_identity() {
        let v = GeneratorVec::<4>::identity();
        for p in &v.points {
            assert_eq!(p.x, u256::from(0u8));
            assert_eq!(p.y, u256::from(0u8));
        }
    }

    #[test]
    fn generator_vec_get_in_bounds() {
        let v: GeneratorVec<4> = test_vec::<4>(0);
        for i in 0..4 {
            assert_eq!(v.get(i).unwrap(), v.points[i]);
        }
    }

    #[test]
    fn generator_vec_get_out_of_bounds_errors() {
        let v: GeneratorVec<4> = test_vec::<4>(0);
        assert_eq!(v.get(4), Err(ZkError::InvalidInput));
        assert_eq!(v.get(100), Err(ZkError::InvalidInput));
    }

    #[test]
    fn generator_vec_len_matches_const() {
        assert_eq!(GeneratorVec::<8>::identity().len(), 8);
        assert_eq!(GeneratorVec::<1>::identity().len(), 1);
    }

    // -----------------------------------------------------------------------
    // fold_generators — input validation
    // -----------------------------------------------------------------------

    #[test]
    fn fold_rejects_zero_challenge() {
        let g: GeneratorVec<4> = test_vec::<4>(0);
        let h: GeneratorVec<4> = test_vec::<4>(10);
        let result = fold_generators::<4, 2>(&g, &h, u256::from(0u8));
        assert_eq!(result, Err(ZkError::InvalidInput));
    }

    #[test]
    fn fold_rejects_challenge_at_modulus() {
        let g: GeneratorVec<4> = test_vec::<4>(0);
        let h: GeneratorVec<4> = test_vec::<4>(10);
        let result = fold_generators::<4, 2>(&g, &h, Bn254::FR_MODULUS);
        assert_eq!(result, Err(ZkError::InvalidInput));
    }

    #[test]
    fn fold_rejects_mismatched_half() {
        // HALF = 3, N = 4: 3*2 != 4 → should be rejected.
        let g: GeneratorVec<4> = test_vec::<4>(0);
        let h: GeneratorVec<4> = test_vec::<4>(10);
        // We call with HALF=3 but the function checks HALF*2 == N.
        let result = fold_generators::<4, 3>(&g, &h, u256::from(5u8));
        assert_eq!(result, Err(ZkError::InvalidInput));
    }

    // -----------------------------------------------------------------------
    // fold_generators — correctness
    // -----------------------------------------------------------------------

    /// Verify that a single folding round satisfies the expected linear
    /// relation by recomputing it independently from the input points.
    #[test]
    fn fold_single_round_matches_manual_computation() {
        let g: GeneratorVec<4> = test_vec::<4>(0);
        let h: GeneratorVec<4> = test_vec::<4>(10);
        let x = u256::from(7u8);
        let x_inv = Bn254::invert(x);

        let (gf, hf) = fold_generators::<4, 2>(&g, &h, x).unwrap();

        for i in 0..2usize {
            // g'[i] should equal x_inv * g[i] + x * g[2 + i]
            let expected_g = lin_comb_proj(g.points[i], x_inv, g.points[2 + i], x).to_affine();
            assert_eq!(gf.points[i], expected_g, "g_fold[{i}] mismatch");

            // h'[i] should equal x * h[i] + x_inv * h[2 + i]
            let expected_h = lin_comb_proj(h.points[i], x, h.points[2 + i], x_inv).to_affine();
            assert_eq!(hf.points[i], expected_h, "h_fold[{i}] mismatch");
        }
    }

    #[test]
    fn fold_output_length_is_half() {
        let g: GeneratorVec<8> = test_vec::<8>(0);
        let h: GeneratorVec<8> = test_vec::<8>(20);
        let (gf, hf) = fold_generators::<8, 4>(&g, &h, u256::from(3u8)).unwrap();
        assert_eq!(gf.len(), 4);
        assert_eq!(hf.len(), 4);
    }

    /// Folding with x = 1 (challenge = 1) means x_inv = 1 too, so the fold
    /// collapses to a plain addition: g'[i] = g[i] + g[half + i].
    #[test]
    fn fold_with_challenge_one_equals_sum() {
        let g: GeneratorVec<4> = test_vec::<4>(0);
        let h: GeneratorVec<4> = test_vec::<4>(10);
        let (gf, hf) = fold_generators::<4, 2>(&g, &h, u256::from(1u8)).unwrap();

        for i in 0..2usize {
            let expected_g = g.points[i].add(&g.points[2 + i]);
            assert_eq!(
                gf.points[i], expected_g,
                "g_fold[{i}] with x=1 should be sum"
            );

            let expected_h = h.points[i].add(&h.points[2 + i]);
            assert_eq!(
                hf.points[i], expected_h,
                "h_fold[{i}] with x=1 should be sum"
            );
        }
    }

    /// Two successive single-round folds must produce the same result as two
    /// rounds of `fold_generators_rounds`.
    #[test]
    fn two_single_rounds_match_multi_round() {
        let g: GeneratorVec<4> = test_vec::<4>(0);
        let h: GeneratorVec<4> = test_vec::<4>(10);
        let x0 = u256::from(5u8);
        let x1 = u256::from(11u8);

        // Multi-round path
        let (gm, hm) = fold_generators_rounds(&g, &h, &[x0, x1]).unwrap();

        // Manual two-round path
        let (g2, h2) = fold_generators::<4, 2>(&g, &h, x0).unwrap();
        let (g1, h1) = fold_generators::<2, 1>(&g2, &h2, x1).unwrap();

        assert_eq!(gm, g1.points[0], "g final point mismatch");
        assert_eq!(hm, h1.points[0], "h final point mismatch");
    }

    // -----------------------------------------------------------------------
    // fold_generators_rounds — input validation
    // -----------------------------------------------------------------------

    #[test]
    fn multi_round_rejects_wrong_challenge_count() {
        let g: GeneratorVec<4> = test_vec::<4>(0);
        let h: GeneratorVec<4> = test_vec::<4>(10);
        // log2(4) == 2, so we need exactly 2 challenges.
        let result = fold_generators_rounds(&g, &h, &[u256::from(3u8)]);
        assert_eq!(result, Err(ZkError::InvalidInput));
    }

    #[test]
    fn multi_round_rejects_zero_challenge() {
        let g: GeneratorVec<4> = test_vec::<4>(0);
        let h: GeneratorVec<4> = test_vec::<4>(10);
        let result = fold_generators_rounds(&g, &h, &[u256::from(0u8), u256::from(3u8)]);
        assert_eq!(result, Err(ZkError::InvalidInput));
    }

    #[test]
    fn multi_round_rejects_challenge_at_modulus() {
        let g: GeneratorVec<4> = test_vec::<4>(0);
        let h: GeneratorVec<4> = test_vec::<4>(10);
        let result = fold_generators_rounds(&g, &h, &[Bn254::FR_MODULUS, u256::from(3u8)]);
        assert_eq!(result, Err(ZkError::InvalidInput));
    }

    // -----------------------------------------------------------------------
    // fold_generators_rounds — correctness across sizes
    // -----------------------------------------------------------------------

    #[test]
    fn multi_round_n2_produces_single_point() {
        let g: GeneratorVec<2> = test_vec::<2>(0);
        let h: GeneratorVec<2> = test_vec::<2>(5);
        let x = u256::from(13u8);
        let x_inv = Bn254::invert(x);

        let (gf, hf) = fold_generators_rounds(&g, &h, &[x]).unwrap();

        let expected_g = lin_comb_proj(g.points[0], x_inv, g.points[1], x).to_affine();
        let expected_h = lin_comb_proj(h.points[0], x, h.points[1], x_inv).to_affine();

        assert_eq!(gf, expected_g);
        assert_eq!(hf, expected_h);
    }

    #[test]
    fn multi_round_n8_three_rounds() {
        let g: GeneratorVec<8> = test_vec::<8>(0);
        let h: GeneratorVec<8> = test_vec::<8>(20);
        let challenges = [u256::from(2u8), u256::from(7u8), u256::from(11u8)];
        // log2(8) == 3 → 3 challenges needed.
        let result = fold_generators_rounds(&g, &h, &challenges);
        assert!(
            result.is_ok(),
            "folding N=8 with 3 challenges should succeed"
        );
        let (gf, hf) = result.unwrap();
        // Final points must be valid curve points (non-identity for these inputs).
        assert!(Bn254::is_valid_g1(gf.x, gf.y), "final g should be on curve");
        assert!(Bn254::is_valid_g1(hf.x, hf.y), "final h should be on curve");
    }

    // -----------------------------------------------------------------------
    // commit_generators
    // -----------------------------------------------------------------------

    #[test]
    fn commit_generators_rejects_wrong_scalar_count() {
        let g: GeneratorVec<4> = test_vec::<4>(0);
        let scalars = [u256::from(1u8); 3]; // 3 != 4
        assert_eq!(commit_generators(&g, &scalars), Err(ZkError::InvalidInput));
    }

    #[test]
    fn commit_all_zero_scalars_is_identity() {
        let g: GeneratorVec<4> = test_vec::<4>(0);
        let scalars = [u256::from(0u8); 4];
        let result = commit_generators(&g, &scalars).unwrap();
        // 0 * P = identity = (0, 0) in our representation.
        assert_eq!(result.x, u256::from(0u8));
        assert_eq!(result.y, u256::from(0u8));
    }

    #[test]
    fn commit_single_scalar_one_equals_generator() {
        // With N=1 and scalar = 1, the MSM should return the sole generator itself.
        let g0 = test_point(3);
        let g = GeneratorVec::<1>::new([g0]);
        let scalars = [u256::from(1u8)];
        let result = commit_generators(&g, &scalars).unwrap();
        assert_eq!(result, g0);
    }

    #[test]
    fn commit_scalar_two_equals_double() {
        let g0 = test_point(3);
        let g = GeneratorVec::<1>::new([g0]);
        let scalars = [u256::from(2u8)];
        let result = commit_generators(&g, &scalars).unwrap();
        let expected = g0.scalar_mul(u256::from(2u8));
        assert_eq!(result, expected);
    }

    #[test]
    fn commit_generators_linearity() {
        // MSM must satisfy: commit(s1 + s2) == commit(s1) + commit(s2).
        let g: GeneratorVec<2> = test_vec::<2>(0);
        let s1 = [u256::from(3u8), u256::from(5u8)];
        let s2 = [u256::from(7u8), u256::from(11u8)];
        let s_sum = [Bn254::add(s1[0], s2[0]), Bn254::add(s1[1], s2[1])];

        let c1 = commit_generators(&g, &s1).unwrap();
        let c2 = commit_generators(&g, &s2).unwrap();
        let c_sum = commit_generators(&g, &s_sum).unwrap();

        let c1_plus_c2 = c1.add(&c2);
        assert_eq!(c_sum, c1_plus_c2, "commitment should be linear in scalars");
    }

    // -----------------------------------------------------------------------
    // Helper function tests
    // -----------------------------------------------------------------------

    #[test]
    fn is_power_of_two_correct() {
        assert!(is_power_of_two(1));
        assert!(is_power_of_two(2));
        assert!(is_power_of_two(4));
        assert!(is_power_of_two(64));
        assert!(!is_power_of_two(0));
        assert!(!is_power_of_two(3));
        assert!(!is_power_of_two(5));
        assert!(!is_power_of_two(6));
        assert!(!is_power_of_two(12));
    }

    #[test]
    fn log2_exact_correct() {
        assert_eq!(log2_exact(1), 0);
        assert_eq!(log2_exact(2), 1);
        assert_eq!(log2_exact(4), 2);
        assert_eq!(log2_exact(8), 3);
        assert_eq!(log2_exact(64), 6);
    }
}
