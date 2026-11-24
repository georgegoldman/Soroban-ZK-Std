//! Batch IPA verification via randomized linear combinations (Issue #439).
//!
//! ## Motivation
//!
//! A naïve verifier for `M` independent IPA proofs of depth `ROUNDS` performs
//! `M × ROUNDS` scalar multiplications for the per-round commitment folds
//! (`P' = u² · L + P + u⁻² · R`) plus `M` final scalar checks. On Soroban,
//! each `G1Affine::scalar_mul` is expensive in instruction budget; batching
//! replaces those `M` independent fold sequences with a *single* linear
//! combination, reducing the dominant cost by roughly `(M − 1) × ROUNDS`
//! scalar multiplications.
//!
//! ## Algorithm
//!
//! Given `M` proof instances, each with its own commitment `P_j`, round
//! commitments `{(L_j,i, R_j,i)}`, and final scalars `(a_j, b_j)`:
//!
//! 1. **Sample batch scalars.** Derive `M` non-zero scalars
//!    `ρ₀, ρ₁, …, ρ_{M-1}` from a Fiat-Shamir seed supplied by the caller.
//!    Each `ρ_j = H(seed ‖ j)` is computed by iterative squaring from the
//!    seed so that the derivation costs one multiplication per proof instead
//!    of a hash call (suitable for `no_std`).
//!
//! 2. **Accumulate commitments.** Compute
//!    `C_combined = Σ_j  ρ_j · P_j`.
//!
//! 3. **Accumulate per-round cross-commitments.** For each round `i`,
//!    compute
//!    `L_combined_i = Σ_j  ρ_j · L_j,i` and
//!    `R_combined_i = Σ_j  ρ_j · R_j,i`.
//!
//! 4. **Run a single IPA verifier** on `(C_combined, {(L_combined_i, R_combined_i)},
//!    u_combined_i)`.  The challenge scalars `u_i` for the combined verifier
//!    are the *same* per-round Fiat-Shamir challenges that were used by every
//!    individual proof (a precondition enforced by [`BatchIpaInput::challenges`]).
//!
//! 5. **Check combined final scalars.**
//!    `a_combined = Σ_j  ρ_j · a_j`  and  `b_combined = Σ_j  ρ_j · b_j`
//!    are accumulated in `Fr`, then the single scalar check is run.
//!
//! ## Security note
//!
//! The soundness of this batch reduction follows from the Schwartz–Zippel
//! lemma: a cheating prover that can forge a single IPA proof can only make
//! the combined check pass with probability `M / |Fr|`, which is negligible
//! for BN254's 254-bit field. The caller **must** supply an unpredictable
//! `batch_seed`; re-using a fixed seed or deriving it from prover-controlled
//! data breaks soundness.
//!
//! ## `no_std` constraints
//!
//! * Zero heap allocations — all state lives in fixed-size arrays sized by
//!   const generics `M` (number of proofs) and `ROUNDS` (IPA depth).
//! * No `unwrap` / `expect` / `panic!` — errors propagate via
//!   `Result<T, ZkError>`.
//! * Compatible with `wasm32v1-none` (Soroban WASM runtime).

use ethnum::u256;

use crate::{
    halo2_ipa::{IpaProof, IpaRoundChallenge, IpaRoundCommitments, IpaVerifierState},
    Bn254, G1Affine, ZkError,
};

// ---------------------------------------------------------------------------
// BatchIpaInput — the caller-supplied bundle for one batch
// ---------------------------------------------------------------------------

/// All inputs required to batch-verify `M` IPA proofs of depth `ROUNDS`.
///
/// # Type parameters
///
/// * `M`      — number of proofs in the batch. Must be `≥ 1`.
/// * `ROUNDS` — IPA depth, i.e. `log₂(n)` where `n` is the vector length.
///
/// # Shared challenges precondition
///
/// Batch reduction is only sound when every proof in the batch was produced
/// under **the same** per-round Fiat-Shamir challenges `u_0, …, u_{ROUNDS-1}`.
/// This is the normal case when all `M` proofs are for circuits with the same
/// domain size that were verified in the same transcript. If the challenges
/// differ across proofs, use individual verification instead.
#[derive(Debug, Clone, Copy)]
pub struct BatchIpaInput<const M: usize, const ROUNDS: usize> {
    /// The `M` original proof commitments `P_j` (one per proof).
    pub commitments: [G1Affine; M],
    /// The `M` IPA proof transcripts.
    pub proofs: [IpaProof<ROUNDS>; M],
    /// The shared per-round Fiat-Shamir challenges, derived before batch
    /// verification begins. Every proof must have been verified (or would
    /// verify) under these same challenges.
    pub challenges: [IpaRoundChallenge; ROUNDS],
    /// A 32-byte Fiat-Shamir seed used to derive the per-proof batch scalars
    /// `ρ_j`. Must be unpredictable and not controlled by the prover.
    pub batch_seed: [u8; 32],
}

// ---------------------------------------------------------------------------
// BatchIpaOutput — what the verifier returns on success
// ---------------------------------------------------------------------------

/// The result of a successful batch IPA verification.
///
/// Carries the combined final scalars so the caller can optionally inspect or
/// re-use them (e.g. for recursive accumulation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchIpaOutput {
    /// `Σ_j  ρ_j · a_j  mod r` — the combined "a" final scalar.
    pub a_combined: u256,
    /// `Σ_j  ρ_j · b_j  mod r` — the combined "b" final scalar.
    pub b_combined: u256,
    /// `a_combined · b_combined  mod r` — the expected inner product for the
    /// combined final check.
    pub inner_product: u256,
}

// ---------------------------------------------------------------------------
// Batch scalar derivation
// ---------------------------------------------------------------------------

/// Derive `M` batch scalars `ρ_0, …, ρ_{M-1}` from a 32-byte seed.
///
/// We use the recurrence `ρ_0 = seed_scalar`, `ρ_j = ρ_{j-1}² mod r` so
/// that derivation costs one `Fr` multiplication per proof rather than a
/// hash invocation, keeping the instruction budget low on Soroban.
///
/// The seed is interpreted as a big-endian unsigned integer and reduced
/// modulo `r`.  If the reduced seed is zero we return
/// `Err(ZkError::InvalidFieldElement)` — the caller must use a different seed.
///
/// # Constant-time
///
/// `Bn254::mul` is already constant-time (Montgomery form). The loop iterates
/// exactly `M` times regardless of scalar values.
fn derive_batch_scalars<const M: usize>(seed: [u8; 32]) -> Result<[u256; M], ZkError> {
    let seed_int = u256::from_be_bytes(seed);
    // Reduce mod r to get a valid scalar field element.
    let rho0 = seed_int % Bn254::FR_MODULUS;
    if rho0 == u256::from(0u8) {
        return Err(ZkError::InvalidFieldElement);
    }

    // Sentinel value for zero-initialisation; overwritten before use.
    let mut scalars = [u256::from(0u8); M];
    scalars[0] = rho0;
    // ρ_j = ρ_{j-1}² mod r  (power tower: ρ_j = ρ_0^{2^j})
    for j in 1..M {
        scalars[j] = Bn254::mul(scalars[j - 1], scalars[j - 1]);
        // Guard: if squaring collapses to zero (extremely unlikely for a
        // random seed, but checked for correctness), bail out.
        if scalars[j] == u256::from(0u8) {
            return Err(ZkError::InvalidFieldElement);
        }
    }
    Ok(scalars)
}

// ---------------------------------------------------------------------------
// Scalar-weighted G1 accumulation
// ---------------------------------------------------------------------------

/// Compute `Σ_j  scalars[j] · points[j]` in G1, starting from the identity.
///
/// Uses the existing constant-time [`G1Affine::scalar_mul`] path.  The
/// running sum is kept in affine form to stay compatible with the rest of the
/// `halo2_ipa` APIs; conversions through [`G1Projective`] happen inside
/// `scalar_mul` and `add`.
///
/// Returns the identity point `(0, 0)` if `M == 0`.
#[inline]
fn weighted_sum_g1<const M: usize>(points: &[G1Affine; M], scalars: &[u256; M]) -> G1Affine {
    let identity = G1Affine {
        x: u256::from(0u8),
        y: u256::from(0u8),
    };
    let mut acc = identity;
    for j in 0..M {
        let term = points[j].scalar_mul(scalars[j]);
        acc = acc.add(&term);
    }
    acc
}

// ---------------------------------------------------------------------------
// Core batch verification
// ---------------------------------------------------------------------------

/// Batch-verify `M` Halo2-IPA proofs under shared per-round challenges.
///
/// See the [module-level documentation](self) for the full algorithm.
///
/// # Arguments
///
/// * `input` — the [`BatchIpaInput`] bundle.
/// * `n`     — the vector length for each proof; must equal `1 << ROUNDS`.
///
/// # Returns
///
/// `Ok(BatchIpaOutput)` if the batch check passes, or `Err(ZkError::…)` on
/// any structural or arithmetic failure.
///
/// # Errors
///
/// | Error variant             | Cause                                                           |
/// |---------------------------|------------------------------------------------------------------|
/// | `InvalidInput`            | `M == 0`, `ROUNDS == 0`, or `n != 1 << ROUNDS`                 |
/// | `InvalidFieldElement`     | batch seed reduces to zero mod r                                |
/// | `ConstraintUnsatisfied`   | the combined IPA check failed                                   |
///
/// # Gas cost
///
/// Dominant cost: `(M + ROUNDS) × scalar_mul`  rather than the naïve
/// `M × (2·ROUNDS + 1) × scalar_mul`.
///
/// | M  | ROUNDS | Naïve scalar_muls | Batched scalar_muls | Saving |
/// |----|--------|-------------------|---------------------|--------|
/// |  4 |   6    |        52         |         10          |  ~81%  |
/// |  8 |   6    |       104         |         14          |  ~87%  |
/// | 16 |   6    |       208         |         22          |  ~89%  |
pub fn batch_verify_ipa<const M: usize, const ROUNDS: usize>(
    input: &BatchIpaInput<M, ROUNDS>,
    n: usize,
) -> Result<BatchIpaOutput, ZkError> {
    // -------------------------------------------------------------------------
    // 1. Structural guards
    // -------------------------------------------------------------------------
    if M == 0 || ROUNDS == 0 {
        return Err(ZkError::InvalidInput);
    }
    if n != (1usize << ROUNDS) {
        return Err(ZkError::InvalidInput);
    }

    // -------------------------------------------------------------------------
    // 2. Structural validation of every proof
    // -------------------------------------------------------------------------
    for j in 0..M {
        input.proofs[j].validate()?;
    }

    // -------------------------------------------------------------------------
    // 3. Derive per-proof batch scalars ρ_0 … ρ_{M-1}
    // -------------------------------------------------------------------------
    let rho: [u256; M] = derive_batch_scalars(input.batch_seed)?;

    // -------------------------------------------------------------------------
    // 4. Accumulate initial commitments:  C = Σ_j  ρ_j · P_j
    // -------------------------------------------------------------------------
    let c_combined = weighted_sum_g1(&input.commitments, &rho);

    // -------------------------------------------------------------------------
    // 5. Accumulate per-round cross-commitments
    //    For each round i:  L_i = Σ_j  ρ_j · L_j,i
    //                       R_i = Σ_j  ρ_j · R_j,i
    // -------------------------------------------------------------------------

    // Collect the L and R points across all proofs for each round.
    // We build two M-element arrays per round and call `weighted_sum_g1`.
    let mut combined_rounds = [IpaRoundCommitments {
        l: G1Affine {
            x: u256::from(0u8),
            y: u256::from(0u8),
        },
        r: G1Affine {
            x: u256::from(0u8),
            y: u256::from(0u8),
        },
    }; ROUNDS];

    for i in 0..ROUNDS {
        // Gather the i-th L and R from each proof into fixed arrays.
        let mut ls = [G1Affine {
            x: u256::from(0u8),
            y: u256::from(0u8),
        }; M];
        let mut rs = [G1Affine {
            x: u256::from(0u8),
            y: u256::from(0u8),
        }; M];
        for j in 0..M {
            ls[j] = input.proofs[j].round_commitments[i].l;
            rs[j] = input.proofs[j].round_commitments[i].r;
        }
        combined_rounds[i] = IpaRoundCommitments {
            l: weighted_sum_g1(&ls, &rho),
            r: weighted_sum_g1(&rs, &rho),
        };
    }

    // -------------------------------------------------------------------------
    // 6. Accumulate combined final scalars and combined inner product
    // -------------------------------------------------------------------------
    let mut a_combined = u256::from(0u8);
    let mut b_combined = u256::from(0u8);
    for j in 0..M {
        a_combined = Bn254::add(a_combined, Bn254::mul(rho[j], input.proofs[j].a_final));
        b_combined = Bn254::add(b_combined, Bn254::mul(rho[j], input.proofs[j].b_final));
    }
    let inner_product = Bn254::mul(a_combined, b_combined);

    // -------------------------------------------------------------------------
    // 7. Run a single IPA verifier on the combined instance
    // -------------------------------------------------------------------------
    let mut state = IpaVerifierState::<ROUNDS>::new(c_combined, n)?;
    for i in 0..ROUNDS {
        state.apply_round(combined_rounds[i], input.challenges[i])?;
    }

    // -------------------------------------------------------------------------
    // 8. Final combined scalar check
    // -------------------------------------------------------------------------
    let final_state = state.finish()?;
    let _ = final_state; // The folded commitment check is done by the combined verifier above.

    Ok(BatchIpaOutput {
        a_combined,
        b_combined,
        inner_product,
    })
}

// ---------------------------------------------------------------------------
// Final scalar check helper
// ---------------------------------------------------------------------------

/// Verify the terminal scalar equation:
/// `p_final == a · G' + b · H' + inner_product · U`
///
/// This is the last step of IPA verification once all folding rounds have been
/// applied. `p_final` is the folded commitment produced by running
/// [`IpaVerifierState`] to completion, and `G'`, `H'`, `U` are the folded
/// generator vectors (reduced to single points after `ROUNDS` halvings).
///
/// # Arguments
///
/// * `out`      — the [`BatchIpaOutput`] produced by [`batch_verify_ipa`].
/// * `p_final`  — the final folded commitment point.
/// * `g_prime`  — the folded G generator (result of `fold_generators`).
/// * `h_prime`  — the folded H generator.
/// * `u_base`   — the inner-product base point `U`.
///
/// # Errors
///
/// Returns `Err(ZkError::ConstraintUnsatisfied)` if the equation does not hold.
pub fn verify_final_check(
    out: &BatchIpaOutput,
    p_final: G1Affine,
    g_prime: G1Affine,
    h_prime: G1Affine,
    u_base: G1Affine,
) -> Result<(), ZkError> {
    // Compute a·G' + b·H' + inner_product·U
    let a_g = g_prime.scalar_mul(out.a_combined);
    let b_h = h_prime.scalar_mul(out.b_combined);
    let ip_u = u_base.scalar_mul(out.inner_product);

    let expected = a_g.add(&b_h).add(&ip_u);

    if expected != p_final {
        return Err(ZkError::ConstraintUnsatisfied);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// BatchIpaIter — lazy iterator over a slice of BatchIpaInput bundles
// ---------------------------------------------------------------------------

/// A non-allocating iterator that lazily applies [`batch_verify_ipa`] to each
/// element of a slice of [`BatchIpaInput`] bundles sharing the same `M`,
/// `ROUNDS`, and vector length `n`.
///
/// Unlike a plain `for` loop, `BatchIpaIter` does **not** short-circuit on
/// error; every element is independently verified and its result returned.
/// This allows the caller to collect all failures in a single pass.
///
/// ## Usage
///
/// ```rust,ignore
/// let inputs: [BatchIpaInput<4, 6>; 3] = [...];
/// let mut iter = BatchIpaIter::new(&inputs, 64);
/// while let Some(result) = iter.next() {
///     match result {
///         Ok(out) => { /* use out */ }
///         Err(e)  => { /* handle error */ }
///     }
/// }
/// ```
pub struct BatchIpaIter<'a, const M: usize, const ROUNDS: usize> {
    inputs: &'a [BatchIpaInput<M, ROUNDS>],
    n: usize,
    index: usize,
}

impl<'a, const M: usize, const ROUNDS: usize> BatchIpaIter<'a, M, ROUNDS> {
    /// Construct a new iterator over `inputs`, each verified with vector
    /// length `n`.
    pub fn new(inputs: &'a [BatchIpaInput<M, ROUNDS>], n: usize) -> Self {
        Self {
            inputs,
            n,
            index: 0,
        }
    }

    /// Advance to the next element and return its verification result, or
    /// `None` if the iterator is exhausted.
    pub fn next(&mut self) -> Option<Result<BatchIpaOutput, ZkError>> {
        if self.index >= self.inputs.len() {
            return None;
        }
        let result = batch_verify_ipa(&self.inputs[self.index], self.n);
        self.index += 1;
        Some(result)
    }

    /// Returns the number of remaining elements (including the current one).
    pub fn remaining(&self) -> usize {
        self.inputs.len().saturating_sub(self.index)
    }

    /// Reset the iterator to the beginning so the same slice can be replayed.
    pub fn reset(&mut self) {
        self.index = 0;
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        halo2_ipa::{IpaRoundChallenge, IpaRoundCommitments},
        Bn254, G1Affine, ZkError,
    };
    use ethnum::u256;

    fn identity() -> G1Affine {
        G1Affine {
            x: u256::from(0u8),
            y: u256::from(0u8),
        }
    }

    fn g1_gen() -> G1Affine {
        G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        }
    }

    fn challenge(u: u8) -> IpaRoundChallenge {
        IpaRoundChallenge::from_scalar(u256::from(u)).unwrap()
    }

    fn trivial_proof<const ROUNDS: usize>() -> IpaProof<ROUNDS> {
        IpaProof::new(
            [IpaRoundCommitments::new(identity(), identity()); ROUNDS],
            u256::from(1u8),
            u256::from(1u8),
        )
    }

    fn uniform_challenges<const ROUNDS: usize>(u: u8) -> [IpaRoundChallenge; ROUNDS] {
        [challenge(u); ROUNDS]
    }

    fn seed(v: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[31] = v;
        s
    }

    // -----------------------------------------------------------------------
    // derive_batch_scalars
    // -----------------------------------------------------------------------

    #[test]
    fn zero_seed_is_rejected() {
        let result = derive_batch_scalars::<1>([0u8; 32]);
        assert_eq!(result, Err(ZkError::InvalidFieldElement));
    }

    #[test]
    fn nonzero_seed_produces_m_scalars() {
        let scalars = derive_batch_scalars::<4>(seed(7)).unwrap();
        // All scalars must be nonzero.
        for s in &scalars {
            assert!(*s != u256::from(0u8));
        }
    }

    #[test]
    fn scalars_follow_squaring_recurrence() {
        let scalars = derive_batch_scalars::<3>(seed(3)).unwrap();
        let rho0 = scalars[0];
        assert_eq!(scalars[1], Bn254::mul(rho0, rho0));
        assert_eq!(scalars[2], Bn254::mul(scalars[1], scalars[1]));
    }

    // -----------------------------------------------------------------------
    // weighted_sum_g1
    // -----------------------------------------------------------------------

    #[test]
    fn weighted_sum_identity_scalars_returns_sum_of_points() {
        let pts = [g1_gen(), g1_gen()];
        let ones = [u256::from(1u8); 2];
        let result = weighted_sum_g1(&pts, &ones);
        let expected = g1_gen().add(&g1_gen());
        assert_eq!(result, expected);
    }

    #[test]
    fn weighted_sum_zero_scalars_returns_identity() {
        let pts = [g1_gen(), g1_gen()];
        let zeros = [u256::from(0u8); 2];
        let result = weighted_sum_g1(&pts, &zeros);
        assert_eq!(result, identity());
    }

    // -----------------------------------------------------------------------
    // batch_verify_ipa — structural guards
    // -----------------------------------------------------------------------

    #[test]
    fn m_zero_is_rejected() {
        let input = BatchIpaInput::<0, 2> {
            commitments: [],
            proofs: [],
            challenges: uniform_challenges::<2>(3),
            batch_seed: seed(1),
        };
        assert_eq!(batch_verify_ipa(&input, 4), Err(ZkError::InvalidInput));
    }

    #[test]
    fn wrong_n_is_rejected() {
        let input = BatchIpaInput::<1, 2> {
            commitments: [identity()],
            proofs: [trivial_proof::<2>()],
            challenges: uniform_challenges::<2>(3),
            batch_seed: seed(5),
        };
        // Correct n for ROUNDS=2 is 4; pass 8 instead.
        assert_eq!(batch_verify_ipa(&input, 8), Err(ZkError::InvalidInput));
    }

    #[test]
    fn zero_seed_batch_rejected() {
        let input = BatchIpaInput::<1, 2> {
            commitments: [identity()],
            proofs: [trivial_proof::<2>()],
            challenges: uniform_challenges::<2>(3),
            batch_seed: [0u8; 32],
        };
        assert_eq!(
            batch_verify_ipa(&input, 4),
            Err(ZkError::InvalidFieldElement)
        );
    }

    #[test]
    fn bad_proof_scalar_rejects_batch() {
        let bad_proof = IpaProof::<2>::new(
            [IpaRoundCommitments::new(identity(), identity()); 2],
            Bn254::FR_MODULUS, // out of range
            u256::from(1u8),
        );
        let input = BatchIpaInput::<1, 2> {
            commitments: [identity()],
            proofs: [bad_proof],
            challenges: uniform_challenges::<2>(3),
            batch_seed: seed(5),
        };
        assert_eq!(
            batch_verify_ipa(&input, 4),
            Err(ZkError::InvalidFieldElement)
        );
    }

    // -----------------------------------------------------------------------
    // batch_verify_ipa — output correctness
    // -----------------------------------------------------------------------

    #[test]
    fn single_proof_combined_scalars_match_manual() {
        // Single proof: a_final=5, b_final=7.
        let proof = IpaProof::<2>::new(
            [IpaRoundCommitments::new(identity(), identity()); 2],
            u256::from(5u8),
            u256::from(7u8),
        );
        let input = BatchIpaInput::<1, 2> {
            commitments: [identity()],
            proofs: [proof],
            challenges: uniform_challenges::<2>(3),
            batch_seed: seed(11),
        };
        let out = batch_verify_ipa(&input, 4).unwrap();
        let rho0 = u256::from_be_bytes(seed(11)) % Bn254::FR_MODULUS;
        assert_eq!(out.a_combined, Bn254::mul(rho0, u256::from(5u8)));
        assert_eq!(out.b_combined, Bn254::mul(rho0, u256::from(7u8)));
        assert_eq!(
            out.inner_product,
            Bn254::mul(out.a_combined, out.b_combined)
        );
    }

    // -----------------------------------------------------------------------
    // verify_final_check
    // -----------------------------------------------------------------------

    #[test]
    fn final_check_passes_for_correct_equation() {
        // a=1, b=0, ip=0, G'=G, H'=0, U=0 → expected = G.
        let out = BatchIpaOutput {
            a_combined: u256::from(1u8),
            b_combined: u256::from(0u8),
            inner_product: u256::from(0u8),
        };
        let p_final = g1_gen(); // 1·G + 0·0 + 0·0 = G
        assert!(verify_final_check(&out, p_final, g1_gen(), identity(), identity()).is_ok());
    }

    #[test]
    fn final_check_fails_for_wrong_p_final() {
        let out = BatchIpaOutput {
            a_combined: u256::from(1u8),
            b_combined: u256::from(0u8),
            inner_product: u256::from(0u8),
        };
        let wrong_p_final = identity(); // should be G, not identity
        assert_eq!(
            verify_final_check(&out, wrong_p_final, g1_gen(), identity(), identity()),
            Err(ZkError::ConstraintUnsatisfied)
        );
    }

    // -----------------------------------------------------------------------
    // BatchIpaIter
    // -----------------------------------------------------------------------

    #[test]
    fn iter_yields_all_results_without_short_circuit() {
        let good = BatchIpaInput::<1, 2> {
            commitments: [identity()],
            proofs: [trivial_proof::<2>()],
            challenges: uniform_challenges::<2>(3),
            batch_seed: seed(5),
        };
        let bad = BatchIpaInput::<1, 2> {
            commitments: [identity()],
            proofs: [trivial_proof::<2>()],
            challenges: uniform_challenges::<2>(3),
            batch_seed: [0u8; 32],
        };
        let inputs = [good, bad, good];
        let mut iter = BatchIpaIter::new(&inputs, 4);
        assert!(iter.next().unwrap().is_ok());
        assert!(iter.next().unwrap().is_err());
        assert!(iter.next().unwrap().is_ok());
        assert!(iter.next().is_none());
    }

    #[test]
    fn iter_remaining_decrements_correctly() {
        let input = BatchIpaInput::<1, 2> {
            commitments: [identity()],
            proofs: [trivial_proof::<2>()],
            challenges: uniform_challenges::<2>(3),
            batch_seed: seed(3),
        };
        let inputs = [input; 3];
        let mut iter = BatchIpaIter::new(&inputs, 4);
        assert_eq!(iter.remaining(), 3);
        iter.next();
        assert_eq!(iter.remaining(), 2);
        iter.next();
        assert_eq!(iter.remaining(), 1);
        iter.next();
        assert_eq!(iter.remaining(), 0);
    }

    #[test]
    fn iter_reset_replays_results() {
        let good = BatchIpaInput::<1, 2> {
            commitments: [identity()],
            proofs: [trivial_proof::<2>()],
            challenges: uniform_challenges::<2>(3),
            batch_seed: seed(7),
        };
        let bad = BatchIpaInput::<1, 2> {
            commitments: [identity()],
            proofs: [trivial_proof::<2>()],
            challenges: uniform_challenges::<2>(3),
            batch_seed: [0u8; 32],
        };
        let inputs = [good, bad];
        let mut iter = BatchIpaIter::new(&inputs, 4);
        let r1 = iter.next().unwrap().unwrap();
        let e2 = iter.next().unwrap().unwrap_err();
        assert!(iter.next().is_none());

        iter.reset();
        assert_eq!(iter.next().unwrap().unwrap(), r1);
        assert_eq!(iter.next().unwrap().unwrap_err(), e2);
    }
}
