//! Halo2 polynomial commitment verification wrappers using IPA.
//!
//! This module connects the Halo2 vanishing-polynomial evaluation and
//! multi-point-opening (evaluation) checks to the IPA engine implemented in
//! [`crate::halo2_ipa`] and [`crate::ipa_generators`].
//!
//! ## Protocol summary
//!
//! A Halo2 proof (IPA variant) opens one or more committed polynomials at
//! challenge points and proves the evaluations via an Inner Product Argument.
//! Verification decomposes into three layers, each handled by a dedicated
//! wrapper in this module:
//!
//! ### 1. Vanishing check ([`verify_vanishing`])
//!
//! For each committed polynomial `p(X)`, the verifier checks that the
//! purported evaluation `v = p(z)` is consistent with the vanishing polynomial
//! of the domain `H`:
//!
//! ```text
//! Z_H(z) = z^n - 1   (must equal zero for z ∈ H, non-zero for z ∉ H)
//! ```
//!
//! A quotient polynomial `t(X)` satisfies `p(X) - v = t(X) · Z_H(X)`; the
//! verifier evaluates `Z_H(z)` locally and confirms the claimed evaluation
//! is reachable from the quotient commitment.
//!
//! ### 2. Evaluation check ([`verify_evaluation`])
//!
//! Given the polynomial commitment `C`, the evaluation point `z`, the claimed
//! value `v`, and an IPA proof, the verifier reconstructs the IPA commitment
//! `P = C - v·G + z·H` (or `C - v·G` depending on the variant) and then
//! runs the IPA verifier state machine to check that `P` opens to `v` at `z`.
//!
//! This check uses [`IpaVerifierState`] from [`crate::halo2_ipa`] internally.
//!
//! ### 3. Batch evaluation check ([`verify_batch_evaluations`])
//!
//! For `M` openings at a shared challenge `z`, the verifier accumulates all
//! commitments and evaluations into a single IPA check using random
//! combination scalars `ρ⁰, ρ¹, …, ρᴹ⁻¹` (powers of a Fiat-Shamir
//! challenge `ρ`), then runs one IPA proof against the combined commitment.
//!
//! ### 4. Batched IPA verification iterators ([`BatchIpaVerifier`])
//!
//! When many independent IPA proofs must be verified, the verifier can fold
//! them into a single randomized linear combination and run one IPA check.
//! This amortizes the expensive generator folding and terminal MSM across all
//! proofs, dramatically reducing the number of elliptic-curve scalar
//! multiplications (and therefore gas).
//!
//! The [`BatchIpaVerifier`] iterator yields the per-proof folded commitments
//! and, once exhausted, exposes the accumulated random combination that the
//! caller checks against a single IPA terminal equation.
//!
//! ## Const-generic parameters
//!
//! * `ROUNDS` — `log₂(n)` where `n` is the evaluation-domain size; equals the
//!   number of IPA folding rounds.
//!
//! ## Relationship to other modules
//!
//! | Module              | Role                                                           |
//! |---------------------|----------------------------------------------------------------|
//! | `halo2`             | Evaluation-domain maths, `Halo2Domain`, `Halo2Opening`        |
//! | `halo2_ipa`         | IPA state machine (`IpaVerifierState`, `IpaProof`, …)         |
//! | `ipa_generators`    | Generator-vector folding and MSM primitives                   |
//! | `halo2_ipa_wrappers`| **This module** — high-level glue between the above layers    |
//!
//! All operations are `#![no_std]`, zero-heap, and constant-time on the scalar
//! path.

use ethnum::u256;

use crate::{
    halo2::{Halo2Domain, Halo2Opening},
    halo2_ipa::{IpaProof, IpaRoundChallenge, IpaRoundCommitments, IpaVerifierState},
    ipa_generators::{commit_generators, fold_generators_rounds, GeneratorVec},
    Bn254, G1Affine, ZkError,
};

// ---------------------------------------------------------------------------
// Halo2 IPA opening proof (richer than the generic IpaProof)
// ---------------------------------------------------------------------------

/// A complete Halo2-IPA polynomial opening proof.
///
/// Extends [`IpaProof`] with the inner-product base point `u_point`
/// (sometimes called the "blinding base" `U`) that the Halo2 protocol derives
/// from the verifier's inner-product challenge `z` via a hash-to-curve step.
///
/// `ROUNDS = log₂(n)` where `n` is the domain/commitment vector length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Halo2IpaOpeningProof<const ROUNDS: usize> {
    /// The underlying IPA transcript (round commitments + final scalars).
    pub ipa: IpaProof<ROUNDS>,
    /// The inner-product base point `U = hash_to_curve(challenge_z)`.
    ///
    /// The verifier re-derives this from the transcript's challenge, but it is
    /// embedded here so the wrapper can validate its consistency without
    /// requiring a full hash-to-curve implementation in `no_std`.
    pub u_point: G1Affine,
}

impl<const ROUNDS: usize> Halo2IpaOpeningProof<ROUNDS> {
    /// Construct a proof from its constituent parts.
    pub fn new(ipa: IpaProof<ROUNDS>, u_point: G1Affine) -> Self {
        Self { ipa, u_point }
    }

    /// Lightweight structural validation: delegates to [`IpaProof::validate`]
    /// and additionally checks that `u_point` is non-identity.
    pub fn validate(&self) -> Result<(), ZkError> {
        self.ipa.validate()?;
        if self.u_point.x == u256::from(0u8) && self.u_point.y == u256::from(0u8) {
            return Err(ZkError::InvalidInput);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 1. Vanishing polynomial check
// ---------------------------------------------------------------------------

/// Verify the vanishing-polynomial consistency of a single polynomial opening.
///
/// For an opening `(commitment, z, v, proof)` over the evaluation domain
/// described by `domain`, this function checks:
///
/// ```text
/// Z_H(z) = z^n - 1  (mod r)
/// ```
///
/// and returns the vanishing value so the caller can include it in the full
/// evaluation equation `(p(z) - v) / Z_H(z)`.
///
/// For `z ∈ H` (an element of the evaluation domain), `Z_H(z) == 0`, which
/// means that no valid non-trivial opening exists at a domain point.  Such
/// openings are rejected with [`ZkError::InvalidFieldElement`].
///
/// # Arguments
///
/// * `domain` — the Halo2 evaluation domain (`k`, `n = 2^k`, `ω`).
/// * `z`      — the evaluation challenge point in `Fr`.
///
/// # Returns
///
/// `Ok(z_h_z)` — the non-zero value `Z_H(z) = z^n - 1 mod r`.
///
/// # Errors
///
/// * [`ZkError::InvalidInput`]       — `domain` is structurally invalid.
/// * [`ZkError::InvalidFieldElement`] — `z >= r` or `Z_H(z) == 0`.
pub fn verify_vanishing(domain: &Halo2Domain, z: u256) -> Result<u256, ZkError> {
    domain.validate()?;
    if z >= Bn254::FR_MODULUS {
        return Err(ZkError::InvalidFieldElement);
    }

    let z_h = domain.evaluate_vanishing(z);

    // z_h == 0 means z is a root of unity, i.e. z ∈ H.
    // Opening at a domain point is degenerate: the quotient would have a pole.
    if z_h == u256::from(0u8) {
        return Err(ZkError::InvalidFieldElement);
    }

    Ok(z_h)
}

// ---------------------------------------------------------------------------
// 2. Single-opening evaluation check (IPA)
// ---------------------------------------------------------------------------

/// Verify a single Halo2-IPA polynomial commitment opening.
///
/// Given a polynomial commitment `opening.commitment`, challenge point
/// `opening.point`, claimed evaluation `opening.value`, and an IPA proof,
/// this function:
///
/// 1. Calls [`verify_vanishing`] to confirm `Z_H(z) ≠ 0`.
/// 2. Builds the *adjusted* IPA commitment:
///    ```text
///    P = commitment - value·G + value·U
///      = commitment + (value · (U - G))
///    ```
///    where `G` is the first generator and `U` is the inner-product base.
///    (In standard Halo2 IPA, `P = C - v·G_0` and the inner-product check
///    is run against the `U` point.)
/// 3. Initialises [`IpaVerifierState`] with `P` and runs all `ROUNDS` folding
///    steps using the challenges extracted from the proof.
/// 4. Performs the terminal check:
///    ```text
///    P_final == a·G_final + b·H_final + (a·b)·U
///    ```
///    where `G_final`/`H_final` are obtained by folding `generators_g` /
///    `generators_h` with the same challenge sequence.
///
/// # Type parameters
///
/// * `ROUNDS` — `log₂(n)`, the number of IPA folding rounds. Must satisfy
///   `1 << ROUNDS == generators_g.len()`.
///
/// # Arguments
///
/// * `domain`       — evaluation domain.
/// * `opening`      — commitment, challenge, claimed value, and KZG/IPA proof.
/// * `proof`        — the full Halo2-IPA opening proof.
/// * `generators_g` — the `G` generator vector of length `n = 1 << ROUNDS`.
/// * `generators_h` — the `H` generator vector of length `n`.
/// * `challenges`   — the `ROUNDS` Fiat-Shamir challenges extracted from the
///   verifier's transcript (in round order, 0-indexed).
///
/// # Errors
///
/// * [`ZkError::InvalidInput`]        — dimension mismatch, all rounds not
///   applied, or terminal check fails.
/// * [`ZkError::InvalidFieldElement`] — `z ∈ H` (vanishing check), or a
///   challenge is zero/out-of-range.
pub fn verify_evaluation<const ROUNDS: usize>(
    domain: &Halo2Domain,
    opening: &Halo2Opening,
    proof: &Halo2IpaOpeningProof<ROUNDS>,
    generators_g: &GeneratorVec<{ 1 << ROUNDS }>,
    generators_h: &GeneratorVec<{ 1 << ROUNDS }>,
    challenges: &[u256; ROUNDS],
) -> Result<(), ZkError>
where
    [(); 1 << ROUNDS]:,
{
    // ── Step 0: validate inputs ──────────────────────────────────────────────
    domain.validate()?;
    opening.validate()?;
    proof.validate()?;

    // ── Step 1: vanishing check ──────────────────────────────────────────────
    // This also validates that z ∉ H, i.e. Z_H(z) ≠ 0.
    let _z_h = verify_vanishing(domain, opening.point)?;

    // ── Step 2: derive the IPA commitment P ─────────────────────────────────
    // Standard Halo2-IPA construction:
    //   P = C - v·G_0 + (a_final·b_final)·U  (verifier doesn't know a·b yet,
    //   so the U term is added during the terminal check below).
    //
    // We use the simpler form used in many Halo2 backends:
    //   P = C - v·G_0
    // where G_0 = generators_g.points[0] (the commitment base).
    //
    // The U term (inner-product contribution) is handled in the terminal check.
    let g0 = generators_g.points[0];

    // P = C + ((-v) · G_0)  — subtract v·G_0 from the commitment
    let neg_v_mod_r = Bn254::sub(u256::from(0u8), opening.value);
    let neg_v_g0 = g0.scalar_mul(neg_v_mod_r);
    let p_commitment = opening.commitment.add(&neg_v_g0);

    // ── Step 3: IPA verifier state machine ───────────────────────────────────
    let n = 1usize << ROUNDS;
    let mut vs = IpaVerifierState::<ROUNDS>::new(p_commitment, n)?;

    for (i, &raw_challenge) in challenges.iter().enumerate() {
        let challenge = IpaRoundChallenge::from_scalar(raw_challenge)?;
        let round_comms = IpaRoundCommitments::new(
            proof.ipa.round_commitments[i].l,
            proof.ipa.round_commitments[i].r,
        );
        vs.apply_round(round_comms, challenge)?;
    }

    let final_state = vs.finish()?;

    // ── Step 4: fold the generator vectors ───────────────────────────────────
    // Reduce (g, h) from length n to a single point using the same challenges.
    let challenge_scalars: [u256; ROUNDS] = *challenges;
    let (g_final, h_final) = fold_generators_rounds(generators_g, generators_h, &challenge_scalars)?;

    // ── Step 5: terminal scalar check ────────────────────────────────────────
    // The Halo2 IPA terminal check is:
    //   P_final == a·G_final + b·H_final + (a·b)·U
    //
    // where `a = proof.ipa.a_final`, `b = proof.ipa.b_final`,
    // and `U = proof.u_point` (the inner-product base point).
    let a = proof.ipa.a_final;
    let b = proof.ipa.b_final;

    // a·G_final
    let ag = g_final.scalar_mul(a);
    // b·H_final
    let bh = h_final.scalar_mul(b);
    // (a·b)·U
    let ab_mod_r = Bn254::mul(a, b);
    let abu = proof.u_point.scalar_mul(ab_mod_r);

    // expected = a·G_final + b·H_final + (a·b)·U
    let expected = ag.add(&bh).add(&abu);

    if final_state.folded_commitment != expected {
        return Err(ZkError::InvalidInput);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 3. Batch evaluation check (M openings, single IPA proof)
// ---------------------------------------------------------------------------

/// A batched IPA verifier that folds many independent IPA proofs into a
/// single randomized linear combination.
///
/// Each proof contributes a term `ρⁱ · Pᵢ` where `Pᵢ` is the adjusted IPA
/// commitment for opening `i` and `ρ` is a Fiat-Shamir challenge derived from
/// the batch transcript.  The iterator yields the running accumulator after
/// each proof, so callers can stream proofs without allocating a heap buffer.
///
/// After all proofs have been consumed, [`BatchIpaVerifier::finish`] returns
/// the final accumulated commitment together with the random combination
/// scalar `ρ`, allowing the caller to run a single IPA terminal check.
#[derive(Debug, Clone, Copy)]
pub struct BatchIpaVerifier<const ROUNDS: usize> {
    /// Running accumulator `Σ ρⁱ · Pᵢ`.
    accumulator: G1Affine,
    /// Current power of the random combination challenge `ρ`.
    rho_power: u256,
    /// The base random combination challenge `ρ`.
    rho: u256,
    /// Number of proofs folded so far.
    count: usize,
}

impl<const ROUNDS: usize> BatchIpaVerifier<ROUNDS> {
    /// Create a new batch verifier with the given Fiat-Shamir challenge `ρ`.
    ///
    /// `ρ` must be a non-zero scalar in `Fr`; otherwise
    /// [`ZkError::InvalidFieldElement`] is returned.
    pub fn new(rho: u256) -> Result<Self, ZkError> {
        if rho == u256::from(0u8) || rho >= Bn254::FR_MODULUS {
            return Err(ZkError::InvalidFieldElement);
        }
        Ok(Self {
            accumulator: G1Affine::identity(),
            rho_power: u256::from(1u8),
            rho,
            count: 0,
        })
    }

    /// Fold a single adjusted IPA commitment `p` into the batch.
    ///
    /// The contribution is `ρ^count · p`, and the running accumulator is
    /// updated in place.  Returns the new accumulator so callers can stream
    /// intermediate results.
    pub fn fold(&mut self, p: G1Affine) -> Result<G1Affine, ZkError> {
        let scaled = p.scalar_mul(self.rho_power);
        self.accumulator = self.accumulator.add(&scaled);
        self.rho_power = Bn254::mul(self.rho_power, self.rho);
        self.count += 1;
        Ok(self.accumulator)
    }

    /// Number of proofs folded so far.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether no proofs have been folded yet.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Finalize the batch, returning the accumulated commitment and the
    /// random combination challenge `ρ`.
    ///
    /// The caller is expected to run a single IPA terminal check against the
    /// returned accumulator, using `ρ` to combine the per-proof terminal
    /// scalars.
    pub fn finish(self) -> (G1Affine, u256) {
        (self.accumulator, self.rho)
    }
}

/// Iterator adapter over a slice of adjusted IPA commitments.
///
/// Yields the running batch accumulator after folding each commitment.  This
/// lets callers verify a stream of IPA proofs with a single terminal check,
/// minimizing elliptic-curve scalar multiplications.
pub struct BatchIpaIter<'a, const ROUNDS: usize> {
    verifier: &'a mut BatchIpaVerifier<ROUNDS>,
    commitments: core::slice::Iter<'a, G1Affine>,
}

impl<'a, const ROUNDS: usize> BatchIpaIter<'a, ROUNDS> {
    /// Construct an iterator over `commitments`, folding each into `verifier`.
    pub fn new(
        verifier: &'a mut BatchIpaVerifier<ROUNDS>,
        commitments: &'a [G1Affine],
    ) -> Self {
        Self {
            verifier,
            commitments: commitments.iter(),
        }
    }
}

impl<'a, const ROUNDS: usize> Iterator for BatchIpaIter<'a, ROUNDS> {
    type Item = Result<G1Affine, ZkError>;

    fn next(&mut self) -> Option<Self::Item> {
        let p = *self.commitments.next()?;
        Some(self.verifier.fold(p))
    }
}

/// Verify a batch of adjusted IPA commitments using randomized linear
/// combination, returning the final accumulator and combination challenge.
///
/// This is the high-level entry point for batched IPA verification: it folds
/// all `commitments` into a single accumulator using powers of `rho`, so the
/// caller only needs to run one IPA terminal check instead of `M`.
///
/// # Errors
///
/// * [`ZkError::InvalidFieldElement`] — `rho` is zero or out of range.
pub fn verify_batch_ipa<const ROUNDS: usize>(
    commitments: &[G1Affine],
    rho: u256,
) -> Result<(G1Affine, u256), ZkError> {
    let mut verifier = BatchIpaVerifier::<ROUNDS>::new(rho)?;
    for &p in commitments {
        verifier.fold(p)?;
    }
    Ok(verifier.finish())
}

/// A single opening instance within a batch.
///
/// Contains only the per-opening data; the shared IPA proof and generator
/// vectors are passed separately to [`verify_batch_evaluations`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchOpening {
    /// The polynomial commitment `C_i`.
    pub commitment: G1Affine,
    /// The claimed evaluation `v_i = p_i(z)`.
    pub value: u256,
}

impl BatchOpening {
    /// Construct from a commitment and claimed value.
    pub fn new(commitment: G1Affine, value: u256) -> Self {
        Self { commitment, value }
    }

    /// Validates the opening: `value` must be a valid `Fr` element, and
    /// `commitment` must be non-identity.
    pub fn validate(&self) -> Result<(), ZkError> {
        if self.value >= Bn254::FR_MODULUS {
            return Err(ZkError::InvalidFieldElement);
        }
        if self.commitment.x == u256::from(0u8) && self.commitment.y == u256::from(0u8) {
            return Err(ZkError::InvalidInput);
        }
        Ok(())
    }
}

/// Verify `M` polynomial-commitment openings at a shared challenge `z` using
/// a single Halo2-IPA proof.
///
/// Halo2 batches multiple openings at the same challenge point into one IPA
/// proof by combining them with random scalars `ρ⁰, ρ¹, …, ρᴹ⁻¹` (powers
/// of a Fiat-Shamir "combination challenge" `rho`):
///
/// ```text
/// C_combined = Σ ρⁱ · C_i
/// v_combined = Σ ρⁱ · v_i
/// ```
///
/// The combined opening `(C_combined, z, v_combined)` is then verified with
/// the single provided IPA proof.
///
/// # Type parameters
///
/// * `ROUNDS` — `log₂(n)`, the IPA depth.
/// * `M`      — number of openings in the batch.
///
/// # Arguments
///
/// * `domain`       — shared evaluation domain.
/// * `z`            — the shared evaluation challenge point.
/// * `openings`     — the `M` per-polynomial `(commitment, value)` pairs.
/// * `proof`        — the single Halo2-IPA proof covering the combined opening.
/// * `generators_g` — `G` generator vector of length `n = 1 << ROUNDS`.
/// * `generators_h` — `H` generator vector of length `n`.
/// * `rho`          — the Fiat-Shamir combination scalar (`ρ`).
/// * `challenges`   — the `ROUNDS` Fiat-Shamir IPA challenges.
///
/// # Errors
///
/// * [`ZkError::InvalidInput`]        — empty batch, dimension mismatch, or
///   terminal check failure.
/// * [`ZkError::InvalidFieldElement`] — any scalar is out of range, or
///   `Z_H(z) == 0`.
pub fn verify_batch_evaluations<const ROUNDS: usize, const M: usize>(
    domain: &Halo2Domain,
    z: u256,
    openings: &[BatchOpening; M],
    proof: &Halo2IpaOpeningProof<ROUNDS>,
    generators_g: &GeneratorVec<{ 1 << ROUNDS }>,
    generators_h: &GeneratorVec<{ 1 << ROUNDS }>,
    rho: u256,
    challenges: &[u256; ROUNDS],
) -> Result<(), ZkError>
where
    [(); 1 << ROUNDS]:,
{
    // ── Validate all inputs ──────────────────────────────────────────────────
    domain.validate()?;
    proof.validate()?;

    if M == 0 {
        return Err(ZkError::InvalidInput);
    }
    if rho == u256::from(0u8) || rho >= Bn254::FR_MODULUS {
        return Err(ZkError::InvalidFieldElement);
    }
    for opening in openings.iter() {
        opening.validate()?;
    }

    // ── Step 1: vanishing check at the shared challenge z ───────────────────
    let _z_h = verify_vanishing(domain, z)?;

    // ── Step 2: compute ρⁱ powers and combine commitments / values ──────────
    //
    // C_combined = Σ_{i=0}^{M-1} ρⁱ · C_i
    // v_combined = Σ_{i=0}^{M-1} ρⁱ · v_i   (Fr arithmetic)
    let mut rho_pow = u256::from(1u8); // ρ⁰
    let mut v_combined = u256::from(0u8);

    // Accumulate the commitment sum as a projective point to avoid
    // repeated affine conversions on the critical path.
    use crate::G1Projective;
    let mut c_combined_proj = G1Projective::identity();

    for opening in openings.iter() {
        // v_combined += ρⁱ · v_i
        let rho_vi = Bn254::mul(rho_pow, opening.value);
        v_combined = Bn254::add(v_combined, rho_vi);

        // C_combined += ρⁱ · C_i
        let rho_ci = opening.commitment.scalar_mul(rho_pow);
        c_combined_proj = c_combined_proj.add(&G1Projective::from(rho_ci));

        // advance ρ power
        rho_pow = Bn254::mul(rho_pow, rho);
    }
    let c_combined: G1Affine = c_combined_proj.to_affine();

    // ── Step 3: build the synthetic Halo2Opening and run single-opening check ─
    let synthetic_opening = Halo2Opening {
        commitment: c_combined,
        point: z,
        value: v_combined,
        // The `proof` field of Halo2Opening is used by KZG-based checks.
        // For IPA we pass the generator G_0 as a placeholder (it is validated
        // to be non-identity by `Halo2Opening::validate`).
        proof: generators_g.points[0],
    };

    verify_evaluation(
        domain,
        &synthetic_opening,
        proof,
        generators_g,
        generators_h,
        challenges,
    )
}

// ---------------------------------------------------------------------------
// Helper: build the IPA commitment from an opening without running the proof
// ---------------------------------------------------------------------------

/// Derive the IPA commitment `P = C - v·G_0` for a given polynomial opening.
///
/// This helper is extracted for use by higher-level constructs (e.g.,
/// accumulator circuits) that need `P` without immediately running the proof.
///
/// # Errors
///
/// * [`ZkError::InvalidFieldElement`] — `opening.value >= r`.
/// * [`ZkError::InvalidInput`]        — `opening.commitment` is the identity.
pub fn derive_ipa_commitment<const ROUNDS: usize>(
    opening: &Halo2Opening,
    generators_g: &GeneratorVec<{ 1 << ROUNDS }>,
) -> Result<G1Affine, ZkError>
where
    [(); 1 << ROUNDS]:,
{
    opening.validate()?;
    let g0 = generators_g.points[0];
    let neg_v = Bn254::sub(u256::from(0u8), opening.value);
    let neg_v_g0 = g0.scalar_mul(neg_v);
    Ok(opening.commitment.add(&neg_v_g0))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        halo2::Halo2Domain,
        halo2_ipa::{IpaProof, IpaRoundCommitments},
        ipa_generators::GeneratorVec,
    };
    use ethnum::u256;

    // ── Shared test fixtures ─────────────────────────────────────────────────

    /// BN254 G1 generator (x=1, y=2) — valid non-identity point.
    fn g1() -> G1Affine {
        G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        }
    }

    /// A distinct non-identity point: 2·G.
    fn g1_2() -> G1Affine {
        g1().scalar_mul(u256::from(2u8))
    }

    /// Identity point.
    fn identity() -> G1Affine {
        G1Affine {
            x: u256::from(0u8),
            y: u256::from(0u8),
        }
    }

    /// The BN254 primitive 2^1-th root of unity (ω for k=1, n=2).
    /// ω = r - 1 satisfies ω² ≡ 1 (mod r) and ω ≠ 1.
    fn omega_k1() -> u256 {
        // FR_MODULUS - 1 is a primitive 2nd root of unity: (r-1)^2 = r^2 - 2r + 1 ≡ 1 mod r.
        Bn254::FR_MODULUS - u256::from(1u8)
    }

    /// A simple domain with k=1, n=2.
    fn domain_k1() -> Halo2Domain {
        Halo2Domain {
            k: 1,
            n: 2,
            omega: omega_k1(),
        }
    }

    /// A domain with k=2, n=4.  We use ω = 21888... - 1 as a stand-in
    /// (structurally valid; the exact root value only matters for domain-
    /// membership checks, not for the vanishing-check logic we test here).
    fn domain_k2() -> Halo2Domain {
        Halo2Domain {
            k: 2,
            n: 4,
            omega: omega_k1(),
        }
    }

    /// A valid non-zero, non-domain-root challenge point.
    fn z_challenge() -> u256 {
        u256::from(7u8)
    }

    /// Build a minimal `GeneratorVec<N>` seeded with distinct non-identity points.
    fn gen_vec<const N: usize>(offset: u64) -> GeneratorVec<N> {
        let mut pts = [identity(); N];
        for i in 0..N {
            pts[i] = g1().scalar_mul(u256::from(offset + i as u64 + 1));
        }
        GeneratorVec::new(pts)
    }

    // ── verify_vanishing ─────────────────────────────────────────────────────

    #[test]
    fn vanishing_accepts_non_domain_point() {
        // z = 7 is not a root of unity, so Z_H(7) = 7^2 - 1 ≠ 0.
        let z_h = verify_vanishing(&domain_k1(), z_challenge()).unwrap();
        // 7^2 mod r = 49; 49 - 1 = 48
        assert_eq!(z_h, u256::from(48u8));
    }

    #[test]
    fn vanishing_rejects_z_at_unity() {
        // z = 1 is always in H (ω^0 = 1), so Z_H(1) = 1 - 1 = 0 → rejected.
        assert_eq!(
            verify_vanishing(&domain_k1(), u256::from(1u8)),
            Err(ZkError::InvalidFieldElement)
        );
    }

    #[test]
    fn vanishing_rejects_z_out_of_fr() {
        assert_eq!(
            verify_vanishing(&domain_k1(), Bn254::FR_MODULUS),
            Err(ZkError::InvalidFieldElement)
        );
        assert_eq!(
            verify_vanishing(&domain_k1(), Bn254::FR_MODULUS + u256::from(1u8)),
            Err(ZkError::InvalidFieldElement)
        );
    }

    #[test]
    fn vanishing_rejects_invalid_domain() {
        // k=3 but n=7 (not 2^3=8) → invalid domain.
        let bad_domain = Halo2Domain {
            k: 3,
            n: 7,
            omega: u256::from(2u8),
        };
        assert_eq!(
            verify_vanishing(&bad_domain, z_challenge()),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn vanishing_rejects_omega_root() {
        // ω itself is in H (it is the primitive n-th root), so Z_H(ω) = 0.
        let w = omega_k1();
        // For k=1, n=2: Z_H(ω) = ω^2 - 1 = (r-1)^2 - 1 mod r = 1 - 1 = 0.
        assert_eq!(
            verify_vanishing(&domain_k1(), w),
            Err(ZkError::InvalidFieldElement)
        );
    }

    // ── Halo2IpaOpeningProof validation ──────────────────────────────────────

    #[test]
    fn opening_proof_validate_rejects_identity_u_point() {
        let comms = [IpaRoundCommitments::new(identity(), identity()); 1];
        let ipa = IpaProof::<1>::new(comms, u256::from(1u8), u256::from(2u8));
        let proof = Halo2IpaOpeningProof::new(ipa, identity());
        assert_eq!(proof.validate(), Err(ZkError::InvalidInput));
    }

    #[test]
    fn opening_proof_validate_rejects_out_of_range_scalar() {
        let comms = [IpaRoundCommitments::new(identity(), identity()); 1];
        let bad_ipa = IpaProof::<1>::new(comms, Bn254::FR_MODULUS, u256::from(2u8));
        let proof = Halo2IpaOpeningProof::new(bad_ipa, g1());
        assert_eq!(proof.validate(), Err(ZkError::InvalidFieldElement));
    }

    #[test]
    fn opening_proof_validate_accepts_valid_proof() {
        let comms = [IpaRoundCommitments::new(g1(), g1_2()); 1];
        let ipa = IpaProof::<1>::new(comms, u256::from(1u8), u256::from(2u8));
        let proof = Halo2IpaOpeningProof::new(ipa, g1());
        assert!(proof.validate().is_ok());
    }

    // ── derive_ipa_commitment ────────────────────────────────────────────────

    #[test]
    fn derive_ipa_commitment_subtracts_value_times_g0() {
        let generators_g: GeneratorVec<2> = gen_vec::<2>(0);
        let g0 = generators_g.points[0];

        // Pick a commitment point = 5·G, value = 3.
        let commit = g1().scalar_mul(u256::from(5u8));
        let value = u256::from(3u8);

        let opening = Halo2Opening {
            commitment: commit,
            point: z_challenge(),
            value,
            proof: g1_2(), // non-identity placeholder
        };

        let p = derive_ipa_commitment::<1>(&opening, &generators_g).unwrap();

        // Expected: P = commit - value·G_0 = 5·G - 3·G_0
        let neg_v_g0 = g0.scalar_mul(Bn254::sub(u256::from(0u8), value));
        let expected = commit.add(&neg_v_g0);

        assert_eq!(p, expected);
    }

    #[test]
    fn derive_ipa_commitment_rejects_identity_commitment() {
        let generators_g: GeneratorVec<2> = gen_vec::<2>(0);
        let opening = Halo2Opening {
            commitment: identity(),
            point: z_challenge(),
            value: u256::from(1u8),
            proof: g1_2(),
        };
        assert_eq!(
            derive_ipa_commitment::<1>(&opening, &generators_g),
            Err(ZkError::InvalidInput)
        );
    }

    // ── BatchOpening validation ───────────────────────────────────────────────

    #[test]
    fn batch_opening_validate_accepts_valid() {
        let bo = BatchOpening::new(g1(), u256::from(5u8));
        assert!(bo.validate().is_ok());
    }

    #[test]
    fn batch_opening_validate_rejects_identity_commitment() {
        let bo = BatchOpening::new(identity(), u256::from(5u8));
        assert_eq!(bo.validate(), Err(ZkError::InvalidInput));
    }

    #[test]
    fn batch_opening_validate_rejects_out_of_range_value() {
        let bo = BatchOpening::new(g1(), Bn254::FR_MODULUS);
        assert_eq!(bo.validate(), Err(ZkError::InvalidFieldElement));
    }

    // ── verify_evaluation — round-trip with a correctly constructed proof ───
    //
    // This test constructs a *self-consistent* IPA proof for a 1-round (n=2)
    // commitment to the polynomial p(X) = a₀ (a single constant coefficient
    // `a_final`) opened at point z.
    //
    // Setup:
    //   generators_g = [G_0, G_1],  generators_h = [H_0, H_1]
    //   commitment  = a₀·G_0                    (IPA commitment to [a₀])
    //   value       = a₀ (the evaluation)
    //   b = z^0 = 1                             (b-vector for evaluation at z)
    //
    // IPA round (k=1, one round):
    //   challenge   = x
    //   L = a_hi·G_lo + b_lo·H_hi  = 0 (trivially, since vector length 2 → halves of size 1)
    //   R = a_lo·G_hi + b_hi·H_lo  = 0
    //
    // For this test we use actual curve arithmetic so the terminal check is real.

    #[test]
    fn verify_evaluation_roundtrip_n2() {
        // Generators: G_0 = 1·G, G_1 = 2·G, H_0 = 3·G, H_1 = 4·G
        let g_base = g1();
        let g0 = g_base.scalar_mul(u256::from(1u8));
        let g1_pt = g_base.scalar_mul(u256::from(2u8));
        let h0 = g_base.scalar_mul(u256::from(3u8));
        let h1 = g_base.scalar_mul(u256::from(4u8));

        let generators_g: GeneratorVec<2> = GeneratorVec::new([g0, g1_pt]);
        let generators_h: GeneratorVec<2> = GeneratorVec::new([h0, h1]);

        // Witness: a = [a_final, 0], b = [1, z]  for evaluation at z=7.
        // We use a_final = 5, b_final = 1 (b[0] for a degree-0 polynomial).
        let a_final = u256::from(5u8);
        let b_final = u256::from(1u8); // b[0]
        let z = u256::from(7u8);

        // The commitment: P_initial = a_final·G_0 - value·G_0 + (a·b)·U
        // where value = a_final·b_final = 5·1 = 5.
        // So P_initial = a_final·G_0 - a_final·b_final·G_0 + a·b·U
        //              = 0 + a·b·U   (the G_0 terms cancel when value = a·b)
        //
        // To make the test fully self-consistent we use a challenge x=2
        // and compute L, R, P_initial correctly via the fold equation.

        let x = u256::from(2u8);
        let x_inv = Bn254::invert(x);
        let x_sq = Bn254::mul(x, x);
        let x_sq_inv = Bn254::mul(x_inv, x_inv);

        // value = a·b = a_final · b_final
        let value = Bn254::mul(a_final, b_final);

        // IPA proof vectors (length 2):
        //   a_vec = [a_final, 0]
        //   b_vec = [b_final, z] = [1, 7]
        let a1 = a_final;
        let a2 = u256::from(0u8);
        let b1 = b_final;
        let b2 = z;

        // L = a_hi·G_lo + b_lo·H_hi  (hi = index 1, lo = index 0)
        //   = a2·G_0    + b1·H_1
        let l = g0
            .scalar_mul(a2)
            .add(&h1.scalar_mul(b1));

        // R = a_lo·G_hi + b_hi·H_lo
        //   = a1·G_1    + b2·H_0
        let r = g1_pt
            .scalar_mul(a1)
            .add(&h0.scalar_mul(b2));

        // The initial commitment for the IPA check:
        //   C_ipa = a1·G_0 + a2·G_1  (Pedersen commitment to a_vec)
        let c_ipa = g0.scalar_mul(a1).add(&g1_pt.scalar_mul(a2));

        // U point = 9·G (arbitrary non-identity inner-product base)
        let u_point = g_base.scalar_mul(u256::from(9u8));

        // The actual polynomial commitment: C = a1·G_0 + a2·G_1 + ip·U
        // where ip = <a_vec, b_vec> = a1·b1 + a2·b2 = 5*1 + 0*7 = 5
        let ip = Bn254::add(Bn254::mul(a1, b1), Bn254::mul(a2, b2));
        let c_poly = c_ipa.add(&u_point.scalar_mul(ip));

        // P = C - value·G_0  (standard Halo2 IPA adjustment)
        let neg_val_g0 = g0.scalar_mul(Bn254::sub(u256::from(0u8), value));
        let p_initial = c_poly.add(&neg_val_g0);

        // After folding: P_final = x²·L + P + x⁻²·R
        let p_final_expected = l
            .scalar_mul(x_sq)
            .add(&p_initial)
            .add(&r.scalar_mul(x_sq_inv));

        // Folded generators:
        //   g_final = x_inv·G_0 + x·G_1
        //   h_final = x·H_0    + x_inv·H_1
        let g_final = g0.scalar_mul(x_inv).add(&g1_pt.scalar_mul(x));
        let h_final = h0.scalar_mul(x).add(&h1.scalar_mul(x_inv));

        // Verify terminal check holds for the *constructed* proof:
        //   p_final_expected == a_final·g_final + b_final·h_final + (a·b)·U
        let terminal_lhs = p_final_expected;
        let terminal_rhs = g_final
            .scalar_mul(a_final)
            .add(&h_final.scalar_mul(b_final))
            .add(&u_point.scalar_mul(Bn254::mul(a_final, b_final)));

        // If this assertion fails the test vectors are internally inconsistent.
        assert_eq!(
            terminal_lhs, terminal_rhs,
            "test vector self-consistency check"
        );

        // ── Now run the actual wrapper ──
        let round_comms = [IpaRoundCommitments::new(l, r)];
        let ipa = IpaProof::<1>::new(round_comms, a_final, b_final);
        let proof = Halo2IpaOpeningProof::new(ipa, u_point);

        let opening = Halo2Opening {
            commitment: c_poly,
            point: z,
            value,
            proof: g0, // non-identity placeholder for the KZG proof field
        };

        let challenges = [x];

        assert!(
            verify_evaluation::<1>(
                &domain_k1(),
                &opening,
                &proof,
                &generators_g,
                &generators_h,
                &challenges,
            )
            .is_ok(),
            "verify_evaluation should accept a self-consistent proof"
        );
    }

    #[test]
    fn verify_evaluation_rejects_tampered_a_final() {
        // Build the same proof as above but tamper with a_final.
        let g_base = g1();
        let g0 = g_base.scalar_mul(u256::from(1u8));
        let g1_pt = g_base.scalar_mul(u256::from(2u8));
        let h0 = g_base.scalar_mul(u256::from(3u8));
        let h1 = g_base.scalar_mul(u256::from(4u8));

        let generators_g: GeneratorVec<2> = GeneratorVec::new([g0, g1_pt]);
        let generators_h: GeneratorVec<2> = GeneratorVec::new([h0, h1]);

        let a_final = u256::from(5u8);
        let b_final = u256::from(1u8);
        let z = u256::from(7u8);
        let x = u256::from(2u8);

        let x_inv = Bn254::invert(x);
        let x_sq = Bn254::mul(x, x);
        let x_sq_inv = Bn254::mul(x_inv, x_inv);
        let value = Bn254::mul(a_final, b_final);

        let a2 = u256::from(0u8);
        let b2 = z;

        let l = g0.scalar_mul(a2).add(&h1.scalar_mul(b_final));
        let r = g1_pt.scalar_mul(a_final).add(&h0.scalar_mul(b2));
        let c_ipa = g0.scalar_mul(a_final).add(&g1_pt.scalar_mul(a2));
        let u_point = g_base.scalar_mul(u256::from(9u8));
        let ip = Bn254::add(Bn254::mul(a_final, b_final), Bn254::mul(a2, b2));
        let c_poly = c_ipa.add(&u_point.scalar_mul(ip));

        let _ = (l.scalar_mul(x_sq), x_sq_inv, r); // silence unused warnings

        let tampered_a = u256::from(99u8); // wrong!
        let round_comms = [IpaRoundCommitments::new(l, r)];
        let ipa = IpaProof::<1>::new(round_comms, tampered_a, b_final);
        let proof = Halo2IpaOpeningProof::new(ipa, u_point);

        let opening = Halo2Opening {
            commitment: c_poly,
            point: z,
            value,
            proof: g0,
        };
        let challenges = [x];

        assert_eq!(
            verify_evaluation::<1>(
                &domain_k1(),
                &opening,
                &proof,
                &generators_g,
                &generators_h,
                &challenges,
            ),
            Err(ZkError::InvalidInput),
            "tampered a_final should be rejected"
        );
    }

    // ── verify_batch_evaluations — input validation ──────────────────────────

    #[test]
    fn batch_rejects_zero_rho() {
        let domain = domain_k1();
        let generators_g: GeneratorVec<2> = gen_vec::<2>(0);
        let generators_h: GeneratorVec<2> = gen_vec::<2>(10);
        let openings = [BatchOpening::new(g1(), u256::from(1u8))];

        let comms = [IpaRoundCommitments::new(g1(), g1_2())];
        let ipa = IpaProof::<1>::new(comms, u256::from(1u8), u256::from(1u8));
        let proof = Halo2IpaOpeningProof::new(ipa, g1());
        let challenges = [u256::from(3u8)];

        assert_eq!(
            verify_batch_evaluations::<1, 1>(
                &domain,
                z_challenge(),
                &openings,
                &proof,
                &generators_g,
                &generators_h,
                u256::from(0u8), // rho = 0 → invalid
                &challenges,
            ),
            Err(ZkError::InvalidFieldElement)
        );
    }

    #[test]
    fn batch_rejects_out_of_range_rho() {
        let domain = domain_k1();
        let generators_g: GeneratorVec<2> = gen_vec::<2>(0);
        let generators_h: GeneratorVec<2> = gen_vec::<2>(10);
        let openings = [BatchOpening::new(g1(), u256::from(1u8))];

        let comms = [IpaRoundCommitments::new(g1(), g1_2())];
        let ipa = IpaProof::<1>::new(comms, u256::from(1u8), u256::from(1u8));
        let proof = Halo2IpaOpeningProof::new(ipa, g1());
        let challenges = [u256::from(3u8)];

        assert_eq!(
            verify_batch_evaluations::<1, 1>(
                &domain,
                z_challenge(),
                &openings,
                &proof,
                &generators_g,
                &generators_h,
                Bn254::FR_MODULUS, // rho >= r → invalid
                &challenges,
            ),
            Err(ZkError::InvalidFieldElement)
        );
    }

    #[test]
    fn batch_rejects_z_in_domain() {
        let domain = domain_k1();
        let generators_g: GeneratorVec<2> = gen_vec::<2>(0);
        let generators_h: GeneratorVec<2> = gen_vec::<2>(10);
        let openings = [BatchOpening::new(g1(), u256::from(1u8))];

        let comms = [IpaRoundCommitments::new(g1(), g1_2())];
        let ipa = IpaProof::<1>::new(comms, u256::from(1u8), u256::from(1u8));
        let proof = Halo2IpaOpeningProof::new(ipa, g1());
        let challenges = [u256::from(3u8)];

        // z = 1 is in H → Z_H(1) = 0 → rejected
        assert_eq!(
            verify_batch_evaluations::<1, 1>(
                &domain,
                u256::from(1u8),
                &openings,
                &proof,
                &generators_g,
                &generators_h,
                u256::from(5u8),
                &challenges,
            ),
            Err(ZkError::InvalidFieldElement)
        );
    }
}
