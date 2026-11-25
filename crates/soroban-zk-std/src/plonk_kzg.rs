//! PLONK KZG Evaluation Proof Verifier (Stellar Integration Layer).
//!
//! This module wires the pure-math [`kzg_eval_proof_points`] function from
//! `soroban-zk-core` to the Soroban `bn254_multi_pairing_check` host function
//! via the existing [`pairing_check`] abstraction.
//!
//! ## Protocol
//!
//! The final KZG check in PLONK verification reduces to a two-pair equation:
//!
//! ```text
//! e(W_ζ + u·W_{ζω},  [τ]₂)
//! · e(-(ζ·W_ζ + u·ζω·W_{ζω} + F - [E]₁),  G₂)
//! == 1
//! ```
//!
//! where:
//! - `[τ]₂` is the SRS G2 element (the trusted-setup key)
//! - `G₂` is the BN254 G2 generator
//! - `F` is the batched polynomial commitment (see [`KzgEvalProofInputs`])
//! - `[E]₁` is the batched evaluation encoded as a G1 point
//!
//! [`kzg_eval_proof_points`] handles all G1 arithmetic and returns the two
//! G1 points for the equation above.  This module pairs them against the
//! appropriate G2 points using the Soroban host's native pairing engine.
//!
//! ## Security Notes
//!
//! - All input scalars are validated against the BN254 scalar field modulus
//!   before any curve operation (inside [`kzg_eval_proof_points`]).
//! - G1 points coming from the proof (`w_zeta`, `w_zeta_omega`, and the
//!   commitments) **must** be validated by the caller before constructing
//!   [`KzgEvalProofInputs`].  Use [`crate::host::g1_from_host_bytes`] or
//!   check [`soroban_zk_core::Bn254::is_valid_g1_subgroup`] directly.
//! - G2 points (`srs_g2`, generator) are validated inside [`pairing_check`].

use alloc::vec::Vec;
use ethnum::u256;
use soroban_sdk::Env;
use soroban_zk_core::{Bn254, G1Affine, KzgEvalProofInputs, ZkError};

use crate::host::g1_msm_host_or_software;
use crate::pairing::{pairing_check, validate_g2_coords, G2Affine};
use crate::vk::G1_GENERATOR;

#[inline(always)]
fn is_g1_identity(p: G1Affine) -> bool {
    p.x == u256::from(0u8) && p.y == u256::from(0u8)
}

/// Validates the structural and scalar-field invariants of a single
/// [`KzgEvalProofInputs`] bundle, matching `soroban_zk_core::kzg_eval_proof_points`.
fn validate_kzg_inputs(inputs: &KzgEvalProofInputs<'_>) -> Result<(), ZkError> {
    let k = inputs.commitments.len();
    if k == 0 || k != inputs.evaluations_at_zeta.len() {
        return Err(ZkError::InvalidInput);
    }
    for &s in &[inputs.v, inputs.u, inputs.zeta, inputs.omega] {
        if s >= Bn254::FR_MODULUS {
            return Err(ZkError::InvalidFieldElement);
        }
    }
    for &e in inputs.evaluations_at_zeta {
        if e >= Bn254::FR_MODULUS {
            return Err(ZkError::InvalidFieldElement);
        }
    }
    if inputs.evaluation_at_zeta_omega >= Bn254::FR_MODULUS {
        return Err(ZkError::InvalidFieldElement);
    }
    Ok(())
}

/// Computes `(lhs, rhs)` for a single PLONK KZG evaluation proof using
/// [`g1_msm_host_or_software`] to offload all G1 multi-scalar multiplications
/// to the native CAP-0074 `bn254().g1_msm` host precompile.
pub(crate) fn kzg_eval_proof_points_host(
    env: &Env,
    inputs: &KzgEvalProofInputs<'_>,
) -> Result<(G1Affine, G1Affine), ZkError> {
    validate_kzg_inputs(inputs)?;

    let k = inputs.commitments.len();
    let zeta_omega = Bn254::mul(inputs.zeta, inputs.omega);
    let u_zeta_omega = Bn254::mul(inputs.u, zeta_omega);

    // LHS = W_zeta + u * W_{zeta*omega}
    let lhs = g1_msm_host_or_software(
        env,
        &[inputs.w_zeta, inputs.w_zeta_omega],
        &[u256::from(1u8), inputs.u],
    )?;

    // RHS = zeta * W_zeta + (u*zeta*omega) * W_{zeta*omega} + sum_i v^i * C_i - E * G1
    let mut rhs_points = Vec::with_capacity(k + 3);
    let mut rhs_scalars = Vec::with_capacity(k + 3);

    rhs_points.push(inputs.w_zeta);
    rhs_scalars.push(inputs.zeta);

    rhs_points.push(inputs.w_zeta_omega);
    rhs_scalars.push(u_zeta_omega);

    let mut e_scalar = u256::from(0u8);
    let mut v_pow = u256::from(1u8);
    for i in 0..k {
        rhs_points.push(inputs.commitments[i]);
        rhs_scalars.push(v_pow);
        e_scalar = Bn254::add(e_scalar, Bn254::mul(v_pow, inputs.evaluations_at_zeta[i]));
        v_pow = Bn254::mul(v_pow, inputs.v);
    }

    e_scalar = Bn254::add(
        e_scalar,
        Bn254::mul(inputs.u, inputs.evaluation_at_zeta_omega),
    );
    let neg_e_scalar = Bn254::sub(u256::from(0u8), e_scalar);

    rhs_points.push(G1_GENERATOR);
    rhs_scalars.push(neg_e_scalar);

    let rhs = g1_msm_host_or_software(env, &rhs_points, &rhs_scalars)?;
    Ok((lhs, rhs))
}

/// Computes the aggregated `(lhs, rhs)` for a batch of `M` PLONK KZG proofs
/// using two [`g1_msm_host_or_software`] calls (one for `lhs`, one for `rhs`),
/// matching `soroban_zk_core::plonk_batch_verify_points`.
pub(crate) fn plonk_batch_verify_points_host(
    env: &Env,
    inputs: &[KzgEvalProofInputs<'_>],
    batch_seed: &[u8; 32],
) -> Result<(G1Affine, G1Affine), ZkError> {
    let m = inputs.len();
    if m == 0 {
        return Err(ZkError::InvalidInput);
    }

    let mut rho = u256::from_be_bytes(*batch_seed) % Bn254::FR_MODULUS;
    if rho == u256::from(0u8) {
        return Err(ZkError::InvalidFieldElement);
    }

    let total_commitments: usize = inputs.iter().map(|b| b.commitments.len()).sum();
    let mut lhs_points = Vec::with_capacity(2 * m);
    let mut lhs_scalars = Vec::with_capacity(2 * m);
    let mut rhs_points = Vec::with_capacity(total_commitments + 2 * m + 1);
    let mut rhs_scalars = Vec::with_capacity(total_commitments + 2 * m + 1);
    let mut total_e_scalar = u256::from(0u8);

    for (j, bundle) in inputs.iter().enumerate() {
        validate_kzg_inputs(bundle)?;

        let zeta_omega = Bn254::mul(bundle.zeta, bundle.omega);
        let rho_u = Bn254::mul(rho, bundle.u);

        // LHS terms: rho_j * W_{zeta,j} + (rho_j * u_j) * W_{zeta*omega,j}
        lhs_points.push(bundle.w_zeta);
        lhs_scalars.push(rho);
        lhs_points.push(bundle.w_zeta_omega);
        lhs_scalars.push(rho_u);

        // RHS terms: (rho_j * zeta_j) * W_{zeta,j} + (rho_j * u_j * zeta_j * omega_j) * W_{zeta*omega,j}
        rhs_points.push(bundle.w_zeta);
        rhs_scalars.push(Bn254::mul(rho, bundle.zeta));
        rhs_points.push(bundle.w_zeta_omega);
        rhs_scalars.push(Bn254::mul(rho_u, zeta_omega));

        let mut e_scalar = u256::from(0u8);
        let mut v_pow = u256::from(1u8);
        for i in 0..bundle.commitments.len() {
            rhs_points.push(bundle.commitments[i]);
            rhs_scalars.push(Bn254::mul(rho, v_pow));
            e_scalar = Bn254::add(e_scalar, Bn254::mul(v_pow, bundle.evaluations_at_zeta[i]));
            v_pow = Bn254::mul(v_pow, bundle.v);
        }

        e_scalar = Bn254::add(
            e_scalar,
            Bn254::mul(bundle.u, bundle.evaluation_at_zeta_omega),
        );
        total_e_scalar = Bn254::add(total_e_scalar, Bn254::mul(rho, e_scalar));

        if j + 1 < m {
            rho = Bn254::mul(rho, rho);
            if rho == u256::from(0u8) {
                return Err(ZkError::InvalidFieldElement);
            }
        }
    }

    let neg_total_e = Bn254::sub(u256::from(0u8), total_e_scalar);
    rhs_points.push(G1_GENERATOR);
    rhs_scalars.push(neg_total_e);

    let lhs = g1_msm_host_or_software(env, &lhs_points, &lhs_scalars)?;
    let rhs = g1_msm_host_or_software(env, &rhs_points, &rhs_scalars)?;
    Ok((lhs, rhs))
}

/// Evaluates `e(lhs, srs_g2) · e(-rhs, G₂) == 1`, handling identity G1 terms
/// (`e(𝒪, Q) = 1`) cleanly after validating `srs_g2`.
fn check_kzg_pairing_equation(
    env: &Env,
    lhs: G1Affine,
    rhs: G1Affine,
    srs_g2: G2Affine,
) -> Result<bool, ZkError> {
    if !validate_g2_coords(&srs_g2) {
        return Err(ZkError::InvalidInput);
    }
    let g2_gen = G2Affine::generator();
    match (is_g1_identity(lhs), is_g1_identity(rhs)) {
        (true, true) => Ok(true),
        (false, true) => pairing_check(env, &[(lhs, srs_g2)]),
        (true, false) => pairing_check(env, &[(neg_g1(rhs), g2_gen)]),
        (false, false) => pairing_check(env, &[(lhs, srs_g2), (neg_g1(rhs), g2_gen)]),
    }
}

/// Negates a G1Affine point: `(x, y) -> (x, -y mod Fq)`.
///
/// Returns the identity unchanged.
#[inline(always)]
fn neg_g1(p: G1Affine) -> G1Affine {
    use ethnum::u256;
    if p.x == u256::from(0u8) && p.y == u256::from(0u8) {
        p
    } else {
        G1Affine {
            x: p.x,
            y: Bn254::sub_fq(u256::from(0u8), p.y),
        }
    }
}

/// Verifies the batched KZG evaluation proofs for PLONK at `ζ` and `ζω`.
///
/// This is the entry point for the "opening check" step of a PLONK verifier.
/// It performs the full two-pair pairing equation using the Soroban
/// `bn254_multi_pairing_check` host function (CAP-0075).
///
/// # Arguments
///
/// * `env` – Soroban execution environment (needed for the pairing host call).
/// * `inputs` – All evaluations, commitments, and opening proofs (see
///   [`KzgEvalProofInputs`]).
/// * `srs_g2` – The SRS G2 element `[τ]₂` from the trusted setup.  In
///   practice this is stored in the verifying key.
///
/// # Returns
///
/// * `Ok(true)` if the pairing equation holds (proof accepted).
/// * `Ok(false)` if the pairing equation fails (proof rejected).
/// * `Err(ZkError::InvalidInput)` / `Err(ZkError::InvalidFieldElement)` on
///   malformed inputs (propagated from [`kzg_eval_proof_points`]).
/// * `Err(ZkError::HostError)` if the host pairing call fails unexpectedly.
///
/// # Gas Guidance
///
/// This call performs exactly two pairings via `bn254_multi_pairing_check`.
/// At Protocol 25 rates each pair costs ~40 M instructions; total budget for
/// this call is ~80 M instructions.  The G1 scalar-mul operations in
/// [`kzg_eval_proof_points`] add roughly 10–30 M depending on the batch size.
///
/// # Example
///
/// ```rust,ignore
/// use soroban_zk_std::plonk_kzg::verify_plonk_kzg;
/// use soroban_zk_core::KzgEvalProofInputs;
/// use soroban_zk_std::pairing::G2Affine;
///
/// let accepted = verify_plonk_kzg(&env, &inputs, srs_g2)?;
/// assert!(accepted, "proof verification failed");
/// ```
pub fn verify_plonk_kzg(
    env: &Env,
    inputs: &KzgEvalProofInputs<'_>,
    srs_g2: G2Affine,
) -> Result<bool, ZkError> {
    // 1. Compute the two G1 points using native CAP-0074 host G1 MSM.
    let (lhs, rhs) = kzg_eval_proof_points_host(env, inputs)?;

    // 2. Check:  e(lhs, srs_g2) · e(-rhs, G2_gen) == 1
    check_kzg_pairing_equation(env, lhs, rhs, srs_g2)
}

/// Verifies `M` PLONK proofs with a **single** pairing call (Issue #427).
///
/// Each entry of `inputs` is a full [`KzgEvalProofInputs`] for one proof (the
/// same bundle consumed by [`verify_plonk_kzg`]). Instead of running one
/// two-pair `bn254_multi_pairing_check` per proof (`2·M` pairings total), the
/// per-proof `(lhs_j, rhs_j)` points are combined with random batch scalars
/// `rho_j` derived from `batch_seed` and folded into a single two-pair check:
///
/// ```text
/// e( sum_j rho_j·lhs_j , [tau]_2 ) · e( -sum_j rho_j·rhs_j , G₂ ) == 1
/// ```
///
/// This collapses the dominant on-chain cost (pairings) from `2·M` to `2`, so
/// verifying a batch is far cheaper than verifying each proof independently.
/// The G1 arithmetic is delegated to
/// [`plonk_batch_verify_points`] (allocation-free).
///
/// # Arguments
///
/// * `env` – Soroban execution environment (needed for the pairing host call).
/// * `inputs` – One [`KzgEvalProofInputs`] bundle per proof. Must be
///   non-empty.
/// * `batch_seed` – 32-byte seed used to derive the batch scalars `rho_j`.
/// * `srs_g2` – The SRS G2 element `[tau]₂` from the trusted setup.
///
/// # Returns
///
/// * `Ok(true)` if the aggregated pairing holds (all proofs accepted).
/// * `Ok(false)` if it fails (at least one proof is invalid).
/// * `Err(...)` on malformed inputs (empty batch, out-of-range scalars, or a
///   per-proof bundle failing validation) or a host pairing failure.
///
/// # Security
///
/// `batch_seed` **must** be unpredictable to the prover and not controlled by
/// it — e.g. derived from a transcript that binds every proof in the batch, or
/// an on-chain randomness beacon. A fixed or prover-chosen seed lets a malicious
/// prover cheat the randomized combination and breaks soundness.
///
/// As with [`verify_plonk_kzg`], the G1 points inside each bundle
/// (`w_zeta`, `w_zeta_omega`, commitments) **must** be subgroup-validated by
/// the caller before constructing [`KzgEvalProofInputs`].
///
/// # Example
///
/// ```rust,ignore
/// use soroban_zk_std::plonk_kzg::verify_plonk_kzg_batch;
///
/// let accepted = verify_plonk_kzg_batch(&env, &inputs, &batch_seed, srs_g2)?;
/// assert!(accepted, "batch verification failed");
/// ```
pub fn verify_plonk_kzg_batch(
    env: &Env,
    inputs: &[KzgEvalProofInputs<'_>],
    batch_seed: &[u8; 32],
    srs_g2: G2Affine,
) -> Result<bool, ZkError> {
    // 1. Fold every proof into the two batched G1 points via native CAP-0074 host G1 MSM.
    let (lhs, rhs) = plonk_batch_verify_points_host(env, inputs, batch_seed)?;

    // 2. One two-pair check replaces the M individual checks:
    //        e(lhs, [tau]_2) · e(-rhs, G₂) == 1
    check_kzg_pairing_equation(env, lhs, rhs, srs_g2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethnum::u256;
    use soroban_sdk::Env;
    use soroban_zk_core::G1Affine;

    // ─── helpers ────────────────────────────────────────────────────────────

    fn g1_gen() -> G1Affine {
        G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        }
    }

    fn g2_gen() -> G2Affine {
        G2Affine::generator()
    }

    // ─── unit tests ─────────────────────────────────────────────────────────

    /// Calling `verify_plonk_kzg` with well-formed inputs must not panic and
    /// must return a `bool` (true or false) rather than an error.
    ///
    /// Note: Because the fixture is *not* a valid proof, the pairing will
    /// return `false`.  We only assert the absence of errors here.
    #[test]
    fn verify_plonk_kzg_completes_without_error_for_valid_inputs() {
        let env = Env::default();
        let commitments = [g1_gen()];
        let evaluations = [u256::from(3u8)];

        let inputs = KzgEvalProofInputs {
            commitments: &commitments,
            evaluations_at_zeta: &evaluations,
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: u256::from(5u8),
            w_zeta: g1_gen(),
            w_zeta_omega: g1_gen(),
            v: u256::from(7u8),
            u: u256::from(11u8),
            zeta: u256::from(13u8),
            omega: u256::from(17u8),
        };

        // A random G2 point used as the mock SRS element.
        let srs_g2 = g2_gen();

        // Must return Ok(bool) — not panic, not Err.
        match verify_plonk_kzg(&env, &inputs, srs_g2) {
            Ok(_accepted) => { /* pass — result is mathematically undefined for dummy data */ }
            Err(e) => panic!("unexpected error: {:?}", e),
        }
    }

    /// `verify_plonk_kzg` must propagate `ZkError::InvalidInput` when the
    /// commitment and evaluation slices have different lengths.
    #[test]
    fn verify_plonk_kzg_propagates_invalid_input_error() {
        let env = Env::default();
        let commitments = [g1_gen()];
        let evaluations = [u256::from(1u8), u256::from(2u8)]; // wrong length

        let inputs = KzgEvalProofInputs {
            commitments: &commitments,
            evaluations_at_zeta: &evaluations,
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: u256::from(5u8),
            w_zeta: g1_gen(),
            w_zeta_omega: g1_gen(),
            v: u256::from(7u8),
            u: u256::from(11u8),
            zeta: u256::from(13u8),
            omega: u256::from(17u8),
        };

        assert_eq!(
            verify_plonk_kzg(&env, &inputs, g2_gen()),
            Err(ZkError::InvalidInput)
        );
    }

    /// `verify_plonk_kzg` must propagate `ZkError::InvalidFieldElement` when
    /// any challenge scalar is ≥ the BN254 scalar field modulus.
    #[test]
    fn verify_plonk_kzg_propagates_field_element_error() {
        let env = Env::default();
        let commitments = [g1_gen()];
        let evaluations = [u256::from(3u8)];

        let inputs = KzgEvalProofInputs {
            commitments: &commitments,
            evaluations_at_zeta: &evaluations,
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: u256::from(5u8),
            w_zeta: g1_gen(),
            w_zeta_omega: g1_gen(),
            v: u256::from(7u8),
            u: u256::from(11u8),
            zeta: Bn254::FR_MODULUS, // out-of-range zeta
            omega: u256::from(17u8),
        };

        assert_eq!(
            verify_plonk_kzg(&env, &inputs, g2_gen()),
            Err(ZkError::InvalidFieldElement)
        );
    }

    /// Structural test: verify the full call chain reaches the pairing engine.
    /// With u = 0 and carefully chosen inputs, we confirm no panic/error occurs.
    /// See inline comments for the mathematical reasoning.
    #[test]
    fn verify_plonk_kzg_trivial_self_cancelling_proof() {
        let env = Env::default();

        // With u = 0: lhs = W_ζ
        // With zeta = 0: zeta*W_ζ = identity
        // F = C_0 = G1_gen, [E]_1 = eval_0 * G1_gen = 1 * G1_gen = G1_gen
        // → F - [E]_1 = G1_gen - G1_gen = identity
        // → rhs = identity
        //
        // Pairing check: e(G1_gen, srs_g2) · e(-identity, G2_gen) = e(G1_gen, srs_g2) ≠ 1
        // So the proof is NOT accepted — but no error should be returned.
        let commitments = [g1_gen()];
        let evaluations = [u256::from(1u8)];

        let inputs = KzgEvalProofInputs {
            commitments: &commitments,
            evaluations_at_zeta: &evaluations,
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: u256::from(0u8),
            w_zeta: g1_gen(),
            w_zeta_omega: g1_gen(),
            v: u256::from(1u8),
            u: u256::from(0u8),
            zeta: u256::from(0u8),
            omega: u256::from(1u8),
        };

        let result = verify_plonk_kzg(&env, &inputs, g2_gen());
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    // ─── multi-proof batch tests (Issue #427) ───────────────────────────────

    /// Builds a well-formed [`KzgEvalProofInputs`] bundle for batch tests.
    fn batch_bundle() -> KzgEvalProofInputs<'static> {
        static C: &[G1Affine] = &[G1Affine {
            x: u256::from_words(0, 1),
            y: u256::from_words(0, 2),
        }];
        static E: &[u256] = &[u256::from_words(0, 3)];
        KzgEvalProofInputs {
            commitments: C,
            evaluations_at_zeta: E,
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: u256::from(5u8),
            w_zeta: g1_gen(),
            w_zeta_omega: g1_gen(),
            v: u256::from(7u8),
            u: u256::from(11u8),
            zeta: u256::from(13u8),
            omega: u256::from(17u8),
        }
    }

    /// An empty batch is a structural error, never a pairing call.
    #[test]
    fn verify_plonk_kzg_batch_rejects_empty_batch() {
        let env = Env::default();
        assert_eq!(
            verify_plonk_kzg_batch(&env, &[], &[7u8; 32], g2_gen()),
            Err(ZkError::InvalidInput)
        );
    }

    /// A batch of well-formed bundles must run the single aggregated pairing
    /// and return `Ok(bool)` (the dummy data is not a real proof, so we only
    /// assert the absence of errors).
    #[test]
    fn verify_plonk_kzg_batch_completes_without_error() {
        let env = Env::default();
        let inputs = [batch_bundle(), batch_bundle()];
        match verify_plonk_kzg_batch(&env, &inputs, &[9u8; 32], g2_gen()) {
            Ok(_) => { /* pass — result undefined for dummy data */ }
            Err(e) => panic!("unexpected error: {:?}", e),
        }
    }

    /// A zero `batch_seed` reduces the first batch scalar to zero and must be
    /// rejected before any pairing is attempted.
    #[test]
    fn verify_plonk_kzg_batch_rejects_zero_seed() {
        let env = Env::default();
        let inputs = [batch_bundle()];
        assert_eq!(
            verify_plonk_kzg_batch(&env, &inputs, &[0u8; 32], g2_gen()),
            Err(ZkError::InvalidFieldElement)
        );
    }

    /// Host-accelerated `kzg_eval_proof_points_host` must produce bit-identical
    /// `(lhs, rhs)` points to `soroban_zk_core::kzg_eval_proof_points`.
    #[test]
    fn kzg_eval_proof_points_host_matches_core_reference() {
        let env = Env::default();
        let g1 = g1_gen();
        let g1_2 = g1.add(&g1);
        let g1_3 = g1_2.add(&g1);
        let commitments = [g1, g1_2, g1_3];
        let evaluations = [u256::from(3u8), u256::from(19u8), u256::from(41u8)];

        let inputs = KzgEvalProofInputs {
            commitments: &commitments,
            evaluations_at_zeta: &evaluations,
            commitment_at_zeta_omega: g1_2,
            evaluation_at_zeta_omega: u256::from(5u8),
            w_zeta: g1_3,
            w_zeta_omega: g1,
            v: u256::from(7u8),
            u: u256::from(11u8),
            zeta: u256::from(13u8),
            omega: u256::from(17u8),
        };

        let expected = soroban_zk_core::kzg_eval_proof_points(&inputs).unwrap();
        let actual = kzg_eval_proof_points_host(&env, &inputs).unwrap();
        assert_eq!(actual, expected);

        // Boundary case: zero scalars (u = 0, v = 0, zeta = 0)
        let zero_inputs = KzgEvalProofInputs {
            v: u256::from(0u8),
            u: u256::from(0u8),
            zeta: u256::from(0u8),
            ..inputs
        };
        let expected_zero = soroban_zk_core::kzg_eval_proof_points(&zero_inputs).unwrap();
        let actual_zero = kzg_eval_proof_points_host(&env, &zero_inputs).unwrap();
        assert_eq!(actual_zero, expected_zero);
    }

    /// Host-accelerated `plonk_batch_verify_points_host` must produce bit-identical
    /// `(lhs, rhs)` points to `soroban_zk_core::plonk_batch_verify_points`.
    #[test]
    fn plonk_batch_verify_points_host_matches_core_reference() {
        let env = Env::default();
        let seed = [42u8; 32];
        let inputs = [batch_bundle(), batch_bundle()];

        let expected = soroban_zk_core::plonk_batch_verify_points(&inputs, &seed).unwrap();
        let actual = plonk_batch_verify_points_host(&env, &inputs, &seed).unwrap();
        assert_eq!(actual, expected);
    }

    /// An off-curve `srs_g2` must be rejected with `ZkError::InvalidInput`.
    #[test]
    fn verify_plonk_kzg_rejects_invalid_srs_g2() {
        let env = Env::default();
        let mut bad_srs = g2_gen();
        bad_srs.y.0 = Bn254::add_fq(bad_srs.y.0, u256::from(1u8));
        assert_eq!(
            verify_plonk_kzg(&env, &batch_bundle(), bad_srs),
            Err(ZkError::InvalidInput)
        );
    }
}
