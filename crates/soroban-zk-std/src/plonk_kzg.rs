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

use soroban_sdk::Env;
use soroban_zk_core::{
    kzg_eval_proof_points, plonk_batch_verify_points, Bn254, G1Affine, KzgEvalProofInputs, ZkError,
};

use crate::pairing::{pairing_check, validate_g2_coords, G2Affine};

#[inline(always)]
fn is_g1_identity(p: G1Affine) -> bool {
    use ethnum::u256;
    p.x == u256::from(0u8) && p.y == u256::from(0u8)
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
    // 1. Compute the two G1 points from the batched polynomial arithmetic.
    let (lhs, rhs) = kzg_eval_proof_points(inputs)?;

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
    // 1. Fold every proof into the two batched G1 points (single accumulator
    //    pass, no heap allocation).
    let (lhs, rhs) = plonk_batch_verify_points(inputs, batch_seed)?;

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

    fn off_curve_g1() -> G1Affine {
        G1Affine {
            x: u256::from(1u8),
            y: u256::from(3u8), // 3^2 != 1^3 + 3
        }
    }

    /// Constructs a mathematically satisfying KZG opening against `G2::generator()`
    /// so positive and tampered-proof negative tests assert exact booleans.
    ///
    /// Let `P = [witness_mult]G1` and `W_zeta = W_{zeta*omega} = P`:
    /// - `lhs = (1 + u)·P`
    /// - `rhs = (zeta + u·zeta·omega)·P + F - [E]_1`
    ///
    /// Solving `C_0 = [(1 + u - zeta - u·zeta·omega)·witness_mult + eval_0 + u·eval_omega]G1`
    /// yields `lhs == rhs`, so `e(lhs, G2)·e(-rhs, G2) == 1`.
    fn satisfying_single_fixture(
        witness_mult: u64,
        eval_zeta: u256,
        eval_zeta_omega: u256,
    ) -> ([G1Affine; 1], [u256; 1], G1Affine) {
        let v = u256::from(7u8);
        let u = u256::from(11u8);
        let zeta = u256::from(13u8);
        let omega = u256::from(17u8);
        let _ = v;

        let p = g1_gen().scalar_mul(u256::from(witness_mult));
        let u_zeta_omega = Bn254::mul(u, Bn254::mul(zeta, omega));
        let t = Bn254::sub(
            Bn254::add(u256::from(1u8), u),
            Bn254::add(zeta, u_zeta_omega),
        );
        let e_batch = Bn254::add(eval_zeta, Bn254::mul(u, eval_zeta_omega));
        let c0_scalar = Bn254::add(Bn254::mul(u256::from(witness_mult), t), e_batch);
        let c0 = g1_gen().scalar_mul(c0_scalar);

        ([c0], [eval_zeta], p)
    }

    // ─── unit tests ─────────────────────────────────────────────────────────

    /// `verify_plonk_kzg` must accept a genuinely satisfying opening (`Ok(true)`)
    /// and explicitly reject (`Ok(false)`) when the opening proof, commitment,
    /// or evaluations are corrupted with otherwise well-formed values.
    #[test]
    fn verify_plonk_kzg_accepts_valid_and_rejects_mismatched_proofs() {
        let env = Env::default();
        let eval_zeta = u256::from(3u8);
        let eval_omega = u256::from(5u8);
        let (commitments, evaluations, witness) =
            satisfying_single_fixture(69, eval_zeta, eval_omega);
        let alt_point = g1_gen().scalar_mul(u256::from(2u8));

        let valid = KzgEvalProofInputs {
            commitments: &commitments,
            evaluations_at_zeta: &evaluations,
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: eval_omega,
            w_zeta: witness,
            w_zeta_omega: witness,
            v: u256::from(7u8),
            u: u256::from(11u8),
            zeta: u256::from(13u8),
            omega: u256::from(17u8),
        };
        assert_eq!(verify_plonk_kzg(&env, &valid, g2_gen()), Ok(true));

        // Mismatched W_zeta opening proof must be rejected (Ok(false)).
        let bad_w_zeta = KzgEvalProofInputs {
            w_zeta: alt_point,
            ..valid.clone()
        };
        assert_eq!(verify_plonk_kzg(&env, &bad_w_zeta, g2_gen()), Ok(false));

        // Mismatched W_{zeta*omega} opening proof must be rejected (Ok(false)).
        let bad_w_omega = KzgEvalProofInputs {
            w_zeta_omega: alt_point,
            ..valid.clone()
        };
        assert_eq!(verify_plonk_kzg(&env, &bad_w_omega, g2_gen()), Ok(false));

        // Tampered wire commitment must be rejected (Ok(false)).
        let bad_commitments = [alt_point];
        let bad_commit = KzgEvalProofInputs {
            commitments: &bad_commitments,
            ..valid.clone()
        };
        assert_eq!(verify_plonk_kzg(&env, &bad_commit, g2_gen()), Ok(false));

        // Tampered evaluation scalar at zeta must be rejected (Ok(false)).
        let bad_evals = [Bn254::add(eval_zeta, u256::from(1u8))];
        let bad_eval = KzgEvalProofInputs {
            evaluations_at_zeta: &bad_evals,
            ..valid.clone()
        };
        assert_eq!(verify_plonk_kzg(&env, &bad_eval, g2_gen()), Ok(false));

        // Tampered shifted evaluation at zeta*omega must be rejected (Ok(false)).
        let bad_eval_omega = KzgEvalProofInputs {
            evaluation_at_zeta_omega: Bn254::add(eval_omega, u256::from(1u8)),
            ..valid
        };
        assert_eq!(verify_plonk_kzg(&env, &bad_eval_omega, g2_gen()), Ok(false));
    }

    /// `verify_plonk_kzg` must return `Err(ZkError::InvalidInput)` on off-curve
    /// wire commitments, opening proofs, or invalid SRS G2 points, and
    /// `Err(ZkError::InvalidFieldElement)` on out-of-range evaluations.
    #[test]
    fn verify_plonk_kzg_rejects_corrupted_points_and_out_of_range_evals() {
        let env = Env::default();
        let (commitments, evaluations, witness) =
            satisfying_single_fixture(69, u256::from(3u8), u256::from(5u8));
        let valid = KzgEvalProofInputs {
            commitments: &commitments,
            evaluations_at_zeta: &evaluations,
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: u256::from(5u8),
            w_zeta: witness,
            w_zeta_omega: witness,
            v: u256::from(7u8),
            u: u256::from(11u8),
            zeta: u256::from(13u8),
            omega: u256::from(17u8),
        };

        // 1. Off-curve wire commitment point.
        let bad_c = [off_curve_g1()];
        assert_eq!(
            verify_plonk_kzg(
                &env,
                &KzgEvalProofInputs {
                    commitments: &bad_c,
                    ..valid.clone()
                },
                g2_gen(),
            ),
            Err(ZkError::InvalidInput)
        );

        // 2. Off-curve opening proof W_zeta.
        assert_eq!(
            verify_plonk_kzg(
                &env,
                &KzgEvalProofInputs {
                    w_zeta: off_curve_g1(),
                    ..valid.clone()
                },
                g2_gen(),
            ),
            Err(ZkError::InvalidInput)
        );

        // 3. Invalid SRS G2 point.
        let mut bad_g2 = g2_gen();
        bad_g2.y.0 = Bn254::add_fq(bad_g2.y.0, u256::from(1u8));
        assert_eq!(
            verify_plonk_kzg(&env, &valid, bad_g2),
            Err(ZkError::InvalidInput)
        );

        // 4. Out-of-bounds evaluation scalar at zeta (>= FR_MODULUS).
        let oob_eval = [Bn254::FR_MODULUS];
        assert_eq!(
            verify_plonk_kzg(
                &env,
                &KzgEvalProofInputs {
                    evaluations_at_zeta: &oob_eval,
                    ..valid.clone()
                },
                g2_gen(),
            ),
            Err(ZkError::InvalidFieldElement)
        );

        // 5. Out-of-bounds evaluation_at_zeta_omega (>= FR_MODULUS).
        assert_eq!(
            verify_plonk_kzg(
                &env,
                &KzgEvalProofInputs {
                    evaluation_at_zeta_omega: Bn254::FR_MODULUS,
                    ..valid
                },
                g2_gen(),
            ),
            Err(ZkError::InvalidFieldElement)
        );
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
        assert_eq!(result, Ok(false));
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

    /// A batch of satisfying proofs must return `Ok(true)`, whereas a batch
    /// containing any mismatched, off-curve, or out-of-range proof must fail
    /// explicitly.
    #[test]
    fn verify_plonk_kzg_batch_accepts_valid_and_rejects_corrupted_proofs() {
        let env = Env::default();
        let seed = [9u8; 32];
        let (c1, e1, w1) = satisfying_single_fixture(69, u256::from(3u8), u256::from(5u8));
        let (c2, e2, w2) = satisfying_single_fixture(73, u256::from(9u8), u256::from(11u8));

        let p1 = KzgEvalProofInputs {
            commitments: &c1,
            evaluations_at_zeta: &e1,
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: u256::from(5u8),
            w_zeta: w1,
            w_zeta_omega: w1,
            v: u256::from(7u8),
            u: u256::from(11u8),
            zeta: u256::from(13u8),
            omega: u256::from(17u8),
        };
        let p2 = KzgEvalProofInputs {
            commitments: &c2,
            evaluations_at_zeta: &e2,
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: u256::from(11u8),
            w_zeta: w2,
            w_zeta_omega: w2,
            v: u256::from(7u8),
            u: u256::from(11u8),
            zeta: u256::from(13u8),
            omega: u256::from(17u8),
        };

        assert_eq!(
            verify_plonk_kzg_batch(&env, &[p1.clone(), p2.clone()], &seed, g2_gen()),
            Ok(true)
        );

        // Corrupt the second proof with a mismatched W_zeta -> Ok(false).
        let mismatched = KzgEvalProofInputs {
            w_zeta: g1_gen().scalar_mul(u256::from(2u8)),
            ..p2.clone()
        };
        assert_eq!(
            verify_plonk_kzg_batch(&env, &[p1.clone(), mismatched], &seed, g2_gen()),
            Ok(false)
        );

        // Dummy unsatisfied proof pair must also be rejected via Ok(false).
        assert_eq!(
            verify_plonk_kzg_batch(&env, &[batch_bundle(), batch_bundle()], &seed, g2_gen()),
            Ok(false)
        );

        // Off-curve commitment inside the batch -> Err(ZkError::InvalidInput).
        let bad_c = [off_curve_g1()];
        let off_curve_proof = KzgEvalProofInputs {
            commitments: &bad_c,
            ..p2.clone()
        };
        assert_eq!(
            verify_plonk_kzg_batch(&env, &[p1.clone(), off_curve_proof], &seed, g2_gen()),
            Err(ZkError::InvalidInput)
        );

        // Out-of-range evaluation scalar inside the batch -> Err(ZkError::InvalidFieldElement).
        let oob_e = [Bn254::FR_MODULUS];
        let oob_proof = KzgEvalProofInputs {
            evaluations_at_zeta: &oob_e,
            ..p2
        };
        assert_eq!(
            verify_plonk_kzg_batch(&env, &[p1, oob_proof], &seed, g2_gen()),
            Err(ZkError::InvalidFieldElement)
        );
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
}
