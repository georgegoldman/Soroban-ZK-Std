//! Integration tests for PLONK-KZG verification negative vectors (Issue #538).
//!
//! Ensures `cargo test -p soroban-zk-std --test plonk_kzg` explicitly exercises
//! rejection of off-curve commitments/proofs, out-of-range scalars, and
//! mismatched openings across both single and batched KZG verification.

use ethnum::u256;
use soroban_sdk::Env;
use soroban_zk_core::{Bn254, G1Affine, KzgEvalProofInputs, ZkError};
use soroban_zk_std::pairing::G2Affine;
use soroban_zk_std::plonk_kzg::{verify_plonk_kzg, verify_plonk_kzg_batch};

fn g1_gen() -> G1Affine {
    G1Affine {
        x: u256::from(1u8),
        y: u256::from(2u8),
    }
}

fn off_curve_g1() -> G1Affine {
    G1Affine {
        x: u256::from(1u8),
        y: u256::from(3u8),
    }
}

fn build_satisfying(
    witness_mult: u64,
    eval_zeta: u256,
    eval_zeta_omega: u256,
) -> ([G1Affine; 1], [u256; 1], G1Affine) {
    let u = u256::from(11u8);
    let zeta = u256::from(13u8);
    let omega = u256::from(17u8);

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

#[test]
fn single_verify_rejects_corrupted_points_scalars_and_mismatched_openings() {
    let env = Env::default();
    let g2 = G2Affine::generator();
    let (commitments, evaluations, witness) =
        build_satisfying(69, u256::from(3u8), u256::from(5u8));

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
    assert_eq!(verify_plonk_kzg(&env, &valid, g2), Ok(true));

    // Off-curve wire commitment -> Err(ZkError::InvalidInput).
    let bad_c = [off_curve_g1()];
    assert_eq!(
        verify_plonk_kzg(
            &env,
            &KzgEvalProofInputs {
                commitments: &bad_c,
                ..valid.clone()
            },
            g2,
        ),
        Err(ZkError::InvalidInput)
    );

    // Off-curve opening proof -> Err(ZkError::InvalidInput).
    assert_eq!(
        verify_plonk_kzg(
            &env,
            &KzgEvalProofInputs {
                w_zeta: off_curve_g1(),
                ..valid.clone()
            },
            g2,
        ),
        Err(ZkError::InvalidInput)
    );

    // Out-of-bounds evaluation scalar -> Err(ZkError::InvalidFieldElement).
    let oob_eval = [Bn254::FR_MODULUS];
    assert_eq!(
        verify_plonk_kzg(
            &env,
            &KzgEvalProofInputs {
                evaluations_at_zeta: &oob_eval,
                ..valid.clone()
            },
            g2,
        ),
        Err(ZkError::InvalidFieldElement)
    );

    // Mismatched opening proof -> Ok(false).
    assert_eq!(
        verify_plonk_kzg(
            &env,
            &KzgEvalProofInputs {
                w_zeta_omega: g1_gen().scalar_mul(u256::from(2u8)),
                ..valid
            },
            g2,
        ),
        Ok(false)
    );
}

#[test]
fn batch_verify_rejects_corrupted_points_scalars_and_mismatched_openings() {
    let env = Env::default();
    let g2 = G2Affine::generator();
    let seed = [9u8; 32];
    let (c1, e1, w1) = build_satisfying(69, u256::from(3u8), u256::from(5u8));
    let (c2, e2, w2) = build_satisfying(73, u256::from(9u8), u256::from(11u8));

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
        verify_plonk_kzg_batch(&env, &[p1.clone(), p2.clone()], &seed, g2),
        Ok(true)
    );

    // Off-curve proof in batch -> Err(ZkError::InvalidInput).
    assert_eq!(
        verify_plonk_kzg_batch(
            &env,
            &[
                p1.clone(),
                KzgEvalProofInputs {
                    w_zeta_omega: off_curve_g1(),
                    ..p2.clone()
                }
            ],
            &seed,
            g2,
        ),
        Err(ZkError::InvalidInput)
    );

    // Out-of-bounds shifted evaluation in batch -> Err(ZkError::InvalidFieldElement).
    assert_eq!(
        verify_plonk_kzg_batch(
            &env,
            &[
                p1.clone(),
                KzgEvalProofInputs {
                    evaluation_at_zeta_omega: Bn254::FR_MODULUS,
                    ..p2.clone()
                }
            ],
            &seed,
            g2,
        ),
        Err(ZkError::InvalidFieldElement)
    );

    // Mismatched opening in batch -> Ok(false).
    assert_eq!(
        verify_plonk_kzg_batch(
            &env,
            &[
                p1,
                KzgEvalProofInputs {
                    w_zeta: g1_gen().scalar_mul(u256::from(2u8)),
                    ..p2
                }
            ],
            &seed,
            g2,
        ),
        Ok(false)
    );
}
