//! Exhaustive 64-bit range-proof boundary & edge-case tests for Bulletproofs (Issue #448).
//!
//! Verifies that:
//! - Valid boundary and power-of-two values across `[0, 2^64 - 1]` prove and verify.
//! - Out-of-range values (`>= 2^64`, overflow, and negative values mod `Fr`) are rejected.
//! - Blinding extremes (`gamma = 0`, `1`, `FR_MODULUS - 1`) and forged/tampered proofs fail.
//! - Batch verification (`verify_batch`, `BatchVerifyContext`) respects boundary cases.

use ethnum::u256;
use soroban_zk_core::bulletproofs::{
    commit_value, prove, validate_proof, verify, verify_batch, BatchVerifyContext, Generators,
    RangeProof, TWO64,
};
use soroban_zk_core::{Bn254, ZkError};

fn gens() -> Generators {
    Generators::new()
}

fn f_add(a: u256, b: u256) -> u256 {
    Bn254::add(a, b)
}

#[test]
#[cfg_attr(miri, ignore)]
fn range_proof_accepts_all_64bit_boundary_and_power_of_two_values() {
    let g = gens();
    let boundaries: &[u64] = &[
        0,
        1,
        2,
        (1u64 << 31) - 1,
        1u64 << 31,
        u32::MAX as u64,
        1u64 << 32,
        (1u64 << 63) - 1,
        1u64 << 63,
        u64::MAX - 1,
        u64::MAX,
    ];

    for (idx, &v) in boundaries.iter().enumerate() {
        let mut randomness = [0x10u8.wrapping_add(idx as u8); 64];
        randomness[0] ^= idx as u8;
        let gamma = u256::from((idx as u64) + 1);
        let proof = prove(&g, u256::from(v), gamma, &randomness)
            .expect("valid 64-bit boundary value must prove");
        assert!(verify(&g, &proof), "valid 64-bit value {v} must verify");
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn range_proof_rejects_overflow_and_negative_modular_values() {
    let g = gens();
    let invalid_values: &[(&str, u256)] = &[
        ("2^64", TWO64),
        ("2^64 + 1", TWO64 + u256::from(1u8)),
        ("2^65", TWO64 << 1),
        ("u128::MAX", u256::from(u128::MAX)),
        ("FR_MODULUS - 2^64", Bn254::FR_MODULUS - TWO64),
        ("-2 mod Fr", Bn254::FR_MODULUS - u256::from(2u8)),
        ("-1 mod Fr", Bn254::FR_MODULUS - u256::from(1u8)),
        ("FR_MODULUS", Bn254::FR_MODULUS),
        ("FR_MODULUS + 1", Bn254::FR_MODULUS + u256::from(1u8)),
        ("u256::MAX", u256::MAX),
    ];

    for (idx, (label, val)) in invalid_values.iter().enumerate() {
        let randomness = [0x40u8.wrapping_add(idx as u8); 64];
        let res = prove(&g, *val, u256::from(7u8), &randomness);
        assert_eq!(
            res,
            Err(ZkError::InvalidInput),
            "out-of-range value {label} must be rejected by prove"
        );
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn range_proof_handles_blinding_extremes_zero_and_fr_minus_one() {
    let g = gens();

    // Unblinded (gamma = 0) at non-zero values v = 1 and v = 2^64 - 1.
    for (idx, &v) in [1u64, u64::MAX].iter().enumerate() {
        let proof = prove(&g, u256::from(v), u256::ZERO, &[0x71u8 + idx as u8; 64])
            .expect("zero blinding at non-zero value must prove");
        assert!(verify(&g, &proof), "gamma = 0 must verify for v = {v}");
    }

    // Degenerate unblinded zero (v = 0, gamma = 0) produces V = O (identity),
    // which validate_proof/verify explicitly reject to block identity-point malleability.
    let zero_unblinded = prove(&g, u256::ZERO, u256::ZERO, &[0x75u8; 64])
        .expect("prover returns proof struct for v = 0");
    assert_eq!(zero_unblinded.v.x, u256::ZERO);
    assert_eq!(zero_unblinded.v.y, u256::ZERO);
    assert_eq!(
        validate_proof(&zero_unblinded),
        Err(ZkError::InvalidInput),
        "identity commitment V = O must be rejected by validate_proof"
    );
    assert!(!verify(&g, &zero_unblinded));

    // Maximum canonical blinding factor (gamma = FR_MODULUS - 1) at v = 0 and v = 2^64 - 1.
    let max_gamma = Bn254::FR_MODULUS - u256::ONE;
    for (idx, &v) in [0u64, u64::MAX].iter().enumerate() {
        let proof_max_gamma = prove(&g, u256::from(v), max_gamma, &[0x79u8 + idx as u8; 64])
            .expect("FR_MODULUS - 1 blinding must prove");
        assert!(
            verify(&g, &proof_max_gamma),
            "gamma = FR_MODULUS - 1 must verify for v = {v}"
        );
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn verifier_rejects_forged_out_of_range_commitments_and_corrupted_fields() {
    let g = gens();
    let proof = prove(&g, u256::from(0u8), u256::from(11u8), &[0x90u8; 64]).unwrap();
    assert!(verify(&g, &proof));

    // Swap V to a Pedersen commitment of out-of-range / negative values.
    let mut forged_2_64 = proof;
    forged_2_64.v = commit_value(&g, TWO64, u256::from(11u8));
    assert!(!verify(&g, &forged_2_64));
    assert!(!verify_batch(&g, &[forged_2_64]));

    let mut forged_neg = proof;
    forged_neg.v = commit_value(&g, Bn254::FR_MODULUS - u256::ONE, u256::from(11u8));
    assert!(!verify(&g, &forged_neg));
    assert!(!verify_batch(&g, &[forged_neg]));

    // Corrupt individual proof fields one by one and confirm verifier rejection.
    let mut bad_a = proof;
    bad_a.a.x = f_add(bad_a.a.x, u256::ONE);
    assert!(!verify(&g, &bad_a));

    let mut bad_s = proof;
    bad_s.s.x = f_add(bad_s.s.x, u256::ONE);
    assert!(!verify(&g, &bad_s));

    let mut bad_t1 = proof;
    bad_t1.t1.x = f_add(bad_t1.t1.x, u256::ONE);
    assert!(!verify(&g, &bad_t1));

    let mut bad_t2 = proof;
    bad_t2.t2.x = f_add(bad_t2.t2.x, u256::ONE);
    assert!(!verify(&g, &bad_t2));

    let mut bad_mu = proof;
    bad_mu.mu = f_add(bad_mu.mu, u256::ONE);
    assert!(!verify(&g, &bad_mu));

    let mut bad_taux = proof;
    bad_taux.taux = f_add(bad_taux.taux, u256::ONE);
    assert!(!verify(&g, &bad_taux));

    let mut bad_r0 = proof;
    bad_r0.ip_proof.r[0].x = f_add(bad_r0.ip_proof.r[0].x, u256::ONE);
    assert!(!verify(&g, &bad_r0));

    let mut bad_b = proof;
    bad_b.ip_proof.b = f_add(bad_b.ip_proof.b, u256::ONE);
    assert!(!verify(&g, &bad_b));
}

#[test]
#[cfg_attr(miri, ignore)]
fn batch_verifier_accepts_boundary_mix_and_rejects_single_bad_boundary() {
    let g = gens();
    let vals: [u64; 5] = [0, 1, (1u64 << 63) - 1, 1u64 << 63, u64::MAX];
    let mut proofs: [RangeProof; 5] = core::array::from_fn(|i| {
        prove(
            &g,
            u256::from(vals[i]),
            u256::from((i as u64) + 1),
            &[0xa0u8 + i as u8; 64],
        )
        .unwrap()
    });

    assert!(verify_batch(&g, &proofs));

    let mut ctx = BatchVerifyContext::new();
    for p in proofs {
        ctx.add(p).expect("within MAX_BATCH");
    }
    assert!(ctx.verify(&g));

    // Corrupting the u64::MAX proof in the batch must fail both verify_batch and BatchVerifyContext.
    proofs[4].t_hat = f_add(proofs[4].t_hat, u256::ONE);
    assert!(!verify_batch(&g, &proofs));

    let mut bad_ctx = BatchVerifyContext::new();
    for p in proofs {
        bad_ctx.add(p).expect("within MAX_BATCH");
    }
    assert!(!bad_ctx.verify(&g));
}
