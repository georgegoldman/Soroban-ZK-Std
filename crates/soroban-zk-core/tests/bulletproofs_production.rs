//! Production end-to-end Bulletproofs 64-bit range-proof test suite.
//!
//! Exercises the complete prover-to-verifier pipeline across boundary values
//! (`0`, `1`, `u32::MAX`, `u64::MAX - 1`, `u64::MAX`) for both single proofs
//! and batched verification (`m = 1, 2, 8, 16, 32`) via [`verify_batch`]
//! (which delegates to `verify_batch_optimized`) and [`BatchVerifyContext`].
//!
//! Also verifies that corrupting a single proof inside a 16-proof or 32-proof
//! batch reliably rejects the entire batch, and that [`BatchVerifyContext`]
//! enforces the `MAX_BATCH + 1` capacity limit.

#![cfg(feature = "prover")]

use ethnum::u256;
use soroban_zk_core::bulletproofs::{
    commit_value, prove, verify, verify_batch, BatchVerifyContext, Generators, RangeProof,
    MAX_BATCH, TWO64,
};
use soroban_zk_core::{Bn254, ZkError};

const BOUNDARY_VALUES: [u64; 5] = [0, 1, u32::MAX as u64, u64::MAX - 1, u64::MAX];

fn deterministic_randomness(seed: u64) -> [u8; 64] {
    let mut out = [0u8; 64];
    let bytes = seed.to_le_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = bytes[i % 8].wrapping_add(i as u8).wrapping_add(1);
    }
    out
}

fn deterministic_blinding(seed: u64) -> u256 {
    (u256::from(seed) * u256::from(0x9e37_79b9_7f4a_7c15u64) + u256::from(1u8)) % Bn254::FR_MODULUS
}

fn make_proof(gens: &Generators, value: u64, seed: u64) -> RangeProof {
    let gamma = deterministic_blinding(seed);
    let randomness = deterministic_randomness(seed);
    let proof = prove(gens, u256::from(value), gamma, &randomness)
        .expect("in-range 64-bit value must prove");
    assert_eq!(proof.v, commit_value(gens, u256::from(value), gamma));
    proof
}

fn build_batch_proofs(gens: &Generators, count: usize, seed_base: u64) -> Vec<RangeProof> {
    (0..count)
        .map(|i| {
            let value = BOUNDARY_VALUES[i % BOUNDARY_VALUES.len()];
            make_proof(gens, value, seed_base + i as u64)
        })
        .collect()
}

fn add_one_mod_fr(x: u256) -> u256 {
    (x + u256::from(1u8)) % Bn254::FR_MODULUS
}

// ---------------------------------------------------------------------------
// Single 64-bit range-proof boundary tests
// ---------------------------------------------------------------------------

#[test]
fn bulletproofs_single_boundary_values_verify() {
    let gens = Generators::new();
    for (idx, &value) in BOUNDARY_VALUES.iter().enumerate() {
        let proof = make_proof(&gens, value, 100 + idx as u64);
        assert!(
            verify(&gens, &proof),
            "single range proof for boundary value {value} must verify"
        );
    }
}

#[test]
fn bulletproofs_out_of_range_values_rejected() {
    let gens = Generators::new();
    let gamma = deterministic_blinding(77);
    let randomness = deterministic_randomness(77);

    assert_eq!(
        prove(&gens, TWO64, gamma, &randomness),
        Err(ZkError::InvalidInput)
    );
    assert_eq!(
        prove(&gens, TWO64 + u256::from(1u8), gamma, &randomness),
        Err(ZkError::InvalidInput)
    );
}

// ---------------------------------------------------------------------------
// Batch verification (m = 1, 2, 8, 16, 32)
// ---------------------------------------------------------------------------

#[test]
fn bulletproofs_batch_sizes_1_to_32_verify() {
    let gens = Generators::new();

    for (run, &m) in [1usize, 2, 8, 16, 32].iter().enumerate() {
        let proofs = build_batch_proofs(&gens, m, 1_000 + (run as u64) * 100);

        // verify_batch (delegates to verify_batch_optimized)
        assert!(
            verify_batch(&gens, &proofs),
            "verify_batch failed for m={m}"
        );

        // BatchVerifyContext
        let mut ctx = BatchVerifyContext::new();
        for &p in &proofs {
            ctx.add(p).expect("batch size <= MAX_BATCH must fit");
        }
        assert_eq!(ctx.len(), m);
        assert!(ctx.verify(&gens), "BatchVerifyContext failed for m={m}");
    }
}

// ---------------------------------------------------------------------------
// Corruption detection in 16-proof and 32-proof batches
// ---------------------------------------------------------------------------

#[test]
fn bulletproofs_corrupted_proof_in_16_and_32_batch_rejected() {
    let gens = Generators::new();

    for &m in &[16usize, 32usize] {
        for &corrupt_idx in &[0usize, m / 2, m - 1] {
            // Mode 1: perturb t_hat
            {
                let mut proofs = build_batch_proofs(&gens, m, 10_000 + m as u64);
                proofs[corrupt_idx].t_hat = add_one_mod_fr(proofs[corrupt_idx].t_hat);
                assert!(
                    !verify_batch(&gens, &proofs),
                    "verify_batch must reject corrupted t_hat at {corrupt_idx} in m={m}"
                );

                let mut ctx = BatchVerifyContext::new();
                for &p in &proofs {
                    ctx.add(p).unwrap();
                }
                assert!(
                    !ctx.verify(&gens),
                    "BatchVerifyContext must reject corrupted t_hat at {corrupt_idx} in m={m}"
                );
            }

            // Mode 2: perturb taux
            {
                let mut proofs = build_batch_proofs(&gens, m, 20_000 + m as u64);
                proofs[corrupt_idx].taux = add_one_mod_fr(proofs[corrupt_idx].taux);
                assert!(
                    !verify_batch(&gens, &proofs),
                    "verify_batch must reject corrupted taux at {corrupt_idx} in m={m}"
                );

                let mut ctx = BatchVerifyContext::new();
                for &p in &proofs {
                    ctx.add(p).unwrap();
                }
                assert!(
                    !ctx.verify(&gens),
                    "BatchVerifyContext must reject corrupted taux at {corrupt_idx} in m={m}"
                );
            }

            // Mode 3: perturb IPA final scalar `a`
            {
                let mut proofs = build_batch_proofs(&gens, m, 30_000 + m as u64);
                proofs[corrupt_idx].ip_proof.a = add_one_mod_fr(proofs[corrupt_idx].ip_proof.a);
                assert!(
                    !verify_batch(&gens, &proofs),
                    "verify_batch must reject corrupted ip_proof.a at {corrupt_idx} in m={m}"
                );

                let mut ctx = BatchVerifyContext::new();
                for &p in &proofs {
                    ctx.add(p).unwrap();
                }
                assert!(
                    !ctx.verify(&gens),
                    "BatchVerifyContext must reject corrupted ip_proof.a at {corrupt_idx} in m={m}"
                );
            }

            // Mode 4: swap commitment V to a different value
            {
                let mut proofs = build_batch_proofs(&gens, m, 40_000 + m as u64);
                proofs[corrupt_idx].v = commit_value(
                    &gens,
                    u256::from(123_456u64),
                    deterministic_blinding(40_000 + m as u64 + corrupt_idx as u64),
                );
                assert!(
                    !verify_batch(&gens, &proofs),
                    "verify_batch must reject swapped commitment V at {corrupt_idx} in m={m}"
                );

                let mut ctx = BatchVerifyContext::new();
                for &p in &proofs {
                    ctx.add(p).unwrap();
                }
                assert!(
                    !ctx.verify(&gens),
                    "BatchVerifyContext must reject swapped commitment V at {corrupt_idx} in m={m}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MAX_BATCH + 1 capacity enforcement
// ---------------------------------------------------------------------------

#[test]
fn bulletproofs_batch_context_enforces_max_batch_plus_one() {
    assert_eq!(MAX_BATCH, 32);

    let gens = Generators::new();
    let proofs = build_batch_proofs(&gens, MAX_BATCH, 50_000);
    let extra = make_proof(&gens, u64::MAX, 50_999);

    let mut ctx = BatchVerifyContext::new();
    assert!(ctx.is_empty());

    for (i, &p) in proofs.iter().enumerate() {
        assert_eq!(ctx.add(p), Ok(()), "add #{i} within MAX_BATCH must succeed");
    }
    assert_eq!(ctx.len(), MAX_BATCH);

    // Adding the (MAX_BATCH + 1)-th proof must fail without mutating length or
    // invalidating the existing 32 proofs.
    assert_eq!(ctx.add(extra), Err(()));
    assert_eq!(ctx.len(), MAX_BATCH);
    assert!(ctx.verify(&gens));

    // Clearing restores capacity for a full batch again.
    ctx.clear();
    assert!(ctx.is_empty());
    assert_eq!(ctx.len(), 0);
    for &p in &proofs {
        assert_eq!(ctx.add(p), Ok(()));
    }
    assert_eq!(ctx.len(), MAX_BATCH);
    assert!(ctx.verify(&gens));
}
