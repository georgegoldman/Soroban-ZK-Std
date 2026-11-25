//! Stack-budget regression tests for Bulletproofs and Pippenger MSM (Issue #541).
//!
//! Soroban contracts execute on `wasm32v1-none` with a 64 KiB call/shadow stack.
//! Verifiers (`verify`, `verify_batch`) and the bounded-stack Pippenger MSM
//! (`g1_msm_pippenger`) must execute cleanly inside tightly bounded threads and
//! preserve exact verification semantics after removing large on-stack `[G1Affine; 64]`
//! and `[u256; 64]` temporaries.

extern crate std;

use ethnum::u256;
use soroban_zk_core::bulletproofs::{prove, verify, verify_batch, BatchVerifyContext, Generators};
use soroban_zk_core::{g1_msm_pippenger, Bn254};
use std::sync::Arc;

/// Use Soroban's 64 KiB budget in release builds; allow 128 KiB under unoptimized
/// host debug builds where LLVM spills loop temporaries more aggressively.
const VERIFY_THREAD_STACK_BYTES: usize = if cfg!(debug_assertions) {
    128 * 1024
} else {
    64 * 1024
};

#[test]
#[cfg_attr(miri, ignore)]
fn pippenger_msm_executes_within_64kb_stack_budget() {
    let gens = Arc::new(Generators::new());
    let scalars: [u256; 64] = core::array::from_fn(|i| u256::from((i as u64) + 1));

    let g_ref = Arc::clone(&gens);
    let handle = std::thread::Builder::new()
        .name("pippenger_64kb_stack".to_string())
        .stack_size(VERIFY_THREAD_STACK_BYTES)
        .spawn(move || {
            let msm_res = g1_msm_pippenger(&g_ref.g, &scalars).expect("64-point MSM succeeds");
            assert!(!msm_res.is_identity());

            // Verify linearity against splitting into two 32-point MSMs.
            let left = g1_msm_pippenger(&g_ref.g[..32], &scalars[..32]).expect("left half");
            let right = g1_msm_pippenger(&g_ref.g[32..], &scalars[32..]).expect("right half");
            assert_eq!(msm_res.to_affine(), left.add(&right).to_affine());
        })
        .expect("spawn pippenger thread");

    handle
        .join()
        .expect("pippenger MSM thread did not overflow");
}

#[test]
#[cfg_attr(miri, ignore)]
fn single_and_batch_bulletproof_verify_execute_within_64kb_stack_budget() {
    let gens = Arc::new(Generators::new());
    let values = [0u64, 1u64, 42u64, u64::MAX];
    let proofs: Vec<_> = values
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            prove(
                &gens,
                u256::from(v),
                u256::from((i as u64) + 5),
                &[0x33u8 + i as u8; 64],
            )
            .expect("proving valid 64-bit value succeeds")
        })
        .collect();

    let mut tampered = proofs[2];
    tampered.t_hat = Bn254::add(tampered.t_hat, u256::ONE);

    let g_ref = Arc::clone(&gens);
    let proofs_arc = Arc::new(proofs);
    let p_ref = Arc::clone(&proofs_arc);

    let handle = std::thread::Builder::new()
        .name("bulletproofs_verify_64kb_stack".to_string())
        .stack_size(VERIFY_THREAD_STACK_BYTES)
        .spawn(move || {
            for (idx, proof) in p_ref.iter().enumerate() {
                assert!(verify(&g_ref, proof), "valid proof {idx} failed verify");
            }
            assert!(!verify(&g_ref, &tampered), "tampered proof accepted");
            assert!(verify_batch(&g_ref, &p_ref), "valid batch rejected");

            let mut bad_batch = (*p_ref).clone();
            bad_batch[1].mu = Bn254::add(bad_batch[1].mu, u256::ONE);
            assert!(!verify_batch(&g_ref, &bad_batch), "tampered batch accepted");
        })
        .expect("spawn verifier thread");

    handle
        .join()
        .expect("bulletproofs verify/verify_batch thread did not overflow");

    // Also confirm BatchVerifyContext agrees on the same batch.
    let mut ctx = BatchVerifyContext::new();
    for proof in proofs_arc.iter().copied() {
        ctx.add(proof).expect("within MAX_BATCH");
    }
    assert!(ctx.verify(&gens));
}
